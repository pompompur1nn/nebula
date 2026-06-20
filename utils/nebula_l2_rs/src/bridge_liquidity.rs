use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type BridgeLiquidityResult<T> = Result<T, String>;

pub const BRIDGE_LIQUIDITY_PROTOCOL_VERSION: &str = "nebula-bridge-liquidity-v1";
pub const BRIDGE_LIQUIDITY_DEFAULT_BUCKET_SIZE: u64 = 10_000;
pub const BRIDGE_LIQUIDITY_DEFAULT_RELEASE_DELAY_BLOCKS: u64 = 4;
pub const BRIDGE_LIQUIDITY_DEFAULT_RELEASE_TTL_BLOCKS: u64 = 120;
pub const BRIDGE_LIQUIDITY_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 8;
pub const BRIDGE_LIQUIDITY_DEFAULT_MAX_RELEASE_UNITS_PER_BLOCK: u64 = 250_000;
pub const BRIDGE_LIQUIDITY_DEFAULT_MAX_QUEUE_DEPTH: u64 = 512;
pub const BRIDGE_LIQUIDITY_MIN_HEALTHY_COVERAGE_BPS: u64 = 10_000;
pub const BRIDGE_LIQUIDITY_WARN_COVERAGE_BPS: u64 = 9_500;
pub const BRIDGE_LIQUIDITY_MAX_BPS: u64 = 10_000;
pub const BRIDGE_LIQUIDITY_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const BRIDGE_LIQUIDITY_DEVNET_MONERO_NETWORK: &str = "monero-devnet";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ReserveLaneKind {
    Hot,
    Warm,
    Cold,
    MarketMaker,
    Insurance,
}

impl ReserveLaneKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Hot => "hot",
            Self::Warm => "warm",
            Self::Cold => "cold",
            Self::MarketMaker => "market_maker",
            Self::Insurance => "insurance",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ReserveLaneStatus {
    Active,
    Draining,
    Paused,
    Exhausted,
    Retired,
}

impl ReserveLaneStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Draining => "draining",
            Self::Paused => "paused",
            Self::Exhausted => "exhausted",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum WithdrawalBucketStatus {
    Open,
    Congested,
    Throttled,
    Suspended,
}

impl WithdrawalBucketStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Congested => "congested",
            Self::Throttled => "throttled",
            Self::Suspended => "suspended",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DelayedReleaseStatus {
    Queued,
    Ready,
    Assigned,
    Released,
    Cancelled,
    Expired,
}

impl DelayedReleaseStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Ready => "ready",
            Self::Assigned => "assigned",
            Self::Released => "released",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MarketMakerQuoteStatus {
    Open,
    Reserved,
    Filled,
    Cancelled,
    Expired,
}

impl MarketMakerQuoteStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Filled => "filled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EmergencyThrottleMode {
    Observe,
    RateLimit,
    DelayOnly,
    SponsorOnly,
    HaltWithdrawals,
}

impl EmergencyThrottleMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::RateLimit => "rate_limit",
            Self::DelayOnly => "delay_only",
            Self::SponsorOnly => "sponsor_only",
            Self::HaltWithdrawals => "halt_withdrawals",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EmergencyThrottleStatus {
    Inactive,
    Active,
    CoolingDown,
    Retired,
}

impl EmergencyThrottleStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Inactive => "inactive",
            Self::Active => "active",
            Self::CoolingDown => "cooling_down",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LiquidityProofStatus {
    Fresh,
    Watch,
    Stale,
    Disputed,
    Revoked,
}

impl LiquidityProofStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Watch => "watch",
            Self::Stale => "stale",
            Self::Disputed => "disputed",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SponsorshipStatus {
    Reserved,
    Applied,
    Reclaimed,
    Expired,
}

impl SponsorshipStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Reclaimed => "reclaimed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum NettingBatchStatus {
    Open,
    Netted,
    Released,
    Cancelled,
}

impl NettingBatchStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Netted => "netted",
            Self::Released => "released",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveLane {
    pub lane_id: String,
    pub label: String,
    pub lane_kind: ReserveLaneKind,
    pub asset_id: String,
    pub monero_network: String,
    pub reserve_address_hash_root: String,
    pub liquidity_proof_root: String,
    pub gross_reserve_units: u64,
    pub pending_inbound_units: u64,
    pub pending_outbound_units: u64,
    pub reserved_withdrawal_units: u64,
    pub target_capacity_units: u64,
    pub min_confirmations: u64,
    pub release_delay_blocks: u64,
    pub max_release_units_per_block: u64,
    pub priority: u64,
    pub status: ReserveLaneStatus,
    pub metadata_root: String,
}

impl ReserveLane {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: &str,
        lane_kind: ReserveLaneKind,
        asset_id: &str,
        monero_network: &str,
        reserve_address_hash_root: &str,
        gross_reserve_units: u64,
        target_capacity_units: u64,
        max_release_units_per_block: u64,
        min_confirmations: u64,
        priority: u64,
        metadata: &Value,
    ) -> BridgeLiquidityResult<Self> {
        if label.is_empty() {
            return Err("reserve lane label is required".to_string());
        }
        if asset_id.is_empty() {
            return Err("reserve lane asset id is required".to_string());
        }
        if monero_network.is_empty() {
            return Err("reserve lane monero network is required".to_string());
        }
        if reserve_address_hash_root.is_empty() {
            return Err("reserve lane address hash root is required".to_string());
        }
        let metadata_root =
            bridge_liquidity_payload_root("BRIDGE-LIQUIDITY-LANE-METADATA", metadata);
        let lane_id = reserve_lane_id(
            label,
            &lane_kind,
            asset_id,
            monero_network,
            reserve_address_hash_root,
        );
        Ok(Self {
            lane_id,
            label: label.to_string(),
            lane_kind,
            asset_id: asset_id.to_string(),
            monero_network: monero_network.to_string(),
            reserve_address_hash_root: reserve_address_hash_root.to_string(),
            liquidity_proof_root: String::new(),
            gross_reserve_units,
            pending_inbound_units: 0,
            pending_outbound_units: 0,
            reserved_withdrawal_units: 0,
            target_capacity_units,
            min_confirmations,
            release_delay_blocks: BRIDGE_LIQUIDITY_DEFAULT_RELEASE_DELAY_BLOCKS,
            max_release_units_per_block: max_release_units_per_block.max(1),
            priority,
            status: ReserveLaneStatus::Active,
            metadata_root,
        })
    }

    pub fn validate(&self) -> BridgeLiquidityResult<()> {
        if self.lane_id
            != reserve_lane_id(
                &self.label,
                &self.lane_kind,
                &self.asset_id,
                &self.monero_network,
                &self.reserve_address_hash_root,
            )
        {
            return Err("reserve lane id mismatch".to_string());
        }
        if self.max_release_units_per_block == 0 {
            return Err("reserve lane max release must be positive".to_string());
        }
        Ok(())
    }

    pub fn available_units(&self) -> u64 {
        self.gross_reserve_units
            .saturating_add(self.pending_inbound_units)
            .saturating_sub(self.pending_outbound_units)
            .saturating_sub(self.reserved_withdrawal_units)
    }

    pub fn liability_units(&self) -> u64 {
        self.pending_outbound_units
            .saturating_add(self.reserved_withdrawal_units)
    }

    pub fn utilization_bps(&self) -> u64 {
        bridge_liquidity_ratio_bps(
            self.target_capacity_units
                .saturating_sub(self.available_units()),
            self.target_capacity_units.max(1),
        )
    }

    pub fn coverage_bps(&self) -> u64 {
        if self.liability_units() == 0 {
            BRIDGE_LIQUIDITY_MIN_HEALTHY_COVERAGE_BPS
        } else {
            bridge_liquidity_ratio_bps(self.gross_reserve_units, self.liability_units())
        }
    }

    pub fn can_route(&self, amount: u64) -> bool {
        matches!(
            self.status,
            ReserveLaneStatus::Active | ReserveLaneStatus::Draining
        ) && amount > 0
            && self.available_units() >= amount
    }

    pub fn reserve_for_withdrawal(&mut self, amount: u64) -> BridgeLiquidityResult<()> {
        if !self.can_route(amount) {
            return Err("reserve lane cannot satisfy withdrawal amount".to_string());
        }
        self.reserved_withdrawal_units = self.reserved_withdrawal_units.saturating_add(amount);
        if self.available_units() == 0 {
            self.status = ReserveLaneStatus::Exhausted;
        }
        Ok(())
    }

    pub fn release_reserved(&mut self, amount: u64) {
        self.reserved_withdrawal_units = self.reserved_withdrawal_units.saturating_sub(amount);
    }

    pub fn apply_net_release(&mut self, net_release_units: u64) {
        self.pending_outbound_units = self
            .pending_outbound_units
            .saturating_add(net_release_units);
        self.gross_reserve_units = self.gross_reserve_units.saturating_sub(net_release_units);
    }

    pub fn set_liquidity_proof_root(&mut self, liquidity_proof_root: &str) {
        self.liquidity_proof_root = liquidity_proof_root.to_string();
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "bridge_liquidity_reserve_lane",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_LIQUIDITY_PROTOCOL_VERSION,
            "lane_id": self.lane_id,
            "label": self.label,
            "lane_kind": self.lane_kind.as_str(),
            "asset_id": self.asset_id,
            "monero_network": self.monero_network,
            "reserve_address_hash_root": self.reserve_address_hash_root,
            "liquidity_proof_root": self.liquidity_proof_root,
            "gross_reserve_units": self.gross_reserve_units,
            "pending_inbound_units": self.pending_inbound_units,
            "pending_outbound_units": self.pending_outbound_units,
            "reserved_withdrawal_units": self.reserved_withdrawal_units,
            "available_units": self.available_units(),
            "target_capacity_units": self.target_capacity_units,
            "liability_units": self.liability_units(),
            "coverage_bps": self.coverage_bps(),
            "utilization_bps": self.utilization_bps(),
            "min_confirmations": self.min_confirmations,
            "release_delay_blocks": self.release_delay_blocks,
            "max_release_units_per_block": self.max_release_units_per_block,
            "priority": self.priority,
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root,
        })
    }

    pub fn lane_root(&self) -> String {
        domain_hash(
            "BRIDGE-LIQUIDITY-RESERVE-LANE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalLiquidityBucket {
    pub bucket_id: String,
    pub lane_id: String,
    pub min_amount: u64,
    pub max_amount: u64,
    pub release_delay_blocks: u64,
    pub max_release_units_per_batch: u64,
    pub target_liquidity_units: u64,
    pub available_liquidity_units: u64,
    pub reserved_liquidity_units: u64,
    pub queued_withdrawal_count: u64,
    pub queued_withdrawal_units: u64,
    pub sponsor_budget_units: u64,
    pub sponsor_spent_units: u64,
    pub priority: u64,
    pub status: WithdrawalBucketStatus,
}

impl WithdrawalLiquidityBucket {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_id: &str,
        min_amount: u64,
        max_amount: u64,
        target_liquidity_units: u64,
        available_liquidity_units: u64,
        max_release_units_per_batch: u64,
        release_delay_blocks: u64,
        sponsor_budget_units: u64,
        priority: u64,
    ) -> BridgeLiquidityResult<Self> {
        if lane_id.is_empty() {
            return Err("withdrawal bucket lane id is required".to_string());
        }
        if max_amount != 0 && min_amount > max_amount {
            return Err("withdrawal bucket min amount exceeds max amount".to_string());
        }
        let bucket_id = withdrawal_liquidity_bucket_id(lane_id, min_amount, max_amount);
        Ok(Self {
            bucket_id,
            lane_id: lane_id.to_string(),
            min_amount,
            max_amount,
            release_delay_blocks,
            max_release_units_per_batch: max_release_units_per_batch.max(1),
            target_liquidity_units,
            available_liquidity_units,
            reserved_liquidity_units: 0,
            queued_withdrawal_count: 0,
            queued_withdrawal_units: 0,
            sponsor_budget_units,
            sponsor_spent_units: 0,
            priority,
            status: WithdrawalBucketStatus::Open,
        })
    }

    pub fn validate(&self) -> BridgeLiquidityResult<()> {
        if self.bucket_id
            != withdrawal_liquidity_bucket_id(&self.lane_id, self.min_amount, self.max_amount)
        {
            return Err("withdrawal bucket id mismatch".to_string());
        }
        if self.max_amount != 0 && self.min_amount > self.max_amount {
            return Err("withdrawal bucket min amount exceeds max amount".to_string());
        }
        Ok(())
    }

    pub fn contains_amount(&self, amount: u64) -> bool {
        amount >= self.min_amount && (self.max_amount == 0 || amount <= self.max_amount)
    }

    pub fn available_units(&self) -> u64 {
        self.available_liquidity_units
            .saturating_sub(self.reserved_liquidity_units)
    }

    pub fn sponsor_available_units(&self) -> u64 {
        self.sponsor_budget_units
            .saturating_sub(self.sponsor_spent_units)
    }

    pub fn can_route(&self, amount: u64) -> bool {
        matches!(
            self.status,
            WithdrawalBucketStatus::Open | WithdrawalBucketStatus::Congested
        ) && self.contains_amount(amount)
            && self.available_units() >= amount
    }

    pub fn reserve_for_withdrawal(&mut self, amount: u64) -> BridgeLiquidityResult<()> {
        if !self.can_route(amount) {
            return Err("withdrawal bucket cannot satisfy amount".to_string());
        }
        self.reserved_liquidity_units = self.reserved_liquidity_units.saturating_add(amount);
        self.queued_withdrawal_count = self.queued_withdrawal_count.saturating_add(1);
        self.queued_withdrawal_units = self.queued_withdrawal_units.saturating_add(amount);
        if self.queued_withdrawal_count >= BRIDGE_LIQUIDITY_DEFAULT_MAX_QUEUE_DEPTH {
            self.status = WithdrawalBucketStatus::Congested;
        }
        Ok(())
    }

    pub fn release_reserved(&mut self, amount: u64) {
        self.reserved_liquidity_units = self.reserved_liquidity_units.saturating_sub(amount);
        self.available_liquidity_units = self.available_liquidity_units.saturating_sub(amount);
        self.queued_withdrawal_units = self.queued_withdrawal_units.saturating_sub(amount);
        self.queued_withdrawal_count = self.queued_withdrawal_count.saturating_sub(1);
    }

    pub fn spend_sponsor_units(&mut self, amount: u64) -> BridgeLiquidityResult<()> {
        if amount > self.sponsor_available_units() {
            return Err("withdrawal bucket sponsor budget exceeded".to_string());
        }
        self.sponsor_spent_units = self.sponsor_spent_units.saturating_add(amount);
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "bridge_liquidity_withdrawal_bucket",
            "chain_id": CHAIN_ID,
            "bucket_id": self.bucket_id,
            "lane_id": self.lane_id,
            "min_amount": self.min_amount,
            "max_amount": self.max_amount,
            "release_delay_blocks": self.release_delay_blocks,
            "max_release_units_per_batch": self.max_release_units_per_batch,
            "target_liquidity_units": self.target_liquidity_units,
            "available_liquidity_units": self.available_liquidity_units,
            "reserved_liquidity_units": self.reserved_liquidity_units,
            "routeable_units": self.available_units(),
            "queued_withdrawal_count": self.queued_withdrawal_count,
            "queued_withdrawal_units": self.queued_withdrawal_units,
            "sponsor_budget_units": self.sponsor_budget_units,
            "sponsor_spent_units": self.sponsor_spent_units,
            "sponsor_available_units": self.sponsor_available_units(),
            "priority": self.priority,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelayedReleaseQueueItem {
    pub release_id: String,
    pub withdrawal_id: String,
    pub lane_id: String,
    pub bucket_id: String,
    pub nullifier_hash: String,
    pub recipient_address_hash: String,
    pub amount: u64,
    pub bridge_fee_units: u64,
    pub sponsored_fee_units: u64,
    pub maker_quote_id: String,
    pub liquidity_proof_root: String,
    pub queue_root_before: String,
    pub queued_at_height: u64,
    pub release_not_before_height: u64,
    pub expires_at_height: u64,
    pub priority: u64,
    pub status: DelayedReleaseStatus,
}

impl DelayedReleaseQueueItem {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        withdrawal_id: &str,
        lane_id: &str,
        bucket_id: &str,
        nullifier: &str,
        recipient_address_hash: &str,
        amount: u64,
        bridge_fee_units: u64,
        sponsored_fee_units: u64,
        maker_quote_id: &str,
        liquidity_proof_root: &str,
        queue_root_before: &str,
        queued_at_height: u64,
        release_delay_blocks: u64,
        ttl_blocks: u64,
        priority: u64,
    ) -> BridgeLiquidityResult<Self> {
        if withdrawal_id.is_empty() {
            return Err("delayed release withdrawal id is required".to_string());
        }
        if lane_id.is_empty() || bucket_id.is_empty() {
            return Err("delayed release route ids are required".to_string());
        }
        if amount == 0 {
            return Err("delayed release amount must be positive".to_string());
        }
        if sponsored_fee_units > bridge_fee_units {
            return Err("delayed release sponsorship exceeds bridge fee".to_string());
        }
        let nullifier_hash = bridge_liquidity_string_root("BRIDGE-LIQUIDITY-NULLIFIER", nullifier);
        let release_not_before_height = queued_at_height.saturating_add(release_delay_blocks);
        let expires_at_height =
            queued_at_height.saturating_add(ttl_blocks.max(release_delay_blocks.saturating_add(1)));
        let release_id = delayed_release_id(
            withdrawal_id,
            lane_id,
            bucket_id,
            amount,
            recipient_address_hash,
            queued_at_height,
            &nullifier_hash,
        );
        Ok(Self {
            release_id,
            withdrawal_id: withdrawal_id.to_string(),
            lane_id: lane_id.to_string(),
            bucket_id: bucket_id.to_string(),
            nullifier_hash,
            recipient_address_hash: recipient_address_hash.to_string(),
            amount,
            bridge_fee_units,
            sponsored_fee_units,
            maker_quote_id: maker_quote_id.to_string(),
            liquidity_proof_root: liquidity_proof_root.to_string(),
            queue_root_before: queue_root_before.to_string(),
            queued_at_height,
            release_not_before_height,
            expires_at_height,
            priority,
            status: DelayedReleaseStatus::Queued,
        })
    }

    pub fn is_releasable(&self, height: u64) -> bool {
        matches!(
            self.status,
            DelayedReleaseStatus::Queued | DelayedReleaseStatus::Ready
        ) && height >= self.release_not_before_height
            && height <= self.expires_at_height
    }

    pub fn mark_ready(&self) -> Self {
        Self {
            status: DelayedReleaseStatus::Ready,
            ..self.clone()
        }
    }

    pub fn mark_assigned(&self) -> Self {
        Self {
            status: DelayedReleaseStatus::Assigned,
            ..self.clone()
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "bridge_liquidity_delayed_release",
            "chain_id": CHAIN_ID,
            "release_id": self.release_id,
            "withdrawal_id": self.withdrawal_id,
            "lane_id": self.lane_id,
            "bucket_id": self.bucket_id,
            "nullifier_hash": self.nullifier_hash,
            "recipient_address_hash": self.recipient_address_hash,
            "amount": self.amount,
            "bridge_fee_units": self.bridge_fee_units,
            "sponsored_fee_units": self.sponsored_fee_units,
            "maker_quote_id": self.maker_quote_id,
            "liquidity_proof_root": self.liquidity_proof_root,
            "queue_root_before": self.queue_root_before,
            "queued_at_height": self.queued_at_height,
            "release_not_before_height": self.release_not_before_height,
            "expires_at_height": self.expires_at_height,
            "priority": self.priority,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketMakerQuote {
    pub quote_id: String,
    pub maker_id: String,
    pub maker_commitment: String,
    pub lane_id: String,
    pub bucket_id: String,
    pub quote_asset_id: String,
    pub amount: u64,
    pub min_fill_amount: u64,
    pub max_fill_amount: u64,
    pub gross_fee_units: u64,
    pub spread_bps: u64,
    pub sponsor_units: u64,
    pub net_release_units: u64,
    pub inventory_root: String,
    pub liquidity_proof_root: String,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub priority: u64,
    pub status: MarketMakerQuoteStatus,
    pub metadata_root: String,
}

impl MarketMakerQuote {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        maker_id: &str,
        lane_id: &str,
        bucket_id: &str,
        quote_asset_id: &str,
        amount: u64,
        min_fill_amount: u64,
        max_fill_amount: u64,
        gross_fee_units: u64,
        spread_bps: u64,
        sponsor_units: u64,
        inventory: &Value,
        liquidity_proof_root: &str,
        valid_from_height: u64,
        valid_until_height: u64,
        priority: u64,
        metadata: &Value,
    ) -> BridgeLiquidityResult<Self> {
        if maker_id.is_empty() {
            return Err("market maker id is required".to_string());
        }
        if lane_id.is_empty() || bucket_id.is_empty() {
            return Err("market maker quote route ids are required".to_string());
        }
        if quote_asset_id.is_empty() {
            return Err("market maker quote asset id is required".to_string());
        }
        if amount == 0 {
            return Err("market maker quote amount must be positive".to_string());
        }
        if min_fill_amount > max_fill_amount || max_fill_amount > amount {
            return Err("market maker quote fill range is invalid".to_string());
        }
        if sponsor_units > gross_fee_units {
            return Err("market maker quote sponsorship exceeds fee".to_string());
        }
        if spread_bps > BRIDGE_LIQUIDITY_MAX_BPS {
            return Err("market maker quote spread exceeds 10000 bps".to_string());
        }
        if valid_until_height < valid_from_height {
            return Err("market maker quote validity window is invalid".to_string());
        }
        let maker_commitment = bridge_liquidity_string_root("BRIDGE-LIQUIDITY-MAKER", maker_id);
        let inventory_root =
            bridge_liquidity_payload_root("BRIDGE-LIQUIDITY-MAKER-INVENTORY", inventory);
        let metadata_root =
            bridge_liquidity_payload_root("BRIDGE-LIQUIDITY-QUOTE-METADATA", metadata);
        let net_release_units =
            amount.saturating_sub(gross_fee_units.saturating_sub(sponsor_units));
        let quote_id = market_maker_quote_id(
            &maker_commitment,
            lane_id,
            bucket_id,
            quote_asset_id,
            amount,
            gross_fee_units,
            spread_bps,
            valid_until_height,
            &inventory_root,
        );
        Ok(Self {
            quote_id,
            maker_id: maker_id.to_string(),
            maker_commitment,
            lane_id: lane_id.to_string(),
            bucket_id: bucket_id.to_string(),
            quote_asset_id: quote_asset_id.to_string(),
            amount,
            min_fill_amount,
            max_fill_amount,
            gross_fee_units,
            spread_bps,
            sponsor_units,
            net_release_units,
            inventory_root,
            liquidity_proof_root: liquidity_proof_root.to_string(),
            valid_from_height,
            valid_until_height,
            priority,
            status: MarketMakerQuoteStatus::Open,
            metadata_root,
        })
    }

    pub fn validate(&self) -> BridgeLiquidityResult<()> {
        if self.quote_id
            != market_maker_quote_id(
                &self.maker_commitment,
                &self.lane_id,
                &self.bucket_id,
                &self.quote_asset_id,
                self.amount,
                self.gross_fee_units,
                self.spread_bps,
                self.valid_until_height,
                &self.inventory_root,
            )
        {
            return Err("market maker quote id mismatch".to_string());
        }
        if self.sponsor_units > self.gross_fee_units {
            return Err("market maker quote sponsorship exceeds fee".to_string());
        }
        Ok(())
    }

    pub fn accepts(&self, lane_id: &str, bucket_id: &str, amount: u64, height: u64) -> bool {
        matches!(
            self.status,
            MarketMakerQuoteStatus::Open | MarketMakerQuoteStatus::Reserved
        ) && self.lane_id == lane_id
            && self.bucket_id == bucket_id
            && amount >= self.min_fill_amount
            && amount <= self.max_fill_amount
            && height >= self.valid_from_height
            && height <= self.valid_until_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "bridge_liquidity_market_maker_quote",
            "chain_id": CHAIN_ID,
            "quote_id": self.quote_id,
            "maker_commitment": self.maker_commitment,
            "lane_id": self.lane_id,
            "bucket_id": self.bucket_id,
            "quote_asset_id": self.quote_asset_id,
            "amount": self.amount,
            "min_fill_amount": self.min_fill_amount,
            "max_fill_amount": self.max_fill_amount,
            "gross_fee_units": self.gross_fee_units,
            "spread_bps": self.spread_bps,
            "sponsor_units": self.sponsor_units,
            "net_release_units": self.net_release_units,
            "inventory_root": self.inventory_root,
            "liquidity_proof_root": self.liquidity_proof_root,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "priority": self.priority,
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyThrottle {
    pub throttle_id: String,
    pub scope: String,
    pub mode: EmergencyThrottleMode,
    pub max_release_units_per_block: u64,
    pub max_queue_depth: u64,
    pub extra_delay_blocks: u64,
    pub sponsor_haircut_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub reason_root: String,
    pub authority_commitment: String,
    pub status: EmergencyThrottleStatus,
}

impl EmergencyThrottle {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: &str,
        mode: EmergencyThrottleMode,
        max_release_units_per_block: u64,
        max_queue_depth: u64,
        extra_delay_blocks: u64,
        sponsor_haircut_bps: u64,
        opened_at_height: u64,
        expires_at_height: u64,
        reason: &Value,
        authority_label: &str,
    ) -> BridgeLiquidityResult<Self> {
        if sponsor_haircut_bps > BRIDGE_LIQUIDITY_MAX_BPS {
            return Err("emergency throttle sponsor haircut exceeds 10000 bps".to_string());
        }
        if expires_at_height != 0 && expires_at_height < opened_at_height {
            return Err("emergency throttle expires before it opens".to_string());
        }
        let scope = if scope.is_empty() { "global" } else { scope };
        let reason_root = bridge_liquidity_payload_root("BRIDGE-LIQUIDITY-THROTTLE-REASON", reason);
        let authority_commitment =
            bridge_liquidity_string_root("BRIDGE-LIQUIDITY-THROTTLE-AUTHORITY", authority_label);
        let throttle_id = emergency_throttle_id(
            scope,
            &mode,
            opened_at_height,
            expires_at_height,
            &reason_root,
            &authority_commitment,
        );
        Ok(Self {
            throttle_id,
            scope: scope.to_string(),
            mode,
            max_release_units_per_block,
            max_queue_depth: max_queue_depth.max(1),
            extra_delay_blocks,
            sponsor_haircut_bps,
            opened_at_height,
            expires_at_height,
            reason_root,
            authority_commitment,
            status: EmergencyThrottleStatus::Active,
        })
    }

    pub fn is_active(&self, lane_id: &str, height: u64) -> bool {
        matches!(
            self.status,
            EmergencyThrottleStatus::Active | EmergencyThrottleStatus::CoolingDown
        ) && (self.scope == "global" || self.scope == lane_id)
            && height >= self.opened_at_height
            && (self.expires_at_height == 0 || height <= self.expires_at_height)
    }

    pub fn allows_withdrawals(&self, lane_id: &str, height: u64) -> bool {
        !(self.is_active(lane_id, height)
            && matches!(self.mode, EmergencyThrottleMode::HaltWithdrawals))
    }

    pub fn effective_sponsor_units(&self, sponsor_units: u64) -> u64 {
        sponsor_units
            .saturating_mul(BRIDGE_LIQUIDITY_MAX_BPS.saturating_sub(self.sponsor_haircut_bps))
            / BRIDGE_LIQUIDITY_MAX_BPS
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "bridge_liquidity_emergency_throttle",
            "chain_id": CHAIN_ID,
            "throttle_id": self.throttle_id,
            "scope": self.scope,
            "mode": self.mode.as_str(),
            "max_release_units_per_block": self.max_release_units_per_block,
            "max_queue_depth": self.max_queue_depth,
            "extra_delay_blocks": self.extra_delay_blocks,
            "sponsor_haircut_bps": self.sponsor_haircut_bps,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "reason_root": self.reason_root,
            "authority_commitment": self.authority_commitment,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityProof {
    pub proof_id: String,
    pub lane_id: String,
    pub reported_reserve_units: u64,
    pub reserve_amount_bucket: u64,
    pub pending_liability_units: u64,
    pub queued_withdrawal_units: u64,
    pub maker_inventory_units: u64,
    pub sponsored_fee_liability_units: u64,
    pub coverage_bps: u64,
    pub reserve_address_hash_root: String,
    pub withdrawal_queue_root: String,
    pub maker_quote_root: String,
    pub sponsorship_root: String,
    pub observer_set_root: String,
    pub proof_payload_root: String,
    pub reported_at_height: u64,
    pub expires_at_height: u64,
    pub status: LiquidityProofStatus,
}

impl LiquidityProof {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_id: &str,
        reported_reserve_units: u64,
        pending_liability_units: u64,
        queued_withdrawal_units: u64,
        maker_inventory_units: u64,
        sponsored_fee_liability_units: u64,
        reserve_address_hash_root: &str,
        withdrawal_queue_root: &str,
        maker_quote_root: &str,
        sponsorship_root: &str,
        observer_set_root: &str,
        reported_at_height: u64,
        expires_at_height: u64,
    ) -> BridgeLiquidityResult<Self> {
        if lane_id.is_empty() {
            return Err("liquidity proof lane id is required".to_string());
        }
        if reserve_address_hash_root.is_empty() || observer_set_root.is_empty() {
            return Err("liquidity proof roots are required".to_string());
        }
        if expires_at_height < reported_at_height {
            return Err("liquidity proof expires before report height".to_string());
        }
        let reserve_amount_bucket = bridge_liquidity_amount_bucket(reported_reserve_units);
        let liability_units = pending_liability_units
            .saturating_add(queued_withdrawal_units)
            .saturating_add(sponsored_fee_liability_units);
        let backing_units = reported_reserve_units.saturating_add(maker_inventory_units);
        let coverage_bps = if liability_units == 0 {
            BRIDGE_LIQUIDITY_MIN_HEALTHY_COVERAGE_BPS
        } else {
            bridge_liquidity_ratio_bps(backing_units, liability_units)
        };
        let status = if coverage_bps >= BRIDGE_LIQUIDITY_MIN_HEALTHY_COVERAGE_BPS {
            LiquidityProofStatus::Fresh
        } else if coverage_bps >= BRIDGE_LIQUIDITY_WARN_COVERAGE_BPS {
            LiquidityProofStatus::Watch
        } else {
            LiquidityProofStatus::Stale
        };
        let proof_payload = json!({
            "lane_id": lane_id,
            "reported_reserve_units": reported_reserve_units,
            "reserve_amount_bucket": reserve_amount_bucket,
            "pending_liability_units": pending_liability_units,
            "queued_withdrawal_units": queued_withdrawal_units,
            "maker_inventory_units": maker_inventory_units,
            "sponsored_fee_liability_units": sponsored_fee_liability_units,
            "coverage_bps": coverage_bps,
            "reserve_address_hash_root": reserve_address_hash_root,
            "withdrawal_queue_root": withdrawal_queue_root,
            "maker_quote_root": maker_quote_root,
            "sponsorship_root": sponsorship_root,
            "observer_set_root": observer_set_root,
            "reported_at_height": reported_at_height,
            "expires_at_height": expires_at_height,
        });
        let proof_payload_root =
            bridge_liquidity_payload_root("BRIDGE-LIQUIDITY-PROOF-PAYLOAD", &proof_payload);
        let proof_id = liquidity_proof_id(
            lane_id,
            reserve_amount_bucket,
            liability_units,
            reported_at_height,
            &proof_payload_root,
        );
        Ok(Self {
            proof_id,
            lane_id: lane_id.to_string(),
            reported_reserve_units,
            reserve_amount_bucket,
            pending_liability_units,
            queued_withdrawal_units,
            maker_inventory_units,
            sponsored_fee_liability_units,
            coverage_bps,
            reserve_address_hash_root: reserve_address_hash_root.to_string(),
            withdrawal_queue_root: withdrawal_queue_root.to_string(),
            maker_quote_root: maker_quote_root.to_string(),
            sponsorship_root: sponsorship_root.to_string(),
            observer_set_root: observer_set_root.to_string(),
            proof_payload_root,
            reported_at_height,
            expires_at_height,
            status,
        })
    }

    pub fn proof_root(&self) -> String {
        domain_hash(
            "BRIDGE-LIQUIDITY-PROOF",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "bridge_liquidity_proof",
            "chain_id": CHAIN_ID,
            "proof_id": self.proof_id,
            "lane_id": self.lane_id,
            "reported_reserve_units": self.reported_reserve_units,
            "reserve_amount_bucket": self.reserve_amount_bucket,
            "pending_liability_units": self.pending_liability_units,
            "queued_withdrawal_units": self.queued_withdrawal_units,
            "maker_inventory_units": self.maker_inventory_units,
            "sponsored_fee_liability_units": self.sponsored_fee_liability_units,
            "coverage_bps": self.coverage_bps,
            "reserve_address_hash_root": self.reserve_address_hash_root,
            "withdrawal_queue_root": self.withdrawal_queue_root,
            "maker_quote_root": self.maker_quote_root,
            "sponsorship_root": self.sponsorship_root,
            "observer_set_root": self.observer_set_root,
            "proof_payload_root": self.proof_payload_root,
            "reported_at_height": self.reported_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeWithdrawalSponsorship {
    pub sponsorship_id: String,
    pub withdrawal_id: String,
    pub lane_id: String,
    pub bucket_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub gross_fee_units: u64,
    pub sponsored_fee_units: u64,
    pub settled_fee_units: u64,
    pub sponsor_budget_root: String,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
    pub status: SponsorshipStatus,
}

impl LowFeeWithdrawalSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        withdrawal_id: &str,
        lane_id: &str,
        bucket_id: &str,
        sponsor_label: &str,
        fee_asset_id: &str,
        gross_fee_units: u64,
        sponsored_fee_units: u64,
        sponsor_budget_root: &str,
        reserved_at_height: u64,
        expires_at_height: u64,
    ) -> BridgeLiquidityResult<Self> {
        if withdrawal_id.is_empty() {
            return Err("low fee sponsorship withdrawal id is required".to_string());
        }
        if sponsored_fee_units > gross_fee_units {
            return Err("low fee sponsorship exceeds gross fee".to_string());
        }
        if expires_at_height < reserved_at_height {
            return Err("low fee sponsorship expires before reservation".to_string());
        }
        let sponsor_commitment =
            bridge_liquidity_string_root("BRIDGE-LIQUIDITY-SPONSOR", sponsor_label);
        let settled_fee_units = gross_fee_units.saturating_sub(sponsored_fee_units);
        let sponsorship_id = low_fee_withdrawal_sponsorship_id(
            withdrawal_id,
            lane_id,
            bucket_id,
            &sponsor_commitment,
            fee_asset_id,
            gross_fee_units,
            sponsored_fee_units,
            reserved_at_height,
        );
        Ok(Self {
            sponsorship_id,
            withdrawal_id: withdrawal_id.to_string(),
            lane_id: lane_id.to_string(),
            bucket_id: bucket_id.to_string(),
            sponsor_commitment,
            fee_asset_id: fee_asset_id.to_string(),
            gross_fee_units,
            sponsored_fee_units,
            settled_fee_units,
            sponsor_budget_root: sponsor_budget_root.to_string(),
            reserved_at_height,
            expires_at_height,
            status: SponsorshipStatus::Reserved,
        })
    }

    pub fn apply(&self) -> Self {
        Self {
            status: SponsorshipStatus::Applied,
            ..self.clone()
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "bridge_liquidity_low_fee_sponsorship",
            "chain_id": CHAIN_ID,
            "sponsorship_id": self.sponsorship_id,
            "withdrawal_id": self.withdrawal_id,
            "lane_id": self.lane_id,
            "bucket_id": self.bucket_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "gross_fee_units": self.gross_fee_units,
            "sponsored_fee_units": self.sponsored_fee_units,
            "settled_fee_units": self.settled_fee_units,
            "sponsor_budget_root": self.sponsor_budget_root,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeNettingBatch {
    pub batch_id: String,
    pub lane_id: String,
    pub bucket_id: String,
    pub height: u64,
    pub deposit_credit_units: u64,
    pub withdrawal_debit_units: u64,
    pub maker_fill_units: u64,
    pub sponsored_fee_units: u64,
    pub net_release_units: u64,
    pub netted_withdrawal_count: u64,
    pub input_queue_root: String,
    pub output_release_root: String,
    pub quote_root: String,
    pub sponsorship_root: String,
    pub proof_root: String,
    pub status: NettingBatchStatus,
}

impl BridgeNettingBatch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_id: &str,
        bucket_id: &str,
        height: u64,
        deposit_credit_units: u64,
        withdrawal_debit_units: u64,
        maker_fill_units: u64,
        sponsored_fee_units: u64,
        netted_withdrawal_count: u64,
        input_queue_root: &str,
        output_release_root: &str,
        quote_root: &str,
        sponsorship_root: &str,
        proof_root: &str,
    ) -> BridgeLiquidityResult<Self> {
        if lane_id.is_empty() || bucket_id.is_empty() {
            return Err("netting batch route ids are required".to_string());
        }
        let netting_credit = deposit_credit_units.saturating_add(maker_fill_units);
        let net_release_units = withdrawal_debit_units.saturating_sub(netting_credit);
        let batch_id = bridge_netting_batch_id(
            lane_id,
            bucket_id,
            height,
            input_queue_root,
            output_release_root,
            withdrawal_debit_units,
            deposit_credit_units,
        );
        Ok(Self {
            batch_id,
            lane_id: lane_id.to_string(),
            bucket_id: bucket_id.to_string(),
            height,
            deposit_credit_units,
            withdrawal_debit_units,
            maker_fill_units,
            sponsored_fee_units,
            net_release_units,
            netted_withdrawal_count,
            input_queue_root: input_queue_root.to_string(),
            output_release_root: output_release_root.to_string(),
            quote_root: quote_root.to_string(),
            sponsorship_root: sponsorship_root.to_string(),
            proof_root: proof_root.to_string(),
            status: NettingBatchStatus::Open,
        })
    }

    pub fn mark_netted(&self) -> Self {
        Self {
            status: NettingBatchStatus::Netted,
            ..self.clone()
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "bridge_liquidity_netting_batch",
            "chain_id": CHAIN_ID,
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "bucket_id": self.bucket_id,
            "height": self.height,
            "deposit_credit_units": self.deposit_credit_units,
            "withdrawal_debit_units": self.withdrawal_debit_units,
            "maker_fill_units": self.maker_fill_units,
            "sponsored_fee_units": self.sponsored_fee_units,
            "net_release_units": self.net_release_units,
            "netted_withdrawal_count": self.netted_withdrawal_count,
            "input_queue_root": self.input_queue_root,
            "output_release_root": self.output_release_root,
            "quote_root": self.quote_root,
            "sponsorship_root": self.sponsorship_root,
            "proof_root": self.proof_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeLiquidityRoute {
    pub route_id: String,
    pub withdrawal_id: String,
    pub lane_id: String,
    pub bucket_id: String,
    pub selected_quote_id: String,
    pub selected_sponsorship_id: String,
    pub amount: u64,
    pub gross_fee_units: u64,
    pub sponsored_fee_units: u64,
    pub release_delay_blocks: u64,
    pub release_not_before_height: u64,
    pub throttle_root: String,
    pub proof_root: String,
    pub route_score: u64,
    pub status: String,
}

impl BridgeLiquidityRoute {
    pub fn refresh_id(&mut self) {
        self.route_id = bridge_liquidity_route_id(
            &self.withdrawal_id,
            &self.lane_id,
            &self.bucket_id,
            &self.selected_quote_id,
            &self.selected_sponsorship_id,
            self.amount,
            self.gross_fee_units,
            self.sponsored_fee_units,
            self.release_not_before_height,
        );
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "bridge_liquidity_route",
            "chain_id": CHAIN_ID,
            "route_id": self.route_id,
            "withdrawal_id": self.withdrawal_id,
            "lane_id": self.lane_id,
            "bucket_id": self.bucket_id,
            "selected_quote_id": self.selected_quote_id,
            "selected_sponsorship_id": self.selected_sponsorship_id,
            "amount": self.amount,
            "gross_fee_units": self.gross_fee_units,
            "sponsored_fee_units": self.sponsored_fee_units,
            "settled_fee_units": self.gross_fee_units.saturating_sub(self.sponsored_fee_units),
            "release_delay_blocks": self.release_delay_blocks,
            "release_not_before_height": self.release_not_before_height,
            "throttle_root": self.throttle_root,
            "proof_root": self.proof_root,
            "route_score": self.route_score,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeLiquidityPublicRecord {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub payload_root: String,
    pub emitted_at_height: u64,
    pub payload: Value,
}

impl BridgeLiquidityPublicRecord {
    pub fn new(
        record_kind: &str,
        subject_id: &str,
        payload: &Value,
        emitted_at_height: u64,
    ) -> Self {
        let subject_root =
            bridge_liquidity_string_root("BRIDGE-LIQUIDITY-PUBLIC-SUBJECT", subject_id);
        let payload_root =
            bridge_liquidity_payload_root("BRIDGE-LIQUIDITY-PUBLIC-PAYLOAD", payload);
        let record_id = bridge_liquidity_public_record_id(
            record_kind,
            subject_id,
            &subject_root,
            &payload_root,
            emitted_at_height,
        );
        Self {
            record_id,
            record_kind: record_kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root,
            payload_root,
            emitted_at_height,
            payload: payload.clone(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "bridge_liquidity_public_record",
            "chain_id": CHAIN_ID,
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "payload_root": self.payload_root,
            "emitted_at_height": self.emitted_at_height,
            "payload": self.payload,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeLiquidityState {
    pub height: u64,
    pub active_lane_id: String,
    pub reserve_lanes: BTreeMap<String, ReserveLane>,
    pub withdrawal_buckets: BTreeMap<String, WithdrawalLiquidityBucket>,
    pub delayed_releases: BTreeMap<String, DelayedReleaseQueueItem>,
    pub market_maker_quotes: BTreeMap<String, MarketMakerQuote>,
    pub emergency_throttles: BTreeMap<String, EmergencyThrottle>,
    pub liquidity_proofs: BTreeMap<String, LiquidityProof>,
    pub sponsorships: BTreeMap<String, LowFeeWithdrawalSponsorship>,
    pub netting_batches: BTreeMap<String, BridgeNettingBatch>,
    pub public_records: BTreeMap<String, BridgeLiquidityPublicRecord>,
}

impl BridgeLiquidityState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn devnet(operator_label: &str) -> BridgeLiquidityResult<Self> {
        let operator_label = if operator_label.is_empty() {
            "devnet-bridge-liquidity"
        } else {
            operator_label
        };
        let mut state = Self::new();
        let hot_reserve_root = bridge_liquidity_string_set_root(
            "BRIDGE-LIQUIDITY-DEVNET-HOT-RESERVES",
            &[
                "xmr-devnet-hot-reserve-0".to_string(),
                "xmr-devnet-hot-reserve-1".to_string(),
            ],
        );
        let warm_reserve_root = bridge_liquidity_string_set_root(
            "BRIDGE-LIQUIDITY-DEVNET-WARM-RESERVES",
            &["xmr-devnet-warm-reserve-0".to_string()],
        );
        let maker_reserve_root = bridge_liquidity_string_set_root(
            "BRIDGE-LIQUIDITY-DEVNET-MAKER-RESERVES",
            &[
                "xmr-devnet-maker-a".to_string(),
                "xmr-devnet-maker-b".to_string(),
            ],
        );

        let hot_lane = ReserveLane::new(
            "devnet-hot-reserve",
            ReserveLaneKind::Hot,
            BRIDGE_LIQUIDITY_DEVNET_ASSET_ID,
            BRIDGE_LIQUIDITY_DEVNET_MONERO_NETWORK,
            &hot_reserve_root,
            5_000_000,
            8_000_000,
            500_000,
            10,
            100,
            &json!({"purpose": "fast small and medium withdrawals"}),
        )?;
        let hot_lane_id = hot_lane.lane_id.clone();
        state.insert_reserve_lane(hot_lane)?;

        let warm_lane = ReserveLane::new(
            "devnet-warm-reserve",
            ReserveLaneKind::Warm,
            BRIDGE_LIQUIDITY_DEVNET_ASSET_ID,
            BRIDGE_LIQUIDITY_DEVNET_MONERO_NETWORK,
            &warm_reserve_root,
            20_000_000,
            30_000_000,
            1_000_000,
            20,
            50,
            &json!({"purpose": "batched larger withdrawals"}),
        )?;
        let warm_lane_id = warm_lane.lane_id.clone();
        state.insert_reserve_lane(warm_lane)?;

        let maker_lane = ReserveLane::new(
            "devnet-maker-reserve",
            ReserveLaneKind::MarketMaker,
            BRIDGE_LIQUIDITY_DEVNET_ASSET_ID,
            BRIDGE_LIQUIDITY_DEVNET_MONERO_NETWORK,
            &maker_reserve_root,
            2_500_000,
            5_000_000,
            750_000,
            10,
            80,
            &json!({"purpose": "maker routed urgent withdrawals"}),
        )?;
        let maker_lane_id = maker_lane.lane_id.clone();
        state.insert_reserve_lane(maker_lane)?;
        state.active_lane_id = hot_lane_id.clone();

        let hot_small = WithdrawalLiquidityBucket::new(
            &hot_lane_id,
            1,
            10_000,
            1_000_000,
            1_000_000,
            100_000,
            2,
            25_000,
            100,
        )?;
        let hot_medium = WithdrawalLiquidityBucket::new(
            &hot_lane_id,
            10_001,
            250_000,
            3_000_000,
            3_000_000,
            250_000,
            4,
            75_000,
            90,
        )?;
        let warm_large = WithdrawalLiquidityBucket::new(
            &warm_lane_id,
            250_001,
            0,
            10_000_000,
            10_000_000,
            1_000_000,
            12,
            50_000,
            40,
        )?;
        let maker_fast = WithdrawalLiquidityBucket::new(
            &maker_lane_id,
            1,
            500_000,
            2_000_000,
            2_000_000,
            250_000,
            1,
            100_000,
            95,
        )?;
        let hot_small_id = hot_small.bucket_id.clone();
        let hot_medium_id = hot_medium.bucket_id.clone();
        let maker_fast_id = maker_fast.bucket_id.clone();
        state.insert_withdrawal_bucket(hot_small)?;
        state.insert_withdrawal_bucket(hot_medium)?;
        state.insert_withdrawal_bucket(warm_large)?;
        state.insert_withdrawal_bucket(maker_fast)?;

        let quote_a = MarketMakerQuote::new(
            "devnet-maker-a",
            &maker_lane_id,
            &maker_fast_id,
            BRIDGE_LIQUIDITY_DEVNET_ASSET_ID,
            500_000,
            1,
            250_000,
            35,
            45,
            10,
            &json!({"inventory_units": 750_000, "settlement": "monero-devnet"}),
            "",
            0,
            BRIDGE_LIQUIDITY_DEFAULT_QUOTE_TTL_BLOCKS,
            90,
            &json!({"route": "fast-maker"}),
        )?;
        let quote_b = MarketMakerQuote::new(
            "devnet-maker-b",
            &hot_lane_id,
            &hot_medium_id,
            BRIDGE_LIQUIDITY_DEVNET_ASSET_ID,
            250_000,
            10_001,
            200_000,
            20,
            30,
            5,
            &json!({"inventory_units": 250_000, "settlement": "monero-devnet"}),
            "",
            0,
            BRIDGE_LIQUIDITY_DEFAULT_QUOTE_TTL_BLOCKS,
            50,
            &json!({"route": "medium-overflow"}),
        )?;
        state.insert_market_maker_quote(quote_a)?;
        state.insert_market_maker_quote(quote_b)?;

        let mut throttle = EmergencyThrottle::new(
            "global",
            EmergencyThrottleMode::Observe,
            BRIDGE_LIQUIDITY_DEFAULT_MAX_RELEASE_UNITS_PER_BLOCK,
            BRIDGE_LIQUIDITY_DEFAULT_MAX_QUEUE_DEPTH,
            0,
            0,
            0,
            0,
            &json!({"mode": "devnet baseline monitor"}),
            operator_label,
        )?;
        throttle.status = EmergencyThrottleStatus::Inactive;
        state.insert_emergency_throttle(throttle)?;

        for lane_id in [
            hot_lane_id.as_str(),
            warm_lane_id.as_str(),
            maker_lane_id.as_str(),
        ] {
            let proof = state.build_liquidity_proof(
                lane_id,
                &[
                    "devnet-liquidity-observer-a".to_string(),
                    "devnet-liquidity-observer-b".to_string(),
                ],
                0,
                64,
            )?;
            state.insert_liquidity_proof(proof)?;
        }

        let bootstrap_batch = BridgeNettingBatch::new(
            &hot_lane_id,
            &hot_small_id,
            0,
            0,
            0,
            0,
            0,
            0,
            &state.delayed_release_root(),
            &merkle_root("BRIDGE-LIQUIDITY-BOOTSTRAP-RELEASE", &[]),
            &state.market_maker_quote_root(),
            &state.sponsorship_root(),
            &state.liquidity_proof_root(),
        )?;
        state.insert_netting_batch(bootstrap_batch)?;
        let record = state.public_record_without_root();
        state.publish_public_record("bridge_liquidity_devnet", "bootstrap", &record)?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn insert_reserve_lane(&mut self, lane: ReserveLane) -> BridgeLiquidityResult<ReserveLane> {
        lane.validate()?;
        if self.active_lane_id.is_empty() {
            self.active_lane_id = lane.lane_id.clone();
        }
        self.reserve_lanes
            .insert(lane.lane_id.clone(), lane.clone());
        Ok(lane)
    }

    pub fn insert_withdrawal_bucket(
        &mut self,
        bucket: WithdrawalLiquidityBucket,
    ) -> BridgeLiquidityResult<WithdrawalLiquidityBucket> {
        bucket.validate()?;
        if !self.reserve_lanes.contains_key(&bucket.lane_id) {
            return Err("withdrawal bucket lane is missing".to_string());
        }
        self.withdrawal_buckets
            .insert(bucket.bucket_id.clone(), bucket.clone());
        Ok(bucket)
    }

    pub fn insert_market_maker_quote(
        &mut self,
        quote: MarketMakerQuote,
    ) -> BridgeLiquidityResult<MarketMakerQuote> {
        quote.validate()?;
        if !self.reserve_lanes.contains_key(&quote.lane_id) {
            return Err("market maker quote lane is missing".to_string());
        }
        if !self.withdrawal_buckets.contains_key(&quote.bucket_id) {
            return Err("market maker quote bucket is missing".to_string());
        }
        self.market_maker_quotes
            .insert(quote.quote_id.clone(), quote.clone());
        Ok(quote)
    }

    pub fn insert_emergency_throttle(
        &mut self,
        throttle: EmergencyThrottle,
    ) -> BridgeLiquidityResult<EmergencyThrottle> {
        if throttle.sponsor_haircut_bps > BRIDGE_LIQUIDITY_MAX_BPS {
            return Err("emergency throttle sponsor haircut exceeds 10000 bps".to_string());
        }
        self.emergency_throttles
            .insert(throttle.throttle_id.clone(), throttle.clone());
        Ok(throttle)
    }

    pub fn insert_liquidity_proof(
        &mut self,
        proof: LiquidityProof,
    ) -> BridgeLiquidityResult<LiquidityProof> {
        let lane = self
            .reserve_lanes
            .get_mut(&proof.lane_id)
            .ok_or_else(|| "liquidity proof lane is missing".to_string())?;
        let proof_root = proof.proof_root();
        lane.set_liquidity_proof_root(&proof_root);
        self.liquidity_proofs
            .insert(proof.proof_id.clone(), proof.clone());
        Ok(proof)
    }

    pub fn insert_sponsorship(
        &mut self,
        sponsorship: LowFeeWithdrawalSponsorship,
    ) -> BridgeLiquidityResult<LowFeeWithdrawalSponsorship> {
        if sponsorship.sponsored_fee_units > sponsorship.gross_fee_units {
            return Err("low fee sponsorship exceeds gross fee".to_string());
        }
        self.sponsorships
            .insert(sponsorship.sponsorship_id.clone(), sponsorship.clone());
        Ok(sponsorship)
    }

    pub fn insert_netting_batch(
        &mut self,
        batch: BridgeNettingBatch,
    ) -> BridgeLiquidityResult<BridgeNettingBatch> {
        if !self.reserve_lanes.contains_key(&batch.lane_id) {
            return Err("netting batch lane is missing".to_string());
        }
        self.netting_batches
            .insert(batch.batch_id.clone(), batch.clone());
        Ok(batch)
    }

    pub fn publish_public_record(
        &mut self,
        record_kind: &str,
        subject_id: &str,
        payload: &Value,
    ) -> BridgeLiquidityResult<BridgeLiquidityPublicRecord> {
        if record_kind.is_empty() || subject_id.is_empty() {
            return Err("public record kind and subject are required".to_string());
        }
        let record =
            BridgeLiquidityPublicRecord::new(record_kind, subject_id, payload, self.height);
        self.public_records
            .insert(record.record_id.clone(), record.clone());
        Ok(record)
    }

    pub fn build_liquidity_proof(
        &self,
        lane_id: &str,
        observer_labels: &[String],
        reported_at_height: u64,
        ttl_blocks: u64,
    ) -> BridgeLiquidityResult<LiquidityProof> {
        let lane = self
            .reserve_lanes
            .get(lane_id)
            .ok_or_else(|| "liquidity proof lane is missing".to_string())?;
        let queued_units = self
            .delayed_releases
            .values()
            .filter(|release| release.lane_id == lane_id)
            .fold(0_u64, |total, release| total.saturating_add(release.amount));
        let maker_inventory_units = self
            .market_maker_quotes
            .values()
            .filter(|quote| quote.lane_id == lane_id)
            .fold(0_u64, |total, quote| total.saturating_add(quote.amount));
        let sponsored_fee_liability_units = self
            .sponsorships
            .values()
            .filter(|sponsorship| sponsorship.lane_id == lane_id)
            .fold(0_u64, |total, sponsorship| {
                total.saturating_add(sponsorship.sponsored_fee_units)
            });
        LiquidityProof::new(
            lane_id,
            lane.gross_reserve_units,
            lane.liability_units(),
            queued_units,
            maker_inventory_units,
            sponsored_fee_liability_units,
            &lane.reserve_address_hash_root,
            &self.delayed_release_root_for_lane(lane_id),
            &self.market_maker_quote_root_for_lane(lane_id),
            &self.sponsorship_root_for_lane(lane_id),
            &bridge_liquidity_string_set_root("BRIDGE-LIQUIDITY-OBSERVER-SET", observer_labels),
            reported_at_height,
            reported_at_height.saturating_add(ttl_blocks.max(1)),
        )
    }

    pub fn plan_withdrawal(
        &self,
        withdrawal_id: &str,
        amount: u64,
        gross_fee_units: u64,
    ) -> BridgeLiquidityResult<BridgeLiquidityRoute> {
        if withdrawal_id.is_empty() {
            return Err("withdrawal id is required".to_string());
        }
        if amount == 0 {
            return Err("withdrawal amount must be positive".to_string());
        }
        let (lane, bucket) = self.select_lane_and_bucket(amount)?;
        if self.withdrawals_halted(&lane.lane_id) {
            return Err(
                "bridge liquidity withdrawals are halted by emergency throttle".to_string(),
            );
        }
        let quote = self.best_quote(&lane.lane_id, &bucket.bucket_id, amount);
        let selected_quote_id = quote
            .as_ref()
            .map(|quote| quote.quote_id.clone())
            .unwrap_or_default();
        let release_delay_blocks = self.effective_release_delay(&lane, &bucket);
        let release_limit =
            self.effective_release_limit(&lane.lane_id, lane.max_release_units_per_block);
        let sponsored_fee_units = self.effective_sponsor_units(
            &lane.lane_id,
            gross_fee_units.min(bucket.sponsor_available_units()),
        );
        let release_not_before_height = self.height.saturating_add(release_delay_blocks);
        let proof_root = if lane.liquidity_proof_root.is_empty() {
            lane.lane_root()
        } else {
            lane.liquidity_proof_root.clone()
        };
        let route_score = lane
            .priority
            .saturating_mul(1_000_000)
            .saturating_add(bucket.priority.saturating_mul(10_000))
            .saturating_add(bucket.available_units().saturating_sub(amount))
            .saturating_add(quote.as_ref().map(|quote| quote.priority).unwrap_or(0));
        let status = if amount > release_limit {
            "queued_throttled"
        } else if selected_quote_id.is_empty() {
            "queued"
        } else {
            "queued_with_quote"
        }
        .to_string();
        let mut route = BridgeLiquidityRoute {
            route_id: String::new(),
            withdrawal_id: withdrawal_id.to_string(),
            lane_id: lane.lane_id,
            bucket_id: bucket.bucket_id,
            selected_quote_id,
            selected_sponsorship_id: String::new(),
            amount,
            gross_fee_units,
            sponsored_fee_units,
            release_delay_blocks,
            release_not_before_height,
            throttle_root: self.active_throttle_root(),
            proof_root,
            route_score,
            status,
        };
        route.refresh_id();
        Ok(route)
    }

    pub fn queue_withdrawal(
        &mut self,
        withdrawal_id: &str,
        nullifier: &str,
        recipient_address_hash: &str,
        amount: u64,
        gross_fee_units: u64,
        ttl_blocks: u64,
    ) -> BridgeLiquidityResult<BridgeLiquidityRoute> {
        let mut route = self.plan_withdrawal(withdrawal_id, amount, gross_fee_units)?;
        let sponsor_budget_root = self
            .withdrawal_buckets
            .get(&route.bucket_id)
            .map(WithdrawalLiquidityBucket::public_record)
            .map(|record| bridge_liquidity_payload_root("BRIDGE-LIQUIDITY-SPONSOR-BUDGET", &record))
            .unwrap_or_else(|| merkle_root("BRIDGE-LIQUIDITY-SPONSOR-BUDGET", &[]));
        let sponsorship = if route.sponsored_fee_units > 0 {
            Some(LowFeeWithdrawalSponsorship::new(
                withdrawal_id,
                &route.lane_id,
                &route.bucket_id,
                "bridge-liquidity-devnet-sponsor",
                BRIDGE_LIQUIDITY_DEVNET_ASSET_ID,
                gross_fee_units,
                route.sponsored_fee_units,
                &sponsor_budget_root,
                self.height,
                self.height
                    .saturating_add(ttl_blocks.max(BRIDGE_LIQUIDITY_DEFAULT_RELEASE_TTL_BLOCKS)),
            )?)
        } else {
            None
        };
        if let Some(sponsorship) = sponsorship.as_ref() {
            route.selected_sponsorship_id = sponsorship.sponsorship_id.clone();
            route.refresh_id();
        }
        let release = DelayedReleaseQueueItem::new(
            withdrawal_id,
            &route.lane_id,
            &route.bucket_id,
            nullifier,
            recipient_address_hash,
            amount,
            gross_fee_units,
            route.sponsored_fee_units,
            &route.selected_quote_id,
            &route.proof_root,
            &self.delayed_release_root(),
            self.height,
            route.release_delay_blocks,
            ttl_blocks.max(BRIDGE_LIQUIDITY_DEFAULT_RELEASE_TTL_BLOCKS),
            route.route_score,
        )?;
        self.reserve_lanes
            .get_mut(&route.lane_id)
            .ok_or_else(|| "route lane missing during queue".to_string())?
            .reserve_for_withdrawal(amount)?;
        let bucket = self
            .withdrawal_buckets
            .get_mut(&route.bucket_id)
            .ok_or_else(|| "route bucket missing during queue".to_string())?;
        bucket.reserve_for_withdrawal(amount)?;
        bucket.spend_sponsor_units(route.sponsored_fee_units)?;
        if let Some(sponsorship) = sponsorship {
            self.insert_sponsorship(sponsorship)?;
        }
        self.delayed_releases
            .insert(release.release_id.clone(), release);
        self.publish_public_record(
            "bridge_liquidity_route",
            &route.route_id,
            &route.public_record(),
        )?;
        Ok(route)
    }

    pub fn build_netting_batch(
        &mut self,
        lane_id: &str,
        bucket_id: &str,
        deposit_credit_units: u64,
        maker_fill_units: u64,
        max_items: usize,
    ) -> BridgeLiquidityResult<BridgeNettingBatch> {
        if !self.reserve_lanes.contains_key(lane_id) {
            return Err("netting batch lane is missing".to_string());
        }
        if !self.withdrawal_buckets.contains_key(bucket_id) {
            return Err("netting batch bucket is missing".to_string());
        }
        let mut ready = self
            .delayed_releases
            .values()
            .filter(|release| {
                release.lane_id == lane_id
                    && release.bucket_id == bucket_id
                    && release.is_releasable(self.height)
            })
            .cloned()
            .collect::<Vec<_>>();
        ready.sort_by(|left, right| {
            left.release_not_before_height
                .cmp(&right.release_not_before_height)
                .then_with(|| right.priority.cmp(&left.priority))
                .then_with(|| left.release_id.cmp(&right.release_id))
        });
        ready.truncate(max_items.max(1));
        let withdrawal_debit_units = ready
            .iter()
            .fold(0_u64, |total, release| total.saturating_add(release.amount));
        let sponsored_fee_units = ready.iter().fold(0_u64, |total, release| {
            total.saturating_add(release.sponsored_fee_units)
        });
        let output_release_root = delayed_release_root(&ready);
        let input_queue_root = self.delayed_release_root_for_lane(lane_id);
        let batch = BridgeNettingBatch::new(
            lane_id,
            bucket_id,
            self.height,
            deposit_credit_units,
            withdrawal_debit_units,
            maker_fill_units,
            sponsored_fee_units,
            ready.len() as u64,
            &input_queue_root,
            &output_release_root,
            &self.market_maker_quote_root_for_lane(lane_id),
            &self.sponsorship_root_for_lane(lane_id),
            &self.liquidity_proof_root_for_lane(lane_id),
        )?
        .mark_netted();
        for release in &ready {
            self.delayed_releases
                .insert(release.release_id.clone(), release.mark_assigned());
        }
        self.reserve_lanes
            .get_mut(lane_id)
            .ok_or_else(|| "netting batch lane is missing".to_string())?
            .release_reserved(withdrawal_debit_units);
        self.reserve_lanes
            .get_mut(lane_id)
            .ok_or_else(|| "netting batch lane is missing".to_string())?
            .apply_net_release(batch.net_release_units);
        self.withdrawal_buckets
            .get_mut(bucket_id)
            .ok_or_else(|| "netting batch bucket is missing".to_string())?
            .release_reserved(withdrawal_debit_units);
        self.insert_netting_batch(batch.clone())?;
        self.publish_public_record(
            "bridge_liquidity_netting_batch",
            &batch.batch_id,
            &batch.public_record(),
        )?;
        Ok(batch)
    }

    pub fn ready_releases(&self, height: u64) -> Vec<DelayedReleaseQueueItem> {
        let mut releases = self
            .delayed_releases
            .values()
            .filter(|release| release.is_releasable(height))
            .cloned()
            .collect::<Vec<_>>();
        releases.sort_by(|left, right| {
            left.release_not_before_height
                .cmp(&right.release_not_before_height)
                .then_with(|| right.priority.cmp(&left.priority))
                .then_with(|| left.release_id.cmp(&right.release_id))
        });
        releases
    }

    pub fn reserve_lane_root(&self) -> String {
        reserve_lane_root(&self.reserve_lanes.values().cloned().collect::<Vec<_>>())
    }

    pub fn withdrawal_bucket_root(&self) -> String {
        withdrawal_liquidity_bucket_root(
            &self
                .withdrawal_buckets
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn delayed_release_root(&self) -> String {
        delayed_release_root(&self.delayed_releases.values().cloned().collect::<Vec<_>>())
    }

    pub fn market_maker_quote_root(&self) -> String {
        market_maker_quote_root(
            &self
                .market_maker_quotes
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn emergency_throttle_root(&self) -> String {
        emergency_throttle_root(
            &self
                .emergency_throttles
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn active_throttle_root(&self) -> String {
        emergency_throttle_root(
            &self
                .emergency_throttles
                .values()
                .filter(|throttle| {
                    self.reserve_lanes
                        .keys()
                        .any(|lane_id| throttle.is_active(lane_id, self.height))
                        || throttle.is_active("global", self.height)
                })
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn liquidity_proof_root(&self) -> String {
        liquidity_proof_root(&self.liquidity_proofs.values().cloned().collect::<Vec<_>>())
    }

    pub fn sponsorship_root(&self) -> String {
        low_fee_withdrawal_sponsorship_root(
            &self.sponsorships.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn netting_batch_root(&self) -> String {
        bridge_netting_batch_root(&self.netting_batches.values().cloned().collect::<Vec<_>>())
    }

    pub fn public_record_root(&self) -> String {
        bridge_liquidity_public_record_root(
            &self.public_records.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn state_root(&self) -> String {
        bridge_liquidity_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("bridge liquidity state record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "bridge_liquidity_state",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_LIQUIDITY_PROTOCOL_VERSION,
            "height": self.height,
            "active_lane_id": self.active_lane_id,
            "reserve_lane_count": self.reserve_lanes.len() as u64,
            "withdrawal_bucket_count": self.withdrawal_buckets.len() as u64,
            "delayed_release_count": self.delayed_releases.len() as u64,
            "market_maker_quote_count": self.market_maker_quotes.len() as u64,
            "emergency_throttle_count": self.emergency_throttles.len() as u64,
            "liquidity_proof_count": self.liquidity_proofs.len() as u64,
            "sponsorship_count": self.sponsorships.len() as u64,
            "netting_batch_count": self.netting_batches.len() as u64,
            "public_record_count": self.public_records.len() as u64,
            "reserve_lane_root": self.reserve_lane_root(),
            "withdrawal_bucket_root": self.withdrawal_bucket_root(),
            "delayed_release_root": self.delayed_release_root(),
            "market_maker_quote_root": self.market_maker_quote_root(),
            "emergency_throttle_root": self.emergency_throttle_root(),
            "active_throttle_root": self.active_throttle_root(),
            "liquidity_proof_root": self.liquidity_proof_root(),
            "sponsorship_root": self.sponsorship_root(),
            "netting_batch_root": self.netting_batch_root(),
            "public_record_root": self.public_record_root(),
            "total_available_units": self.total_available_units(),
            "total_reserved_units": self.total_reserved_units(),
            "total_queued_units": self.total_queued_units(),
            "ready_release_count": self.ready_releases(self.height).len() as u64,
        })
    }

    pub fn total_available_units(&self) -> u64 {
        self.reserve_lanes.values().fold(0_u64, |total, lane| {
            total.saturating_add(lane.available_units())
        })
    }

    pub fn total_reserved_units(&self) -> u64 {
        self.reserve_lanes.values().fold(0_u64, |total, lane| {
            total.saturating_add(lane.reserved_withdrawal_units)
        })
    }

    pub fn total_queued_units(&self) -> u64 {
        self.delayed_releases
            .values()
            .fold(0_u64, |total, release| total.saturating_add(release.amount))
    }

    fn select_lane_and_bucket(
        &self,
        amount: u64,
    ) -> BridgeLiquidityResult<(ReserveLane, WithdrawalLiquidityBucket)> {
        let mut candidates =
            Vec::<(u64, String, String, ReserveLane, WithdrawalLiquidityBucket)>::new();
        for lane in self.reserve_lanes.values() {
            if !lane.can_route(amount) || self.withdrawals_halted(&lane.lane_id) {
                continue;
            }
            for bucket in self
                .withdrawal_buckets
                .values()
                .filter(|bucket| bucket.lane_id == lane.lane_id)
            {
                if !bucket.can_route(amount) {
                    continue;
                }
                let routeable_units =
                    std::cmp::min(lane.available_units(), bucket.available_units());
                let score = lane
                    .priority
                    .saturating_mul(1_000_000)
                    .saturating_add(bucket.priority.saturating_mul(10_000))
                    .saturating_add(routeable_units.saturating_sub(amount));
                candidates.push((
                    score,
                    lane.lane_id.clone(),
                    bucket.bucket_id.clone(),
                    lane.clone(),
                    bucket.clone(),
                ));
            }
        }
        candidates.sort_by(|left, right| {
            right
                .0
                .cmp(&left.0)
                .then_with(|| left.1.cmp(&right.1))
                .then_with(|| left.2.cmp(&right.2))
        });
        candidates
            .into_iter()
            .next()
            .map(|(_, _, _, lane, bucket)| (lane, bucket))
            .ok_or_else(|| "no bridge liquidity route can satisfy withdrawal".to_string())
    }

    fn best_quote(&self, lane_id: &str, bucket_id: &str, amount: u64) -> Option<MarketMakerQuote> {
        let mut quotes = self
            .market_maker_quotes
            .values()
            .filter(|quote| quote.accepts(lane_id, bucket_id, amount, self.height))
            .cloned()
            .collect::<Vec<_>>();
        quotes.sort_by(|left, right| {
            left.gross_fee_units
                .cmp(&right.gross_fee_units)
                .then_with(|| left.spread_bps.cmp(&right.spread_bps))
                .then_with(|| right.priority.cmp(&left.priority))
                .then_with(|| left.quote_id.cmp(&right.quote_id))
        });
        quotes.into_iter().next()
    }

    fn withdrawals_halted(&self, lane_id: &str) -> bool {
        self.emergency_throttles
            .values()
            .any(|throttle| !throttle.allows_withdrawals(lane_id, self.height))
    }

    fn effective_release_delay(
        &self,
        lane: &ReserveLane,
        bucket: &WithdrawalLiquidityBucket,
    ) -> u64 {
        let throttle_delay = self
            .emergency_throttles
            .values()
            .filter(|throttle| throttle.is_active(&lane.lane_id, self.height))
            .map(|throttle| throttle.extra_delay_blocks)
            .max()
            .unwrap_or(0);
        std::cmp::max(lane.release_delay_blocks, bucket.release_delay_blocks)
            .saturating_add(throttle_delay)
    }

    fn effective_release_limit(&self, lane_id: &str, default_limit: u64) -> u64 {
        self.emergency_throttles
            .values()
            .filter(|throttle| throttle.is_active(lane_id, self.height))
            .filter(|throttle| throttle.max_release_units_per_block > 0)
            .map(|throttle| throttle.max_release_units_per_block)
            .min()
            .unwrap_or(default_limit)
    }

    fn effective_sponsor_units(&self, lane_id: &str, sponsor_units: u64) -> u64 {
        self.emergency_throttles
            .values()
            .filter(|throttle| throttle.is_active(lane_id, self.height))
            .fold(sponsor_units, |units, throttle| {
                throttle.effective_sponsor_units(units)
            })
    }

    fn delayed_release_root_for_lane(&self, lane_id: &str) -> String {
        delayed_release_root(
            &self
                .delayed_releases
                .values()
                .filter(|release| release.lane_id == lane_id)
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    fn market_maker_quote_root_for_lane(&self, lane_id: &str) -> String {
        market_maker_quote_root(
            &self
                .market_maker_quotes
                .values()
                .filter(|quote| quote.lane_id == lane_id)
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    fn sponsorship_root_for_lane(&self, lane_id: &str) -> String {
        low_fee_withdrawal_sponsorship_root(
            &self
                .sponsorships
                .values()
                .filter(|sponsorship| sponsorship.lane_id == lane_id)
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    fn liquidity_proof_root_for_lane(&self, lane_id: &str) -> String {
        liquidity_proof_root(
            &self
                .liquidity_proofs
                .values()
                .filter(|proof| proof.lane_id == lane_id)
                .cloned()
                .collect::<Vec<_>>(),
        )
    }
}

pub fn reserve_lane_id(
    label: &str,
    lane_kind: &ReserveLaneKind,
    asset_id: &str,
    monero_network: &str,
    reserve_address_hash_root: &str,
) -> String {
    domain_hash(
        "BRIDGE-LIQUIDITY-RESERVE-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(lane_kind.as_str()),
            HashPart::Str(asset_id),
            HashPart::Str(monero_network),
            HashPart::Str(reserve_address_hash_root),
        ],
        32,
    )
}

pub fn withdrawal_liquidity_bucket_id(lane_id: &str, min_amount: u64, max_amount: u64) -> String {
    domain_hash(
        "BRIDGE-LIQUIDITY-WITHDRAWAL-BUCKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Int(min_amount as i128),
            HashPart::Int(max_amount as i128),
        ],
        32,
    )
}

pub fn delayed_release_id(
    withdrawal_id: &str,
    lane_id: &str,
    bucket_id: &str,
    amount: u64,
    recipient_address_hash: &str,
    queued_at_height: u64,
    nullifier_hash: &str,
) -> String {
    domain_hash(
        "BRIDGE-LIQUIDITY-DELAYED-RELEASE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(withdrawal_id),
            HashPart::Str(lane_id),
            HashPart::Str(bucket_id),
            HashPart::Int(amount as i128),
            HashPart::Str(recipient_address_hash),
            HashPart::Int(queued_at_height as i128),
            HashPart::Str(nullifier_hash),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn market_maker_quote_id(
    maker_commitment: &str,
    lane_id: &str,
    bucket_id: &str,
    quote_asset_id: &str,
    amount: u64,
    gross_fee_units: u64,
    spread_bps: u64,
    valid_until_height: u64,
    inventory_root: &str,
) -> String {
    domain_hash(
        "BRIDGE-LIQUIDITY-MARKET-MAKER-QUOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(maker_commitment),
            HashPart::Str(lane_id),
            HashPart::Str(bucket_id),
            HashPart::Str(quote_asset_id),
            HashPart::Int(amount as i128),
            HashPart::Int(gross_fee_units as i128),
            HashPart::Int(spread_bps as i128),
            HashPart::Int(valid_until_height as i128),
            HashPart::Str(inventory_root),
        ],
        32,
    )
}

pub fn emergency_throttle_id(
    scope: &str,
    mode: &EmergencyThrottleMode,
    opened_at_height: u64,
    expires_at_height: u64,
    reason_root: &str,
    authority_commitment: &str,
) -> String {
    domain_hash(
        "BRIDGE-LIQUIDITY-EMERGENCY-THROTTLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scope),
            HashPart::Str(mode.as_str()),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(expires_at_height as i128),
            HashPart::Str(reason_root),
            HashPart::Str(authority_commitment),
        ],
        32,
    )
}

pub fn liquidity_proof_id(
    lane_id: &str,
    reserve_amount_bucket: u64,
    liability_units: u64,
    reported_at_height: u64,
    proof_payload_root: &str,
) -> String {
    domain_hash(
        "BRIDGE-LIQUIDITY-PROOF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Int(reserve_amount_bucket as i128),
            HashPart::Int(liability_units as i128),
            HashPart::Int(reported_at_height as i128),
            HashPart::Str(proof_payload_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn low_fee_withdrawal_sponsorship_id(
    withdrawal_id: &str,
    lane_id: &str,
    bucket_id: &str,
    sponsor_commitment: &str,
    fee_asset_id: &str,
    gross_fee_units: u64,
    sponsored_fee_units: u64,
    reserved_at_height: u64,
) -> String {
    domain_hash(
        "BRIDGE-LIQUIDITY-LOW-FEE-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(withdrawal_id),
            HashPart::Str(lane_id),
            HashPart::Str(bucket_id),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(fee_asset_id),
            HashPart::Int(gross_fee_units as i128),
            HashPart::Int(sponsored_fee_units as i128),
            HashPart::Int(reserved_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn bridge_netting_batch_id(
    lane_id: &str,
    bucket_id: &str,
    height: u64,
    input_queue_root: &str,
    output_release_root: &str,
    withdrawal_debit_units: u64,
    deposit_credit_units: u64,
) -> String {
    domain_hash(
        "BRIDGE-LIQUIDITY-NETTING-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(bucket_id),
            HashPart::Int(height as i128),
            HashPart::Str(input_queue_root),
            HashPart::Str(output_release_root),
            HashPart::Int(withdrawal_debit_units as i128),
            HashPart::Int(deposit_credit_units as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn bridge_liquidity_route_id(
    withdrawal_id: &str,
    lane_id: &str,
    bucket_id: &str,
    quote_id: &str,
    sponsorship_id: &str,
    amount: u64,
    gross_fee_units: u64,
    sponsored_fee_units: u64,
    release_not_before_height: u64,
) -> String {
    domain_hash(
        "BRIDGE-LIQUIDITY-ROUTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(withdrawal_id),
            HashPart::Str(lane_id),
            HashPart::Str(bucket_id),
            HashPart::Str(quote_id),
            HashPart::Str(sponsorship_id),
            HashPart::Int(amount as i128),
            HashPart::Int(gross_fee_units as i128),
            HashPart::Int(sponsored_fee_units as i128),
            HashPart::Int(release_not_before_height as i128),
        ],
        32,
    )
}

pub fn bridge_liquidity_public_record_id(
    record_kind: &str,
    subject_id: &str,
    subject_root: &str,
    payload_root: &str,
    emitted_at_height: u64,
) -> String {
    domain_hash(
        "BRIDGE-LIQUIDITY-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(record_kind),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(payload_root),
            HashPart::Int(emitted_at_height as i128),
        ],
        32,
    )
}

pub fn reserve_lane_root(lanes: &[ReserveLane]) -> String {
    keyed_record_root(
        "BRIDGE-LIQUIDITY-RESERVE-LANE",
        lanes
            .iter()
            .map(|lane| (lane.lane_id.clone(), lane.public_record()))
            .collect(),
    )
}

pub fn withdrawal_liquidity_bucket_root(buckets: &[WithdrawalLiquidityBucket]) -> String {
    keyed_record_root(
        "BRIDGE-LIQUIDITY-WITHDRAWAL-BUCKET",
        buckets
            .iter()
            .map(|bucket| (bucket.bucket_id.clone(), bucket.public_record()))
            .collect(),
    )
}

pub fn delayed_release_root(releases: &[DelayedReleaseQueueItem]) -> String {
    keyed_record_root(
        "BRIDGE-LIQUIDITY-DELAYED-RELEASE",
        releases
            .iter()
            .map(|release| (release.release_id.clone(), release.public_record()))
            .collect(),
    )
}

pub fn market_maker_quote_root(quotes: &[MarketMakerQuote]) -> String {
    keyed_record_root(
        "BRIDGE-LIQUIDITY-MARKET-MAKER-QUOTE",
        quotes
            .iter()
            .map(|quote| (quote.quote_id.clone(), quote.public_record()))
            .collect(),
    )
}

pub fn emergency_throttle_root(throttles: &[EmergencyThrottle]) -> String {
    keyed_record_root(
        "BRIDGE-LIQUIDITY-EMERGENCY-THROTTLE",
        throttles
            .iter()
            .map(|throttle| (throttle.throttle_id.clone(), throttle.public_record()))
            .collect(),
    )
}

pub fn liquidity_proof_root(proofs: &[LiquidityProof]) -> String {
    keyed_record_root(
        "BRIDGE-LIQUIDITY-PROOF",
        proofs
            .iter()
            .map(|proof| (proof.proof_id.clone(), proof.public_record()))
            .collect(),
    )
}

pub fn low_fee_withdrawal_sponsorship_root(sponsorships: &[LowFeeWithdrawalSponsorship]) -> String {
    keyed_record_root(
        "BRIDGE-LIQUIDITY-LOW-FEE-SPONSORSHIP",
        sponsorships
            .iter()
            .map(|sponsorship| {
                (
                    sponsorship.sponsorship_id.clone(),
                    sponsorship.public_record(),
                )
            })
            .collect(),
    )
}

pub fn bridge_netting_batch_root(batches: &[BridgeNettingBatch]) -> String {
    keyed_record_root(
        "BRIDGE-LIQUIDITY-NETTING-BATCH",
        batches
            .iter()
            .map(|batch| (batch.batch_id.clone(), batch.public_record()))
            .collect(),
    )
}

pub fn bridge_liquidity_public_record_root(records: &[BridgeLiquidityPublicRecord]) -> String {
    keyed_record_root(
        "BRIDGE-LIQUIDITY-PUBLIC-RECORD",
        records
            .iter()
            .map(|record| (record.record_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn bridge_liquidity_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "BRIDGE-LIQUIDITY-STATE",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn bridge_liquidity_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn bridge_liquidity_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn bridge_liquidity_string_set_root(domain: &str, values: &[String]) -> String {
    let ordered = values.iter().cloned().collect::<BTreeSet<_>>();
    merkle_root(
        domain,
        &ordered
            .iter()
            .map(|value| Value::String(bridge_liquidity_string_root(domain, value)))
            .collect::<Vec<_>>(),
    )
}

pub fn bridge_liquidity_amount_bucket(amount: u64) -> u64 {
    if amount == 0 {
        0
    } else {
        amount.div_ceil(BRIDGE_LIQUIDITY_DEFAULT_BUCKET_SIZE) * BRIDGE_LIQUIDITY_DEFAULT_BUCKET_SIZE
    }
}

pub fn bridge_liquidity_ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return BRIDGE_LIQUIDITY_MAX_BPS;
    }
    ((numerator as u128).saturating_mul(BRIDGE_LIQUIDITY_MAX_BPS as u128) / denominator as u128)
        as u64
}

fn keyed_record_root(domain: &str, mut records: Vec<(String, Value)>) -> String {
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        domain,
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}
