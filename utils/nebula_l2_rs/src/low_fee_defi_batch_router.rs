use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash as stable_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type LowFeeDefiBatchRouterResult<T> = Result<T, String>;

pub const LOW_FEE_DEFI_BATCH_ROUTER_PROTOCOL_VERSION: &str = "nebula-low-fee-defi-batch-router-v1";
pub const LOW_FEE_DEFI_BATCH_ROUTER_SCHEMA_VERSION: u64 = 1;
pub const LOW_FEE_DEFI_BATCH_ROUTER_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const LOW_FEE_DEFI_BATCH_ROUTER_PQ_AUTH_SCHEME: &str = "ml-dsa-87-low-fee-defi-batch-router-v1";
pub const LOW_FEE_DEFI_BATCH_ROUTER_ORDERING_SCHEME: &str =
    "commit-reveal-bucketed-fair-ordering-v1";
pub const LOW_FEE_DEFI_BATCH_ROUTER_ROUTE_SCHEME: &str = "zk-private-defi-route-intent-v1";
pub const LOW_FEE_DEFI_BATCH_ROUTER_RECEIPT_SCHEME: &str =
    "zk-netted-defi-batch-settlement-receipt-v1";
pub const LOW_FEE_DEFI_BATCH_ROUTER_DEVNET_HEIGHT: u64 = 512;
pub const LOW_FEE_DEFI_BATCH_ROUTER_MAX_BPS: u64 = 10_000;
pub const LOW_FEE_DEFI_BATCH_ROUTER_DEFAULT_EPOCH_BLOCKS: u64 = 240;
pub const LOW_FEE_DEFI_BATCH_ROUTER_DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 6;
pub const LOW_FEE_DEFI_BATCH_ROUTER_DEFAULT_INTENT_TTL_BLOCKS: u64 = 24;
pub const LOW_FEE_DEFI_BATCH_ROUTER_DEFAULT_SOLVER_BOND_TTL_BLOCKS: u64 = 720;
pub const LOW_FEE_DEFI_BATCH_ROUTER_DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 720;
pub const LOW_FEE_DEFI_BATCH_ROUTER_DEFAULT_MAX_INTENTS_PER_BATCH: u64 = 256;
pub const LOW_FEE_DEFI_BATCH_ROUTER_DEFAULT_MAX_ROUTE_HOPS: u64 = 8;
pub const LOW_FEE_DEFI_BATCH_ROUTER_DEFAULT_MIN_PRIVACY_BUCKET_SIZE: u64 = 64;
pub const LOW_FEE_DEFI_BATCH_ROUTER_DEFAULT_MAX_FEE_CEILING_BPS: u64 = 45;
pub const LOW_FEE_DEFI_BATCH_ROUTER_DEFAULT_MAX_SOLVER_SHARE_BPS: u64 = 7_500;
pub const LOW_FEE_DEFI_BATCH_ROUTER_DEFAULT_MIN_BOND_COVERAGE_BPS: u64 = 11_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefiActionKind {
    Swap,
    Lend,
    Borrow,
    Repay,
    VaultDeposit,
    VaultWithdraw,
    LiquidityAdd,
    LiquidityRemove,
}

impl DefiActionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Swap => "swap",
            Self::Lend => "lend",
            Self::Borrow => "borrow",
            Self::Repay => "repay",
            Self::VaultDeposit => "vault_deposit",
            Self::VaultWithdraw => "vault_withdraw",
            Self::LiquidityAdd => "liquidity_add",
            Self::LiquidityRemove => "liquidity_remove",
        }
    }

    pub fn default_fee_ceiling_bps(self) -> u64 {
        match self {
            Self::Swap => 35,
            Self::Lend => 18,
            Self::Borrow => 28,
            Self::Repay => 12,
            Self::VaultDeposit => 16,
            Self::VaultWithdraw => 20,
            Self::LiquidityAdd => 24,
            Self::LiquidityRemove => 24,
        }
    }

    pub fn default_privacy_cost_bps(self) -> u64 {
        match self {
            Self::Swap => 180,
            Self::Lend => 130,
            Self::Borrow => 160,
            Self::Repay => 110,
            Self::VaultDeposit => 120,
            Self::VaultWithdraw => 150,
            Self::LiquidityAdd => 170,
            Self::LiquidityRemove => 170,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteIntentStatus {
    Queued,
    Bucketed,
    Packed,
    Netted,
    Settled,
    Expired,
    Cancelled,
    Rejected,
}

impl RouteIntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Bucketed => "bucketed",
            Self::Packed => "packed",
            Self::Netted => "netted",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Rejected => "rejected",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Queued | Self::Bucketed | Self::Packed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverBondStatus {
    Active,
    Reserved,
    Released,
    Slashed,
    Expired,
    Paused,
}

impl SolverBondStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Reserved => "reserved",
            Self::Released => "released",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
            Self::Paused => "paused",
        }
    }

    pub fn reservable(self) -> bool {
        matches!(self, Self::Active | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyBucketStatus {
    Open,
    Sealed,
    Draining,
    Exhausted,
    Expired,
}

impl PrivacyBucketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Draining => "draining",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_intents(self) -> bool {
        matches!(self, Self::Open | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderingBatchStatus {
    Open,
    Sealed,
    Proving,
    Posted,
    Settled,
    Challenged,
    Abandoned,
}

impl OrderingBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Proving => "proving",
            Self::Posted => "posted",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Abandoned => "abandoned",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Sealed | Self::Proving | Self::Posted
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorCreditStatus {
    Available,
    Reserved,
    Spent,
    Expired,
    Revoked,
}

impl SponsorCreditStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Reserved => "reserved",
            Self::Spent => "spent",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn spendable(self) -> bool {
        matches!(self, Self::Available | Self::Reserved)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub epoch_blocks: u64,
    pub batch_window_blocks: u64,
    pub intent_ttl_blocks: u64,
    pub solver_bond_ttl_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub max_intents_per_batch: u64,
    pub max_route_hops: u64,
    pub min_privacy_bucket_size: u64,
    pub max_fee_ceiling_bps: u64,
    pub max_solver_share_bps: u64,
    pub min_bond_coverage_bps: u64,
    pub pq_authorization_scheme: String,
    pub ordering_scheme: String,
    pub route_commitment_scheme: String,
    pub settlement_receipt_scheme: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: LOW_FEE_DEFI_BATCH_ROUTER_PROTOCOL_VERSION.to_string(),
            schema_version: LOW_FEE_DEFI_BATCH_ROUTER_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            epoch_blocks: LOW_FEE_DEFI_BATCH_ROUTER_DEFAULT_EPOCH_BLOCKS,
            batch_window_blocks: LOW_FEE_DEFI_BATCH_ROUTER_DEFAULT_BATCH_WINDOW_BLOCKS,
            intent_ttl_blocks: LOW_FEE_DEFI_BATCH_ROUTER_DEFAULT_INTENT_TTL_BLOCKS,
            solver_bond_ttl_blocks: LOW_FEE_DEFI_BATCH_ROUTER_DEFAULT_SOLVER_BOND_TTL_BLOCKS,
            sponsor_ttl_blocks: LOW_FEE_DEFI_BATCH_ROUTER_DEFAULT_SPONSOR_TTL_BLOCKS,
            max_intents_per_batch: LOW_FEE_DEFI_BATCH_ROUTER_DEFAULT_MAX_INTENTS_PER_BATCH,
            max_route_hops: LOW_FEE_DEFI_BATCH_ROUTER_DEFAULT_MAX_ROUTE_HOPS,
            min_privacy_bucket_size: LOW_FEE_DEFI_BATCH_ROUTER_DEFAULT_MIN_PRIVACY_BUCKET_SIZE,
            max_fee_ceiling_bps: LOW_FEE_DEFI_BATCH_ROUTER_DEFAULT_MAX_FEE_CEILING_BPS,
            max_solver_share_bps: LOW_FEE_DEFI_BATCH_ROUTER_DEFAULT_MAX_SOLVER_SHARE_BPS,
            min_bond_coverage_bps: LOW_FEE_DEFI_BATCH_ROUTER_DEFAULT_MIN_BOND_COVERAGE_BPS,
            pq_authorization_scheme: LOW_FEE_DEFI_BATCH_ROUTER_PQ_AUTH_SCHEME.to_string(),
            ordering_scheme: LOW_FEE_DEFI_BATCH_ROUTER_ORDERING_SCHEME.to_string(),
            route_commitment_scheme: LOW_FEE_DEFI_BATCH_ROUTER_ROUTE_SCHEME.to_string(),
            settlement_receipt_scheme: LOW_FEE_DEFI_BATCH_ROUTER_RECEIPT_SCHEME.to_string(),
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            epoch_blocks: 120,
            batch_window_blocks: 4,
            intent_ttl_blocks: 16,
            max_intents_per_batch: 96,
            min_privacy_bucket_size: 32,
            ..Self::default()
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_defi_batch_router_config",
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "epoch_blocks": self.epoch_blocks,
            "batch_window_blocks": self.batch_window_blocks,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "solver_bond_ttl_blocks": self.solver_bond_ttl_blocks,
            "sponsor_ttl_blocks": self.sponsor_ttl_blocks,
            "max_intents_per_batch": self.max_intents_per_batch,
            "max_route_hops": self.max_route_hops,
            "min_privacy_bucket_size": self.min_privacy_bucket_size,
            "max_fee_ceiling_bps": self.max_fee_ceiling_bps,
            "max_solver_share_bps": self.max_solver_share_bps,
            "min_bond_coverage_bps": self.min_bond_coverage_bps,
            "pq_authorization_scheme": self.pq_authorization_scheme,
            "ordering_scheme": self.ordering_scheme,
            "route_commitment_scheme": self.route_commitment_scheme,
            "settlement_receipt_scheme": self.settlement_receipt_scheme,
            "hash_suite": LOW_FEE_DEFI_BATCH_ROUTER_HASH_SUITE,
        })
    }

    pub fn config_root(&self) -> String {
        payload_root("LOW-FEE-DEFI-BATCH-ROUTER-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> LowFeeDefiBatchRouterResult<String> {
        ensure_eq(
            "protocol version",
            &self.protocol_version,
            LOW_FEE_DEFI_BATCH_ROUTER_PROTOCOL_VERSION,
        )?;
        if self.schema_version != LOW_FEE_DEFI_BATCH_ROUTER_SCHEMA_VERSION {
            return Err("schema version mismatch".to_string());
        }
        ensure_eq("chain id", &self.chain_id, CHAIN_ID)?;
        ensure_positive("epoch blocks", self.epoch_blocks)?;
        ensure_positive("batch window blocks", self.batch_window_blocks)?;
        ensure_positive("intent ttl blocks", self.intent_ttl_blocks)?;
        ensure_positive("solver bond ttl blocks", self.solver_bond_ttl_blocks)?;
        ensure_positive("sponsor ttl blocks", self.sponsor_ttl_blocks)?;
        ensure_positive("max intents per batch", self.max_intents_per_batch)?;
        ensure_positive("max route hops", self.max_route_hops)?;
        ensure_positive("min privacy bucket size", self.min_privacy_bucket_size)?;
        ensure_bps("max fee ceiling bps", self.max_fee_ceiling_bps)?;
        ensure_bps("max solver share bps", self.max_solver_share_bps)?;
        if self.min_bond_coverage_bps < LOW_FEE_DEFI_BATCH_ROUTER_MAX_BPS {
            return Err("minimum bond coverage below one hundred percent".to_string());
        }
        ensure_eq(
            "pq authorization scheme",
            &self.pq_authorization_scheme,
            LOW_FEE_DEFI_BATCH_ROUTER_PQ_AUTH_SCHEME,
        )?;
        ensure_eq(
            "ordering scheme",
            &self.ordering_scheme,
            LOW_FEE_DEFI_BATCH_ROUTER_ORDERING_SCHEME,
        )?;
        ensure_eq(
            "route commitment scheme",
            &self.route_commitment_scheme,
            LOW_FEE_DEFI_BATCH_ROUTER_ROUTE_SCHEME,
        )?;
        ensure_eq(
            "settlement receipt scheme",
            &self.settlement_receipt_scheme,
            LOW_FEE_DEFI_BATCH_ROUTER_RECEIPT_SCHEME,
        )?;
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeCeiling {
    pub ceiling_id: String,
    pub action_kind: DefiActionKind,
    pub fee_asset_id: String,
    pub max_fee_bps: u64,
    pub max_fee_units: u64,
    pub solver_tip_bps: u64,
    pub sponsor_share_bps: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
}

impl FeeCeiling {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        action_kind: DefiActionKind,
        fee_asset_id: &str,
        max_fee_bps: u64,
        max_fee_units: u64,
        solver_tip_bps: u64,
        sponsor_share_bps: u64,
        valid_from_height: u64,
        valid_until_height: u64,
    ) -> LowFeeDefiBatchRouterResult<Self> {
        ensure_non_empty("fee asset id", fee_asset_id)?;
        let ceiling_id = fee_ceiling_id(
            action_kind,
            fee_asset_id,
            max_fee_bps,
            valid_from_height,
            valid_until_height,
        );
        let ceiling = Self {
            ceiling_id,
            action_kind,
            fee_asset_id: fee_asset_id.to_string(),
            max_fee_bps,
            max_fee_units,
            solver_tip_bps,
            sponsor_share_bps,
            valid_from_height,
            valid_until_height,
        };
        ceiling.validate()?;
        Ok(ceiling)
    }

    pub fn live_at(&self, height: u64) -> bool {
        self.valid_from_height <= height && height <= self.valid_until_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_defi_fee_ceiling",
            "protocol_version": LOW_FEE_DEFI_BATCH_ROUTER_PROTOCOL_VERSION,
            "ceiling_id": self.ceiling_id,
            "action_kind": self.action_kind.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "max_fee_bps": self.max_fee_bps,
            "max_fee_units": self.max_fee_units,
            "solver_tip_bps": self.solver_tip_bps,
            "sponsor_share_bps": self.sponsor_share_bps,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
        })
    }

    pub fn ceiling_root(&self) -> String {
        payload_root("LOW-FEE-DEFI-FEE-CEILING", &self.public_record())
    }

    pub fn validate(&self) -> LowFeeDefiBatchRouterResult<String> {
        ensure_non_empty("ceiling id", &self.ceiling_id)?;
        ensure_non_empty("fee asset id", &self.fee_asset_id)?;
        ensure_bps("max fee bps", self.max_fee_bps)?;
        ensure_positive("max fee units", self.max_fee_units)?;
        ensure_bps("solver tip bps", self.solver_tip_bps)?;
        ensure_bps("sponsor share bps", self.sponsor_share_bps)?;
        ensure_height_window(
            self.valid_from_height,
            self.valid_until_height,
            "fee ceiling",
        )?;
        Ok(self.ceiling_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBucket {
    pub bucket_id: String,
    pub status: PrivacyBucketStatus,
    pub action_kind: DefiActionKind,
    pub asset_pair_root: String,
    pub epoch_index: u64,
    pub target_size: u64,
    pub queued_intent_count: u64,
    pub reserved_privacy_bps: u64,
    pub consumed_privacy_bps: u64,
    pub commitment_root: String,
}

impl PrivacyBucket {
    pub fn new(
        action_kind: DefiActionKind,
        asset_pair_root: &str,
        epoch_index: u64,
        target_size: u64,
    ) -> LowFeeDefiBatchRouterResult<Self> {
        ensure_non_empty("asset pair root", asset_pair_root)?;
        ensure_positive("target size", target_size)?;
        let bucket_id = privacy_bucket_id(action_kind, asset_pair_root, epoch_index);
        let bucket = Self {
            bucket_id,
            status: PrivacyBucketStatus::Open,
            action_kind,
            asset_pair_root: asset_pair_root.to_string(),
            epoch_index,
            target_size,
            queued_intent_count: 0,
            reserved_privacy_bps: 0,
            consumed_privacy_bps: 0,
            commitment_root: string_root("LOW-FEE-DEFI-EMPTY-BUCKET-COMMITMENT", asset_pair_root),
        };
        bucket.validate()?;
        Ok(bucket)
    }

    pub fn reserve(&mut self, privacy_cost_bps: u64, commitment_root: &str) {
        self.queued_intent_count = self.queued_intent_count.saturating_add(1);
        self.reserved_privacy_bps = self.reserved_privacy_bps.saturating_add(privacy_cost_bps);
        self.commitment_root = string_root("LOW-FEE-DEFI-BUCKET-COMMITMENT", commitment_root);
        if self.queued_intent_count >= self.target_size {
            self.status = PrivacyBucketStatus::Sealed;
        }
    }

    pub fn consume(&mut self, privacy_cost_bps: u64) {
        self.reserved_privacy_bps = self.reserved_privacy_bps.saturating_sub(privacy_cost_bps);
        self.consumed_privacy_bps = self.consumed_privacy_bps.saturating_add(privacy_cost_bps);
        if self.status == PrivacyBucketStatus::Sealed {
            self.status = PrivacyBucketStatus::Draining;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_defi_privacy_bucket",
            "protocol_version": LOW_FEE_DEFI_BATCH_ROUTER_PROTOCOL_VERSION,
            "bucket_id": self.bucket_id,
            "status": self.status.as_str(),
            "action_kind": self.action_kind.as_str(),
            "asset_pair_root": self.asset_pair_root,
            "epoch_index": self.epoch_index,
            "target_size": self.target_size,
            "queued_intent_count": self.queued_intent_count,
            "reserved_privacy_bps": self.reserved_privacy_bps,
            "consumed_privacy_bps": self.consumed_privacy_bps,
            "commitment_root": self.commitment_root,
        })
    }

    pub fn bucket_root(&self) -> String {
        payload_root("LOW-FEE-DEFI-PRIVACY-BUCKET", &self.public_record())
    }

    pub fn validate(&self) -> LowFeeDefiBatchRouterResult<String> {
        ensure_non_empty("bucket id", &self.bucket_id)?;
        ensure_non_empty("asset pair root", &self.asset_pair_root)?;
        ensure_positive("target size", self.target_size)?;
        ensure_bps("reserved privacy bps", self.reserved_privacy_bps)?;
        ensure_bps("consumed privacy bps", self.consumed_privacy_bps)?;
        ensure_non_empty("commitment root", &self.commitment_root)?;
        Ok(self.bucket_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverBond {
    pub bond_id: String,
    pub status: SolverBondStatus,
    pub solver_commitment: String,
    pub bond_asset_id: String,
    pub total_bond_units: u64,
    pub reserved_bond_units: u64,
    pub slashed_bond_units: u64,
    pub max_batch_notional_units: u64,
    pub supported_action_kinds: Vec<DefiActionKind>,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub pq_authorization_root: String,
}

impl SolverBond {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        solver_commitment: &str,
        bond_asset_id: &str,
        total_bond_units: u64,
        max_batch_notional_units: u64,
        supported_action_kinds: Vec<DefiActionKind>,
        valid_from_height: u64,
        valid_until_height: u64,
        pq_authorization_root: &str,
    ) -> LowFeeDefiBatchRouterResult<Self> {
        ensure_non_empty("solver commitment", solver_commitment)?;
        ensure_non_empty("bond asset id", bond_asset_id)?;
        ensure_non_empty("pq authorization root", pq_authorization_root)?;
        let bond_id = solver_bond_id(
            solver_commitment,
            bond_asset_id,
            total_bond_units,
            valid_from_height,
        );
        let bond = Self {
            bond_id,
            status: SolverBondStatus::Active,
            solver_commitment: solver_commitment.to_string(),
            bond_asset_id: bond_asset_id.to_string(),
            total_bond_units,
            reserved_bond_units: 0,
            slashed_bond_units: 0,
            max_batch_notional_units,
            supported_action_kinds,
            valid_from_height,
            valid_until_height,
            pq_authorization_root: pq_authorization_root.to_string(),
        };
        bond.validate()?;
        Ok(bond)
    }

    pub fn available_bond_units(&self) -> u64 {
        self.total_bond_units
            .saturating_sub(self.reserved_bond_units)
            .saturating_sub(self.slashed_bond_units)
    }

    pub fn covers_action(&self, action_kind: DefiActionKind) -> bool {
        self.supported_action_kinds.contains(&action_kind)
    }

    pub fn live_at(&self, height: u64) -> bool {
        self.status.reservable()
            && self.valid_from_height <= height
            && height <= self.valid_until_height
    }

    pub fn reserve(&mut self, amount_units: u64) -> LowFeeDefiBatchRouterResult<()> {
        ensure_positive("bond reserve amount", amount_units)?;
        if amount_units > self.available_bond_units() {
            return Err("solver bond reserve exceeds available balance".to_string());
        }
        self.reserved_bond_units = self.reserved_bond_units.saturating_add(amount_units);
        self.status = SolverBondStatus::Reserved;
        Ok(())
    }

    pub fn release(&mut self, amount_units: u64) {
        self.reserved_bond_units = self.reserved_bond_units.saturating_sub(amount_units);
        if self.reserved_bond_units == 0 && self.status == SolverBondStatus::Reserved {
            self.status = SolverBondStatus::Active;
        }
    }

    pub fn slash(&mut self, amount_units: u64) {
        self.reserved_bond_units = self.reserved_bond_units.saturating_sub(amount_units);
        self.slashed_bond_units = self.slashed_bond_units.saturating_add(amount_units);
        self.status = SolverBondStatus::Slashed;
    }

    pub fn public_record(&self) -> Value {
        let supported_action_kinds = self
            .supported_action_kinds
            .iter()
            .map(|kind| kind.as_str())
            .collect::<Vec<_>>();
        json!({
            "kind": "low_fee_defi_solver_bond",
            "protocol_version": LOW_FEE_DEFI_BATCH_ROUTER_PROTOCOL_VERSION,
            "bond_id": self.bond_id,
            "status": self.status.as_str(),
            "solver_commitment": self.solver_commitment,
            "bond_asset_id": self.bond_asset_id,
            "total_bond_units": self.total_bond_units,
            "reserved_bond_units": self.reserved_bond_units,
            "slashed_bond_units": self.slashed_bond_units,
            "available_bond_units": self.available_bond_units(),
            "max_batch_notional_units": self.max_batch_notional_units,
            "supported_action_kinds": supported_action_kinds,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "pq_authorization_root": self.pq_authorization_root,
        })
    }

    pub fn bond_root(&self) -> String {
        payload_root("LOW-FEE-DEFI-SOLVER-BOND", &self.public_record())
    }

    pub fn validate(&self) -> LowFeeDefiBatchRouterResult<String> {
        ensure_non_empty("bond id", &self.bond_id)?;
        ensure_non_empty("solver commitment", &self.solver_commitment)?;
        ensure_non_empty("bond asset id", &self.bond_asset_id)?;
        ensure_positive("total bond units", self.total_bond_units)?;
        ensure_positive("max batch notional units", self.max_batch_notional_units)?;
        ensure_height_window(
            self.valid_from_height,
            self.valid_until_height,
            "solver bond",
        )?;
        ensure_non_empty("pq authorization root", &self.pq_authorization_root)?;
        if self.supported_action_kinds.is_empty() {
            return Err("solver bond has no supported action kinds".to_string());
        }
        if self
            .reserved_bond_units
            .saturating_add(self.slashed_bond_units)
            > self.total_bond_units
        {
            return Err("solver bond is over-reserved".to_string());
        }
        Ok(self.bond_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsoredExecutionCredit {
    pub credit_id: String,
    pub status: SponsorCreditStatus,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub total_credit_units: u64,
    pub reserved_credit_units: u64,
    pub spent_credit_units: u64,
    pub max_per_intent_units: u64,
    pub allowed_action_kinds: Vec<DefiActionKind>,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
}

impl SponsoredExecutionCredit {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_commitment: &str,
        fee_asset_id: &str,
        total_credit_units: u64,
        max_per_intent_units: u64,
        allowed_action_kinds: Vec<DefiActionKind>,
        valid_from_height: u64,
        valid_until_height: u64,
    ) -> LowFeeDefiBatchRouterResult<Self> {
        ensure_non_empty("sponsor commitment", sponsor_commitment)?;
        ensure_non_empty("fee asset id", fee_asset_id)?;
        let credit_id = sponsor_credit_id(
            sponsor_commitment,
            fee_asset_id,
            total_credit_units,
            valid_from_height,
        );
        let credit = Self {
            credit_id,
            status: SponsorCreditStatus::Available,
            sponsor_commitment: sponsor_commitment.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            total_credit_units,
            reserved_credit_units: 0,
            spent_credit_units: 0,
            max_per_intent_units,
            allowed_action_kinds,
            valid_from_height,
            valid_until_height,
        };
        credit.validate()?;
        Ok(credit)
    }

    pub fn available_credit_units(&self) -> u64 {
        self.total_credit_units
            .saturating_sub(self.reserved_credit_units)
            .saturating_sub(self.spent_credit_units)
    }

    pub fn allows_action(&self, action_kind: DefiActionKind) -> bool {
        self.allowed_action_kinds.contains(&action_kind)
    }

    pub fn reserve(&mut self, amount_units: u64) -> LowFeeDefiBatchRouterResult<()> {
        ensure_positive("sponsor credit reserve amount", amount_units)?;
        if amount_units > self.max_per_intent_units {
            return Err("sponsor credit exceeds per-intent ceiling".to_string());
        }
        if amount_units > self.available_credit_units() {
            return Err("sponsor credit reserve exceeds available balance".to_string());
        }
        self.reserved_credit_units = self.reserved_credit_units.saturating_add(amount_units);
        self.status = SponsorCreditStatus::Reserved;
        Ok(())
    }

    pub fn spend_reserved(&mut self, amount_units: u64) {
        self.reserved_credit_units = self.reserved_credit_units.saturating_sub(amount_units);
        self.spent_credit_units = self.spent_credit_units.saturating_add(amount_units);
        if self.available_credit_units() == 0 {
            self.status = SponsorCreditStatus::Spent;
        }
    }

    pub fn public_record(&self) -> Value {
        let allowed_action_kinds = self
            .allowed_action_kinds
            .iter()
            .map(|kind| kind.as_str())
            .collect::<Vec<_>>();
        json!({
            "kind": "low_fee_defi_sponsored_execution_credit",
            "protocol_version": LOW_FEE_DEFI_BATCH_ROUTER_PROTOCOL_VERSION,
            "credit_id": self.credit_id,
            "status": self.status.as_str(),
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "total_credit_units": self.total_credit_units,
            "reserved_credit_units": self.reserved_credit_units,
            "spent_credit_units": self.spent_credit_units,
            "available_credit_units": self.available_credit_units(),
            "max_per_intent_units": self.max_per_intent_units,
            "allowed_action_kinds": allowed_action_kinds,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
        })
    }

    pub fn credit_root(&self) -> String {
        payload_root("LOW-FEE-DEFI-SPONSORED-CREDIT", &self.public_record())
    }

    pub fn validate(&self) -> LowFeeDefiBatchRouterResult<String> {
        ensure_non_empty("credit id", &self.credit_id)?;
        ensure_non_empty("sponsor commitment", &self.sponsor_commitment)?;
        ensure_non_empty("fee asset id", &self.fee_asset_id)?;
        ensure_positive("total credit units", self.total_credit_units)?;
        ensure_positive("max per intent units", self.max_per_intent_units)?;
        ensure_height_window(
            self.valid_from_height,
            self.valid_until_height,
            "sponsor credit",
        )?;
        if self.allowed_action_kinds.is_empty() {
            return Err("sponsor credit has no allowed action kinds".to_string());
        }
        if self
            .reserved_credit_units
            .saturating_add(self.spent_credit_units)
            > self.total_credit_units
        {
            return Err("sponsor credit is over-reserved".to_string());
        }
        Ok(self.credit_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteIntent {
    pub intent_id: String,
    pub status: RouteIntentStatus,
    pub action_kind: DefiActionKind,
    pub owner_commitment: String,
    pub input_asset_id: String,
    pub output_asset_id: String,
    pub amount_in_commitment: String,
    pub min_amount_out_commitment: String,
    pub route_commitment_root: String,
    pub encrypted_witness_root: String,
    pub fee_ceiling_id: String,
    pub max_fee_units: u64,
    pub privacy_bucket_id: String,
    pub privacy_cost_bps: u64,
    pub sponsor_credit_id: Option<String>,
    pub sponsored_fee_units: u64,
    pub solver_bond_id: Option<String>,
    pub route_hop_count: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub nullifier: String,
}

impl RouteIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        action_kind: DefiActionKind,
        owner_commitment: &str,
        input_asset_id: &str,
        output_asset_id: &str,
        amount_in_commitment: &str,
        min_amount_out_commitment: &str,
        route_commitment_root: &str,
        encrypted_witness_root: &str,
        fee_ceiling_id: &str,
        max_fee_units: u64,
        privacy_bucket_id: &str,
        privacy_cost_bps: u64,
        sponsor_credit_id: Option<String>,
        sponsored_fee_units: u64,
        solver_bond_id: Option<String>,
        route_hop_count: u64,
        opened_at_height: u64,
        expires_at_height: u64,
        nullifier: &str,
    ) -> LowFeeDefiBatchRouterResult<Self> {
        ensure_non_empty("owner commitment", owner_commitment)?;
        ensure_non_empty("route commitment root", route_commitment_root)?;
        ensure_non_empty("nullifier", nullifier)?;
        let intent_id = route_intent_id(
            action_kind,
            owner_commitment,
            route_commitment_root,
            opened_at_height,
            nullifier,
        );
        let intent = Self {
            intent_id,
            status: RouteIntentStatus::Queued,
            action_kind,
            owner_commitment: owner_commitment.to_string(),
            input_asset_id: input_asset_id.to_string(),
            output_asset_id: output_asset_id.to_string(),
            amount_in_commitment: amount_in_commitment.to_string(),
            min_amount_out_commitment: min_amount_out_commitment.to_string(),
            route_commitment_root: route_commitment_root.to_string(),
            encrypted_witness_root: encrypted_witness_root.to_string(),
            fee_ceiling_id: fee_ceiling_id.to_string(),
            max_fee_units,
            privacy_bucket_id: privacy_bucket_id.to_string(),
            privacy_cost_bps,
            sponsor_credit_id,
            sponsored_fee_units,
            solver_bond_id,
            route_hop_count,
            opened_at_height,
            expires_at_height,
            nullifier: nullifier.to_string(),
        };
        intent.validate()?;
        Ok(intent)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_defi_route_intent",
            "protocol_version": LOW_FEE_DEFI_BATCH_ROUTER_PROTOCOL_VERSION,
            "intent_id": self.intent_id,
            "status": self.status.as_str(),
            "action_kind": self.action_kind.as_str(),
            "owner_commitment": self.owner_commitment,
            "input_asset_id": self.input_asset_id,
            "output_asset_id": self.output_asset_id,
            "amount_in_commitment": self.amount_in_commitment,
            "min_amount_out_commitment": self.min_amount_out_commitment,
            "route_commitment_root": self.route_commitment_root,
            "encrypted_witness_root": self.encrypted_witness_root,
            "fee_ceiling_id": self.fee_ceiling_id,
            "max_fee_units": self.max_fee_units,
            "privacy_bucket_id": self.privacy_bucket_id,
            "privacy_cost_bps": self.privacy_cost_bps,
            "sponsor_credit_id": self.sponsor_credit_id,
            "sponsored_fee_units": self.sponsored_fee_units,
            "solver_bond_id": self.solver_bond_id,
            "route_hop_count": self.route_hop_count,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "nullifier": self.nullifier,
        })
    }

    pub fn intent_root(&self) -> String {
        payload_root("LOW-FEE-DEFI-ROUTE-INTENT", &self.public_record())
    }

    pub fn validate(&self) -> LowFeeDefiBatchRouterResult<String> {
        ensure_non_empty("intent id", &self.intent_id)?;
        ensure_non_empty("owner commitment", &self.owner_commitment)?;
        ensure_non_empty("input asset id", &self.input_asset_id)?;
        ensure_non_empty("output asset id", &self.output_asset_id)?;
        ensure_non_empty("amount in commitment", &self.amount_in_commitment)?;
        ensure_non_empty("min amount out commitment", &self.min_amount_out_commitment)?;
        ensure_non_empty("route commitment root", &self.route_commitment_root)?;
        ensure_non_empty("encrypted witness root", &self.encrypted_witness_root)?;
        ensure_non_empty("fee ceiling id", &self.fee_ceiling_id)?;
        ensure_non_empty("privacy bucket id", &self.privacy_bucket_id)?;
        ensure_non_empty("nullifier", &self.nullifier)?;
        ensure_positive("max fee units", self.max_fee_units)?;
        ensure_bps("privacy cost bps", self.privacy_cost_bps)?;
        ensure_positive("route hop count", self.route_hop_count)?;
        ensure_height_window(
            self.opened_at_height,
            self.expires_at_height,
            "route intent",
        )?;
        Ok(self.intent_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderingBatch {
    pub batch_id: String,
    pub status: OrderingBatchStatus,
    pub action_kind: DefiActionKind,
    pub bucket_id: String,
    pub solver_bond_id: String,
    pub intent_ids: BTreeSet<String>,
    pub ordered_intent_root: String,
    pub net_position_root: String,
    pub sponsor_debit_root: String,
    pub fairness_commitment_root: String,
    pub mev_guard_root: String,
    pub opened_at_height: u64,
    pub sealed_at_height: Option<u64>,
    pub planned_settlement_height: u64,
}

impl OrderingBatch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        action_kind: DefiActionKind,
        bucket_id: &str,
        solver_bond_id: &str,
        intent_ids: BTreeSet<String>,
        fairness_commitment_root: &str,
        mev_guard_root: &str,
        opened_at_height: u64,
        planned_settlement_height: u64,
    ) -> LowFeeDefiBatchRouterResult<Self> {
        ensure_non_empty("bucket id", bucket_id)?;
        ensure_non_empty("solver bond id", solver_bond_id)?;
        ensure_non_empty("fairness commitment root", fairness_commitment_root)?;
        ensure_non_empty("mev guard root", mev_guard_root)?;
        if intent_ids.is_empty() {
            return Err("ordering batch has no intents".to_string());
        }
        let ordered_intent_root = string_set_root("LOW-FEE-DEFI-ORDERED-INTENT-SET", &intent_ids);
        let batch_id = ordering_batch_id(
            action_kind,
            bucket_id,
            solver_bond_id,
            &ordered_intent_root,
            opened_at_height,
        );
        let batch = Self {
            batch_id,
            status: OrderingBatchStatus::Open,
            action_kind,
            bucket_id: bucket_id.to_string(),
            solver_bond_id: solver_bond_id.to_string(),
            intent_ids,
            ordered_intent_root,
            net_position_root: collection_root("LOW-FEE-DEFI-EMPTY-NET-POSITIONS", Vec::new()),
            sponsor_debit_root: collection_root("LOW-FEE-DEFI-EMPTY-SPONSOR-DEBITS", Vec::new()),
            fairness_commitment_root: fairness_commitment_root.to_string(),
            mev_guard_root: mev_guard_root.to_string(),
            opened_at_height,
            sealed_at_height: None,
            planned_settlement_height,
        };
        batch.validate()?;
        Ok(batch)
    }

    pub fn seal(
        &mut self,
        net_position_root: &str,
        sponsor_debit_root: &str,
        sealed_at_height: u64,
    ) -> LowFeeDefiBatchRouterResult<()> {
        ensure_non_empty("net position root", net_position_root)?;
        ensure_non_empty("sponsor debit root", sponsor_debit_root)?;
        if sealed_at_height < self.opened_at_height {
            return Err("batch seal height is before open height".to_string());
        }
        self.net_position_root = net_position_root.to_string();
        self.sponsor_debit_root = sponsor_debit_root.to_string();
        self.sealed_at_height = Some(sealed_at_height);
        self.status = OrderingBatchStatus::Sealed;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_defi_ordering_batch",
            "protocol_version": LOW_FEE_DEFI_BATCH_ROUTER_PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "action_kind": self.action_kind.as_str(),
            "bucket_id": self.bucket_id,
            "solver_bond_id": self.solver_bond_id,
            "intent_ids": self.intent_ids,
            "ordered_intent_root": self.ordered_intent_root,
            "net_position_root": self.net_position_root,
            "sponsor_debit_root": self.sponsor_debit_root,
            "fairness_commitment_root": self.fairness_commitment_root,
            "mev_guard_root": self.mev_guard_root,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "planned_settlement_height": self.planned_settlement_height,
        })
    }

    pub fn batch_root(&self) -> String {
        payload_root("LOW-FEE-DEFI-ORDERING-BATCH", &self.public_record())
    }

    pub fn validate(&self) -> LowFeeDefiBatchRouterResult<String> {
        ensure_non_empty("batch id", &self.batch_id)?;
        ensure_non_empty("bucket id", &self.bucket_id)?;
        ensure_non_empty("solver bond id", &self.solver_bond_id)?;
        ensure_non_empty("ordered intent root", &self.ordered_intent_root)?;
        ensure_non_empty("net position root", &self.net_position_root)?;
        ensure_non_empty("sponsor debit root", &self.sponsor_debit_root)?;
        ensure_non_empty("fairness commitment root", &self.fairness_commitment_root)?;
        ensure_non_empty("mev guard root", &self.mev_guard_root)?;
        if self.intent_ids.is_empty() {
            return Err("ordering batch has no intents".to_string());
        }
        Ok(self.batch_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementNetPosition {
    pub position_id: String,
    pub batch_id: String,
    pub asset_id: String,
    pub debit_units: u64,
    pub credit_units: u64,
    pub participant_root: String,
}

impl SettlementNetPosition {
    pub fn new(
        batch_id: &str,
        asset_id: &str,
        debit_units: u64,
        credit_units: u64,
        participant_root: &str,
    ) -> LowFeeDefiBatchRouterResult<Self> {
        ensure_non_empty("batch id", batch_id)?;
        ensure_non_empty("asset id", asset_id)?;
        ensure_non_empty("participant root", participant_root)?;
        let position_id = net_position_id(batch_id, asset_id, debit_units, credit_units);
        let position = Self {
            position_id,
            batch_id: batch_id.to_string(),
            asset_id: asset_id.to_string(),
            debit_units,
            credit_units,
            participant_root: participant_root.to_string(),
        };
        position.validate()?;
        Ok(position)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_defi_settlement_net_position",
            "protocol_version": LOW_FEE_DEFI_BATCH_ROUTER_PROTOCOL_VERSION,
            "position_id": self.position_id,
            "batch_id": self.batch_id,
            "asset_id": self.asset_id,
            "debit_units": self.debit_units,
            "credit_units": self.credit_units,
            "participant_root": self.participant_root,
        })
    }

    pub fn position_root(&self) -> String {
        payload_root("LOW-FEE-DEFI-NET-POSITION", &self.public_record())
    }

    pub fn validate(&self) -> LowFeeDefiBatchRouterResult<String> {
        ensure_non_empty("position id", &self.position_id)?;
        ensure_non_empty("batch id", &self.batch_id)?;
        ensure_non_empty("asset id", &self.asset_id)?;
        ensure_non_empty("participant root", &self.participant_root)?;
        if self.debit_units == 0 && self.credit_units == 0 {
            return Err("net position has no debit or credit".to_string());
        }
        Ok(self.position_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub ordered_intent_root: String,
    pub net_position_root: String,
    pub proof_root: String,
    pub settled_at_height: u64,
}

impl SettlementReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: &str,
        state_root_before: &str,
        state_root_after: &str,
        ordered_intent_root: &str,
        net_position_root: &str,
        proof_root: &str,
        settled_at_height: u64,
    ) -> LowFeeDefiBatchRouterResult<Self> {
        ensure_non_empty("batch id", batch_id)?;
        ensure_non_empty("state root before", state_root_before)?;
        ensure_non_empty("state root after", state_root_after)?;
        ensure_non_empty("ordered intent root", ordered_intent_root)?;
        ensure_non_empty("net position root", net_position_root)?;
        ensure_non_empty("proof root", proof_root)?;
        let receipt_id = settlement_receipt_id(batch_id, state_root_after, settled_at_height);
        let receipt = Self {
            receipt_id,
            batch_id: batch_id.to_string(),
            state_root_before: state_root_before.to_string(),
            state_root_after: state_root_after.to_string(),
            ordered_intent_root: ordered_intent_root.to_string(),
            net_position_root: net_position_root.to_string(),
            proof_root: proof_root.to_string(),
            settled_at_height,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_defi_settlement_receipt",
            "protocol_version": LOW_FEE_DEFI_BATCH_ROUTER_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "ordered_intent_root": self.ordered_intent_root,
            "net_position_root": self.net_position_root,
            "proof_root": self.proof_root,
            "settled_at_height": self.settled_at_height,
            "receipt_scheme": LOW_FEE_DEFI_BATCH_ROUTER_RECEIPT_SCHEME,
        })
    }

    pub fn receipt_root(&self) -> String {
        payload_root("LOW-FEE-DEFI-SETTLEMENT-RECEIPT", &self.public_record())
    }

    pub fn validate(&self) -> LowFeeDefiBatchRouterResult<String> {
        ensure_non_empty("receipt id", &self.receipt_id)?;
        ensure_non_empty("batch id", &self.batch_id)?;
        ensure_non_empty("state root before", &self.state_root_before)?;
        ensure_non_empty("state root after", &self.state_root_after)?;
        ensure_non_empty("ordered intent root", &self.ordered_intent_root)?;
        ensure_non_empty("net position root", &self.net_position_root)?;
        ensure_non_empty("proof root", &self.proof_root)?;
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub fee_ceiling_root: String,
    pub privacy_bucket_root: String,
    pub solver_bond_root: String,
    pub sponsor_credit_root: String,
    pub route_intent_root: String,
    pub ordering_batch_root: String,
    pub net_position_root: String,
    pub receipt_root: String,
    pub nullifier_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "fee_ceiling_root": self.fee_ceiling_root,
            "privacy_bucket_root": self.privacy_bucket_root,
            "solver_bond_root": self.solver_bond_root,
            "sponsor_credit_root": self.sponsor_credit_root,
            "route_intent_root": self.route_intent_root,
            "ordering_batch_root": self.ordering_batch_root,
            "net_position_root": self.net_position_root,
            "receipt_root": self.receipt_root,
            "nullifier_root": self.nullifier_root,
        })
    }

    pub fn roots_root(&self) -> String {
        payload_root("LOW-FEE-DEFI-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub fee_ceiling_count: u64,
    pub privacy_bucket_count: u64,
    pub open_privacy_bucket_count: u64,
    pub solver_bond_count: u64,
    pub active_solver_bond_count: u64,
    pub sponsor_credit_count: u64,
    pub spendable_sponsor_credit_count: u64,
    pub route_intent_count: u64,
    pub live_route_intent_count: u64,
    pub settled_route_intent_count: u64,
    pub ordering_batch_count: u64,
    pub live_ordering_batch_count: u64,
    pub net_position_count: u64,
    pub receipt_count: u64,
    pub total_sponsored_credit_units: u64,
    pub reserved_sponsored_credit_units: u64,
    pub spent_sponsored_credit_units: u64,
    pub total_solver_bond_units: u64,
    pub reserved_solver_bond_units: u64,
    pub slashed_solver_bond_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "fee_ceiling_count": self.fee_ceiling_count,
            "privacy_bucket_count": self.privacy_bucket_count,
            "open_privacy_bucket_count": self.open_privacy_bucket_count,
            "solver_bond_count": self.solver_bond_count,
            "active_solver_bond_count": self.active_solver_bond_count,
            "sponsor_credit_count": self.sponsor_credit_count,
            "spendable_sponsor_credit_count": self.spendable_sponsor_credit_count,
            "route_intent_count": self.route_intent_count,
            "live_route_intent_count": self.live_route_intent_count,
            "settled_route_intent_count": self.settled_route_intent_count,
            "ordering_batch_count": self.ordering_batch_count,
            "live_ordering_batch_count": self.live_ordering_batch_count,
            "net_position_count": self.net_position_count,
            "receipt_count": self.receipt_count,
            "total_sponsored_credit_units": self.total_sponsored_credit_units,
            "reserved_sponsored_credit_units": self.reserved_sponsored_credit_units,
            "spent_sponsored_credit_units": self.spent_sponsored_credit_units,
            "total_solver_bond_units": self.total_solver_bond_units,
            "reserved_solver_bond_units": self.reserved_solver_bond_units,
            "slashed_solver_bond_units": self.slashed_solver_bond_units,
        })
    }

    pub fn counters_root(&self) -> String {
        payload_root("LOW-FEE-DEFI-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub fee_ceilings: BTreeMap<String, FeeCeiling>,
    pub privacy_buckets: BTreeMap<String, PrivacyBucket>,
    pub solver_bonds: BTreeMap<String, SolverBond>,
    pub sponsor_credits: BTreeMap<String, SponsoredExecutionCredit>,
    pub route_intents: BTreeMap<String, RouteIntent>,
    pub ordering_batches: BTreeMap<String, OrderingBatch>,
    pub net_positions: BTreeMap<String, SettlementNetPosition>,
    pub receipts: BTreeMap<String, SettlementReceipt>,
    pub nullifier_index: BTreeMap<String, String>,
}

impl State {
    pub fn new(config: Config, height: u64) -> LowFeeDefiBatchRouterResult<Self> {
        config.validate()?;
        Ok(Self {
            height,
            config,
            fee_ceilings: BTreeMap::new(),
            privacy_buckets: BTreeMap::new(),
            solver_bonds: BTreeMap::new(),
            sponsor_credits: BTreeMap::new(),
            route_intents: BTreeMap::new(),
            ordering_batches: BTreeMap::new(),
            net_positions: BTreeMap::new(),
            receipts: BTreeMap::new(),
            nullifier_index: BTreeMap::new(),
        })
    }

    pub fn devnet() -> LowFeeDefiBatchRouterResult<State> {
        let mut state = Self::new(Config::devnet(), LOW_FEE_DEFI_BATCH_ROUTER_DEVNET_HEIGHT)?;
        for action_kind in [
            DefiActionKind::Swap,
            DefiActionKind::Lend,
            DefiActionKind::VaultDeposit,
        ] {
            let ceiling = FeeCeiling::new(
                action_kind,
                "wxmr-devnet",
                action_kind.default_fee_ceiling_bps(),
                4_000,
                8,
                6_500,
                state.height,
                state.height + state.config.sponsor_ttl_blocks,
            )?;
            state.insert_fee_ceiling(ceiling)?;
        }
        let asset_pair_root = collection_root(
            "LOW-FEE-DEFI-DEVNET-ASSET-PAIR",
            vec![json!({"input_asset_id": "wxmr-devnet", "output_asset_id": "dusd-devnet"})],
        );
        let bucket = PrivacyBucket::new(
            DefiActionKind::Swap,
            &asset_pair_root,
            current_epoch(state.height, state.config.epoch_blocks),
            state.config.min_privacy_bucket_size,
        )?;
        let bucket_id = bucket.bucket_id.clone();
        state.insert_privacy_bucket(bucket)?;
        let solver_bond = SolverBond::new(
            "solver:devnet:defi-router:alpha",
            "wxmr-devnet",
            500_000,
            2_500_000,
            vec![
                DefiActionKind::Swap,
                DefiActionKind::Lend,
                DefiActionKind::VaultDeposit,
            ],
            state.height,
            state.height + state.config.solver_bond_ttl_blocks,
            &string_root("LOW-FEE-DEFI-DEVNET-SOLVER-PQ-AUTH", "solver-alpha"),
        )?;
        let solver_bond_id = solver_bond.bond_id.clone();
        state.insert_solver_bond(solver_bond)?;
        let credit = SponsoredExecutionCredit::new(
            "sponsor:devnet:defi-router:low-fee",
            "wxmr-devnet",
            250_000,
            2_000,
            vec![DefiActionKind::Swap, DefiActionKind::Lend],
            state.height,
            state.height + state.config.sponsor_ttl_blocks,
        )?;
        let credit_id = credit.credit_id.clone();
        state.insert_sponsor_credit(credit)?;
        let fee_ceiling_id = state
            .fee_ceilings
            .values()
            .find(|ceiling| ceiling.action_kind == DefiActionKind::Swap)
            .map(|ceiling| ceiling.ceiling_id.clone())
            .ok_or_else(|| "devnet fee ceiling missing".to_string())?;
        let intent = RouteIntent::new(
            DefiActionKind::Swap,
            "owner:commitment:devnet:alice",
            "wxmr-devnet",
            "dusd-devnet",
            &string_root("LOW-FEE-DEFI-DEVNET-AMOUNT-IN", "alice-swap-in"),
            &string_root("LOW-FEE-DEFI-DEVNET-MIN-OUT", "alice-swap-out"),
            &string_root("LOW-FEE-DEFI-DEVNET-ROUTE", "stable-swap-route"),
            &string_root("LOW-FEE-DEFI-DEVNET-WITNESS", "encrypted-witness"),
            &fee_ceiling_id,
            2_000,
            &bucket_id,
            DefiActionKind::Swap.default_privacy_cost_bps(),
            Some(credit_id),
            1_000,
            Some(solver_bond_id),
            2,
            state.height,
            state.height + state.config.intent_ttl_blocks,
            "nullifier:devnet:defi-router:alice:swap:1",
        )?;
        state.queue_route_intent(intent)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> LowFeeDefiBatchRouterResult<String> {
        if height < self.height {
            return Err("low-fee defi batch router height cannot move backwards".to_string());
        }
        self.height = height;
        for intent in self.route_intents.values_mut() {
            if intent.status.live() && intent.expires_at_height < height {
                intent.status = RouteIntentStatus::Expired;
            }
        }
        for bond in self.solver_bonds.values_mut() {
            if bond.status.reservable() && bond.valid_until_height < height {
                bond.status = SolverBondStatus::Expired;
            }
        }
        for credit in self.sponsor_credits.values_mut() {
            if credit.status.spendable() && credit.valid_until_height < height {
                credit.status = SponsorCreditStatus::Expired;
            }
        }
        for bucket in self.privacy_buckets.values_mut() {
            if bucket.status.accepts_intents()
                && bucket.epoch_index < current_epoch(height, self.config.epoch_blocks)
            {
                bucket.status = PrivacyBucketStatus::Expired;
            }
        }
        self.validate()
    }

    pub fn update_height(&mut self, height: u64) -> LowFeeDefiBatchRouterResult<String> {
        self.set_height(height)
    }

    pub fn insert_fee_ceiling(
        &mut self,
        ceiling: FeeCeiling,
    ) -> LowFeeDefiBatchRouterResult<String> {
        let root = ceiling.validate()?;
        if ceiling.max_fee_bps > self.config.max_fee_ceiling_bps {
            return Err("fee ceiling exceeds configured maximum".to_string());
        }
        self.fee_ceilings
            .insert(ceiling.ceiling_id.clone(), ceiling);
        Ok(root)
    }

    pub fn insert_privacy_bucket(
        &mut self,
        bucket: PrivacyBucket,
    ) -> LowFeeDefiBatchRouterResult<String> {
        let root = bucket.validate()?;
        if bucket.target_size < self.config.min_privacy_bucket_size {
            return Err("privacy bucket target below configured minimum".to_string());
        }
        self.privacy_buckets
            .insert(bucket.bucket_id.clone(), bucket);
        Ok(root)
    }

    pub fn insert_solver_bond(&mut self, bond: SolverBond) -> LowFeeDefiBatchRouterResult<String> {
        let root = bond.validate()?;
        self.solver_bonds.insert(bond.bond_id.clone(), bond);
        Ok(root)
    }

    pub fn insert_sponsor_credit(
        &mut self,
        credit: SponsoredExecutionCredit,
    ) -> LowFeeDefiBatchRouterResult<String> {
        let root = credit.validate()?;
        self.sponsor_credits
            .insert(credit.credit_id.clone(), credit);
        Ok(root)
    }

    pub fn queue_route_intent(
        &mut self,
        mut intent: RouteIntent,
    ) -> LowFeeDefiBatchRouterResult<String> {
        let root = intent.validate()?;
        if intent.route_hop_count > self.config.max_route_hops {
            return Err("route hop count exceeds configured maximum".to_string());
        }
        if self.nullifier_index.contains_key(&intent.nullifier) {
            return Err("duplicate route intent nullifier".to_string());
        }
        let ceiling = self
            .fee_ceilings
            .get(&intent.fee_ceiling_id)
            .ok_or_else(|| "route intent references missing fee ceiling".to_string())?;
        if !ceiling.live_at(self.height) {
            return Err("route intent fee ceiling is not live".to_string());
        }
        if intent.max_fee_units > ceiling.max_fee_units {
            return Err("route intent exceeds fee ceiling units".to_string());
        }
        let bucket = self
            .privacy_buckets
            .get_mut(&intent.privacy_bucket_id)
            .ok_or_else(|| "route intent references missing privacy bucket".to_string())?;
        if !bucket.status.accepts_intents() {
            return Err("privacy bucket is not accepting intents".to_string());
        }
        if bucket.action_kind != intent.action_kind {
            return Err("privacy bucket action kind mismatch".to_string());
        }
        bucket.reserve(intent.privacy_cost_bps, &intent.route_commitment_root);
        if let Some(credit_id) = &intent.sponsor_credit_id {
            let credit = self
                .sponsor_credits
                .get_mut(credit_id)
                .ok_or_else(|| "route intent references missing sponsor credit".to_string())?;
            if !credit.allows_action(intent.action_kind) {
                return Err("sponsor credit does not allow action kind".to_string());
            }
            credit.reserve(intent.sponsored_fee_units)?;
        }
        if let Some(bond_id) = &intent.solver_bond_id {
            let bond = self
                .solver_bonds
                .get(bond_id)
                .ok_or_else(|| "route intent references missing solver bond".to_string())?;
            if !bond.covers_action(intent.action_kind) || !bond.live_at(self.height) {
                return Err("solver bond cannot cover route intent".to_string());
            }
        }
        intent.status = RouteIntentStatus::Bucketed;
        self.nullifier_index
            .insert(intent.nullifier.clone(), intent.intent_id.clone());
        self.route_intents.insert(intent.intent_id.clone(), intent);
        Ok(root)
    }

    pub fn open_ordering_batch(
        &mut self,
        action_kind: DefiActionKind,
        bucket_id: &str,
        solver_bond_id: &str,
        intent_ids: BTreeSet<String>,
        fairness_commitment_root: &str,
        mev_guard_root: &str,
    ) -> LowFeeDefiBatchRouterResult<String> {
        if intent_ids.len() as u64 > self.config.max_intents_per_batch {
            return Err("ordering batch exceeds configured intent limit".to_string());
        }
        let bond = self
            .solver_bonds
            .get_mut(solver_bond_id)
            .ok_or_else(|| "ordering batch references missing solver bond".to_string())?;
        if !bond.covers_action(action_kind) || !bond.live_at(self.height) {
            return Err("solver bond is not live for ordering batch".to_string());
        }
        let reserved_bond_units = intent_ids.len() as u64 * 1_000;
        bond.reserve(reserved_bond_units)?;
        let mut ordered = BTreeSet::new();
        for intent_id in &intent_ids {
            let intent = self
                .route_intents
                .get_mut(intent_id)
                .ok_or_else(|| "ordering batch references missing route intent".to_string())?;
            if intent.action_kind != action_kind {
                return Err("ordering batch action kind mismatch".to_string());
            }
            if intent.privacy_bucket_id != bucket_id {
                return Err("ordering batch privacy bucket mismatch".to_string());
            }
            if !intent.status.live() {
                return Err("ordering batch includes non-live intent".to_string());
            }
            intent.status = RouteIntentStatus::Packed;
            ordered.insert(intent_id.clone());
        }
        let batch = OrderingBatch::new(
            action_kind,
            bucket_id,
            solver_bond_id,
            ordered,
            fairness_commitment_root,
            mev_guard_root,
            self.height,
            self.height + self.config.batch_window_blocks,
        )?;
        let batch_id = batch.batch_id.clone();
        self.ordering_batches.insert(batch_id.clone(), batch);
        Ok(batch_id)
    }

    pub fn seal_batch_with_netting(
        &mut self,
        batch_id: &str,
    ) -> LowFeeDefiBatchRouterResult<String> {
        let batch = self
            .ordering_batches
            .get(batch_id)
            .ok_or_else(|| "unknown ordering batch".to_string())?
            .clone();
        let mut totals: BTreeMap<String, (u64, u64, BTreeSet<String>)> = BTreeMap::new();
        let mut sponsor_debits: BTreeMap<String, u64> = BTreeMap::new();
        for intent_id in &batch.intent_ids {
            let intent = self
                .route_intents
                .get(intent_id)
                .ok_or_else(|| "batch intent missing during netting".to_string())?;
            add_position_delta(
                &mut totals,
                &intent.input_asset_id,
                intent
                    .max_fee_units
                    .saturating_add(intent.sponsored_fee_units),
                0,
                &intent.owner_commitment,
            );
            add_position_delta(
                &mut totals,
                &intent.output_asset_id,
                0,
                intent.max_fee_units,
                &intent.owner_commitment,
            );
            if let Some(credit_id) = &intent.sponsor_credit_id {
                let entry = sponsor_debits.entry(credit_id.clone()).or_insert(0);
                *entry = entry.saturating_add(intent.sponsored_fee_units);
            }
        }
        let mut position_records = Vec::new();
        for (asset_id, (debit_units, credit_units, participants)) in totals {
            let participant_root =
                string_set_root("LOW-FEE-DEFI-NET-POSITION-PARTICIPANTS", &participants);
            let position = SettlementNetPosition::new(
                batch_id,
                &asset_id,
                debit_units,
                credit_units,
                &participant_root,
            )?;
            position_records.push(position.public_record());
            self.net_positions
                .insert(position.position_id.clone(), position);
        }
        let net_position_root = collection_root("LOW-FEE-DEFI-NET-POSITION-SET", position_records);
        let sponsor_debit_root = map_u64_root("LOW-FEE-DEFI-SPONSOR-DEBIT-SET", &sponsor_debits);
        let batch = self
            .ordering_batches
            .get_mut(batch_id)
            .ok_or_else(|| "unknown ordering batch".to_string())?;
        batch.seal(&net_position_root, &sponsor_debit_root, self.height)?;
        for intent_id in &batch.intent_ids {
            if let Some(intent) = self.route_intents.get_mut(intent_id) {
                intent.status = RouteIntentStatus::Netted;
                if let Some(bucket) = self.privacy_buckets.get_mut(&intent.privacy_bucket_id) {
                    bucket.consume(intent.privacy_cost_bps);
                }
            }
        }
        for (credit_id, amount_units) in sponsor_debits {
            if let Some(credit) = self.sponsor_credits.get_mut(&credit_id) {
                credit.spend_reserved(amount_units);
            }
        }
        Ok(batch.batch_root())
    }

    pub fn publish_receipt(
        &mut self,
        batch_id: &str,
        state_root_after: &str,
        proof_root: &str,
    ) -> LowFeeDefiBatchRouterResult<String> {
        let state_root_before = self.state_root();
        let batch = self
            .ordering_batches
            .get_mut(batch_id)
            .ok_or_else(|| "receipt references unknown batch".to_string())?;
        if batch.status != OrderingBatchStatus::Sealed
            && batch.status != OrderingBatchStatus::Posted
        {
            return Err("batch is not receipt-ready".to_string());
        }
        batch.status = OrderingBatchStatus::Settled;
        for intent_id in &batch.intent_ids {
            if let Some(intent) = self.route_intents.get_mut(intent_id) {
                intent.status = RouteIntentStatus::Settled;
            }
        }
        if let Some(bond) = self.solver_bonds.get_mut(&batch.solver_bond_id) {
            bond.release(batch.intent_ids.len() as u64 * 1_000);
        }
        let receipt = SettlementReceipt::new(
            batch_id,
            &state_root_before,
            state_root_after,
            &batch.ordered_intent_root,
            &batch.net_position_root,
            proof_root,
            self.height,
        )?;
        let receipt_id = receipt.receipt_id.clone();
        self.receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.config_root(),
            fee_ceiling_root: collection_root(
                "LOW-FEE-DEFI-FEE-CEILING-SET",
                self.fee_ceilings
                    .values()
                    .map(FeeCeiling::public_record)
                    .collect(),
            ),
            privacy_bucket_root: collection_root(
                "LOW-FEE-DEFI-PRIVACY-BUCKET-SET",
                self.privacy_buckets
                    .values()
                    .map(PrivacyBucket::public_record)
                    .collect(),
            ),
            solver_bond_root: collection_root(
                "LOW-FEE-DEFI-SOLVER-BOND-SET",
                self.solver_bonds
                    .values()
                    .map(SolverBond::public_record)
                    .collect(),
            ),
            sponsor_credit_root: collection_root(
                "LOW-FEE-DEFI-SPONSORED-CREDIT-SET",
                self.sponsor_credits
                    .values()
                    .map(SponsoredExecutionCredit::public_record)
                    .collect(),
            ),
            route_intent_root: collection_root(
                "LOW-FEE-DEFI-ROUTE-INTENT-SET",
                self.route_intents
                    .values()
                    .map(RouteIntent::public_record)
                    .collect(),
            ),
            ordering_batch_root: collection_root(
                "LOW-FEE-DEFI-ORDERING-BATCH-SET",
                self.ordering_batches
                    .values()
                    .map(OrderingBatch::public_record)
                    .collect(),
            ),
            net_position_root: collection_root(
                "LOW-FEE-DEFI-NET-POSITION-SET",
                self.net_positions
                    .values()
                    .map(SettlementNetPosition::public_record)
                    .collect(),
            ),
            receipt_root: collection_root(
                "LOW-FEE-DEFI-RECEIPT-SET",
                self.receipts
                    .values()
                    .map(SettlementReceipt::public_record)
                    .collect(),
            ),
            nullifier_root: map_string_root("LOW-FEE-DEFI-NULLIFIER-INDEX", &self.nullifier_index),
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            fee_ceiling_count: self.fee_ceilings.len() as u64,
            privacy_bucket_count: self.privacy_buckets.len() as u64,
            open_privacy_bucket_count: self
                .privacy_buckets
                .values()
                .filter(|bucket| bucket.status.accepts_intents())
                .count() as u64,
            solver_bond_count: self.solver_bonds.len() as u64,
            active_solver_bond_count: self
                .solver_bonds
                .values()
                .filter(|bond| bond.live_at(self.height))
                .count() as u64,
            sponsor_credit_count: self.sponsor_credits.len() as u64,
            spendable_sponsor_credit_count: self
                .sponsor_credits
                .values()
                .filter(|credit| credit.status.spendable())
                .count() as u64,
            route_intent_count: self.route_intents.len() as u64,
            live_route_intent_count: self
                .route_intents
                .values()
                .filter(|intent| intent.status.live())
                .count() as u64,
            settled_route_intent_count: self
                .route_intents
                .values()
                .filter(|intent| intent.status == RouteIntentStatus::Settled)
                .count() as u64,
            ordering_batch_count: self.ordering_batches.len() as u64,
            live_ordering_batch_count: self
                .ordering_batches
                .values()
                .filter(|batch| batch.status.live())
                .count() as u64,
            net_position_count: self.net_positions.len() as u64,
            receipt_count: self.receipts.len() as u64,
            total_sponsored_credit_units: self
                .sponsor_credits
                .values()
                .map(|credit| credit.total_credit_units)
                .sum(),
            reserved_sponsored_credit_units: self
                .sponsor_credits
                .values()
                .map(|credit| credit.reserved_credit_units)
                .sum(),
            spent_sponsored_credit_units: self
                .sponsor_credits
                .values()
                .map(|credit| credit.spent_credit_units)
                .sum(),
            total_solver_bond_units: self
                .solver_bonds
                .values()
                .map(|bond| bond.total_bond_units)
                .sum(),
            reserved_solver_bond_units: self
                .solver_bonds
                .values()
                .map(|bond| bond.reserved_bond_units)
                .sum(),
            slashed_solver_bond_units: self
                .solver_bonds
                .values()
                .map(|bond| bond.slashed_bond_units)
                .sum(),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "low_fee_defi_batch_router_state",
            "protocol_version": LOW_FEE_DEFI_BATCH_ROUTER_PROTOCOL_VERSION,
            "schema_version": LOW_FEE_DEFI_BATCH_ROUTER_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.roots_root(),
            "counters": counters.public_record(),
            "counters_root": counters.counters_root(),
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(fields) = &mut record {
            fields.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn validate(&self) -> LowFeeDefiBatchRouterResult<String> {
        self.config.validate()?;
        for (ceiling_id, ceiling) in &self.fee_ceilings {
            if ceiling_id != &ceiling.ceiling_id {
                return Err("fee ceiling map key mismatch".to_string());
            }
            ceiling.validate()?;
            if ceiling.max_fee_bps > self.config.max_fee_ceiling_bps {
                return Err("fee ceiling exceeds configured maximum".to_string());
            }
        }
        for (bucket_id, bucket) in &self.privacy_buckets {
            if bucket_id != &bucket.bucket_id {
                return Err("privacy bucket map key mismatch".to_string());
            }
            bucket.validate()?;
        }
        for (bond_id, bond) in &self.solver_bonds {
            if bond_id != &bond.bond_id {
                return Err("solver bond map key mismatch".to_string());
            }
            bond.validate()?;
        }
        for (credit_id, credit) in &self.sponsor_credits {
            if credit_id != &credit.credit_id {
                return Err("sponsor credit map key mismatch".to_string());
            }
            credit.validate()?;
        }
        let mut nullifiers = BTreeSet::new();
        for (intent_id, intent) in &self.route_intents {
            if intent_id != &intent.intent_id {
                return Err("route intent map key mismatch".to_string());
            }
            intent.validate()?;
            if !self.fee_ceilings.contains_key(&intent.fee_ceiling_id) {
                return Err("route intent fee ceiling missing".to_string());
            }
            if !self.privacy_buckets.contains_key(&intent.privacy_bucket_id) {
                return Err("route intent privacy bucket missing".to_string());
            }
            if let Some(credit_id) = &intent.sponsor_credit_id {
                if !self.sponsor_credits.contains_key(credit_id) {
                    return Err("route intent sponsor credit missing".to_string());
                }
            }
            if let Some(bond_id) = &intent.solver_bond_id {
                if !self.solver_bonds.contains_key(bond_id) {
                    return Err("route intent solver bond missing".to_string());
                }
            }
            if !nullifiers.insert(intent.nullifier.clone()) {
                return Err("duplicate route intent nullifier".to_string());
            }
        }
        for (batch_id, batch) in &self.ordering_batches {
            if batch_id != &batch.batch_id {
                return Err("ordering batch map key mismatch".to_string());
            }
            batch.validate()?;
            if !self.privacy_buckets.contains_key(&batch.bucket_id) {
                return Err("ordering batch privacy bucket missing".to_string());
            }
            if !self.solver_bonds.contains_key(&batch.solver_bond_id) {
                return Err("ordering batch solver bond missing".to_string());
            }
            for intent_id in &batch.intent_ids {
                if !self.route_intents.contains_key(intent_id) {
                    return Err("ordering batch route intent missing".to_string());
                }
            }
        }
        for (position_id, position) in &self.net_positions {
            if position_id != &position.position_id {
                return Err("net position map key mismatch".to_string());
            }
            position.validate()?;
            if !self.ordering_batches.contains_key(&position.batch_id) {
                return Err("net position batch missing".to_string());
            }
        }
        for (receipt_id, receipt) in &self.receipts {
            if receipt_id != &receipt.receipt_id {
                return Err("receipt map key mismatch".to_string());
            }
            receipt.validate()?;
            if !self.ordering_batches.contains_key(&receipt.batch_id) {
                return Err("receipt batch missing".to_string());
            }
        }
        Ok(self.state_root())
    }
}

pub fn root_from_record(record: &Value) -> String {
    payload_root("LOW-FEE-DEFI-BATCH-ROUTER-STATE", record)
}

pub fn devnet() -> LowFeeDefiBatchRouterResult<State> {
    State::devnet()
}

fn payload_root(domain: &str, payload: &Value) -> String {
    stable_hash(
        domain,
        &[
            HashPart::Str(LOW_FEE_DEFI_BATCH_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn string_root(domain: &str, value: &str) -> String {
    stable_hash(
        domain,
        &[
            HashPart::Str(LOW_FEE_DEFI_BATCH_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(value),
        ],
        32,
    )
}

fn collection_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

fn string_set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn map_string_root(domain: &str, values: &BTreeMap<String, String>) -> String {
    let leaves = values
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn map_u64_root(domain: &str, values: &BTreeMap<String, u64>) -> String {
    let leaves = values
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn fee_ceiling_id(
    action_kind: DefiActionKind,
    fee_asset_id: &str,
    max_fee_bps: u64,
    valid_from_height: u64,
    valid_until_height: u64,
) -> String {
    payload_root(
        "LOW-FEE-DEFI-FEE-CEILING-ID",
        &json!({
            "action_kind": action_kind.as_str(),
            "fee_asset_id": fee_asset_id,
            "max_fee_bps": max_fee_bps,
            "valid_from_height": valid_from_height,
            "valid_until_height": valid_until_height,
        }),
    )
}

fn privacy_bucket_id(
    action_kind: DefiActionKind,
    asset_pair_root: &str,
    epoch_index: u64,
) -> String {
    payload_root(
        "LOW-FEE-DEFI-PRIVACY-BUCKET-ID",
        &json!({
            "action_kind": action_kind.as_str(),
            "asset_pair_root": asset_pair_root,
            "epoch_index": epoch_index,
        }),
    )
}

fn solver_bond_id(
    solver_commitment: &str,
    bond_asset_id: &str,
    total_bond_units: u64,
    valid_from_height: u64,
) -> String {
    payload_root(
        "LOW-FEE-DEFI-SOLVER-BOND-ID",
        &json!({
            "solver_commitment": solver_commitment,
            "bond_asset_id": bond_asset_id,
            "total_bond_units": total_bond_units,
            "valid_from_height": valid_from_height,
        }),
    )
}

fn sponsor_credit_id(
    sponsor_commitment: &str,
    fee_asset_id: &str,
    total_credit_units: u64,
    valid_from_height: u64,
) -> String {
    payload_root(
        "LOW-FEE-DEFI-SPONSOR-CREDIT-ID",
        &json!({
            "sponsor_commitment": sponsor_commitment,
            "fee_asset_id": fee_asset_id,
            "total_credit_units": total_credit_units,
            "valid_from_height": valid_from_height,
        }),
    )
}

fn route_intent_id(
    action_kind: DefiActionKind,
    owner_commitment: &str,
    route_commitment_root: &str,
    opened_at_height: u64,
    nullifier: &str,
) -> String {
    payload_root(
        "LOW-FEE-DEFI-ROUTE-INTENT-ID",
        &json!({
            "action_kind": action_kind.as_str(),
            "owner_commitment": owner_commitment,
            "route_commitment_root": route_commitment_root,
            "opened_at_height": opened_at_height,
            "nullifier": nullifier,
        }),
    )
}

fn ordering_batch_id(
    action_kind: DefiActionKind,
    bucket_id: &str,
    solver_bond_id: &str,
    ordered_intent_root: &str,
    opened_at_height: u64,
) -> String {
    payload_root(
        "LOW-FEE-DEFI-ORDERING-BATCH-ID",
        &json!({
            "action_kind": action_kind.as_str(),
            "bucket_id": bucket_id,
            "solver_bond_id": solver_bond_id,
            "ordered_intent_root": ordered_intent_root,
            "opened_at_height": opened_at_height,
        }),
    )
}

fn net_position_id(batch_id: &str, asset_id: &str, debit_units: u64, credit_units: u64) -> String {
    payload_root(
        "LOW-FEE-DEFI-NET-POSITION-ID",
        &json!({
            "batch_id": batch_id,
            "asset_id": asset_id,
            "debit_units": debit_units,
            "credit_units": credit_units,
        }),
    )
}

fn settlement_receipt_id(batch_id: &str, state_root_after: &str, settled_at_height: u64) -> String {
    payload_root(
        "LOW-FEE-DEFI-SETTLEMENT-RECEIPT-ID",
        &json!({
            "batch_id": batch_id,
            "state_root_after": state_root_after,
            "settled_at_height": settled_at_height,
        }),
    )
}

fn current_epoch(height: u64, epoch_blocks: u64) -> u64 {
    if epoch_blocks == 0 {
        0
    } else {
        height.saturating_div(epoch_blocks)
    }
}

fn add_position_delta(
    totals: &mut BTreeMap<String, (u64, u64, BTreeSet<String>)>,
    asset_id: &str,
    debit_units: u64,
    credit_units: u64,
    participant_commitment: &str,
) {
    let entry = totals
        .entry(asset_id.to_string())
        .or_insert((0, 0, BTreeSet::new()));
    entry.0 = entry.0.saturating_add(debit_units);
    entry.1 = entry.1.saturating_add(credit_units);
    entry.2.insert(participant_commitment.to_string());
}

fn ensure_non_empty(label: &str, value: &str) -> LowFeeDefiBatchRouterResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} is empty"));
    }
    Ok(())
}

fn ensure_positive(label: &str, value: u64) -> LowFeeDefiBatchRouterResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_bps(label: &str, value: u64) -> LowFeeDefiBatchRouterResult<()> {
    if value > LOW_FEE_DEFI_BATCH_ROUTER_MAX_BPS {
        return Err(format!("{label} exceeds max bps"));
    }
    Ok(())
}

fn ensure_height_window(start: u64, end: u64, label: &str) -> LowFeeDefiBatchRouterResult<()> {
    if end < start {
        return Err(format!("{label} height window is inverted"));
    }
    Ok(())
}

fn ensure_eq(label: &str, actual: &str, wanted: &str) -> LowFeeDefiBatchRouterResult<()> {
    if actual != wanted {
        return Err(format!("{label} mismatch"));
    }
    Ok(())
}
