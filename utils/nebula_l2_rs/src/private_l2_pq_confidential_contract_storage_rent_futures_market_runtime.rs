use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = PrivateL2PqConfidentialContractStorageRentFuturesMarketRuntimeResult<T>;
pub type PrivateL2PqConfidentialContractStorageRentFuturesMarketRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STORAGE_RENT_FUTURES_MARKET_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-contract-storage-rent-futures-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STORAGE_RENT_FUTURES_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_RENT_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-confidential-storage-rent-futures-v1";
pub const ENCRYPTED_STORAGE_COMMITMENT_SUITE: &str =
    "ML-KEM-1024+Poseidon2-confidential-storage-commitment-v1";
pub const RENT_COUPON_SUITE: &str = "roots-only-confidential-storage-rent-settlement-coupon-v1";
pub const COMPACTION_WINDOW_SUITE: &str = "fast-private-l2-contract-storage-compaction-window-v1";
pub const EVICTION_GUARD_SUITE: &str = "pq-confidential-contract-storage-eviction-guard-v1";
pub const REDACTION_BUDGET_SUITE: &str =
    "confidential-contract-storage-rent-market-redaction-budget-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_RENT_ASSET_ID: &str = "asset:private-storage-rent-credit";
pub const DEVNET_L2_HEIGHT: u64 = 2_860_000;
pub const DEVNET_EPOCH: u64 = 13_312;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_QUORUM_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_SUPERMAJORITY_WEIGHT_BPS: u64 = 8_000;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_MAKER_REBATE_BPS: u64 = 3;
pub const DEFAULT_TAKER_FEE_BPS: u64 = 8;
pub const DEFAULT_MAX_RENT_RATE_MICRO_UNITS: u64 = 1_200;
pub const DEFAULT_TARGET_MATCH_MS: u64 = 75;
pub const DEFAULT_TARGET_SETTLEMENT_MS: u64 = 160;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 20;
pub const DEFAULT_ORDER_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_COUPON_TTL_BLOCKS: u64 = 192;
pub const DEFAULT_COMPACTION_WINDOW_BLOCKS: u64 = 256;
pub const DEFAULT_EVICTION_GUARD_BLOCKS: u64 = 512;
pub const DEFAULT_REDACTION_EPOCH_BLOCKS: u64 = 64;
pub const DEFAULT_MAX_BOOKS: usize = 65_536;
pub const DEFAULT_MAX_ORDERS: usize = 4_194_304;
pub const DEFAULT_MAX_HEDGE_LOTS: usize = 2_097_152;
pub const DEFAULT_MAX_STORAGE_COMMITMENTS: usize = 4_194_304;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_COUPONS: usize = 2_097_152;
pub const DEFAULT_MAX_COMPACTION_WINDOWS: usize = 524_288;
pub const DEFAULT_MAX_EVICTION_GUARDS: usize = 524_288;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 262_144;
pub const DEFAULT_MAX_OPERATOR_SUMMARIES: usize = 131_072;
pub const DEFAULT_MAX_EVENTS: usize = 2_097_152;

macro_rules! status_enum {
    ($name:ident { $($variant:ident => $text:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            pub fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $text),+
                }
            }
        }
    };
}

status_enum!(BookStatus {
    Draft => "draft",
    Open => "open",
    MatchingOnly => "matching_only",
    SettlementOnly => "settlement_only",
    Paused => "paused",
    Expired => "expired",
    Closed => "closed",
});
status_enum!(OrderSide {
    Bid => "bid",
    Ask => "ask",
});
status_enum!(OrderStatus {
    Open => "open",
    PartiallyFilled => "partially_filled",
    Filled => "filled",
    Cancelled => "cancelled",
    Expired => "expired",
    Guarded => "guarded",
});
status_enum!(HedgeLotStatus {
    Reserved => "reserved",
    Matched => "matched",
    Attested => "attested",
    Couponed => "couponed",
    Settled => "settled",
    Challenged => "challenged",
    Expired => "expired",
});
status_enum!(StorageCommitmentStatus {
    Announced => "announced",
    Active => "active",
    CompactionQueued => "compaction_queued",
    Guarded => "guarded",
    Released => "released",
    Evicted => "evicted",
    Expired => "expired",
});
status_enum!(PqRentAttestationStatus {
    Draft => "draft",
    Published => "published",
    QuorumAccepted => "quorum_accepted",
    Finalized => "finalized",
    Challenged => "challenged",
    Rejected => "rejected",
    Expired => "expired",
});
status_enum!(SettlementCouponStatus {
    Reserved => "reserved",
    Claimable => "claimable",
    Redeemed => "redeemed",
    Netted => "netted",
    Challenged => "challenged",
    Expired => "expired",
});
status_enum!(CompactionWindowStatus {
    Scheduled => "scheduled",
    Active => "active",
    Sealed => "sealed",
    Settled => "settled",
    Slashed => "slashed",
    Expired => "expired",
});
status_enum!(EvictionGuardStatus {
    Armed => "armed",
    Matched => "matched",
    Frozen => "frozen",
    Released => "released",
    Consumed => "consumed",
    Expired => "expired",
});
status_enum!(RedactionBudgetStatus {
    Open => "open",
    Debited => "debited",
    Exhausted => "exhausted",
    Frozen => "frozen",
    Closed => "closed",
    Expired => "expired",
});
status_enum!(OperatorHealth {
    Green => "green",
    Amber => "amber",
    Red => "red",
    Quarantined => "quarantined",
});

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    Devnet,
    Canary,
    MainnetCandidate,
}

impl RuntimeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Devnet => "devnet",
            Self::Canary => "canary",
            Self::MainnetCandidate => "mainnet_candidate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RentTenor {
    Epoch,
    Week,
    Month,
    Quarter,
    Annual,
}

impl RentTenor {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Epoch => "epoch",
            Self::Week => "week",
            Self::Month => "month",
            Self::Quarter => "quarter",
            Self::Annual => "annual",
        }
    }

    pub fn blocks(self) -> u64 {
        match self {
            Self::Epoch => 64,
            Self::Week => 5_040,
            Self::Month => 21_600,
            Self::Quarter => 64_800,
            Self::Annual => 259_200,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageClass {
    HotContractState,
    WarmContractState,
    ColdContractArchive,
    ProofWitnessCache,
    RollupDataAvailability,
    EmergencyRecovery,
}

impl StorageClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HotContractState => "hot_contract_state",
            Self::WarmContractState => "warm_contract_state",
            Self::ColdContractArchive => "cold_contract_archive",
            Self::ProofWitnessCache => "proof_witness_cache",
            Self::RollupDataAvailability => "rollup_data_availability",
            Self::EmergencyRecovery => "emergency_recovery",
        }
    }

    pub fn privacy_weight(self) -> u64 {
        match self {
            Self::EmergencyRecovery => 1_000,
            Self::HotContractState => 940,
            Self::ProofWitnessCache => 900,
            Self::RollupDataAvailability => 850,
            Self::WarmContractState => 760,
            Self::ColdContractArchive => 620,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub chain_id: String,
    pub fee_asset_id: String,
    pub rent_asset_id: String,
    pub low_fee_lane_id: String,
    pub runtime_mode: RuntimeMode,
    pub hash_suite: String,
    pub pq_attestation_suite: String,
    pub encrypted_storage_commitment_suite: String,
    pub settlement_coupon_suite: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub quorum_weight_bps: u64,
    pub supermajority_weight_bps: u64,
    pub max_user_fee_bps: u64,
    pub maker_rebate_bps: u64,
    pub taker_fee_bps: u64,
    pub max_rent_rate_micro_units: u64,
    pub target_match_ms: u64,
    pub target_settlement_ms: u64,
    pub order_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub coupon_ttl_blocks: u64,
    pub compaction_window_blocks: u64,
    pub eviction_guard_blocks: u64,
    pub redaction_epoch_blocks: u64,
    pub max_books: usize,
    pub max_orders: usize,
    pub max_hedge_lots: usize,
    pub max_storage_commitments: usize,
    pub max_attestations: usize,
    pub max_coupons: usize,
    pub max_compaction_windows: usize,
    pub max_eviction_guards: usize,
    pub max_redaction_budgets: usize,
    pub max_operator_summaries: usize,
    pub max_events: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            chain_id: CHAIN_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            rent_asset_id: DEVNET_RENT_ASSET_ID.to_string(),
            low_fee_lane_id: "devnet-private-storage-rent-futures-low-fee".to_string(),
            runtime_mode: RuntimeMode::Devnet,
            hash_suite: HASH_SUITE.to_string(),
            pq_attestation_suite: PQ_RENT_ATTESTATION_SUITE.to_string(),
            encrypted_storage_commitment_suite: ENCRYPTED_STORAGE_COMMITMENT_SUITE.to_string(),
            settlement_coupon_suite: RENT_COUPON_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            quorum_weight_bps: DEFAULT_QUORUM_WEIGHT_BPS,
            supermajority_weight_bps: DEFAULT_SUPERMAJORITY_WEIGHT_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            maker_rebate_bps: DEFAULT_MAKER_REBATE_BPS,
            taker_fee_bps: DEFAULT_TAKER_FEE_BPS,
            max_rent_rate_micro_units: DEFAULT_MAX_RENT_RATE_MICRO_UNITS,
            target_match_ms: DEFAULT_TARGET_MATCH_MS,
            target_settlement_ms: DEFAULT_TARGET_SETTLEMENT_MS,
            order_ttl_blocks: DEFAULT_ORDER_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            coupon_ttl_blocks: DEFAULT_COUPON_TTL_BLOCKS,
            compaction_window_blocks: DEFAULT_COMPACTION_WINDOW_BLOCKS,
            eviction_guard_blocks: DEFAULT_EVICTION_GUARD_BLOCKS,
            redaction_epoch_blocks: DEFAULT_REDACTION_EPOCH_BLOCKS,
            max_books: DEFAULT_MAX_BOOKS,
            max_orders: DEFAULT_MAX_ORDERS,
            max_hedge_lots: DEFAULT_MAX_HEDGE_LOTS,
            max_storage_commitments: DEFAULT_MAX_STORAGE_COMMITMENTS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_coupons: DEFAULT_MAX_COUPONS,
            max_compaction_windows: DEFAULT_MAX_COMPACTION_WINDOWS,
            max_eviction_guards: DEFAULT_MAX_EVICTION_GUARDS,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
            max_operator_summaries: DEFAULT_MAX_OPERATOR_SUMMARIES,
            max_events: DEFAULT_MAX_EVENTS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("l2_network", &self.l2_network)?;
        ensure_nonempty("monero_network", &self.monero_network)?;
        ensure_nonempty("fee_asset_id", &self.fee_asset_id)?;
        ensure_nonempty("rent_asset_id", &self.rent_asset_id)?;
        ensure_nonempty("low_fee_lane_id", &self.low_fee_lane_id)?;
        ensure_bps("quorum_weight_bps", self.quorum_weight_bps)?;
        ensure_bps("supermajority_weight_bps", self.supermajority_weight_bps)?;
        ensure_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        ensure_bps("maker_rebate_bps", self.maker_rebate_bps)?;
        ensure_bps("taker_fee_bps", self.taker_fee_bps)?;
        if self.min_pq_security_bits < 192 {
            return Err("storage rent futures requires at least 192 pq security bits".to_string());
        }
        if self.min_privacy_set_size < 4_096 {
            return Err(
                "storage rent futures privacy set is below generated runtime floor".to_string(),
            );
        }
        if self.target_match_ms == 0 || self.target_settlement_ms == 0 {
            return Err("storage rent futures latency targets must be positive".to_string());
        }
        if self.order_ttl_blocks == 0 || self.attestation_ttl_blocks == 0 {
            return Err("storage rent futures ttl values must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "chain_id": self.chain_id,
            "compaction_window_blocks": self.compaction_window_blocks,
            "coupon_ttl_blocks": self.coupon_ttl_blocks,
            "encrypted_storage_commitment_suite": self.encrypted_storage_commitment_suite,
            "eviction_guard_blocks": self.eviction_guard_blocks,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "l2_network": self.l2_network,
            "low_fee_lane_id": self.low_fee_lane_id,
            "maker_rebate_bps": self.maker_rebate_bps,
            "max_attestations": self.max_attestations,
            "max_books": self.max_books,
            "max_compaction_windows": self.max_compaction_windows,
            "max_coupons": self.max_coupons,
            "max_events": self.max_events,
            "max_eviction_guards": self.max_eviction_guards,
            "max_hedge_lots": self.max_hedge_lots,
            "max_operator_summaries": self.max_operator_summaries,
            "max_orders": self.max_orders,
            "max_redaction_budgets": self.max_redaction_budgets,
            "max_rent_rate_micro_units": self.max_rent_rate_micro_units,
            "max_storage_commitments": self.max_storage_commitments,
            "max_user_fee_bps": self.max_user_fee_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "monero_network": self.monero_network,
            "order_ttl_blocks": self.order_ttl_blocks,
            "protocol_version": self.protocol_version,
            "pq_attestation_suite": self.pq_attestation_suite,
            "quorum_weight_bps": self.quorum_weight_bps,
            "redaction_epoch_blocks": self.redaction_epoch_blocks,
            "rent_asset_id": self.rent_asset_id,
            "runtime_mode": self.runtime_mode.as_str(),
            "schema_version": self.schema_version,
            "settlement_coupon_suite": self.settlement_coupon_suite,
            "supermajority_weight_bps": self.supermajority_weight_bps,
            "taker_fee_bps": self.taker_fee_bps,
            "target_match_ms": self.target_match_ms,
            "target_settlement_ms": self.target_settlement_ms
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub book_count: u64,
    pub order_count: u64,
    pub hedge_lot_count: u64,
    pub storage_commitment_count: u64,
    pub pq_attestation_count: u64,
    pub settlement_coupon_count: u64,
    pub compaction_window_count: u64,
    pub eviction_guard_count: u64,
    pub redaction_budget_count: u64,
    pub operator_summary_count: u64,
    pub event_count: u64,
    pub open_order_count: u64,
    pub open_notional_micro_units: u128,
    pub matched_notional_micro_units: u128,
    pub settled_coupon_micro_units: u128,
    pub total_fee_micro_units: u128,
    pub total_rebate_micro_units: u128,
    pub guarded_storage_bytes: u128,
    pub compacted_storage_bytes: u128,
    pub redacted_field_count: u64,
    pub challenged_attestation_count: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "book_count": self.book_count,
            "challenged_attestation_count": self.challenged_attestation_count,
            "compacted_storage_bytes": self.compacted_storage_bytes,
            "compaction_window_count": self.compaction_window_count,
            "event_count": self.event_count,
            "eviction_guard_count": self.eviction_guard_count,
            "guarded_storage_bytes": self.guarded_storage_bytes,
            "hedge_lot_count": self.hedge_lot_count,
            "matched_notional_micro_units": self.matched_notional_micro_units.to_string(),
            "open_notional_micro_units": self.open_notional_micro_units.to_string(),
            "open_order_count": self.open_order_count,
            "operator_summary_count": self.operator_summary_count,
            "order_count": self.order_count,
            "pq_attestation_count": self.pq_attestation_count,
            "redacted_field_count": self.redacted_field_count,
            "redaction_budget_count": self.redaction_budget_count,
            "settled_coupon_micro_units": self.settled_coupon_micro_units.to_string(),
            "settlement_coupon_count": self.settlement_coupon_count,
            "storage_commitment_count": self.storage_commitment_count,
            "total_fee_micro_units": self.total_fee_micro_units.to_string(),
            "total_rebate_micro_units": self.total_rebate_micro_units.to_string()
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub books_root: String,
    pub orders_root: String,
    pub hedge_lots_root: String,
    pub storage_commitments_root: String,
    pub pq_attestations_root: String,
    pub settlement_coupons_root: String,
    pub compaction_windows_root: String,
    pub eviction_guards_root: String,
    pub redaction_budgets_root: String,
    pub operator_summaries_root: String,
    pub events_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            config_root: empty_root("config"),
            counters_root: empty_root("counters"),
            books_root: empty_root("books"),
            orders_root: empty_root("orders"),
            hedge_lots_root: empty_root("hedge-lots"),
            storage_commitments_root: empty_root("storage-commitments"),
            pq_attestations_root: empty_root("pq-rent-attestations"),
            settlement_coupons_root: empty_root("settlement-coupons"),
            compaction_windows_root: empty_root("compaction-windows"),
            eviction_guards_root: empty_root("eviction-guards"),
            redaction_budgets_root: empty_root("redaction-budgets"),
            operator_summaries_root: empty_root("operator-summaries"),
            events_root: empty_root("events"),
            state_root: empty_root("state"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "books_root": self.books_root,
            "compaction_windows_root": self.compaction_windows_root,
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "events_root": self.events_root,
            "eviction_guards_root": self.eviction_guards_root,
            "hedge_lots_root": self.hedge_lots_root,
            "operator_summaries_root": self.operator_summaries_root,
            "orders_root": self.orders_root,
            "pq_attestations_root": self.pq_attestations_root,
            "redaction_budgets_root": self.redaction_budgets_root,
            "settlement_coupons_root": self.settlement_coupons_root,
            "state_root": self.state_root,
            "storage_commitments_root": self.storage_commitments_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StorageRentFuturesBook {
    pub book_id: String,
    pub market_symbol: String,
    pub storage_class: StorageClass,
    pub tenor: RentTenor,
    pub status: BookStatus,
    pub quote_asset_id: String,
    pub rent_asset_id: String,
    pub min_lot_bytes: u64,
    pub tick_micro_units: u64,
    pub maker_rebate_bps: u64,
    pub taker_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_l2_height: u64,
    pub expiry_l2_height: u64,
    pub oracle_committee_root: String,
    pub encrypted_order_flow_root: String,
    pub risk_model_root: String,
}

impl StorageRentFuturesBook {
    pub fn new(
        market_symbol: impl Into<String>,
        storage_class: StorageClass,
        tenor: RentTenor,
        sequence: u64,
        config: &Config,
    ) -> Self {
        let market_symbol = market_symbol.into();
        let book_id = deterministic_id("book", sequence, &market_symbol);
        Self {
            book_id,
            market_symbol,
            storage_class,
            tenor,
            status: BookStatus::Open,
            quote_asset_id: config.fee_asset_id.clone(),
            rent_asset_id: config.rent_asset_id.clone(),
            min_lot_bytes: 65_536,
            tick_micro_units: 1,
            maker_rebate_bps: config.maker_rebate_bps,
            taker_fee_bps: config.taker_fee_bps,
            max_user_fee_bps: config.max_user_fee_bps,
            privacy_set_size: config.min_privacy_set_size,
            pq_security_bits: config.min_pq_security_bits,
            opened_l2_height: DEVNET_L2_HEIGHT,
            expiry_l2_height: DEVNET_L2_HEIGHT + tenor.blocks(),
            oracle_committee_root: deterministic_string(
                "oracle-committee",
                sequence,
                &market_symbol,
            ),
            encrypted_order_flow_root: deterministic_string("order-flow", sequence, &market_symbol),
            risk_model_root: deterministic_string("risk-model", sequence, &market_symbol),
        }
    }

    pub fn accepts_orders(&self) -> bool {
        matches!(self.status, BookStatus::Open | BookStatus::MatchingOnly)
    }

    pub fn settlement_ready(&self) -> bool {
        matches!(self.status, BookStatus::Open | BookStatus::SettlementOnly)
    }

    pub fn expiry_blocks_remaining(&self, height: u64) -> u64 {
        self.expiry_l2_height.saturating_sub(height)
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_nonempty("book_id", &self.book_id)?;
        ensure_nonempty("market_symbol", &self.market_symbol)?;
        ensure_nonempty("quote_asset_id", &self.quote_asset_id)?;
        ensure_nonempty("rent_asset_id", &self.rent_asset_id)?;
        if self.min_lot_bytes == 0 || self.tick_micro_units == 0 {
            return Err("storage rent futures book lot and tick must be positive".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("storage rent futures book privacy set below configured floor".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("storage rent futures book pq security below configured floor".to_string());
        }
        ensure_bps("maker_rebate_bps", self.maker_rebate_bps)?;
        ensure_bps("taker_fee_bps", self.taker_fee_bps)?;
        ensure_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "book_id": self.book_id,
            "encrypted_order_flow_root": self.encrypted_order_flow_root,
            "expiry_l2_height": self.expiry_l2_height,
            "maker_rebate_bps": self.maker_rebate_bps,
            "market_symbol": self.market_symbol,
            "max_user_fee_bps": self.max_user_fee_bps,
            "min_lot_bytes": self.min_lot_bytes,
            "opened_l2_height": self.opened_l2_height,
            "oracle_committee_root": self.oracle_committee_root,
            "pq_security_bits": self.pq_security_bits,
            "privacy_set_size": self.privacy_set_size,
            "quote_asset_id": self.quote_asset_id,
            "rent_asset_id": self.rent_asset_id,
            "risk_model_root": self.risk_model_root,
            "status": self.status.as_str(),
            "storage_class": self.storage_class.as_str(),
            "taker_fee_bps": self.taker_fee_bps,
            "tenor": self.tenor.as_str(),
            "tick_micro_units": self.tick_micro_units
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StorageRentOrder {
    pub order_id: String,
    pub book_id: String,
    pub owner_commitment: String,
    pub side: OrderSide,
    pub status: OrderStatus,
    pub lot_bytes: u64,
    pub remaining_bytes: u64,
    pub rent_rate_micro_units: u64,
    pub max_fee_micro_units: u64,
    pub privacy_set_size: u64,
    pub encrypted_terms_root: String,
    pub nullifier_hash: String,
    pub created_l2_height: u64,
    pub expiry_l2_height: u64,
}

impl StorageRentOrder {
    pub fn new(
        book_id: impl Into<String>,
        owner_commitment: impl Into<String>,
        side: OrderSide,
        lot_bytes: u64,
        rent_rate_micro_units: u64,
        sequence: u64,
        config: &Config,
    ) -> Self {
        let book_id = book_id.into();
        let owner_commitment = owner_commitment.into();
        let seed = format!("{book_id}:{owner_commitment}:{}", side.as_str());
        Self {
            order_id: deterministic_id("order", sequence, &seed),
            book_id,
            owner_commitment,
            side,
            status: OrderStatus::Open,
            lot_bytes,
            remaining_bytes: lot_bytes,
            rent_rate_micro_units,
            max_fee_micro_units: fee_for_notional(
                lot_bytes as u128 * rent_rate_micro_units as u128,
                config.max_user_fee_bps,
            ) as u64,
            privacy_set_size: config.min_privacy_set_size,
            encrypted_terms_root: deterministic_string("encrypted-order-terms", sequence, &seed),
            nullifier_hash: deterministic_string("order-nullifier", sequence, &seed),
            created_l2_height: DEVNET_L2_HEIGHT,
            expiry_l2_height: DEVNET_L2_HEIGHT + config.order_ttl_blocks,
        }
    }

    pub fn is_open(&self) -> bool {
        matches!(
            self.status,
            OrderStatus::Open | OrderStatus::PartiallyFilled
        ) && self.remaining_bytes > 0
    }

    pub fn notional_micro_units(&self) -> u128 {
        self.remaining_bytes as u128 * self.rent_rate_micro_units as u128
    }

    pub fn fill(&mut self, bytes: u64) -> Result<()> {
        if bytes == 0 {
            return Err("storage rent order fill bytes must be positive".to_string());
        }
        if bytes > self.remaining_bytes {
            return Err("storage rent order fill exceeds remaining bytes".to_string());
        }
        self.remaining_bytes -= bytes;
        self.status = if self.remaining_bytes == 0 {
            OrderStatus::Filled
        } else {
            OrderStatus::PartiallyFilled
        };
        Ok(())
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_nonempty("order_id", &self.order_id)?;
        ensure_nonempty("book_id", &self.book_id)?;
        ensure_nonempty("owner_commitment", &self.owner_commitment)?;
        if self.lot_bytes == 0 || self.remaining_bytes > self.lot_bytes {
            return Err("storage rent order has invalid lot accounting".to_string());
        }
        if self.rent_rate_micro_units == 0
            || self.rent_rate_micro_units > config.max_rent_rate_micro_units
        {
            return Err("storage rent order rent rate outside configured bounds".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("storage rent order privacy set below configured floor".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "book_id": self.book_id,
            "created_l2_height": self.created_l2_height,
            "encrypted_terms_root": self.encrypted_terms_root,
            "expiry_l2_height": self.expiry_l2_height,
            "lot_bytes": self.lot_bytes,
            "max_fee_micro_units": self.max_fee_micro_units,
            "nullifier_hash": self.nullifier_hash,
            "order_id": self.order_id,
            "owner_commitment": self.owner_commitment,
            "privacy_set_size": self.privacy_set_size,
            "remaining_bytes": self.remaining_bytes,
            "rent_rate_micro_units": self.rent_rate_micro_units,
            "side": self.side.as_str(),
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RentHedgeLot {
    pub lot_id: String,
    pub book_id: String,
    pub bid_order_id: String,
    pub ask_order_id: String,
    pub storage_commitment_id: String,
    pub status: HedgeLotStatus,
    pub hedged_bytes: u64,
    pub fixed_rent_rate_micro_units: u64,
    pub floating_index_root: String,
    pub margin_commitment_root: String,
    pub privacy_bucket_root: String,
    pub opened_l2_height: u64,
    pub maturity_l2_height: u64,
    pub settlement_coupon_id: Option<String>,
}

impl RentHedgeLot {
    pub fn new(
        book: &StorageRentFuturesBook,
        bid_order_id: impl Into<String>,
        ask_order_id: impl Into<String>,
        storage_commitment_id: impl Into<String>,
        hedged_bytes: u64,
        fixed_rent_rate_micro_units: u64,
        sequence: u64,
    ) -> Self {
        let seed = format!(
            "{}:{}:{}",
            book.book_id,
            bid_order_id.into(),
            ask_order_id.into()
        );
        Self {
            lot_id: deterministic_id("hedge-lot", sequence, &seed),
            book_id: book.book_id.clone(),
            bid_order_id: deterministic_id("bid-order-shadow", sequence, &seed),
            ask_order_id: deterministic_id("ask-order-shadow", sequence, &seed),
            storage_commitment_id: storage_commitment_id.into(),
            status: HedgeLotStatus::Reserved,
            hedged_bytes,
            fixed_rent_rate_micro_units,
            floating_index_root: deterministic_string("floating-index", sequence, &seed),
            margin_commitment_root: deterministic_string("margin-commitment", sequence, &seed),
            privacy_bucket_root: deterministic_string("privacy-bucket", sequence, &seed),
            opened_l2_height: DEVNET_L2_HEIGHT,
            maturity_l2_height: DEVNET_L2_HEIGHT + book.tenor.blocks(),
            settlement_coupon_id: None,
        }
    }

    pub fn notional_micro_units(&self) -> u128 {
        self.hedged_bytes as u128 * self.fixed_rent_rate_micro_units as u128
    }

    pub fn attach_coupon(&mut self, coupon_id: impl Into<String>) {
        self.settlement_coupon_id = Some(coupon_id.into());
        self.status = HedgeLotStatus::Couponed;
    }

    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("lot_id", &self.lot_id)?;
        ensure_nonempty("book_id", &self.book_id)?;
        ensure_nonempty("storage_commitment_id", &self.storage_commitment_id)?;
        if self.hedged_bytes == 0 || self.fixed_rent_rate_micro_units == 0 {
            return Err("storage rent hedge lot requires positive bytes and rate".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "ask_order_id": self.ask_order_id,
            "bid_order_id": self.bid_order_id,
            "book_id": self.book_id,
            "fixed_rent_rate_micro_units": self.fixed_rent_rate_micro_units,
            "floating_index_root": self.floating_index_root,
            "hedged_bytes": self.hedged_bytes,
            "lot_id": self.lot_id,
            "margin_commitment_root": self.margin_commitment_root,
            "maturity_l2_height": self.maturity_l2_height,
            "notional_micro_units": self.notional_micro_units().to_string(),
            "opened_l2_height": self.opened_l2_height,
            "privacy_bucket_root": self.privacy_bucket_root,
            "settlement_coupon_id": self.settlement_coupon_id,
            "status": self.status.as_str(),
            "storage_commitment_id": self.storage_commitment_id
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedStorageCommitment {
    pub commitment_id: String,
    pub contract_id: String,
    pub owner_view_tag: String,
    pub status: StorageCommitmentStatus,
    pub storage_class: StorageClass,
    pub encrypted_payload_root: String,
    pub ciphertext_root: String,
    pub key_commitment_root: String,
    pub byte_commitment_root: String,
    pub byte_upper_bound: u64,
    pub rent_index_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub created_l2_height: u64,
    pub expiry_l2_height: u64,
}

impl EncryptedStorageCommitment {
    pub fn new(
        contract_id: impl Into<String>,
        owner_view_tag: impl Into<String>,
        storage_class: StorageClass,
        byte_upper_bound: u64,
        sequence: u64,
        config: &Config,
    ) -> Self {
        let contract_id = contract_id.into();
        let owner_view_tag = owner_view_tag.into();
        let seed = format!("{contract_id}:{owner_view_tag}:{}", storage_class.as_str());
        Self {
            commitment_id: deterministic_id("storage-commitment", sequence, &seed),
            contract_id,
            owner_view_tag,
            status: StorageCommitmentStatus::Active,
            storage_class,
            encrypted_payload_root: deterministic_string(
                "encrypted-storage-payload",
                sequence,
                &seed,
            ),
            ciphertext_root: deterministic_string("storage-ciphertext", sequence, &seed),
            key_commitment_root: deterministic_string("storage-key-commitment", sequence, &seed),
            byte_commitment_root: deterministic_string("storage-byte-commitment", sequence, &seed),
            byte_upper_bound,
            rent_index_root: deterministic_string("storage-rent-index", sequence, &seed),
            privacy_set_size: config.min_privacy_set_size,
            pq_security_bits: config.min_pq_security_bits,
            created_l2_height: DEVNET_L2_HEIGHT,
            expiry_l2_height: DEVNET_L2_HEIGHT + RentTenor::Annual.blocks(),
        }
    }

    pub fn guarded_bytes(&self) -> u128 {
        if matches!(self.status, StorageCommitmentStatus::Guarded) {
            self.byte_upper_bound as u128
        } else {
            0
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_nonempty("commitment_id", &self.commitment_id)?;
        ensure_nonempty("contract_id", &self.contract_id)?;
        ensure_nonempty("owner_view_tag", &self.owner_view_tag)?;
        if self.byte_upper_bound == 0 {
            return Err(
                "encrypted storage commitment requires positive byte upper bound".to_string(),
            );
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(
                "encrypted storage commitment privacy set below configured floor".to_string(),
            );
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err(
                "encrypted storage commitment pq security below configured floor".to_string(),
            );
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "byte_commitment_root": self.byte_commitment_root,
            "byte_upper_bound": self.byte_upper_bound,
            "ciphertext_root": self.ciphertext_root,
            "commitment_id": self.commitment_id,
            "contract_id": self.contract_id,
            "created_l2_height": self.created_l2_height,
            "encrypted_payload_root": self.encrypted_payload_root,
            "expiry_l2_height": self.expiry_l2_height,
            "key_commitment_root": self.key_commitment_root,
            "owner_view_tag": self.owner_view_tag,
            "pq_security_bits": self.pq_security_bits,
            "privacy_set_size": self.privacy_set_size,
            "rent_index_root": self.rent_index_root,
            "status": self.status.as_str(),
            "storage_class": self.storage_class.as_str()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqRentAttestation {
    pub attestation_id: String,
    pub lot_id: String,
    pub commitment_id: String,
    pub operator_id: String,
    pub status: PqRentAttestationStatus,
    pub observed_rent_rate_micro_units: u64,
    pub observed_storage_bytes: u64,
    pub quorum_weight_bps: u64,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub proof_system: String,
    pub public_inputs_root: String,
    pub redacted_fields: BTreeSet<String>,
    pub created_l2_height: u64,
    pub expiry_l2_height: u64,
}

impl PqRentAttestation {
    pub fn new(
        lot: &RentHedgeLot,
        operator_id: impl Into<String>,
        observed_rent_rate_micro_units: u64,
        sequence: u64,
        config: &Config,
    ) -> Self {
        let operator_id = operator_id.into();
        let seed = format!("{}:{operator_id}:{}", lot.lot_id, lot.storage_commitment_id);
        Self {
            attestation_id: deterministic_id("pq-rent-attestation", sequence, &seed),
            lot_id: lot.lot_id.clone(),
            commitment_id: lot.storage_commitment_id.clone(),
            operator_id,
            status: PqRentAttestationStatus::Published,
            observed_rent_rate_micro_units,
            observed_storage_bytes: lot.hedged_bytes,
            quorum_weight_bps: config.quorum_weight_bps,
            pq_signature_root: deterministic_string("pq-rent-signature", sequence, &seed),
            transcript_root: deterministic_string("pq-rent-transcript", sequence, &seed),
            proof_system: PQ_RENT_ATTESTATION_SUITE.to_string(),
            public_inputs_root: deterministic_string("pq-rent-public-inputs", sequence, &seed),
            redacted_fields: BTreeSet::from([
                "owner_view_tag".to_string(),
                "encrypted_terms".to_string(),
            ]),
            created_l2_height: DEVNET_L2_HEIGHT + 1,
            expiry_l2_height: DEVNET_L2_HEIGHT + 1 + config.attestation_ttl_blocks,
        }
    }

    pub fn accepts_settlement(&self, config: &Config) -> bool {
        matches!(
            self.status,
            PqRentAttestationStatus::QuorumAccepted | PqRentAttestationStatus::Finalized
        ) || (matches!(self.status, PqRentAttestationStatus::Published)
            && self.quorum_weight_bps >= config.quorum_weight_bps)
    }

    pub fn finalize(&mut self, config: &Config) -> Result<()> {
        if self.quorum_weight_bps < config.quorum_weight_bps {
            return Err("pq rent attestation lacks configured quorum".to_string());
        }
        self.status = if self.quorum_weight_bps >= config.supermajority_weight_bps {
            PqRentAttestationStatus::Finalized
        } else {
            PqRentAttestationStatus::QuorumAccepted
        };
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "commitment_id": self.commitment_id,
            "created_l2_height": self.created_l2_height,
            "expiry_l2_height": self.expiry_l2_height,
            "observed_rent_rate_micro_units": self.observed_rent_rate_micro_units,
            "observed_storage_bytes": self.observed_storage_bytes,
            "operator_id": self.operator_id,
            "pq_signature_root": self.pq_signature_root,
            "proof_system": self.proof_system,
            "public_inputs_root": self.public_inputs_root,
            "quorum_weight_bps": self.quorum_weight_bps,
            "redacted_fields": self.redacted_fields,
            "status": self.status.as_str(),
            "transcript_root": self.transcript_root,
            "lot_id": self.lot_id
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementCoupon {
    pub coupon_id: String,
    pub lot_id: String,
    pub attestation_id: String,
    pub payee_commitment: String,
    pub status: SettlementCouponStatus,
    pub coupon_value_micro_units: u64,
    pub fee_micro_units: u64,
    pub rebate_micro_units: u64,
    pub redemption_nullifier: String,
    pub encrypted_claim_root: String,
    pub settlement_batch_root: String,
    pub issued_l2_height: u64,
    pub expiry_l2_height: u64,
}

impl SettlementCoupon {
    pub fn new(
        lot: &RentHedgeLot,
        attestation: &PqRentAttestation,
        payee_commitment: impl Into<String>,
        sequence: u64,
        config: &Config,
    ) -> Self {
        let payee_commitment = payee_commitment.into();
        let seed = format!(
            "{}:{}:{payee_commitment}",
            lot.lot_id, attestation.attestation_id
        );
        let notional = lot.notional_micro_units();
        let fee = fee_for_notional(notional, config.taker_fee_bps) as u64;
        let rebate = fee_for_notional(notional, config.maker_rebate_bps) as u64;
        Self {
            coupon_id: deterministic_id("settlement-coupon", sequence, &seed),
            lot_id: lot.lot_id.clone(),
            attestation_id: attestation.attestation_id.clone(),
            payee_commitment,
            status: SettlementCouponStatus::Claimable,
            coupon_value_micro_units: notional.saturating_sub(fee as u128) as u64,
            fee_micro_units: fee,
            rebate_micro_units: rebate,
            redemption_nullifier: deterministic_string("coupon-nullifier", sequence, &seed),
            encrypted_claim_root: deterministic_string("coupon-claim", sequence, &seed),
            settlement_batch_root: deterministic_string("coupon-settlement-batch", sequence, &seed),
            issued_l2_height: DEVNET_L2_HEIGHT + 2,
            expiry_l2_height: DEVNET_L2_HEIGHT + 2 + config.coupon_ttl_blocks,
        }
    }

    pub fn redeem(&mut self) -> Result<()> {
        if !matches!(self.status, SettlementCouponStatus::Claimable) {
            return Err("storage rent coupon is not claimable".to_string());
        }
        self.status = SettlementCouponStatus::Redeemed;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "coupon_id": self.coupon_id,
            "coupon_value_micro_units": self.coupon_value_micro_units,
            "encrypted_claim_root": self.encrypted_claim_root,
            "expiry_l2_height": self.expiry_l2_height,
            "fee_micro_units": self.fee_micro_units,
            "issued_l2_height": self.issued_l2_height,
            "lot_id": self.lot_id,
            "payee_commitment": self.payee_commitment,
            "rebate_micro_units": self.rebate_micro_units,
            "redemption_nullifier": self.redemption_nullifier,
            "settlement_batch_root": self.settlement_batch_root,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompactionWindow {
    pub window_id: String,
    pub commitment_id: String,
    pub operator_id: String,
    pub status: CompactionWindowStatus,
    pub start_l2_height: u64,
    pub end_l2_height: u64,
    pub pre_compaction_root: String,
    pub post_compaction_root: String,
    pub bytes_before: u64,
    pub bytes_after: u64,
    pub saved_fee_micro_units: u64,
    pub witness_root: String,
}

impl CompactionWindow {
    pub fn new(
        commitment: &EncryptedStorageCommitment,
        operator_id: impl Into<String>,
        bytes_after: u64,
        sequence: u64,
        config: &Config,
    ) -> Self {
        let operator_id = operator_id.into();
        let seed = format!("{}:{operator_id}", commitment.commitment_id);
        let saved_bytes = commitment.byte_upper_bound.saturating_sub(bytes_after);
        Self {
            window_id: deterministic_id("compaction-window", sequence, &seed),
            commitment_id: commitment.commitment_id.clone(),
            operator_id,
            status: CompactionWindowStatus::Scheduled,
            start_l2_height: DEVNET_L2_HEIGHT + 3,
            end_l2_height: DEVNET_L2_HEIGHT + 3 + config.compaction_window_blocks,
            pre_compaction_root: commitment.byte_commitment_root.clone(),
            post_compaction_root: deterministic_string("post-compaction", sequence, &seed),
            bytes_before: commitment.byte_upper_bound,
            bytes_after,
            saved_fee_micro_units: fee_for_notional(saved_bytes as u128, config.max_user_fee_bps)
                as u64,
            witness_root: deterministic_string("compaction-witness", sequence, &seed),
        }
    }

    pub fn saved_bytes(&self) -> u64 {
        self.bytes_before.saturating_sub(self.bytes_after)
    }

    pub fn seal(&mut self) -> Result<()> {
        if self.bytes_after > self.bytes_before {
            return Err("compaction window cannot increase committed bytes".to_string());
        }
        self.status = CompactionWindowStatus::Sealed;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bytes_after": self.bytes_after,
            "bytes_before": self.bytes_before,
            "commitment_id": self.commitment_id,
            "end_l2_height": self.end_l2_height,
            "operator_id": self.operator_id,
            "post_compaction_root": self.post_compaction_root,
            "pre_compaction_root": self.pre_compaction_root,
            "saved_bytes": self.saved_bytes(),
            "saved_fee_micro_units": self.saved_fee_micro_units,
            "start_l2_height": self.start_l2_height,
            "status": self.status.as_str(),
            "window_id": self.window_id,
            "witness_root": self.witness_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvictionGuard {
    pub guard_id: String,
    pub commitment_id: String,
    pub lot_id: String,
    pub status: EvictionGuardStatus,
    pub protected_until_l2_height: u64,
    pub guard_weight_bps: u64,
    pub bond_commitment_root: String,
    pub encrypted_recovery_route_root: String,
    pub watchtower_set_root: String,
}

impl EvictionGuard {
    pub fn new(
        commitment: &EncryptedStorageCommitment,
        lot_id: impl Into<String>,
        sequence: u64,
        config: &Config,
    ) -> Self {
        let lot_id = lot_id.into();
        let seed = format!("{}:{lot_id}", commitment.commitment_id);
        Self {
            guard_id: deterministic_id("eviction-guard", sequence, &seed),
            commitment_id: commitment.commitment_id.clone(),
            lot_id,
            status: EvictionGuardStatus::Armed,
            protected_until_l2_height: DEVNET_L2_HEIGHT + config.eviction_guard_blocks,
            guard_weight_bps: config.supermajority_weight_bps,
            bond_commitment_root: deterministic_string("eviction-bond", sequence, &seed),
            encrypted_recovery_route_root: deterministic_string(
                "eviction-recovery-route",
                sequence,
                &seed,
            ),
            watchtower_set_root: deterministic_string("eviction-watchtower-set", sequence, &seed),
        }
    }

    pub fn protects(&self, commitment_id: &str, height: u64) -> bool {
        self.commitment_id == commitment_id
            && matches!(
                self.status,
                EvictionGuardStatus::Armed | EvictionGuardStatus::Matched
            )
            && height <= self.protected_until_l2_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bond_commitment_root": self.bond_commitment_root,
            "commitment_id": self.commitment_id,
            "encrypted_recovery_route_root": self.encrypted_recovery_route_root,
            "guard_id": self.guard_id,
            "guard_weight_bps": self.guard_weight_bps,
            "lot_id": self.lot_id,
            "protected_until_l2_height": self.protected_until_l2_height,
            "status": self.status.as_str(),
            "watchtower_set_root": self.watchtower_set_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub operator_id: String,
    pub status: RedactionBudgetStatus,
    pub epoch: u64,
    pub fields_allowed: u64,
    pub fields_spent: u64,
    pub privacy_set_floor: u64,
    pub reason_root: String,
    pub audit_trail_root: String,
}

impl RedactionBudget {
    pub fn new(operator_id: impl Into<String>, epoch: u64, sequence: u64, config: &Config) -> Self {
        let operator_id = operator_id.into();
        let seed = format!("{operator_id}:{epoch}");
        Self {
            budget_id: deterministic_id("redaction-budget", sequence, &seed),
            operator_id,
            status: RedactionBudgetStatus::Open,
            epoch,
            fields_allowed: 64,
            fields_spent: 0,
            privacy_set_floor: config.min_privacy_set_size,
            reason_root: deterministic_string("redaction-reason", sequence, &seed),
            audit_trail_root: deterministic_string("redaction-audit", sequence, &seed),
        }
    }

    pub fn debit(&mut self, fields: u64) -> Result<()> {
        if fields == 0 {
            return Err("redaction budget debit must be positive".to_string());
        }
        if self.fields_spent.saturating_add(fields) > self.fields_allowed {
            self.status = RedactionBudgetStatus::Exhausted;
            return Err("redaction budget exhausted".to_string());
        }
        self.fields_spent += fields;
        self.status = if self.fields_spent == self.fields_allowed {
            RedactionBudgetStatus::Exhausted
        } else {
            RedactionBudgetStatus::Debited
        };
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "audit_trail_root": self.audit_trail_root,
            "budget_id": self.budget_id,
            "epoch": self.epoch,
            "fields_allowed": self.fields_allowed,
            "fields_spent": self.fields_spent,
            "operator_id": self.operator_id,
            "privacy_set_floor": self.privacy_set_floor,
            "reason_root": self.reason_root,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub operator_id: String,
    pub health: OperatorHealth,
    pub attestation_count: u64,
    pub settlement_count: u64,
    pub compaction_count: u64,
    pub challenged_count: u64,
    pub average_match_ms: u64,
    pub average_settlement_ms: u64,
    pub fee_earned_micro_units: u64,
    pub rebate_paid_micro_units: u64,
    pub pq_key_commitment_root: String,
    pub availability_root: String,
    pub last_l2_height: u64,
}

impl OperatorSummary {
    pub fn new(operator_id: impl Into<String>, sequence: u64) -> Self {
        let operator_id = operator_id.into();
        Self {
            operator_id: operator_id.clone(),
            health: OperatorHealth::Green,
            attestation_count: 0,
            settlement_count: 0,
            compaction_count: 0,
            challenged_count: 0,
            average_match_ms: DEFAULT_TARGET_MATCH_MS,
            average_settlement_ms: DEFAULT_TARGET_SETTLEMENT_MS,
            fee_earned_micro_units: 0,
            rebate_paid_micro_units: 0,
            pq_key_commitment_root: deterministic_string("operator-pq-key", sequence, &operator_id),
            availability_root: deterministic_string(
                "operator-availability",
                sequence,
                &operator_id,
            ),
            last_l2_height: DEVNET_L2_HEIGHT,
        }
    }

    pub fn record_coupon(&mut self, coupon: &SettlementCoupon) {
        self.settlement_count += 1;
        self.fee_earned_micro_units = self
            .fee_earned_micro_units
            .saturating_add(coupon.fee_micro_units);
        self.rebate_paid_micro_units = self
            .rebate_paid_micro_units
            .saturating_add(coupon.rebate_micro_units);
        self.last_l2_height = coupon.issued_l2_height;
    }

    pub fn record_attestation(&mut self, attestation: &PqRentAttestation) {
        self.attestation_count += 1;
        if matches!(attestation.status, PqRentAttestationStatus::Challenged) {
            self.challenged_count += 1;
            self.health = OperatorHealth::Amber;
        }
        self.last_l2_height = attestation.created_l2_height;
    }

    pub fn record_compaction(&mut self, window: &CompactionWindow) {
        self.compaction_count += 1;
        self.last_l2_height = window.end_l2_height;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_count": self.attestation_count,
            "availability_root": self.availability_root,
            "average_match_ms": self.average_match_ms,
            "average_settlement_ms": self.average_settlement_ms,
            "challenged_count": self.challenged_count,
            "compaction_count": self.compaction_count,
            "fee_earned_micro_units": self.fee_earned_micro_units,
            "health": self.health.as_str(),
            "last_l2_height": self.last_l2_height,
            "operator_id": self.operator_id,
            "pq_key_commitment_root": self.pq_key_commitment_root,
            "rebate_paid_micro_units": self.rebate_paid_micro_units,
            "settlement_count": self.settlement_count
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub event_index: u64,
    pub kind: String,
    pub subject_id: String,
    pub l2_height: u64,
    pub record_root: String,
}

impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "event_index": self.event_index,
            "kind": self.kind,
            "l2_height": self.l2_height,
            "record_root": self.record_root,
            "subject_id": self.subject_id
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub books: BTreeMap<String, StorageRentFuturesBook>,
    pub orders: BTreeMap<String, StorageRentOrder>,
    pub hedge_lots: BTreeMap<String, RentHedgeLot>,
    pub storage_commitments: BTreeMap<String, EncryptedStorageCommitment>,
    pub pq_attestations: BTreeMap<String, PqRentAttestation>,
    pub settlement_coupons: BTreeMap<String, SettlementCoupon>,
    pub compaction_windows: BTreeMap<String, CompactionWindow>,
    pub eviction_guards: BTreeMap<String, EvictionGuard>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub events: BTreeMap<String, RuntimeEvent>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::empty(),
            books: BTreeMap::new(),
            orders: BTreeMap::new(),
            hedge_lots: BTreeMap::new(),
            storage_commitments: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            settlement_coupons: BTreeMap::new(),
            compaction_windows: BTreeMap::new(),
            eviction_guards: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            events: BTreeMap::new(),
        };
        state.refresh_accounting();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state =
            Self::new(Config::devnet()).expect("devnet storage rent futures config is valid");
        state.install_devnet_fixtures();
        state
    }

    pub fn open_book(&mut self, book: StorageRentFuturesBook) -> Result<String> {
        if self.books.len() >= self.config.max_books {
            return Err("storage rent futures book capacity exceeded".to_string());
        }
        book.validate(&self.config)?;
        let id = book.book_id.clone();
        self.books.insert(id.clone(), book);
        self.emit_event("book_opened", &id)?;
        self.refresh_accounting();
        Ok(id)
    }

    pub fn submit_order(&mut self, order: StorageRentOrder) -> Result<String> {
        if self.orders.len() >= self.config.max_orders {
            return Err("storage rent futures order capacity exceeded".to_string());
        }
        let book = self
            .books
            .get(&order.book_id)
            .ok_or_else(|| format!("unknown storage rent futures book {}", order.book_id))?;
        if !book.accepts_orders() {
            return Err("storage rent futures book does not accept orders".to_string());
        }
        order.validate(&self.config)?;
        let id = order.order_id.clone();
        self.orders.insert(id.clone(), order);
        self.emit_event("order_submitted", &id)?;
        self.refresh_accounting();
        Ok(id)
    }

    pub fn commit_storage(&mut self, commitment: EncryptedStorageCommitment) -> Result<String> {
        if self.storage_commitments.len() >= self.config.max_storage_commitments {
            return Err("encrypted storage commitment capacity exceeded".to_string());
        }
        commitment.validate(&self.config)?;
        let id = commitment.commitment_id.clone();
        self.storage_commitments.insert(id.clone(), commitment);
        self.emit_event("storage_commitment_announced", &id)?;
        self.refresh_accounting();
        Ok(id)
    }

    pub fn match_orders(
        &mut self,
        bid_order_id: &str,
        ask_order_id: &str,
        commitment_id: &str,
        bytes: u64,
    ) -> Result<String> {
        let bid = self
            .orders
            .get(bid_order_id)
            .cloned()
            .ok_or_else(|| format!("unknown bid order {bid_order_id}"))?;
        let ask = self
            .orders
            .get(ask_order_id)
            .cloned()
            .ok_or_else(|| format!("unknown ask order {ask_order_id}"))?;
        if bid.side != OrderSide::Bid || ask.side != OrderSide::Ask {
            return Err("storage rent futures match requires bid and ask orders".to_string());
        }
        if bid.book_id != ask.book_id {
            return Err(
                "storage rent futures cannot match orders from different books".to_string(),
            );
        }
        let book = self
            .books
            .get(&bid.book_id)
            .cloned()
            .ok_or_else(|| format!("unknown book {}", bid.book_id))?;
        if !book.accepts_orders() {
            return Err("storage rent futures book is not matching".to_string());
        }
        if !self.storage_commitments.contains_key(commitment_id) {
            return Err(format!("unknown storage commitment {commitment_id}"));
        }
        if bytes == 0 || bytes > bid.remaining_bytes || bytes > ask.remaining_bytes {
            return Err(
                "storage rent futures match bytes outside order remaining size".to_string(),
            );
        }
        if bid.rent_rate_micro_units < ask.rent_rate_micro_units {
            return Err("storage rent futures bid rate below ask rate".to_string());
        }
        let sequence = self.hedge_lots.len() as u64 + 1;
        let rate = (bid.rent_rate_micro_units + ask.rent_rate_micro_units) / 2;
        let lot = RentHedgeLot {
            bid_order_id: bid_order_id.to_string(),
            ask_order_id: ask_order_id.to_string(),
            ..RentHedgeLot::new(
                &book,
                bid_order_id,
                ask_order_id,
                commitment_id,
                bytes,
                rate,
                sequence,
            )
        };
        lot.validate()?;
        self.orders
            .get_mut(bid_order_id)
            .expect("bid checked above")
            .fill(bytes)?;
        self.orders
            .get_mut(ask_order_id)
            .expect("ask checked above")
            .fill(bytes)?;
        let id = lot.lot_id.clone();
        self.hedge_lots.insert(id.clone(), lot);
        self.emit_event("hedge_lot_matched", &id)?;
        self.refresh_accounting();
        Ok(id)
    }

    pub fn publish_attestation(&mut self, mut attestation: PqRentAttestation) -> Result<String> {
        if self.pq_attestations.len() >= self.config.max_attestations {
            return Err("pq rent attestation capacity exceeded".to_string());
        }
        let lot = self
            .hedge_lots
            .get_mut(&attestation.lot_id)
            .ok_or_else(|| format!("unknown hedge lot {}", attestation.lot_id))?;
        if lot.storage_commitment_id != attestation.commitment_id {
            return Err("pq rent attestation commitment does not match hedge lot".to_string());
        }
        attestation.finalize(&self.config)?;
        lot.status = HedgeLotStatus::Attested;
        let operator_id = attestation.operator_id.clone();
        let id = attestation.attestation_id.clone();
        self.operator_summaries
            .entry(operator_id.clone())
            .or_insert_with(|| {
                OperatorSummary::new(operator_id, self.operator_summaries.len() as u64 + 1)
            })
            .record_attestation(&attestation);
        self.pq_attestations.insert(id.clone(), attestation);
        self.emit_event("pq_rent_attestation_published", &id)?;
        self.refresh_accounting();
        Ok(id)
    }

    pub fn issue_coupon(
        &mut self,
        lot_id: &str,
        attestation_id: &str,
        payee_commitment: impl Into<String>,
    ) -> Result<String> {
        if self.settlement_coupons.len() >= self.config.max_coupons {
            return Err("storage rent settlement coupon capacity exceeded".to_string());
        }
        let lot = self
            .hedge_lots
            .get(lot_id)
            .cloned()
            .ok_or_else(|| format!("unknown hedge lot {lot_id}"))?;
        let attestation = self
            .pq_attestations
            .get(attestation_id)
            .cloned()
            .ok_or_else(|| format!("unknown pq rent attestation {attestation_id}"))?;
        if attestation.lot_id != lot.lot_id || !attestation.accepts_settlement(&self.config) {
            return Err("pq rent attestation cannot settle requested hedge lot".to_string());
        }
        let sequence = self.settlement_coupons.len() as u64 + 1;
        let coupon =
            SettlementCoupon::new(&lot, &attestation, payee_commitment, sequence, &self.config);
        let id = coupon.coupon_id.clone();
        self.hedge_lots
            .get_mut(lot_id)
            .expect("lot checked above")
            .attach_coupon(id.clone());
        self.operator_summaries
            .entry(attestation.operator_id.clone())
            .or_insert_with(|| OperatorSummary::new(attestation.operator_id.clone(), sequence))
            .record_coupon(&coupon);
        self.settlement_coupons.insert(id.clone(), coupon);
        self.emit_event("settlement_coupon_issued", &id)?;
        self.refresh_accounting();
        Ok(id)
    }

    pub fn schedule_compaction(&mut self, window: CompactionWindow) -> Result<String> {
        if self.compaction_windows.len() >= self.config.max_compaction_windows {
            return Err("compaction window capacity exceeded".to_string());
        }
        if !self.storage_commitments.contains_key(&window.commitment_id) {
            return Err(format!(
                "unknown storage commitment {}",
                window.commitment_id
            ));
        }
        let id = window.window_id.clone();
        let operator_id = window.operator_id.clone();
        self.operator_summaries
            .entry(operator_id.clone())
            .or_insert_with(|| {
                OperatorSummary::new(operator_id, self.operator_summaries.len() as u64 + 1)
            })
            .record_compaction(&window);
        self.compaction_windows.insert(id.clone(), window);
        self.emit_event("compaction_window_scheduled", &id)?;
        self.refresh_accounting();
        Ok(id)
    }

    pub fn arm_eviction_guard(&mut self, guard: EvictionGuard) -> Result<String> {
        if self.eviction_guards.len() >= self.config.max_eviction_guards {
            return Err("eviction guard capacity exceeded".to_string());
        }
        let commitment = self
            .storage_commitments
            .get_mut(&guard.commitment_id)
            .ok_or_else(|| format!("unknown storage commitment {}", guard.commitment_id))?;
        commitment.status = StorageCommitmentStatus::Guarded;
        let id = guard.guard_id.clone();
        self.eviction_guards.insert(id.clone(), guard);
        self.emit_event("eviction_guard_armed", &id)?;
        self.refresh_accounting();
        Ok(id)
    }

    pub fn open_redaction_budget(&mut self, budget: RedactionBudget) -> Result<String> {
        if self.redaction_budgets.len() >= self.config.max_redaction_budgets {
            return Err("redaction budget capacity exceeded".to_string());
        }
        let id = budget.budget_id.clone();
        self.redaction_budgets.insert(id.clone(), budget);
        self.emit_event("redaction_budget_opened", &id)?;
        self.refresh_accounting();
        Ok(id)
    }

    pub fn redeem_coupon(&mut self, coupon_id: &str) -> Result<()> {
        let coupon = self
            .settlement_coupons
            .get_mut(coupon_id)
            .ok_or_else(|| format!("unknown settlement coupon {coupon_id}"))?;
        coupon.redeem()?;
        self.emit_event("settlement_coupon_redeemed", coupon_id)?;
        self.refresh_accounting();
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        set_json_field(&mut record, "state_root", json!(self.state_root()));
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record_without_state_root())
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: root_from_record("config", &self.config.public_record()),
            counters_root: root_from_record("counters", &self.counters.public_record()),
            books_root: map_root("books", &self.books),
            orders_root: map_root("orders", &self.orders),
            hedge_lots_root: map_root("hedge-lots", &self.hedge_lots),
            storage_commitments_root: map_root("storage-commitments", &self.storage_commitments),
            pq_attestations_root: map_root("pq-rent-attestations", &self.pq_attestations),
            settlement_coupons_root: map_root("settlement-coupons", &self.settlement_coupons),
            compaction_windows_root: map_root("compaction-windows", &self.compaction_windows),
            eviction_guards_root: map_root("eviction-guards", &self.eviction_guards),
            redaction_budgets_root: map_root("redaction-budgets", &self.redaction_budgets),
            operator_summaries_root: map_root("operator-summaries", &self.operator_summaries),
            events_root: map_root("events", &self.events),
            state_root: self.state_root(),
        }
    }

    pub fn refresh_accounting(&mut self) {
        self.counters = self.derive_counters();
        self.roots = self.roots();
    }

    fn derive_counters(&self) -> Counters {
        let open_orders = self
            .orders
            .values()
            .filter(|order| order.is_open())
            .collect::<Vec<_>>();
        let open_notional_micro_units = open_orders.iter().fold(0u128, |sum, order| {
            sum.saturating_add(order.notional_micro_units())
        });
        let matched_notional_micro_units = self.hedge_lots.values().fold(0u128, |sum, lot| {
            sum.saturating_add(lot.notional_micro_units())
        });
        let settled_coupon_micro_units = self
            .settlement_coupons
            .values()
            .filter(|coupon| {
                matches!(
                    coupon.status,
                    SettlementCouponStatus::Redeemed | SettlementCouponStatus::Netted
                )
            })
            .fold(0u128, |sum, coupon| {
                sum.saturating_add(coupon.coupon_value_micro_units as u128)
            });
        let total_fee_micro_units = self.settlement_coupons.values().fold(0u128, |sum, coupon| {
            sum.saturating_add(coupon.fee_micro_units as u128)
        });
        let total_rebate_micro_units =
            self.settlement_coupons.values().fold(0u128, |sum, coupon| {
                sum.saturating_add(coupon.rebate_micro_units as u128)
            });
        let guarded_storage_bytes = self
            .storage_commitments
            .values()
            .fold(0u128, |sum, commitment| {
                sum.saturating_add(commitment.guarded_bytes())
            });
        let compacted_storage_bytes =
            self.compaction_windows.values().fold(0u128, |sum, window| {
                sum.saturating_add(window.saved_bytes() as u128)
            });
        let redacted_field_count = self
            .redaction_budgets
            .values()
            .fold(0u64, |sum, budget| sum.saturating_add(budget.fields_spent));
        let challenged_attestation_count = self
            .pq_attestations
            .values()
            .filter(|attestation| matches!(attestation.status, PqRentAttestationStatus::Challenged))
            .count() as u64;
        Counters {
            book_count: self.books.len() as u64,
            order_count: self.orders.len() as u64,
            hedge_lot_count: self.hedge_lots.len() as u64,
            storage_commitment_count: self.storage_commitments.len() as u64,
            pq_attestation_count: self.pq_attestations.len() as u64,
            settlement_coupon_count: self.settlement_coupons.len() as u64,
            compaction_window_count: self.compaction_windows.len() as u64,
            eviction_guard_count: self.eviction_guards.len() as u64,
            redaction_budget_count: self.redaction_budgets.len() as u64,
            operator_summary_count: self.operator_summaries.len() as u64,
            event_count: self.events.len() as u64,
            open_order_count: open_orders.len() as u64,
            open_notional_micro_units,
            matched_notional_micro_units,
            settled_coupon_micro_units,
            total_fee_micro_units,
            total_rebate_micro_units,
            guarded_storage_bytes,
            compacted_storage_bytes,
            redacted_field_count,
            challenged_attestation_count,
        }
    }

    fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "protocol_version": PROTOCOL_VERSION,
            "roots": roots.public_record(),
            "schema_version": SCHEMA_VERSION
        })
    }

    fn emit_event(&mut self, kind: &str, subject_id: &str) -> Result<()> {
        if self.events.len() >= self.config.max_events {
            return Err("storage rent futures event capacity exceeded".to_string());
        }
        let index = self.events.len() as u64 + 1;
        let event_id = deterministic_id("event", index, &format!("{kind}:{subject_id}"));
        let record_root =
            deterministic_string("event-record", index, &format!("{kind}:{subject_id}"));
        self.events.insert(
            event_id.clone(),
            RuntimeEvent {
                event_id,
                event_index: index,
                kind: kind.to_string(),
                subject_id: subject_id.to_string(),
                l2_height: DEVNET_L2_HEIGHT + index,
                record_root,
            },
        );
        Ok(())
    }

    fn install_devnet_fixtures(&mut self) {
        let book_hot = StorageRentFuturesBook::new(
            "SRF-HOT-CONTRACT-STATE-WEEK",
            StorageClass::HotContractState,
            RentTenor::Week,
            1,
            &self.config,
        );
        let book_witness = StorageRentFuturesBook::new(
            "SRF-PROOF-WITNESS-CACHE-MONTH",
            StorageClass::ProofWitnessCache,
            RentTenor::Month,
            2,
            &self.config,
        );
        let hot_book_id = self.open_book(book_hot).expect("devnet hot book opens");
        let witness_book_id = self
            .open_book(book_witness)
            .expect("devnet witness book opens");

        let commitment_a = EncryptedStorageCommitment::new(
            "contract:private-vault-router",
            "viewtag:devnet-alice",
            StorageClass::HotContractState,
            8_388_608,
            1,
            &self.config,
        );
        let commitment_b = EncryptedStorageCommitment::new(
            "contract:zk-options-clearing",
            "viewtag:devnet-bob",
            StorageClass::ProofWitnessCache,
            33_554_432,
            2,
            &self.config,
        );
        let commitment_a_id = self
            .commit_storage(commitment_a)
            .expect("devnet commitment a");
        let commitment_b_id = self
            .commit_storage(commitment_b)
            .expect("devnet commitment b");

        let bid = StorageRentOrder::new(
            hot_book_id.clone(),
            "owner:bidder:private-vault-router",
            OrderSide::Bid,
            2_097_152,
            420,
            1,
            &self.config,
        );
        let ask = StorageRentOrder::new(
            hot_book_id.clone(),
            "owner:asker:storage-underwriter-a",
            OrderSide::Ask,
            2_097_152,
            390,
            2,
            &self.config,
        );
        let bid_id = self.submit_order(bid).expect("devnet bid order");
        let ask_id = self.submit_order(ask).expect("devnet ask order");
        let lot_id = self
            .match_orders(&bid_id, &ask_id, &commitment_a_id, 1_048_576)
            .expect("devnet hot order match");

        let mut lot = self.hedge_lots.get(&lot_id).cloned().expect("lot inserted");
        lot.status = HedgeLotStatus::Matched;
        self.hedge_lots.insert(lot_id.clone(), lot.clone());

        let mut attestation =
            PqRentAttestation::new(&lot, "operator:devnet-storage-rent-0", 405, 1, &self.config);
        attestation.quorum_weight_bps = self.config.supermajority_weight_bps;
        let attestation_id = self
            .publish_attestation(attestation)
            .expect("devnet pq rent attestation");
        let coupon_id = self
            .issue_coupon(&lot_id, &attestation_id, "payee:private-vault-router")
            .expect("devnet coupon");
        self.redeem_coupon(&coupon_id)
            .expect("devnet coupon redeem");

        let compaction = CompactionWindow::new(
            self.storage_commitments
                .get(&commitment_b_id)
                .expect("commitment b exists"),
            "operator:devnet-storage-rent-1",
            25_165_824,
            1,
            &self.config,
        );
        self.schedule_compaction(compaction)
            .expect("devnet compaction window");
        let guard = EvictionGuard::new(
            self.storage_commitments
                .get(&commitment_a_id)
                .expect("commitment a exists"),
            lot_id,
            1,
            &self.config,
        );
        self.arm_eviction_guard(guard)
            .expect("devnet eviction guard");
        let mut budget = RedactionBudget::new(
            "operator:devnet-storage-rent-0",
            DEVNET_EPOCH,
            1,
            &self.config,
        );
        budget.debit(2).expect("devnet redaction debit");
        self.open_redaction_budget(budget)
            .expect("devnet redaction budget");

        let witness_bid = StorageRentOrder::new(
            witness_book_id.clone(),
            "owner:bidder:witness-cache",
            OrderSide::Bid,
            4_194_304,
            180,
            3,
            &self.config,
        );
        let witness_ask = StorageRentOrder::new(
            witness_book_id,
            "owner:asker:witness-underwriter",
            OrderSide::Ask,
            4_194_304,
            170,
            4,
            &self.config,
        );
        self.submit_order(witness_bid).expect("devnet witness bid");
        self.submit_order(witness_ask).expect("devnet witness ask");
        self.refresh_accounting();
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> Value {
    State::devnet().public_record()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn state_root_from_public_record(record: &Value) -> String {
    domain_hash(
        "private-l2-pq-confidential-contract-storage-rent-futures-market:state-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn empty_root(name: &str) -> String {
    merkle_root(
        &format!("private-l2-pq-confidential-contract-storage-rent-futures-market:{name}"),
        &Vec::<Value>::new(),
    )
}

fn map_root<T: PublicRecord>(name: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": value.public_record() }))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("private-l2-pq-confidential-contract-storage-rent-futures-market:{name}"),
        &leaves,
    )
}

fn root_from_record(name: &str, record: &Value) -> String {
    domain_hash(
        "private-l2-pq-confidential-contract-storage-rent-futures-market:record-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(name),
            HashPart::Json(record),
        ],
        32,
    )
}

fn deterministic_id(kind: &str, index: u64, seed: &str) -> String {
    format!(
        "{kind}-{}",
        domain_hash(
            "private-l2-pq-confidential-contract-storage-rent-futures-market:id",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(kind),
                HashPart::U64(index),
                HashPart::Str(seed),
            ],
            16,
        )
    )
}

fn deterministic_string(kind: &str, index: u64, seed: &str) -> String {
    domain_hash(
        "private-l2-pq-confidential-contract-storage-rent-futures-market:deterministic-string",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::U64(index),
            HashPart::Str(seed),
        ],
        32,
    )
}

fn fee_for_notional(notional_micro_units: u128, bps: u64) -> u128 {
    notional_micro_units.saturating_mul(bps as u128) / MAX_BPS as u128
}

fn ensure_nonempty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("storage rent futures {label} must be non-empty"))
    } else {
        Ok(())
    }
}

fn ensure_bps(label: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!(
            "storage rent futures {label} exceeds {MAX_BPS} bps"
        ))
    } else {
        Ok(())
    }
}

fn set_json_field(record: &mut Value, key: &str, value: Value) {
    if let Some(object) = record.as_object_mut() {
        object.insert(key.to_string(), value);
    }
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for StorageRentFuturesBook {
    fn public_record(&self) -> Value {
        StorageRentFuturesBook::public_record(self)
    }
}

impl PublicRecord for StorageRentOrder {
    fn public_record(&self) -> Value {
        StorageRentOrder::public_record(self)
    }
}

impl PublicRecord for RentHedgeLot {
    fn public_record(&self) -> Value {
        RentHedgeLot::public_record(self)
    }
}

impl PublicRecord for EncryptedStorageCommitment {
    fn public_record(&self) -> Value {
        EncryptedStorageCommitment::public_record(self)
    }
}

impl PublicRecord for PqRentAttestation {
    fn public_record(&self) -> Value {
        PqRentAttestation::public_record(self)
    }
}

impl PublicRecord for SettlementCoupon {
    fn public_record(&self) -> Value {
        SettlementCoupon::public_record(self)
    }
}

impl PublicRecord for CompactionWindow {
    fn public_record(&self) -> Value {
        CompactionWindow::public_record(self)
    }
}

impl PublicRecord for EvictionGuard {
    fn public_record(&self) -> Value {
        EvictionGuard::public_record(self)
    }
}

impl PublicRecord for RedactionBudget {
    fn public_record(&self) -> Value {
        RedactionBudget::public_record(self)
    }
}

impl PublicRecord for OperatorSummary {
    fn public_record(&self) -> Value {
        OperatorSummary::public_record(self)
    }
}

impl PublicRecord for RuntimeEvent {
    fn public_record(&self) -> Value {
        RuntimeEvent::public_record(self)
    }
}
