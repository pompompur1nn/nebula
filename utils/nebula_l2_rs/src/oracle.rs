use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    fees::{FeeMarketResource, LowFeeLane},
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub const ORACLE_PROTOCOL_VERSION: &str = "nebula-oracle-v1";
pub const ORACLE_DEFAULT_HEARTBEAT_BLOCKS: u64 = 12;
pub const ORACLE_DEFAULT_TWAP_WINDOW_BLOCKS: u64 = 120;
pub const ORACLE_DEFAULT_MAX_DEVIATION_BPS: u64 = 1_000;
pub const ORACLE_DEFAULT_MIN_SOURCES: u64 = 2;
pub const ORACLE_DEFAULT_DECIMALS: u8 = 12;
pub const ORACLE_MAX_OBSERVATIONS_PER_FEED: usize = 512;
pub const ORACLE_MAX_SOURCES_PER_FEED: usize = 64;
pub const ORACLE_LOW_FEE_UPDATE_UNITS: u64 = 2;
pub const ORACLE_ATTESTATION_PROOF_BYTES: u64 = 768;
pub const ORACLE_PRICE_PROOF_SYSTEM: &str = "devnet-weighted-median-price-proof";
pub const ORACLE_STATUS_ACTIVE: &str = "active";
pub const ORACLE_STATUS_PAUSED: &str = "paused";
pub const ORACLE_STATUS_RETIRED: &str = "retired";

pub type OracleResult<T> = Result<T, String>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleFeedConfig {
    pub feed_id: String,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub decimals: u8,
    pub min_sources: u64,
    pub heartbeat_blocks: u64,
    pub twap_window_blocks: u64,
    pub max_deviation_bps: u64,
    pub status: String,
    pub metadata_root: String,
}

impl OracleFeedConfig {
    pub fn new(base_asset_id: &str, quote_asset_id: &str) -> OracleResult<Self> {
        Self::with_policy(
            base_asset_id,
            quote_asset_id,
            ORACLE_DEFAULT_DECIMALS,
            ORACLE_DEFAULT_MIN_SOURCES,
            ORACLE_DEFAULT_HEARTBEAT_BLOCKS,
            ORACLE_DEFAULT_TWAP_WINDOW_BLOCKS,
            ORACLE_DEFAULT_MAX_DEVIATION_BPS,
            &json!({}),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_policy(
        base_asset_id: &str,
        quote_asset_id: &str,
        decimals: u8,
        min_sources: u64,
        heartbeat_blocks: u64,
        twap_window_blocks: u64,
        max_deviation_bps: u64,
        metadata: &Value,
    ) -> OracleResult<Self> {
        if base_asset_id.is_empty() || quote_asset_id.is_empty() {
            return Err("oracle feed assets cannot be empty".to_string());
        }
        if base_asset_id == quote_asset_id {
            return Err("oracle feed requires two distinct assets".to_string());
        }
        if min_sources == 0 {
            return Err("oracle feed min_sources must be positive".to_string());
        }
        if heartbeat_blocks == 0 || twap_window_blocks == 0 {
            return Err("oracle feed windows must be positive".to_string());
        }
        let metadata_root = oracle_metadata_root(metadata);
        let feed_id = oracle_feed_config_id(
            base_asset_id,
            quote_asset_id,
            decimals,
            min_sources,
            heartbeat_blocks,
            twap_window_blocks,
            max_deviation_bps,
            &metadata_root,
        );
        Ok(Self {
            feed_id,
            base_asset_id: base_asset_id.to_string(),
            quote_asset_id: quote_asset_id.to_string(),
            decimals,
            min_sources,
            heartbeat_blocks,
            twap_window_blocks,
            max_deviation_bps,
            status: ORACLE_STATUS_ACTIVE.to_string(),
            metadata_root,
        })
    }

    pub fn validate(&self) -> OracleResult<()> {
        if self.base_asset_id.is_empty() || self.quote_asset_id.is_empty() {
            return Err("oracle feed assets cannot be empty".to_string());
        }
        if self.base_asset_id == self.quote_asset_id {
            return Err("oracle feed requires two distinct assets".to_string());
        }
        if self.min_sources == 0 {
            return Err("oracle feed min_sources must be positive".to_string());
        }
        if self.heartbeat_blocks == 0 || self.twap_window_blocks == 0 {
            return Err("oracle feed windows must be positive".to_string());
        }
        if !matches!(
            self.status.as_str(),
            ORACLE_STATUS_ACTIVE | ORACLE_STATUS_PAUSED | ORACLE_STATUS_RETIRED
        ) {
            return Err("oracle feed status is unknown".to_string());
        }
        if self.feed_id
            != oracle_feed_config_id(
                &self.base_asset_id,
                &self.quote_asset_id,
                self.decimals,
                self.min_sources,
                self.heartbeat_blocks,
                self.twap_window_blocks,
                self.max_deviation_bps,
                &self.metadata_root,
            )
        {
            return Err("oracle feed id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "oracle_feed_config",
            "chain_id": CHAIN_ID,
            "protocol_version": ORACLE_PROTOCOL_VERSION,
            "feed_id": self.feed_id,
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "decimals": self.decimals,
            "min_sources": self.min_sources,
            "heartbeat_blocks": self.heartbeat_blocks,
            "twap_window_blocks": self.twap_window_blocks,
            "max_deviation_bps": self.max_deviation_bps,
            "status": self.status,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleSource {
    pub source_id: String,
    pub feed_id: String,
    pub publisher_label: String,
    pub publisher_commitment: String,
    pub public_key_root: String,
    pub weight_bps: u64,
    pub min_interval_blocks: u64,
    pub max_staleness_blocks: u64,
    pub active: bool,
    pub metadata_root: String,
}

impl OracleSource {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        feed_id: &str,
        publisher_label: &str,
        public_key_root: &str,
        weight_bps: u64,
        min_interval_blocks: u64,
        max_staleness_blocks: u64,
        metadata: &Value,
    ) -> OracleResult<Self> {
        if feed_id.is_empty() {
            return Err("oracle source feed_id cannot be empty".to_string());
        }
        if publisher_label.is_empty() {
            return Err("oracle source publisher label cannot be empty".to_string());
        }
        if public_key_root.is_empty() {
            return Err("oracle source public key root cannot be empty".to_string());
        }
        if weight_bps == 0 {
            return Err("oracle source weight must be positive".to_string());
        }
        let publisher_commitment = oracle_publisher_commitment(publisher_label);
        let metadata_root = oracle_metadata_root(metadata);
        let source_id = oracle_source_id(
            feed_id,
            &publisher_commitment,
            public_key_root,
            weight_bps,
            min_interval_blocks,
            max_staleness_blocks,
            &metadata_root,
        );
        Ok(Self {
            source_id,
            feed_id: feed_id.to_string(),
            publisher_label: publisher_label.to_string(),
            publisher_commitment,
            public_key_root: public_key_root.to_string(),
            weight_bps,
            min_interval_blocks,
            max_staleness_blocks,
            active: true,
            metadata_root,
        })
    }

    pub fn validate(&self) -> OracleResult<()> {
        if self.feed_id.is_empty() || self.source_id.is_empty() {
            return Err("oracle source identifiers cannot be empty".to_string());
        }
        if self.publisher_label.is_empty() || self.publisher_commitment.is_empty() {
            return Err("oracle source publisher cannot be empty".to_string());
        }
        if self.public_key_root.is_empty() {
            return Err("oracle source public key root cannot be empty".to_string());
        }
        if self.weight_bps == 0 {
            return Err("oracle source weight must be positive".to_string());
        }
        if self.publisher_commitment != oracle_publisher_commitment(&self.publisher_label) {
            return Err("oracle source publisher commitment mismatch".to_string());
        }
        if self.source_id
            != oracle_source_id(
                &self.feed_id,
                &self.publisher_commitment,
                &self.public_key_root,
                self.weight_bps,
                self.min_interval_blocks,
                self.max_staleness_blocks,
                &self.metadata_root,
            )
        {
            return Err("oracle source id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "oracle_source",
            "chain_id": CHAIN_ID,
            "source_id": self.source_id,
            "feed_id": self.feed_id,
            "publisher_commitment": self.publisher_commitment,
            "public_key_root": self.public_key_root,
            "weight_bps": self.weight_bps,
            "min_interval_blocks": self.min_interval_blocks,
            "max_staleness_blocks": self.max_staleness_blocks,
            "active": self.active,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        record
            .as_object_mut()
            .expect("oracle source state record")
            .insert(
                "publisher_label".to_string(),
                Value::String(self.publisher_label.clone()),
            );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleObservation {
    pub observation_id: String,
    pub feed_id: String,
    pub source_id: String,
    pub publisher_commitment: String,
    pub round: u64,
    pub price: u64,
    pub exponent: i32,
    pub confidence_bps: u64,
    pub observed_at_height: u64,
    pub observed_at_ms: u64,
    pub payload_root: String,
    pub signature_root: String,
}

impl OracleObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        feed_id: &str,
        source: &OracleSource,
        round: u64,
        price: u64,
        exponent: i32,
        confidence_bps: u64,
        observed_at_height: u64,
        observed_at_ms: u64,
        signature_root: &str,
    ) -> OracleResult<Self> {
        if feed_id != source.feed_id {
            return Err("oracle observation source feed mismatch".to_string());
        }
        if round == 0 {
            return Err("oracle observation round must be positive".to_string());
        }
        if price == 0 {
            return Err("oracle observation price must be positive".to_string());
        }
        if confidence_bps > 10_000 {
            return Err("oracle observation confidence cannot exceed 10000 bps".to_string());
        }
        if signature_root.is_empty() {
            return Err("oracle observation signature root cannot be empty".to_string());
        }
        let payload_root = oracle_observation_payload_root(
            feed_id,
            &source.source_id,
            round,
            price,
            exponent,
            confidence_bps,
            observed_at_height,
            observed_at_ms,
        );
        let observation_id = oracle_observation_id(
            feed_id,
            &source.source_id,
            round,
            &payload_root,
            signature_root,
        );
        Ok(Self {
            observation_id,
            feed_id: feed_id.to_string(),
            source_id: source.source_id.clone(),
            publisher_commitment: source.publisher_commitment.clone(),
            round,
            price,
            exponent,
            confidence_bps,
            observed_at_height,
            observed_at_ms,
            payload_root,
            signature_root: signature_root.to_string(),
        })
    }

    pub fn validate(&self) -> OracleResult<()> {
        if self.feed_id.is_empty()
            || self.source_id.is_empty()
            || self.observation_id.is_empty()
            || self.signature_root.is_empty()
        {
            return Err("oracle observation identifiers cannot be empty".to_string());
        }
        if self.round == 0 {
            return Err("oracle observation round must be positive".to_string());
        }
        if self.price == 0 {
            return Err("oracle observation price must be positive".to_string());
        }
        if self.confidence_bps > 10_000 {
            return Err("oracle observation confidence cannot exceed 10000 bps".to_string());
        }
        if self.payload_root
            != oracle_observation_payload_root(
                &self.feed_id,
                &self.source_id,
                self.round,
                self.price,
                self.exponent,
                self.confidence_bps,
                self.observed_at_height,
                self.observed_at_ms,
            )
        {
            return Err("oracle observation payload root mismatch".to_string());
        }
        if self.observation_id
            != oracle_observation_id(
                &self.feed_id,
                &self.source_id,
                self.round,
                &self.payload_root,
                &self.signature_root,
            )
        {
            return Err("oracle observation id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "oracle_observation",
            "chain_id": CHAIN_ID,
            "observation_id": self.observation_id,
            "feed_id": self.feed_id,
            "source_id": self.source_id,
            "publisher_commitment": self.publisher_commitment,
            "round": self.round,
            "price": self.price,
            "exponent": self.exponent,
            "confidence_bps": self.confidence_bps,
            "observed_at_height": self.observed_at_height,
            "observed_at_ms": self.observed_at_ms,
            "payload_root": self.payload_root,
            "signature_root": self.signature_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleAggregate {
    pub aggregate_id: String,
    pub feed_id: String,
    pub round: u64,
    pub median_price: u64,
    pub weighted_price: u64,
    pub twap_price: u64,
    pub exponent: i32,
    pub confidence_bps: u64,
    pub min_price: u64,
    pub max_price: u64,
    pub observation_root: String,
    pub source_weight_root: String,
    pub published_at_height: u64,
    pub stale_after_height: u64,
    pub proof_system: String,
}

impl OracleAggregate {
    pub fn validate(&self) -> OracleResult<()> {
        if self.feed_id.is_empty() || self.aggregate_id.is_empty() {
            return Err("oracle aggregate identifiers cannot be empty".to_string());
        }
        if self.round == 0 {
            return Err("oracle aggregate round must be positive".to_string());
        }
        if self.median_price == 0 || self.weighted_price == 0 || self.twap_price == 0 {
            return Err("oracle aggregate prices must be positive".to_string());
        }
        if self.min_price > self.max_price {
            return Err("oracle aggregate min price exceeds max price".to_string());
        }
        if self.published_at_height >= self.stale_after_height {
            return Err("oracle aggregate must have a future stale height".to_string());
        }
        if self.aggregate_id
            != oracle_aggregate_id(
                &self.feed_id,
                self.round,
                self.median_price,
                self.weighted_price,
                self.twap_price,
                self.exponent,
                &self.observation_root,
                &self.source_weight_root,
                self.published_at_height,
                self.stale_after_height,
            )
        {
            return Err("oracle aggregate id mismatch".to_string());
        }
        Ok(())
    }

    pub fn is_stale(&self, height: u64) -> bool {
        height > self.stale_after_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "oracle_aggregate",
            "chain_id": CHAIN_ID,
            "aggregate_id": self.aggregate_id,
            "feed_id": self.feed_id,
            "round": self.round,
            "median_price": self.median_price,
            "weighted_price": self.weighted_price,
            "twap_price": self.twap_price,
            "exponent": self.exponent,
            "confidence_bps": self.confidence_bps,
            "min_price": self.min_price,
            "max_price": self.max_price,
            "observation_root": self.observation_root,
            "source_weight_root": self.source_weight_root,
            "published_at_height": self.published_at_height,
            "stale_after_height": self.stale_after_height,
            "proof_system": self.proof_system,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleTwapWindow {
    pub window_id: String,
    pub feed_id: String,
    pub from_height: u64,
    pub to_height: u64,
    pub aggregate_root: String,
    pub sample_count: u64,
    pub twap_price: u64,
}

impl OracleTwapWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "oracle_twap_window",
            "chain_id": CHAIN_ID,
            "window_id": self.window_id,
            "feed_id": self.feed_id,
            "from_height": self.from_height,
            "to_height": self.to_height,
            "aggregate_root": self.aggregate_root,
            "sample_count": self.sample_count,
            "twap_price": self.twap_price,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleUpdateReceipt {
    pub receipt_id: String,
    pub feed_id: String,
    pub round: u64,
    pub observation_root: String,
    pub aggregate_root: String,
    pub previous_aggregate_root: String,
    pub update_fee_units: u64,
    pub low_fee_lane_id: String,
    pub accepted: bool,
    pub reason: String,
}

impl OracleUpdateReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "oracle_update_receipt",
            "chain_id": CHAIN_ID,
            "receipt_id": self.receipt_id,
            "feed_id": self.feed_id,
            "round": self.round,
            "observation_root": self.observation_root,
            "aggregate_root": self.aggregate_root,
            "previous_aggregate_root": self.previous_aggregate_root,
            "update_fee_units": self.update_fee_units,
            "low_fee_lane_id": self.low_fee_lane_id,
            "accepted": self.accepted,
            "reason": self.reason,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleDeviationEvidence {
    pub evidence_id: String,
    pub feed_id: String,
    pub left_observation_id: String,
    pub right_observation_id: String,
    pub left_price: u64,
    pub right_price: u64,
    pub deviation_bps: u64,
    pub max_deviation_bps: u64,
    pub reporter_commitment: String,
    pub reported_at_height: u64,
}

impl OracleDeviationEvidence {
    pub fn validate(&self) -> OracleResult<()> {
        if self.left_observation_id == self.right_observation_id {
            return Err("oracle deviation evidence requires two observations".to_string());
        }
        if self.deviation_bps <= self.max_deviation_bps {
            return Err("oracle deviation evidence is below threshold".to_string());
        }
        if self.evidence_id
            != oracle_deviation_evidence_id(
                &self.feed_id,
                &self.left_observation_id,
                &self.right_observation_id,
                self.left_price,
                self.right_price,
                self.deviation_bps,
                self.max_deviation_bps,
                &self.reporter_commitment,
                self.reported_at_height,
            )
        {
            return Err("oracle deviation evidence id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "oracle_deviation_evidence",
            "chain_id": CHAIN_ID,
            "evidence_id": self.evidence_id,
            "feed_id": self.feed_id,
            "left_observation_id": self.left_observation_id,
            "right_observation_id": self.right_observation_id,
            "left_price": self.left_price,
            "right_price": self.right_price,
            "deviation_bps": self.deviation_bps,
            "max_deviation_bps": self.max_deviation_bps,
            "reporter_commitment": self.reporter_commitment,
            "reported_at_height": self.reported_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleLiquidationGuard {
    pub guard_id: String,
    pub market_id: String,
    pub feed_id: String,
    pub aggregate_id: String,
    pub collateral_asset_id: String,
    pub debt_asset_id: String,
    pub protected_price: u64,
    pub max_staleness_blocks: u64,
    pub checked_at_height: u64,
    pub allows_liquidation: bool,
    pub reason: String,
}

impl OracleLiquidationGuard {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "oracle_liquidation_guard",
            "chain_id": CHAIN_ID,
            "guard_id": self.guard_id,
            "market_id": self.market_id,
            "feed_id": self.feed_id,
            "aggregate_id": self.aggregate_id,
            "collateral_asset_id": self.collateral_asset_id,
            "debt_asset_id": self.debt_asset_id,
            "protected_price": self.protected_price,
            "max_staleness_blocks": self.max_staleness_blocks,
            "checked_at_height": self.checked_at_height,
            "allows_liquidation": self.allows_liquidation,
            "reason": self.reason,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleState {
    pub feeds: BTreeMap<String, OracleFeedConfig>,
    pub sources: BTreeMap<String, OracleSource>,
    pub observations: BTreeMap<String, Vec<OracleObservation>>,
    pub aggregates: BTreeMap<String, OracleAggregate>,
    pub twap_windows: BTreeMap<String, OracleTwapWindow>,
    pub receipts: BTreeMap<String, OracleUpdateReceipt>,
    pub deviation_evidence: BTreeMap<String, OracleDeviationEvidence>,
    pub liquidation_guards: BTreeMap<String, OracleLiquidationGuard>,
    pub height: u64,
}

impl OracleState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn insert_feed(&mut self, feed: OracleFeedConfig) -> OracleResult<OracleFeedConfig> {
        feed.validate()?;
        if self.feeds.contains_key(&feed.feed_id) {
            return Err("oracle feed already exists".to_string());
        }
        self.feeds.insert(feed.feed_id.clone(), feed.clone());
        Ok(feed)
    }

    pub fn insert_source(&mut self, source: OracleSource) -> OracleResult<OracleSource> {
        source.validate()?;
        self.require_feed(&source.feed_id)?;
        if self
            .sources_for_feed(&source.feed_id)
            .len()
            .saturating_add(1)
            > ORACLE_MAX_SOURCES_PER_FEED
        {
            return Err("oracle feed source limit exceeded".to_string());
        }
        self.sources
            .insert(source.source_id.clone(), source.clone());
        Ok(source)
    }

    pub fn publish_observation(
        &mut self,
        observation: OracleObservation,
    ) -> OracleResult<OracleUpdateReceipt> {
        observation.validate()?;
        let feed = self.require_feed(&observation.feed_id)?.clone();
        if feed.status != ORACLE_STATUS_ACTIVE {
            return Err("oracle feed is not active".to_string());
        }
        let source = self
            .sources
            .get(&observation.source_id)
            .ok_or_else(|| "unknown oracle source".to_string())?
            .clone();
        if !source.active {
            return Err("oracle source is inactive".to_string());
        }
        if source.feed_id != observation.feed_id {
            return Err("oracle source feed mismatch".to_string());
        }
        if let Some(previous) = self.latest_observation_for_source(&source.source_id) {
            if observation.observed_at_height
                < previous
                    .observed_at_height
                    .saturating_add(source.min_interval_blocks)
            {
                return Err("oracle observation violates source interval".to_string());
            }
        }
        let previous_aggregate_root = self
            .aggregates
            .get(&observation.feed_id)
            .map(|aggregate| oracle_aggregate_root(&[aggregate.clone()]))
            .unwrap_or_else(|| oracle_empty_root("aggregate"));
        let observations = self
            .observations
            .entry(observation.feed_id.clone())
            .or_default();
        observations.push(observation.clone());
        observations
            .sort_by_key(|item| (item.round, item.observed_at_height, item.source_id.clone()));
        if observations.len() > ORACLE_MAX_OBSERVATIONS_PER_FEED {
            let excess = observations.len() - ORACLE_MAX_OBSERVATIONS_PER_FEED;
            observations.drain(0..excess);
        }
        let aggregate = self.aggregate_feed(&feed.feed_id, observation.round)?;
        let aggregate_root = oracle_aggregate_root(&[aggregate.clone()]);
        self.aggregates
            .insert(feed.feed_id.clone(), aggregate.clone());
        let receipt_id = oracle_update_receipt_id(
            &feed.feed_id,
            observation.round,
            &oracle_observation_root(&[observation]),
            &aggregate_root,
            &previous_aggregate_root,
            true,
        );
        let receipt = OracleUpdateReceipt {
            receipt_id,
            feed_id: feed.feed_id,
            round: aggregate.round,
            observation_root: aggregate.observation_root,
            aggregate_root,
            previous_aggregate_root,
            update_fee_units: ORACLE_LOW_FEE_UPDATE_UNITS,
            low_fee_lane_id: LowFeeLane::small_defi_calls().lane_id(),
            accepted: true,
            reason: "accepted".to_string(),
        };
        self.receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        Ok(receipt)
    }

    pub fn aggregate_feed(&mut self, feed_id: &str, round: u64) -> OracleResult<OracleAggregate> {
        let feed = self.require_feed(feed_id)?.clone();
        let round_observations = self.round_observations(feed_id, round);
        if round_observations.len() < feed.min_sources as usize {
            return Err("insufficient oracle sources for aggregate".to_string());
        }
        let source_weights = self.source_weight_map(feed_id);
        let active_source_ids = round_observations
            .iter()
            .map(|observation| observation.source_id.clone())
            .collect::<BTreeSet<_>>();
        if active_source_ids.len() < feed.min_sources as usize {
            return Err("insufficient distinct oracle sources for aggregate".to_string());
        }
        self.detect_deviation(&feed, &round_observations)?;
        let median_price = median_price(&round_observations);
        let weighted_price = weighted_price(&round_observations, &source_weights);
        let twap_price = self.twap_price(feed_id, feed.twap_window_blocks, weighted_price);
        let min_price = round_observations
            .iter()
            .map(|observation| observation.price)
            .min()
            .unwrap_or(weighted_price);
        let max_price = round_observations
            .iter()
            .map(|observation| observation.price)
            .max()
            .unwrap_or(weighted_price);
        let confidence_bps = weighted_confidence(&round_observations, &source_weights);
        let observation_root = oracle_observation_root(&round_observations);
        let source_weight_root = oracle_source_weight_root(&source_weights);
        let published_at_height = round_observations
            .iter()
            .map(|observation| observation.observed_at_height)
            .max()
            .unwrap_or(self.height);
        let stale_after_height = published_at_height.saturating_add(feed.heartbeat_blocks);
        let aggregate_id = oracle_aggregate_id(
            feed_id,
            round,
            median_price,
            weighted_price,
            twap_price,
            round_observations[0].exponent,
            &observation_root,
            &source_weight_root,
            published_at_height,
            stale_after_height,
        );
        let aggregate = OracleAggregate {
            aggregate_id,
            feed_id: feed_id.to_string(),
            round,
            median_price,
            weighted_price,
            twap_price,
            exponent: round_observations[0].exponent,
            confidence_bps,
            min_price,
            max_price,
            observation_root,
            source_weight_root,
            published_at_height,
            stale_after_height,
            proof_system: ORACLE_PRICE_PROOF_SYSTEM.to_string(),
        };
        aggregate.validate()?;
        let window = self.build_twap_window(feed_id, feed.twap_window_blocks, aggregate.twap_price);
        self.twap_windows.insert(window.window_id.clone(), window);
        Ok(aggregate)
    }

    pub fn liquidation_guard(
        &mut self,
        market_id: &str,
        feed_id: &str,
        collateral_asset_id: &str,
        debt_asset_id: &str,
        max_staleness_blocks: u64,
    ) -> OracleResult<OracleLiquidationGuard> {
        if market_id.is_empty() {
            return Err("oracle liquidation guard market_id cannot be empty".to_string());
        }
        let aggregate = self
            .aggregates
            .get(feed_id)
            .ok_or_else(|| "missing oracle aggregate for liquidation guard".to_string())?
            .clone();
        let age = self.height.saturating_sub(aggregate.published_at_height);
        let allows_liquidation = age <= max_staleness_blocks && !aggregate.is_stale(self.height);
        let reason = if allows_liquidation {
            "fresh_price".to_string()
        } else {
            "stale_price".to_string()
        };
        let guard_id = oracle_liquidation_guard_id(
            market_id,
            feed_id,
            &aggregate.aggregate_id,
            collateral_asset_id,
            debt_asset_id,
            aggregate.weighted_price,
            max_staleness_blocks,
            self.height,
            allows_liquidation,
        );
        let guard = OracleLiquidationGuard {
            guard_id,
            market_id: market_id.to_string(),
            feed_id: feed_id.to_string(),
            aggregate_id: aggregate.aggregate_id,
            collateral_asset_id: collateral_asset_id.to_string(),
            debt_asset_id: debt_asset_id.to_string(),
            protected_price: aggregate.weighted_price,
            max_staleness_blocks,
            checked_at_height: self.height,
            allows_liquidation,
            reason,
        };
        self.liquidation_guards
            .insert(guard.guard_id.clone(), guard.clone());
        Ok(guard)
    }

    pub fn stale_feed_ids(&self) -> Vec<String> {
        self.aggregates
            .values()
            .filter(|aggregate| aggregate.is_stale(self.height))
            .map(|aggregate| aggregate.feed_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn state_root(&self) -> String {
        oracle_state_root(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "oracle_state",
            "chain_id": CHAIN_ID,
            "protocol_version": ORACLE_PROTOCOL_VERSION,
            "height": self.height,
            "feed_root": oracle_feed_root(&self.feeds.values().cloned().collect::<Vec<_>>()),
            "source_root": oracle_source_root(&self.sources.values().cloned().collect::<Vec<_>>()),
            "observation_root": oracle_observation_root(
                &self.observations.values().flat_map(|items| items.clone()).collect::<Vec<_>>()
            ),
            "aggregate_root": oracle_aggregate_root(&self.aggregates.values().cloned().collect::<Vec<_>>()),
            "twap_window_root": oracle_twap_window_root(&self.twap_windows.values().cloned().collect::<Vec<_>>()),
            "receipt_root": oracle_update_receipt_root(&self.receipts.values().cloned().collect::<Vec<_>>()),
            "deviation_evidence_root": oracle_deviation_evidence_root(&self.deviation_evidence.values().cloned().collect::<Vec<_>>()),
            "liquidation_guard_root": oracle_liquidation_guard_root(&self.liquidation_guards.values().cloned().collect::<Vec<_>>()),
            "stale_feed_ids": self.stale_feed_ids(),
        })
    }

    fn require_feed(&self, feed_id: &str) -> OracleResult<&OracleFeedConfig> {
        self.feeds
            .get(feed_id)
            .ok_or_else(|| "unknown oracle feed".to_string())
    }

    fn sources_for_feed(&self, feed_id: &str) -> Vec<OracleSource> {
        self.sources
            .values()
            .filter(|source| source.feed_id == feed_id && source.active)
            .cloned()
            .collect()
    }

    fn source_weight_map(&self, feed_id: &str) -> BTreeMap<String, u64> {
        self.sources_for_feed(feed_id)
            .into_iter()
            .map(|source| (source.source_id, source.weight_bps))
            .collect()
    }

    fn latest_observation_for_source(&self, source_id: &str) -> Option<OracleObservation> {
        self.observations
            .values()
            .flat_map(|items| items.iter())
            .filter(|observation| observation.source_id == source_id)
            .max_by_key(|observation| observation.observed_at_height)
            .cloned()
    }

    fn round_observations(&self, feed_id: &str, round: u64) -> Vec<OracleObservation> {
        let mut latest_by_source = BTreeMap::<String, OracleObservation>::new();
        for observation in self
            .observations
            .get(feed_id)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|observation| observation.round == round)
        {
            latest_by_source.insert(observation.source_id.clone(), observation);
        }
        latest_by_source.into_values().collect()
    }

    fn detect_deviation(
        &mut self,
        feed: &OracleFeedConfig,
        observations: &[OracleObservation],
    ) -> OracleResult<()> {
        for left_index in 0..observations.len() {
            for right_index in (left_index + 1)..observations.len() {
                let left = &observations[left_index];
                let right = &observations[right_index];
                let deviation = price_deviation_bps(left.price, right.price);
                if deviation > feed.max_deviation_bps {
                    let reporter_commitment = oracle_publisher_commitment("devnet-oracle-monitor");
                    let evidence_id = oracle_deviation_evidence_id(
                        &feed.feed_id,
                        &left.observation_id,
                        &right.observation_id,
                        left.price,
                        right.price,
                        deviation,
                        feed.max_deviation_bps,
                        &reporter_commitment,
                        self.height,
                    );
                    let evidence = OracleDeviationEvidence {
                        evidence_id,
                        feed_id: feed.feed_id.clone(),
                        left_observation_id: left.observation_id.clone(),
                        right_observation_id: right.observation_id.clone(),
                        left_price: left.price,
                        right_price: right.price,
                        deviation_bps: deviation,
                        max_deviation_bps: feed.max_deviation_bps,
                        reporter_commitment,
                        reported_at_height: self.height,
                    };
                    evidence.validate()?;
                    self.deviation_evidence
                        .insert(evidence.evidence_id.clone(), evidence);
                }
            }
        }
        Ok(())
    }

    fn twap_price(&self, feed_id: &str, window_blocks: u64, fallback_price: u64) -> u64 {
        let from_height = self.height.saturating_sub(window_blocks);
        let samples = self
            .aggregates
            .values()
            .filter(|aggregate| {
                aggregate.feed_id == feed_id && aggregate.published_at_height >= from_height
            })
            .map(|aggregate| aggregate.weighted_price)
            .chain(std::iter::once(fallback_price))
            .collect::<Vec<_>>();
        if samples.is_empty() {
            fallback_price
        } else {
            bounded_u128_to_u64(
                samples.iter().map(|price| *price as u128).sum::<u128>() / samples.len() as u128,
            )
        }
    }

    fn build_twap_window(
        &self,
        feed_id: &str,
        window_blocks: u64,
        twap_price: u64,
    ) -> OracleTwapWindow {
        let from_height = self.height.saturating_sub(window_blocks);
        let aggregates = self
            .aggregates
            .values()
            .filter(|aggregate| {
                aggregate.feed_id == feed_id && aggregate.published_at_height >= from_height
            })
            .cloned()
            .collect::<Vec<_>>();
        let aggregate_root = oracle_aggregate_root(&aggregates);
        let sample_count = aggregates.len() as u64 + 1;
        let window_id = oracle_twap_window_id(
            feed_id,
            from_height,
            self.height,
            &aggregate_root,
            sample_count,
            twap_price,
        );
        OracleTwapWindow {
            window_id,
            feed_id: feed_id.to_string(),
            from_height,
            to_height: self.height,
            aggregate_root,
            sample_count,
            twap_price,
        }
    }
}

pub fn fee_market_resource_for_oracle_update(receipt: &OracleUpdateReceipt) -> FeeMarketResource {
    let mut resource =
        FeeMarketResource::operation("oracle_price_update", receipt.update_fee_units, "piconero")
            .with_low_fee_lane(LowFeeLane::small_defi_calls());
    resource.public_record = json!({
        "kind": "oracle_price_update_fee_resource",
        "feed_id": receipt.feed_id,
        "round": receipt.round,
        "receipt_id": receipt.receipt_id,
        "aggregate_root": receipt.aggregate_root,
        "observed_fee_units": receipt.update_fee_units,
        "low_fee_lane_id": receipt.low_fee_lane_id,
    });
    resource.execution_fuel = 4_000;
    resource.privacy_proof_count = 0;
    resource.estimated_proof_bytes = ORACLE_ATTESTATION_PROOF_BYTES;
    resource.authorization_count = 1;
    resource
}

pub fn oracle_feed_config_id(
    base_asset_id: &str,
    quote_asset_id: &str,
    decimals: u8,
    min_sources: u64,
    heartbeat_blocks: u64,
    twap_window_blocks: u64,
    max_deviation_bps: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "ORACLE-FEED-CONFIG-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(base_asset_id),
            HashPart::Str(quote_asset_id),
            HashPart::Int(decimals as i128),
            HashPart::Int(min_sources as i128),
            HashPart::Int(heartbeat_blocks as i128),
            HashPart::Int(twap_window_blocks as i128),
            HashPart::Int(max_deviation_bps as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn oracle_source_id(
    feed_id: &str,
    publisher_commitment: &str,
    public_key_root: &str,
    weight_bps: u64,
    min_interval_blocks: u64,
    max_staleness_blocks: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "ORACLE-SOURCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(feed_id),
            HashPart::Str(publisher_commitment),
            HashPart::Str(public_key_root),
            HashPart::Int(weight_bps as i128),
            HashPart::Int(min_interval_blocks as i128),
            HashPart::Int(max_staleness_blocks as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn oracle_observation_payload_root(
    feed_id: &str,
    source_id: &str,
    round: u64,
    price: u64,
    exponent: i32,
    confidence_bps: u64,
    observed_at_height: u64,
    observed_at_ms: u64,
) -> String {
    domain_hash(
        "ORACLE-OBSERVATION-PAYLOAD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(feed_id),
            HashPart::Str(source_id),
            HashPart::Int(round as i128),
            HashPart::Int(price as i128),
            HashPart::Int(exponent as i128),
            HashPart::Int(confidence_bps as i128),
            HashPart::Int(observed_at_height as i128),
            HashPart::Int(observed_at_ms as i128),
        ],
        32,
    )
}

pub fn oracle_observation_id(
    feed_id: &str,
    source_id: &str,
    round: u64,
    payload_root: &str,
    signature_root: &str,
) -> String {
    domain_hash(
        "ORACLE-OBSERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(feed_id),
            HashPart::Str(source_id),
            HashPart::Int(round as i128),
            HashPart::Str(payload_root),
            HashPart::Str(signature_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn oracle_aggregate_id(
    feed_id: &str,
    round: u64,
    median_price: u64,
    weighted_price: u64,
    twap_price: u64,
    exponent: i32,
    observation_root: &str,
    source_weight_root: &str,
    published_at_height: u64,
    stale_after_height: u64,
) -> String {
    domain_hash(
        "ORACLE-AGGREGATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(feed_id),
            HashPart::Int(round as i128),
            HashPart::Int(median_price as i128),
            HashPart::Int(weighted_price as i128),
            HashPart::Int(twap_price as i128),
            HashPart::Int(exponent as i128),
            HashPart::Str(observation_root),
            HashPart::Str(source_weight_root),
            HashPart::Int(published_at_height as i128),
            HashPart::Int(stale_after_height as i128),
        ],
        32,
    )
}

pub fn oracle_twap_window_id(
    feed_id: &str,
    from_height: u64,
    to_height: u64,
    aggregate_root: &str,
    sample_count: u64,
    twap_price: u64,
) -> String {
    domain_hash(
        "ORACLE-TWAP-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(feed_id),
            HashPart::Int(from_height as i128),
            HashPart::Int(to_height as i128),
            HashPart::Str(aggregate_root),
            HashPart::Int(sample_count as i128),
            HashPart::Int(twap_price as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn oracle_update_receipt_id(
    feed_id: &str,
    round: u64,
    observation_root: &str,
    aggregate_root: &str,
    previous_aggregate_root: &str,
    accepted: bool,
) -> String {
    domain_hash(
        "ORACLE-UPDATE-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(feed_id),
            HashPart::Int(round as i128),
            HashPart::Str(observation_root),
            HashPart::Str(aggregate_root),
            HashPart::Str(previous_aggregate_root),
            HashPart::Str(if accepted { "accepted" } else { "rejected" }),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn oracle_deviation_evidence_id(
    feed_id: &str,
    left_observation_id: &str,
    right_observation_id: &str,
    left_price: u64,
    right_price: u64,
    deviation_bps: u64,
    max_deviation_bps: u64,
    reporter_commitment: &str,
    reported_at_height: u64,
) -> String {
    domain_hash(
        "ORACLE-DEVIATION-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(feed_id),
            HashPart::Str(left_observation_id),
            HashPart::Str(right_observation_id),
            HashPart::Int(left_price as i128),
            HashPart::Int(right_price as i128),
            HashPart::Int(deviation_bps as i128),
            HashPart::Int(max_deviation_bps as i128),
            HashPart::Str(reporter_commitment),
            HashPart::Int(reported_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn oracle_liquidation_guard_id(
    market_id: &str,
    feed_id: &str,
    aggregate_id: &str,
    collateral_asset_id: &str,
    debt_asset_id: &str,
    protected_price: u64,
    max_staleness_blocks: u64,
    checked_at_height: u64,
    allows_liquidation: bool,
) -> String {
    domain_hash(
        "ORACLE-LIQUIDATION-GUARD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(feed_id),
            HashPart::Str(aggregate_id),
            HashPart::Str(collateral_asset_id),
            HashPart::Str(debt_asset_id),
            HashPart::Int(protected_price as i128),
            HashPart::Int(max_staleness_blocks as i128),
            HashPart::Int(checked_at_height as i128),
            HashPart::Str(if allows_liquidation { "allow" } else { "deny" }),
        ],
        32,
    )
}

pub fn oracle_feed_root(feeds: &[OracleFeedConfig]) -> String {
    merkle_root(
        "ORACLE-FEED",
        &feeds
            .iter()
            .map(OracleFeedConfig::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn oracle_source_root(sources: &[OracleSource]) -> String {
    merkle_root(
        "ORACLE-SOURCE",
        &sources
            .iter()
            .map(OracleSource::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn oracle_observation_root(observations: &[OracleObservation]) -> String {
    merkle_root(
        "ORACLE-OBSERVATION",
        &observations
            .iter()
            .map(OracleObservation::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn oracle_aggregate_root(aggregates: &[OracleAggregate]) -> String {
    merkle_root(
        "ORACLE-AGGREGATE",
        &aggregates
            .iter()
            .map(OracleAggregate::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn oracle_twap_window_root(windows: &[OracleTwapWindow]) -> String {
    merkle_root(
        "ORACLE-TWAP-WINDOW",
        &windows
            .iter()
            .map(OracleTwapWindow::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn oracle_update_receipt_root(receipts: &[OracleUpdateReceipt]) -> String {
    merkle_root(
        "ORACLE-UPDATE-RECEIPT",
        &receipts
            .iter()
            .map(OracleUpdateReceipt::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn oracle_deviation_evidence_root(evidence: &[OracleDeviationEvidence]) -> String {
    merkle_root(
        "ORACLE-DEVIATION-EVIDENCE",
        &evidence
            .iter()
            .map(OracleDeviationEvidence::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn oracle_liquidation_guard_root(guards: &[OracleLiquidationGuard]) -> String {
    merkle_root(
        "ORACLE-LIQUIDATION-GUARD",
        &guards
            .iter()
            .map(OracleLiquidationGuard::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn oracle_source_weight_root(weights: &BTreeMap<String, u64>) -> String {
    merkle_root(
        "ORACLE-SOURCE-WEIGHT",
        &weights
            .iter()
            .map(|(source_id, weight_bps)| {
                json!({
                    "source_id": source_id,
                    "weight_bps": weight_bps,
                })
            })
            .collect::<Vec<_>>(),
    )
}

pub fn oracle_state_root(record: &Value) -> String {
    domain_hash("ORACLE-STATE", &[HashPart::Json(record)], 32)
}

pub fn oracle_metadata_root(metadata: &Value) -> String {
    domain_hash("ORACLE-METADATA", &[HashPart::Json(metadata)], 32)
}

pub fn oracle_publisher_commitment(label: &str) -> String {
    domain_hash("ORACLE-PUBLISHER", &[HashPart::Str(label)], 32)
}

pub fn oracle_signature_root(label: &str, payload_root: &str) -> String {
    domain_hash(
        "ORACLE-SIGNATURE-ROOT",
        &[HashPart::Str(label), HashPart::Str(payload_root)],
        32,
    )
}

pub fn oracle_empty_root(domain: &str) -> String {
    domain_hash("ORACLE-EMPTY", &[HashPart::Str(domain)], 32)
}

pub fn price_deviation_bps(left: u64, right: u64) -> u64 {
    if left == right {
        return 0;
    }
    let high = left.max(right) as u128;
    let low = left.min(right) as u128;
    if low == 0 {
        return 10_000;
    }
    bounded_u128_to_u64(high.saturating_sub(low).saturating_mul(10_000) / low)
}

fn median_price(observations: &[OracleObservation]) -> u64 {
    let mut prices = observations
        .iter()
        .map(|observation| observation.price)
        .collect::<Vec<_>>();
    prices.sort_unstable();
    prices[prices.len() / 2]
}

fn weighted_price(
    observations: &[OracleObservation],
    source_weights: &BTreeMap<String, u64>,
) -> u64 {
    let mut numerator = 0_u128;
    let mut denominator = 0_u128;
    for observation in observations {
        let weight = source_weights
            .get(&observation.source_id)
            .copied()
            .unwrap_or(1) as u128;
        numerator = numerator.saturating_add((observation.price as u128).saturating_mul(weight));
        denominator = denominator.saturating_add(weight);
    }
    if denominator == 0 {
        median_price(observations)
    } else {
        bounded_u128_to_u64(numerator / denominator)
    }
}

fn weighted_confidence(
    observations: &[OracleObservation],
    source_weights: &BTreeMap<String, u64>,
) -> u64 {
    let mut numerator = 0_u128;
    let mut denominator = 0_u128;
    for observation in observations {
        let weight = source_weights
            .get(&observation.source_id)
            .copied()
            .unwrap_or(1) as u128;
        numerator =
            numerator.saturating_add((observation.confidence_bps as u128).saturating_mul(weight));
        denominator = denominator.saturating_add(weight);
    }
    if denominator == 0 {
        0
    } else {
        bounded_u128_to_u64(numerator / denominator)
    }
}

fn bounded_u128_to_u64(value: u128) -> u64 {
    if value > u64::MAX as u128 {
        u64::MAX
    } else {
        value as u64
    }
}
