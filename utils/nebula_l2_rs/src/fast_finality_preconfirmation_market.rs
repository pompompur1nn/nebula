use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, HashPart},
    CHAIN_ID,
};

pub type FastFinalityPreconfirmationMarketResult<T> = Result<T, String>;

pub const FAST_FINALITY_PRECONFIRMATION_MARKET_PROTOCOL_VERSION: u32 = 1;
pub const FAST_FINALITY_PRECONFIRMATION_MARKET_PROTOCOL_LABEL: &str =
    "nebula-fast-finality-preconfirmation-market-v1";
pub const FAST_FINALITY_PRECONFIRMATION_MARKET_SCHEMA_VERSION: u64 = 1;
pub const FAST_FINALITY_PRECONFIRMATION_MARKET_DEVNET_HEIGHT: u64 = 896;
pub const FAST_FINALITY_PRECONFIRMATION_MARKET_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const FAST_FINALITY_PRECONFIRMATION_MARKET_PQ_QUORUM_SUITE: &str =
    "ML-DSA-65+SLH-DSA-SHAKE-128s-fast-finality-quorum";
pub const FAST_FINALITY_PRECONFIRMATION_MARKET_ENCRYPTION_SUITE: &str =
    "ML-KEM-768-sealed-preconfirmation-intent-v1";
pub const FAST_FINALITY_PRECONFIRMATION_MARKET_DEFAULT_BID_WINDOW_BLOCKS: u64 = 2;
pub const FAST_FINALITY_PRECONFIRMATION_MARKET_DEFAULT_PROMISE_TTL_BLOCKS: u64 = 8;
pub const FAST_FINALITY_PRECONFIRMATION_MARKET_DEFAULT_SLASH_WINDOW_BLOCKS: u64 = 24;
pub const FAST_FINALITY_PRECONFIRMATION_MARKET_DEFAULT_FINALITY_DEPTH: u64 = 3;
pub const FAST_FINALITY_PRECONFIRMATION_MARKET_DEFAULT_MIN_BOND_UNITS: u64 = 20_000;
pub const FAST_FINALITY_PRECONFIRMATION_MARKET_DEFAULT_LOW_FEE_REBATE_BPS: u64 = 8_000;
pub const FAST_FINALITY_PRECONFIRMATION_MARKET_DEFAULT_SPONSOR_POOL_UNITS: u64 = 275_000;
pub const FAST_FINALITY_PRECONFIRMATION_MARKET_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreconfirmationLane {
    PrivateTransfer,
    PrivateContract,
    DefiSwap,
    MoneroExit,
    BridgeRelease,
    Emergency,
}

impl PreconfirmationLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::PrivateContract => "private_contract",
            Self::DefiSwap => "defi_swap",
            Self::MoneroExit => "monero_exit",
            Self::BridgeRelease => "bridge_release",
            Self::Emergency => "emergency",
        }
    }

    pub fn priority(self) -> u64 {
        match self {
            Self::Emergency => 100,
            Self::BridgeRelease => 94,
            Self::MoneroExit => 90,
            Self::PrivateContract => 84,
            Self::DefiSwap => 80,
            Self::PrivateTransfer => 72,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Open,
    Matched,
    Promised,
    Fulfilled,
    Slashed,
    Expired,
    Cancelled,
}

impl BidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Matched => "matched",
            Self::Promised => "promised",
            Self::Fulfilled => "fulfilled",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(self, Self::Open | Self::Matched | Self::Promised)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromiseStatus {
    Signed,
    Gossiped,
    Included,
    Final,
    Broken,
    Challenged,
    Expired,
}

impl PromiseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Signed => "signed",
            Self::Gossiped => "gossiped",
            Self::Included => "included",
            Self::Final => "final",
            Self::Broken => "broken",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Signed | Self::Gossiped | Self::Included | Self::Challenged
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashStatus {
    Open,
    EvidencePosted,
    Accepted,
    Rejected,
    Paid,
    Expired,
}

impl SlashStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidencePosted => "evidence_posted",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Paid => "paid",
            Self::Expired => "expired",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(self, Self::Open | Self::EvidencePosted | Self::Accepted)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastFinalityPreconfirmationMarketConfig {
    pub bid_window_blocks: u64,
    pub promise_ttl_blocks: u64,
    pub slash_window_blocks: u64,
    pub finality_depth: u64,
    pub min_bond_units: u64,
    pub low_fee_rebate_bps: u64,
    pub sponsor_pool_units: u64,
    pub pq_quorum_suite: String,
    pub encryption_suite: String,
    pub hash_suite: String,
}

impl FastFinalityPreconfirmationMarketConfig {
    pub fn devnet() -> Self {
        Self {
            bid_window_blocks: FAST_FINALITY_PRECONFIRMATION_MARKET_DEFAULT_BID_WINDOW_BLOCKS,
            promise_ttl_blocks: FAST_FINALITY_PRECONFIRMATION_MARKET_DEFAULT_PROMISE_TTL_BLOCKS,
            slash_window_blocks: FAST_FINALITY_PRECONFIRMATION_MARKET_DEFAULT_SLASH_WINDOW_BLOCKS,
            finality_depth: FAST_FINALITY_PRECONFIRMATION_MARKET_DEFAULT_FINALITY_DEPTH,
            min_bond_units: FAST_FINALITY_PRECONFIRMATION_MARKET_DEFAULT_MIN_BOND_UNITS,
            low_fee_rebate_bps: FAST_FINALITY_PRECONFIRMATION_MARKET_DEFAULT_LOW_FEE_REBATE_BPS,
            sponsor_pool_units: FAST_FINALITY_PRECONFIRMATION_MARKET_DEFAULT_SPONSOR_POOL_UNITS,
            pq_quorum_suite: FAST_FINALITY_PRECONFIRMATION_MARKET_PQ_QUORUM_SUITE.to_string(),
            encryption_suite: FAST_FINALITY_PRECONFIRMATION_MARKET_ENCRYPTION_SUITE.to_string(),
            hash_suite: FAST_FINALITY_PRECONFIRMATION_MARKET_HASH_SUITE.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bid_window_blocks": self.bid_window_blocks,
            "promise_ttl_blocks": self.promise_ttl_blocks,
            "slash_window_blocks": self.slash_window_blocks,
            "finality_depth": self.finality_depth,
            "min_bond_units": self.min_bond_units,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "sponsor_pool_units": self.sponsor_pool_units,
            "pq_quorum_suite": self.pq_quorum_suite,
            "encryption_suite": self.encryption_suite,
            "hash_suite": self.hash_suite,
        })
    }

    pub fn config_root(&self) -> String {
        preconf_hash("CONFIG", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> FastFinalityPreconfirmationMarketResult<()> {
        if self.bid_window_blocks == 0
            || self.promise_ttl_blocks == 0
            || self.slash_window_blocks == 0
            || self.finality_depth == 0
            || self.min_bond_units == 0
        {
            return Err("preconfirmation market windows and bonds must be positive".to_string());
        }
        if self.low_fee_rebate_bps > FAST_FINALITY_PRECONFIRMATION_MARKET_MAX_BPS {
            return Err("preconfirmation low fee rebate exceeds max bps".to_string());
        }
        if self.pq_quorum_suite.is_empty()
            || self.encryption_suite.is_empty()
            || self.hash_suite.is_empty()
        {
            return Err(
                "preconfirmation cryptographic suite identifiers cannot be empty".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreconfirmationBid {
    pub bid_id: String,
    pub sealed_intent_root: String,
    pub bidder_commitment: String,
    pub lane: PreconfirmationLane,
    pub max_fee_units: u64,
    pub bond_units: u64,
    pub opened_height: u64,
    pub expires_height: u64,
    pub status: BidStatus,
    pub privacy_budget_root: String,
    pub sponsor_id: Option<String>,
}

impl PreconfirmationBid {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bidder_label: &str,
        intent_label: &str,
        lane: PreconfirmationLane,
        max_fee_units: u64,
        bond_units: u64,
        opened_height: u64,
        sponsor_id: Option<String>,
        config: &FastFinalityPreconfirmationMarketConfig,
        privacy_budget: &Value,
    ) -> Self {
        let bidder_commitment = preconf_hash("BIDDER", &[HashPart::Str(bidder_label)]);
        let sealed_intent_root = preconf_hash(
            "SEALED-INTENT",
            &[
                HashPart::Str(intent_label),
                HashPart::Str(config.encryption_suite.as_str()),
            ],
        );
        let privacy_budget_root = preconf_hash("PRIVACY-BUDGET", &[HashPart::Json(privacy_budget)]);
        let bid_id = preconf_hash(
            "BID-ID",
            &[
                HashPart::Str(&bidder_commitment),
                HashPart::Str(&sealed_intent_root),
                HashPart::Str(lane.as_str()),
                HashPart::Int(opened_height as i128),
            ],
        );
        Self {
            bid_id,
            sealed_intent_root,
            bidder_commitment,
            lane,
            max_fee_units,
            bond_units: bond_units.max(config.min_bond_units),
            opened_height,
            expires_height: opened_height.saturating_add(config.bid_window_blocks),
            status: BidStatus::Open,
            privacy_budget_root,
            sponsor_id,
        }
    }

    pub fn with_status(mut self, status: BidStatus) -> Self {
        self.status = status;
        self
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "sealed_intent_root": self.sealed_intent_root,
            "bidder_commitment": self.bidder_commitment,
            "lane": self.lane.as_str(),
            "lane_priority": self.lane.priority(),
            "max_fee_units": self.max_fee_units,
            "bond_units": self.bond_units,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
            "privacy_budget_root": self.privacy_budget_root,
            "sponsor_id": self.sponsor_id,
        })
    }

    pub fn record_root(&self) -> String {
        preconf_hash("BID", &[HashPart::Json(&self.public_record())])
    }

    pub fn is_live(&self) -> bool {
        self.status.is_live()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastLaneGuarantee {
    pub guarantee_id: String,
    pub lane: PreconfirmationLane,
    pub capacity_units: u64,
    pub reserved_units: u64,
    pub fee_cap_units: u64,
    pub sponsor_root: String,
    pub valid_until_height: u64,
}

impl FastLaneGuarantee {
    pub fn new(
        lane: PreconfirmationLane,
        capacity_units: u64,
        fee_cap_units: u64,
        sponsor_labels: &[&str],
        height: u64,
        config: &FastFinalityPreconfirmationMarketConfig,
    ) -> Self {
        let sponsor_root = string_set_root("FAST-LANE-SPONSORS", sponsor_labels);
        let guarantee_id = preconf_hash(
            "FAST-LANE-GUARANTEE-ID",
            &[
                HashPart::Str(lane.as_str()),
                HashPart::Int(capacity_units as i128),
                HashPart::Str(&sponsor_root),
            ],
        );
        Self {
            guarantee_id,
            lane,
            capacity_units,
            reserved_units: 0,
            fee_cap_units,
            sponsor_root,
            valid_until_height: height.saturating_add(config.promise_ttl_blocks),
        }
    }

    pub fn available_units(&self) -> u64 {
        self.capacity_units.saturating_sub(self.reserved_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "guarantee_id": self.guarantee_id,
            "lane": self.lane.as_str(),
            "capacity_units": self.capacity_units,
            "reserved_units": self.reserved_units,
            "available_units": self.available_units(),
            "fee_cap_units": self.fee_cap_units,
            "sponsor_root": self.sponsor_root,
            "valid_until_height": self.valid_until_height,
        })
    }

    pub fn record_root(&self) -> String {
        preconf_hash(
            "FAST-LANE-GUARANTEE",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreconfirmationPromise {
    pub promise_id: String,
    pub bid_id: String,
    pub sequencer_commitment: String,
    pub committee_signature_root: String,
    pub promised_inclusion_height: u64,
    pub expires_height: u64,
    pub status: PromiseStatus,
    pub execution_witness_root: String,
}

impl PreconfirmationPromise {
    pub fn new(
        bid: &PreconfirmationBid,
        sequencer_label: &str,
        height: u64,
        config: &FastFinalityPreconfirmationMarketConfig,
        witness: &Value,
    ) -> Self {
        let sequencer_commitment = preconf_hash("SEQUENCER", &[HashPart::Str(sequencer_label)]);
        let execution_witness_root = preconf_hash("EXECUTION-WITNESS", &[HashPart::Json(witness)]);
        let committee_signature_root = preconf_hash(
            "COMMITTEE-SIGNATURE",
            &[
                HashPart::Str(&bid.bid_id),
                HashPart::Str(&sequencer_commitment),
                HashPart::Str(config.pq_quorum_suite.as_str()),
                HashPart::Str(&execution_witness_root),
            ],
        );
        let promise_id = preconf_hash(
            "PROMISE-ID",
            &[
                HashPart::Str(&bid.bid_id),
                HashPart::Str(&sequencer_commitment),
                HashPart::Int(height as i128),
            ],
        );
        Self {
            promise_id,
            bid_id: bid.bid_id.clone(),
            sequencer_commitment,
            committee_signature_root,
            promised_inclusion_height: height.saturating_add(1),
            expires_height: height.saturating_add(config.promise_ttl_blocks),
            status: PromiseStatus::Signed,
            execution_witness_root,
        }
    }

    pub fn with_status(mut self, status: PromiseStatus) -> Self {
        self.status = status;
        self
    }

    pub fn public_record(&self) -> Value {
        json!({
            "promise_id": self.promise_id,
            "bid_id": self.bid_id,
            "sequencer_commitment": self.sequencer_commitment,
            "committee_signature_root": self.committee_signature_root,
            "promised_inclusion_height": self.promised_inclusion_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
            "execution_witness_root": self.execution_witness_root,
        })
    }

    pub fn record_root(&self) -> String {
        preconf_hash("PROMISE", &[HashPart::Json(&self.public_record())])
    }

    pub fn is_open(&self) -> bool {
        self.status.is_open()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeePreconfirmationSponsor {
    pub sponsor_id: String,
    pub sponsor_commitment: String,
    pub lane: PreconfirmationLane,
    pub budget_units: u64,
    pub consumed_units: u64,
    pub rebate_bps: u64,
    pub policy_root: String,
}

impl LowFeePreconfirmationSponsor {
    pub fn new(
        sponsor_label: &str,
        lane: PreconfirmationLane,
        budget_units: u64,
        rebate_bps: u64,
        policy: &Value,
    ) -> Self {
        let sponsor_commitment = preconf_hash("LOW-FEE-SPONSOR", &[HashPart::Str(sponsor_label)]);
        let policy_root = preconf_hash("LOW-FEE-SPONSOR-POLICY", &[HashPart::Json(policy)]);
        let sponsor_id = preconf_hash(
            "LOW-FEE-SPONSOR-ID",
            &[
                HashPart::Str(&sponsor_commitment),
                HashPart::Str(lane.as_str()),
                HashPart::Int(budget_units as i128),
            ],
        );
        Self {
            sponsor_id,
            sponsor_commitment,
            lane,
            budget_units,
            consumed_units: 0,
            rebate_bps: rebate_bps.min(FAST_FINALITY_PRECONFIRMATION_MARKET_MAX_BPS),
            policy_root,
        }
    }

    pub fn available_units(&self) -> u64 {
        self.budget_units.saturating_sub(self.consumed_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "sponsor_commitment": self.sponsor_commitment,
            "lane": self.lane.as_str(),
            "budget_units": self.budget_units,
            "consumed_units": self.consumed_units,
            "available_units": self.available_units(),
            "rebate_bps": self.rebate_bps,
            "policy_root": self.policy_root,
        })
    }

    pub fn record_root(&self) -> String {
        preconf_hash("LOW-FEE-SPONSOR", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashClaim {
    pub claim_id: String,
    pub promise_id: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub opened_height: u64,
    pub expires_height: u64,
    pub slash_units: u64,
    pub status: SlashStatus,
}

impl SlashClaim {
    pub fn new(
        promise: &PreconfirmationPromise,
        challenger_label: &str,
        opened_height: u64,
        slash_units: u64,
        config: &FastFinalityPreconfirmationMarketConfig,
        evidence: &Value,
    ) -> Self {
        let challenger_commitment =
            preconf_hash("SLASH-CHALLENGER", &[HashPart::Str(challenger_label)]);
        let evidence_root = preconf_hash("SLASH-EVIDENCE", &[HashPart::Json(evidence)]);
        let claim_id = preconf_hash(
            "SLASH-CLAIM-ID",
            &[
                HashPart::Str(&promise.promise_id),
                HashPart::Str(&challenger_commitment),
                HashPart::Int(opened_height as i128),
                HashPart::Str(&evidence_root),
            ],
        );
        Self {
            claim_id,
            promise_id: promise.promise_id.clone(),
            challenger_commitment,
            evidence_root,
            opened_height,
            expires_height: opened_height.saturating_add(config.slash_window_blocks),
            slash_units,
            status: SlashStatus::Open,
        }
    }

    pub fn with_status(mut self, status: SlashStatus) -> Self {
        self.status = status;
        self
    }

    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "promise_id": self.promise_id,
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "slash_units": self.slash_units,
            "status": self.status.as_str(),
        })
    }

    pub fn record_root(&self) -> String {
        preconf_hash("SLASH-CLAIM", &[HashPart::Json(&self.public_record())])
    }

    pub fn is_open(&self) -> bool {
        self.status.is_open()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastFinalityPreconfirmationMarketRoots {
    pub config_root: String,
    pub bid_root: String,
    pub guarantee_root: String,
    pub promise_root: String,
    pub sponsor_root: String,
    pub slash_root: String,
}

impl FastFinalityPreconfirmationMarketRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "bid_root": self.bid_root,
            "guarantee_root": self.guarantee_root,
            "promise_root": self.promise_root,
            "sponsor_root": self.sponsor_root,
            "slash_root": self.slash_root,
        })
    }

    pub fn state_root(&self) -> String {
        preconf_hash("ROOTS", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastFinalityPreconfirmationMarketCounters {
    pub bid_count: u64,
    pub live_bid_count: u64,
    pub guarantee_count: u64,
    pub promise_count: u64,
    pub open_promise_count: u64,
    pub sponsor_count: u64,
    pub slash_claim_count: u64,
    pub open_slash_claim_count: u64,
    pub bonded_units: u64,
    pub sponsor_available_units: u64,
    pub fast_lane_available_units: u64,
}

impl FastFinalityPreconfirmationMarketCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "bid_count": self.bid_count,
            "live_bid_count": self.live_bid_count,
            "guarantee_count": self.guarantee_count,
            "promise_count": self.promise_count,
            "open_promise_count": self.open_promise_count,
            "sponsor_count": self.sponsor_count,
            "slash_claim_count": self.slash_claim_count,
            "open_slash_claim_count": self.open_slash_claim_count,
            "bonded_units": self.bonded_units,
            "sponsor_available_units": self.sponsor_available_units,
            "fast_lane_available_units": self.fast_lane_available_units,
        })
    }

    pub fn state_root(&self) -> String {
        preconf_hash("COUNTERS", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastFinalityPreconfirmationMarketState {
    pub height: u64,
    pub config: FastFinalityPreconfirmationMarketConfig,
    pub bids: BTreeMap<String, PreconfirmationBid>,
    pub guarantees: BTreeMap<String, FastLaneGuarantee>,
    pub promises: BTreeMap<String, PreconfirmationPromise>,
    pub sponsors: BTreeMap<String, LowFeePreconfirmationSponsor>,
    pub slash_claims: BTreeMap<String, SlashClaim>,
}

impl FastFinalityPreconfirmationMarketState {
    pub fn devnet() -> FastFinalityPreconfirmationMarketResult<Self> {
        let config = FastFinalityPreconfirmationMarketConfig::devnet();
        let height = FAST_FINALITY_PRECONFIRMATION_MARKET_DEVNET_HEIGHT;
        let mut state = Self {
            height,
            config,
            bids: BTreeMap::new(),
            guarantees: BTreeMap::new(),
            promises: BTreeMap::new(),
            sponsors: BTreeMap::new(),
            slash_claims: BTreeMap::new(),
        };

        let sponsor = LowFeePreconfirmationSponsor::new(
            "preconf-sponsor-low-fee",
            PreconfirmationLane::PrivateTransfer,
            65_000,
            state.config.low_fee_rebate_bps,
            &json!({"max_fee_units": 8, "audience": "wallets"}),
        );
        let sponsor_id = sponsor.sponsor_id.clone();
        state.insert_sponsor(sponsor)?;

        let bid_a = PreconfirmationBid::new(
            "wallet-alpha",
            "sealed-private-transfer-alpha",
            PreconfirmationLane::PrivateTransfer,
            9,
            24_000,
            height.saturating_sub(1),
            Some(sponsor_id),
            &state.config,
            &json!({"privacy_budget_units": 3}),
        )
        .with_status(BidStatus::Promised);
        let bid_b = PreconfirmationBid::new(
            "dex-beta",
            "sealed-defi-swap-beta",
            PreconfirmationLane::DefiSwap,
            35,
            42_000,
            height,
            None,
            &state.config,
            &json!({"privacy_budget_units": 7}),
        )
        .with_status(BidStatus::Matched);
        let bid_c = PreconfirmationBid::new(
            "bridge-gamma",
            "sealed-monero-exit-gamma",
            PreconfirmationLane::MoneroExit,
            50,
            50_000,
            height,
            None,
            &state.config,
            &json!({"privacy_budget_units": 9}),
        );
        state.insert_bid(bid_a.clone())?;
        state.insert_bid(bid_b.clone())?;
        state.insert_bid(bid_c.clone())?;

        let guarantee_a = FastLaneGuarantee::new(
            PreconfirmationLane::PrivateTransfer,
            1_000,
            10,
            &["preconf-sponsor-low-fee", "sequencer-a"],
            height,
            &state.config,
        );
        let guarantee_b = FastLaneGuarantee::new(
            PreconfirmationLane::MoneroExit,
            500,
            64,
            &["bridge-sponsor-a", "sequencer-b"],
            height,
            &state.config,
        );
        state.insert_guarantee(guarantee_a)?;
        state.insert_guarantee(guarantee_b)?;

        let promise_a = PreconfirmationPromise::new(
            &bid_a,
            "sequencer-a",
            height,
            &state.config,
            &json!({"execution_class": "private_transfer", "state_reads": 2}),
        )
        .with_status(PromiseStatus::Gossiped);
        let promise_b = PreconfirmationPromise::new(
            &bid_b,
            "sequencer-b",
            height,
            &state.config,
            &json!({"execution_class": "defi_swap", "state_reads": 8}),
        )
        .with_status(PromiseStatus::Challenged);
        state.insert_promise(promise_a.clone())?;
        state.insert_promise(promise_b.clone())?;

        let slash = SlashClaim::new(
            &promise_b,
            "watchtower-defi",
            height,
            12_000,
            &state.config,
            &json!({"reason": "missing_bundle_before_promised_height"}),
        )
        .with_status(SlashStatus::EvidencePosted);
        state.insert_slash_claim(slash)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> FastFinalityPreconfirmationMarketResult<()> {
        if height < self.height {
            return Err("preconfirmation market height cannot decrease".to_string());
        }
        self.height = height;
        for bid in self.bids.values_mut() {
            if bid.status.is_live() && height > bid.expires_height {
                bid.status = BidStatus::Expired;
            }
        }
        for promise in self.promises.values_mut() {
            if promise.status.is_open() && height > promise.expires_height {
                promise.status = PromiseStatus::Expired;
            }
        }
        for claim in self.slash_claims.values_mut() {
            if claim.status.is_open() && height > claim.expires_height {
                claim.status = SlashStatus::Expired;
            }
        }
        self.validate()?;
        Ok(())
    }

    pub fn insert_bid(
        &mut self,
        bid: PreconfirmationBid,
    ) -> FastFinalityPreconfirmationMarketResult<()> {
        if bid.bid_id.is_empty() {
            return Err("preconfirmation bid id cannot be empty".to_string());
        }
        self.bids.insert(bid.bid_id.clone(), bid);
        Ok(())
    }

    pub fn insert_guarantee(
        &mut self,
        guarantee: FastLaneGuarantee,
    ) -> FastFinalityPreconfirmationMarketResult<()> {
        self.guarantees
            .insert(guarantee.guarantee_id.clone(), guarantee);
        Ok(())
    }

    pub fn insert_promise(
        &mut self,
        promise: PreconfirmationPromise,
    ) -> FastFinalityPreconfirmationMarketResult<()> {
        if !self.bids.contains_key(&promise.bid_id) {
            return Err("preconfirmation promise references unknown bid".to_string());
        }
        self.promises.insert(promise.promise_id.clone(), promise);
        Ok(())
    }

    pub fn insert_sponsor(
        &mut self,
        sponsor: LowFeePreconfirmationSponsor,
    ) -> FastFinalityPreconfirmationMarketResult<()> {
        self.sponsors.insert(sponsor.sponsor_id.clone(), sponsor);
        Ok(())
    }

    pub fn insert_slash_claim(
        &mut self,
        claim: SlashClaim,
    ) -> FastFinalityPreconfirmationMarketResult<()> {
        if !self.promises.contains_key(&claim.promise_id) {
            return Err("preconfirmation slash claim references unknown promise".to_string());
        }
        self.slash_claims.insert(claim.claim_id.clone(), claim);
        Ok(())
    }

    pub fn roots(&self) -> FastFinalityPreconfirmationMarketRoots {
        FastFinalityPreconfirmationMarketRoots {
            config_root: self.config.config_root(),
            bid_root: map_root(
                "BIDS",
                self.bids.values().map(PreconfirmationBid::public_record),
            ),
            guarantee_root: map_root(
                "GUARANTEES",
                self.guarantees
                    .values()
                    .map(FastLaneGuarantee::public_record),
            ),
            promise_root: map_root(
                "PROMISES",
                self.promises
                    .values()
                    .map(PreconfirmationPromise::public_record),
            ),
            sponsor_root: map_root(
                "SPONSORS",
                self.sponsors
                    .values()
                    .map(LowFeePreconfirmationSponsor::public_record),
            ),
            slash_root: map_root(
                "SLASH-CLAIMS",
                self.slash_claims.values().map(SlashClaim::public_record),
            ),
        }
    }

    pub fn counters(&self) -> FastFinalityPreconfirmationMarketCounters {
        FastFinalityPreconfirmationMarketCounters {
            bid_count: self.bids.len() as u64,
            live_bid_count: self.bids.values().filter(|bid| bid.is_live()).count() as u64,
            guarantee_count: self.guarantees.len() as u64,
            promise_count: self.promises.len() as u64,
            open_promise_count: self
                .promises
                .values()
                .filter(|promise| promise.is_open())
                .count() as u64,
            sponsor_count: self.sponsors.len() as u64,
            slash_claim_count: self.slash_claims.len() as u64,
            open_slash_claim_count: self
                .slash_claims
                .values()
                .filter(|claim| claim.is_open())
                .count() as u64,
            bonded_units: self.bids.values().map(|bid| bid.bond_units).sum(),
            sponsor_available_units: self
                .sponsors
                .values()
                .map(LowFeePreconfirmationSponsor::available_units)
                .sum(),
            fast_lane_available_units: self
                .guarantees
                .values()
                .map(FastLaneGuarantee::available_units)
                .sum(),
        }
    }

    pub fn live_bid_ids(&self) -> Vec<String> {
        self.bids
            .values()
            .filter(|bid| bid.is_live())
            .map(|bid| bid.bid_id.clone())
            .collect()
    }

    pub fn open_promise_ids(&self) -> Vec<String> {
        self.promises
            .values()
            .filter(|promise| promise.is_open())
            .map(|promise| promise.promise_id.clone())
            .collect()
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "fast_finality_preconfirmation_market_state",
            "chain_id": CHAIN_ID,
            "protocol_version": FAST_FINALITY_PRECONFIRMATION_MARKET_PROTOCOL_VERSION,
            "protocol_label": FAST_FINALITY_PRECONFIRMATION_MARKET_PROTOCOL_LABEL,
            "schema_version": FAST_FINALITY_PRECONFIRMATION_MARKET_SCHEMA_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "bids": self.bids.values().map(PreconfirmationBid::public_record).collect::<Vec<_>>(),
            "guarantees": self.guarantees.values().map(FastLaneGuarantee::public_record).collect::<Vec<_>>(),
            "promises": self.promises.values().map(PreconfirmationPromise::public_record).collect::<Vec<_>>(),
            "sponsors": self.sponsors.values().map(LowFeePreconfirmationSponsor::public_record).collect::<Vec<_>>(),
            "slash_claims": self.slash_claims.values().map(SlashClaim::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        fast_finality_preconfirmation_market_state_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> FastFinalityPreconfirmationMarketResult<String> {
        self.config.validate()?;
        let mut bid_ids = BTreeSet::new();
        for bid in self.bids.values() {
            if bid.bid_id.is_empty()
                || bid.sealed_intent_root.is_empty()
                || bid.bidder_commitment.is_empty()
                || bid.privacy_budget_root.is_empty()
            {
                return Err("preconfirmation bid contains empty commitments".to_string());
            }
            if bid.bond_units < self.config.min_bond_units {
                return Err("preconfirmation bid bond below minimum".to_string());
            }
            if bid.expires_height <= bid.opened_height {
                return Err("preconfirmation bid expiry must exceed open height".to_string());
            }
            if !bid_ids.insert(bid.bid_id.clone()) {
                return Err("duplicate preconfirmation bid id".to_string());
            }
        }
        for promise in self.promises.values() {
            if !self.bids.contains_key(&promise.bid_id) {
                return Err("preconfirmation promise references missing bid".to_string());
            }
            if promise.expires_height <= promise.promised_inclusion_height {
                return Err(
                    "preconfirmation promise expiry must exceed inclusion height".to_string(),
                );
            }
        }
        for sponsor in self.sponsors.values() {
            if sponsor.rebate_bps > FAST_FINALITY_PRECONFIRMATION_MARKET_MAX_BPS {
                return Err("preconfirmation sponsor rebate exceeds max bps".to_string());
            }
        }
        for claim in self.slash_claims.values() {
            if !self.promises.contains_key(&claim.promise_id) {
                return Err("preconfirmation slash claim references missing promise".to_string());
            }
            if claim.expires_height <= claim.opened_height {
                return Err(
                    "preconfirmation slash claim expiry must exceed open height".to_string()
                );
            }
        }
        Ok(self.state_root())
    }
}

pub fn fast_finality_preconfirmation_market_state_root_from_record(record: &Value) -> String {
    preconf_hash("STATE", &[HashPart::Json(record)])
}

fn preconf_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("FAST-FINALITY-PRECONFIRMATION-MARKET-{domain}"),
        parts,
        32,
    )
}

fn map_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let values = records.into_iter().collect::<Vec<_>>();
    preconf_hash(domain, &[HashPart::Json(&json!(values))])
}

fn string_set_root(domain: &str, values: &[&str]) -> String {
    let mut values = values.to_vec();
    values.sort();
    preconf_hash(domain, &[HashPart::Json(&json!(values))])
}
