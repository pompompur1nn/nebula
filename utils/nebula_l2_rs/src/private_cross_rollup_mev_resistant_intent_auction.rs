use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateCrossRollupMevResistantIntentAuctionResult<T> = Result<T, String>;

pub const PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_PROTOCOL_VERSION: &str =
    "private-cross-rollup-mev-resistant-intent-auction-v1";
pub const PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_HASH_SUITE: &str = "shake256-domain-v1";
pub const PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_PQ_AUTH_SUITE: &str =
    "ml-dsa-65+slh-dsa-shake-128s";
pub const PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_DEFAULT_AUCTION_BLOCKS: u64 = 8;
pub const PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_DEFAULT_REVEAL_BLOCKS: u64 = 5;
pub const PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_DEFAULT_SETTLEMENT_BLOCKS: u64 = 12;
pub const PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_DEFAULT_CHALLENGE_BLOCKS: u64 = 18;
pub const PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_MAX_ROLLUPS: usize = 32;
pub const PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_MAX_INTENTS: usize = 512;
pub const PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_MAX_SOLVERS: usize = 96;
pub const PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_MAX_BIDS: usize = 1024;
pub const PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_MAX_RECEIPTS: usize = 1024;
pub const PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_MAX_CHALLENGES: usize = 256;
pub const PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_MAX_BPS: u64 = 10_000;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RollupSettlementKind {
    MoneroAnchor,
    ZkRollup,
    OptimisticRollup,
    Appchain,
    Validium,
}

impl RollupSettlementKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MoneroAnchor => "monero_anchor",
            Self::ZkRollup => "zk_rollup",
            Self::OptimisticRollup => "optimistic_rollup",
            Self::Appchain => "appchain",
            Self::Validium => "validium",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IntentLifecycle {
    Committed,
    Bidding,
    Revealing,
    Matched,
    Settled,
    Expired,
    Challenged,
    Cancelled,
}

impl IntentLifecycle {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Bidding => "bidding",
            Self::Revealing => "revealing",
            Self::Matched => "matched",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BidLifecycle {
    Sealed,
    Revealed,
    Selected,
    Rejected,
    Slashed,
    Expired,
}

impl BidLifecycle {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Revealed => "revealed",
            Self::Selected => "selected",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ChallengeLifecycle {
    Open,
    Upheld,
    Rejected,
    Expired,
}

impl ChallengeLifecycle {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Upheld => "upheld",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollupVenue {
    pub rollup_id: String,
    pub settlement_kind: RollupSettlementKind,
    pub chain_commitment: String,
    pub bridge_committee_root: String,
    pub monero_anchor_hint: String,
    pub max_latency_ms: u64,
    pub base_fee_micro_units: u64,
    pub active: bool,
}

impl RollupVenue {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rollup_id: &str,
        settlement_kind: RollupSettlementKind,
        chain_commitment: &str,
        bridge_committee_root: &str,
        monero_anchor_hint: &str,
        max_latency_ms: u64,
        base_fee_micro_units: u64,
    ) -> PrivateCrossRollupMevResistantIntentAuctionResult<Self> {
        let venue = Self {
            rollup_id: rollup_id.to_string(),
            settlement_kind,
            chain_commitment: chain_commitment.to_string(),
            bridge_committee_root: bridge_committee_root.to_string(),
            monero_anchor_hint: monero_anchor_hint.to_string(),
            max_latency_ms,
            base_fee_micro_units,
            active: true,
        };
        venue.validate()?;
        Ok(venue)
    }

    pub fn validate(&self) -> PrivateCrossRollupMevResistantIntentAuctionResult<()> {
        if self.rollup_id.trim().is_empty() {
            return Err("rollup venue id cannot be empty".to_string());
        }
        if self.chain_commitment.trim().is_empty() {
            return Err("rollup venue chain commitment cannot be empty".to_string());
        }
        if self.bridge_committee_root.trim().is_empty() {
            return Err("rollup venue committee root cannot be empty".to_string());
        }
        if self.monero_anchor_hint.trim().is_empty() {
            return Err("rollup venue monero anchor hint cannot be empty".to_string());
        }
        if self.max_latency_ms == 0 {
            return Err("rollup venue latency must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_cross_rollup_mev_venue",
            "rollup_id": self.rollup_id,
            "settlement_kind": self.settlement_kind.as_str(),
            "chain_commitment": self.chain_commitment,
            "bridge_committee_root": self.bridge_committee_root,
            "monero_anchor_hint": self.monero_anchor_hint,
            "max_latency_ms": self.max_latency_ms,
            "base_fee_micro_units": self.base_fee_micro_units,
            "active": self.active,
        })
    }

    pub fn root(&self) -> String {
        private_cross_rollup_mev_resistant_intent_auction_payload_root(
            "VENUE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverProfile {
    pub solver_id: String,
    pub pq_identity_commitment: String,
    pub stake_commitment: String,
    pub supported_rollup_ids: BTreeSet<String>,
    pub max_batch_weight: u64,
    pub min_rebate_bps: u64,
    pub active: bool,
}

impl SolverProfile {
    pub fn new(
        solver_id: &str,
        pq_identity_commitment: &str,
        stake_commitment: &str,
        supported_rollup_ids: BTreeSet<String>,
        max_batch_weight: u64,
        min_rebate_bps: u64,
    ) -> PrivateCrossRollupMevResistantIntentAuctionResult<Self> {
        let solver = Self {
            solver_id: solver_id.to_string(),
            pq_identity_commitment: pq_identity_commitment.to_string(),
            stake_commitment: stake_commitment.to_string(),
            supported_rollup_ids,
            max_batch_weight,
            min_rebate_bps,
            active: true,
        };
        solver.validate()?;
        Ok(solver)
    }

    pub fn validate(&self) -> PrivateCrossRollupMevResistantIntentAuctionResult<()> {
        if self.solver_id.trim().is_empty() {
            return Err("solver id cannot be empty".to_string());
        }
        if self.pq_identity_commitment.trim().is_empty() {
            return Err("solver pq identity commitment cannot be empty".to_string());
        }
        if self.stake_commitment.trim().is_empty() {
            return Err("solver stake commitment cannot be empty".to_string());
        }
        if self.supported_rollup_ids.is_empty() {
            return Err("solver must support at least one rollup".to_string());
        }
        if self.max_batch_weight == 0 {
            return Err("solver max batch weight must be positive".to_string());
        }
        if self.min_rebate_bps > PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_MAX_BPS {
            return Err("solver min rebate exceeds bps range".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_cross_rollup_mev_solver",
            "solver_id": self.solver_id,
            "pq_identity_commitment": self.pq_identity_commitment,
            "stake_commitment": self.stake_commitment,
            "supported_rollup_ids": self.supported_rollup_ids.iter().cloned().collect::<Vec<_>>(),
            "max_batch_weight": self.max_batch_weight,
            "min_rebate_bps": self.min_rebate_bps,
            "active": self.active,
        })
    }

    pub fn root(&self) -> String {
        private_cross_rollup_mev_resistant_intent_auction_payload_root(
            "SOLVER",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateIntentCommitment {
    pub intent_id: String,
    pub owner_commitment: String,
    pub source_rollup_id: String,
    pub target_rollup_id: String,
    pub asset_pair_commitment: String,
    pub amount_bucket_commitment: String,
    pub max_fee_bps: u64,
    pub mev_budget_bps: u64,
    pub privacy_nullifier: String,
    pub encrypted_payload_root: String,
    pub opened_height: u64,
    pub reveal_height: u64,
    pub expiry_height: u64,
    pub lifecycle: IntentLifecycle,
}

impl PrivateIntentCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner_commitment: &str,
        source_rollup_id: &str,
        target_rollup_id: &str,
        asset_pair_commitment: &str,
        amount_bucket_commitment: &str,
        max_fee_bps: u64,
        mev_budget_bps: u64,
        privacy_nullifier: &str,
        encrypted_payload_root: &str,
        opened_height: u64,
        reveal_blocks: u64,
        settlement_blocks: u64,
    ) -> PrivateCrossRollupMevResistantIntentAuctionResult<Self> {
        let reveal_height = opened_height.saturating_add(reveal_blocks);
        let expiry_height = reveal_height.saturating_add(settlement_blocks);
        let intent_id = private_cross_rollup_mev_resistant_intent_auction_id(
            "INTENT",
            &[
                owner_commitment,
                source_rollup_id,
                target_rollup_id,
                privacy_nullifier,
                encrypted_payload_root,
            ],
        );
        let intent = Self {
            intent_id,
            owner_commitment: owner_commitment.to_string(),
            source_rollup_id: source_rollup_id.to_string(),
            target_rollup_id: target_rollup_id.to_string(),
            asset_pair_commitment: asset_pair_commitment.to_string(),
            amount_bucket_commitment: amount_bucket_commitment.to_string(),
            max_fee_bps,
            mev_budget_bps,
            privacy_nullifier: privacy_nullifier.to_string(),
            encrypted_payload_root: encrypted_payload_root.to_string(),
            opened_height,
            reveal_height,
            expiry_height,
            lifecycle: IntentLifecycle::Committed,
        };
        intent.validate()?;
        Ok(intent)
    }

    pub fn validate(&self) -> PrivateCrossRollupMevResistantIntentAuctionResult<()> {
        if self.intent_id.trim().is_empty() {
            return Err("intent id cannot be empty".to_string());
        }
        if self.owner_commitment.trim().is_empty() {
            return Err("intent owner commitment cannot be empty".to_string());
        }
        if self.source_rollup_id.trim().is_empty() || self.target_rollup_id.trim().is_empty() {
            return Err("intent rollup ids cannot be empty".to_string());
        }
        if self.source_rollup_id == self.target_rollup_id {
            return Err("intent source and target rollups must differ".to_string());
        }
        if self.asset_pair_commitment.trim().is_empty()
            || self.amount_bucket_commitment.trim().is_empty()
            || self.privacy_nullifier.trim().is_empty()
            || self.encrypted_payload_root.trim().is_empty()
        {
            return Err("intent commitments cannot be empty".to_string());
        }
        if self.max_fee_bps > PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_MAX_BPS {
            return Err("intent max fee exceeds bps range".to_string());
        }
        if self.mev_budget_bps > PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_MAX_BPS {
            return Err("intent mev budget exceeds bps range".to_string());
        }
        if self.reveal_height < self.opened_height || self.expiry_height < self.reveal_height {
            return Err("intent heights are inconsistent".to_string());
        }
        Ok(())
    }

    pub fn accepts_bid(&self, height: u64) -> bool {
        matches!(
            self.lifecycle,
            IntentLifecycle::Committed | IntentLifecycle::Bidding
        ) && height <= self.reveal_height
    }

    pub fn can_settle(&self, height: u64) -> bool {
        matches!(self.lifecycle, IntentLifecycle::Matched) && height <= self.expiry_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_cross_rollup_mev_intent",
            "intent_id": self.intent_id,
            "owner_commitment": self.owner_commitment,
            "source_rollup_id": self.source_rollup_id,
            "target_rollup_id": self.target_rollup_id,
            "asset_pair_commitment": self.asset_pair_commitment,
            "amount_bucket_commitment": self.amount_bucket_commitment,
            "max_fee_bps": self.max_fee_bps,
            "mev_budget_bps": self.mev_budget_bps,
            "privacy_nullifier": self.privacy_nullifier,
            "encrypted_payload_root": self.encrypted_payload_root,
            "opened_height": self.opened_height,
            "reveal_height": self.reveal_height,
            "expiry_height": self.expiry_height,
            "lifecycle": self.lifecycle.as_str(),
        })
    }

    pub fn root(&self) -> String {
        private_cross_rollup_mev_resistant_intent_auction_payload_root(
            "INTENT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedSolverBid {
    pub bid_id: String,
    pub intent_id: String,
    pub solver_id: String,
    pub sealed_bid_root: String,
    pub route_commitment_root: String,
    pub fee_bps: u64,
    pub rebate_bps: u64,
    pub latency_ms: u64,
    pub pq_bid_authorization: String,
    pub lifecycle: BidLifecycle,
}

impl SealedSolverBid {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent_id: &str,
        solver_id: &str,
        sealed_bid_root: &str,
        route_commitment_root: &str,
        fee_bps: u64,
        rebate_bps: u64,
        latency_ms: u64,
        pq_bid_authorization: &str,
    ) -> PrivateCrossRollupMevResistantIntentAuctionResult<Self> {
        let bid_id = private_cross_rollup_mev_resistant_intent_auction_id(
            "BID",
            &[
                intent_id,
                solver_id,
                sealed_bid_root,
                route_commitment_root,
                pq_bid_authorization,
            ],
        );
        let bid = Self {
            bid_id,
            intent_id: intent_id.to_string(),
            solver_id: solver_id.to_string(),
            sealed_bid_root: sealed_bid_root.to_string(),
            route_commitment_root: route_commitment_root.to_string(),
            fee_bps,
            rebate_bps,
            latency_ms,
            pq_bid_authorization: pq_bid_authorization.to_string(),
            lifecycle: BidLifecycle::Sealed,
        };
        bid.validate()?;
        Ok(bid)
    }

    pub fn validate(&self) -> PrivateCrossRollupMevResistantIntentAuctionResult<()> {
        if self.bid_id.trim().is_empty()
            || self.intent_id.trim().is_empty()
            || self.solver_id.trim().is_empty()
        {
            return Err("bid ids cannot be empty".to_string());
        }
        if self.sealed_bid_root.trim().is_empty()
            || self.route_commitment_root.trim().is_empty()
            || self.pq_bid_authorization.trim().is_empty()
        {
            return Err("bid commitments cannot be empty".to_string());
        }
        if self.fee_bps > PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_MAX_BPS {
            return Err("bid fee exceeds bps range".to_string());
        }
        if self.rebate_bps > PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_MAX_BPS {
            return Err("bid rebate exceeds bps range".to_string());
        }
        if self.latency_ms == 0 {
            return Err("bid latency must be positive".to_string());
        }
        Ok(())
    }

    pub fn score(&self, mev_budget_bps: u64) -> u64 {
        let fee_penalty = self.fee_bps.saturating_mul(10);
        let latency_penalty = self.latency_ms / 10;
        mev_budget_bps
            .saturating_add(self.rebate_bps.saturating_mul(8))
            .saturating_sub(fee_penalty)
            .saturating_sub(latency_penalty)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_cross_rollup_mev_bid",
            "bid_id": self.bid_id,
            "intent_id": self.intent_id,
            "solver_id": self.solver_id,
            "sealed_bid_root": self.sealed_bid_root,
            "route_commitment_root": self.route_commitment_root,
            "fee_bps": self.fee_bps,
            "rebate_bps": self.rebate_bps,
            "latency_ms": self.latency_ms,
            "pq_bid_authorization": self.pq_bid_authorization,
            "lifecycle": self.lifecycle.as_str(),
        })
    }

    pub fn root(&self) -> String {
        private_cross_rollup_mev_resistant_intent_auction_payload_root("BID", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub intent_id: String,
    pub bid_id: String,
    pub solver_id: String,
    pub settlement_root: String,
    pub cross_rollup_message_root: String,
    pub monero_anchor_commitment: String,
    pub pq_receipt_authorization: String,
    pub settled_height: u64,
}

impl SettlementReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent_id: &str,
        bid_id: &str,
        solver_id: &str,
        settlement_root: &str,
        cross_rollup_message_root: &str,
        monero_anchor_commitment: &str,
        pq_receipt_authorization: &str,
        settled_height: u64,
    ) -> PrivateCrossRollupMevResistantIntentAuctionResult<Self> {
        let receipt_id = private_cross_rollup_mev_resistant_intent_auction_id(
            "RECEIPT",
            &[
                intent_id,
                bid_id,
                solver_id,
                settlement_root,
                cross_rollup_message_root,
                monero_anchor_commitment,
            ],
        );
        let receipt = Self {
            receipt_id,
            intent_id: intent_id.to_string(),
            bid_id: bid_id.to_string(),
            solver_id: solver_id.to_string(),
            settlement_root: settlement_root.to_string(),
            cross_rollup_message_root: cross_rollup_message_root.to_string(),
            monero_anchor_commitment: monero_anchor_commitment.to_string(),
            pq_receipt_authorization: pq_receipt_authorization.to_string(),
            settled_height,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> PrivateCrossRollupMevResistantIntentAuctionResult<()> {
        if self.receipt_id.trim().is_empty()
            || self.intent_id.trim().is_empty()
            || self.bid_id.trim().is_empty()
            || self.solver_id.trim().is_empty()
        {
            return Err("receipt ids cannot be empty".to_string());
        }
        if self.settlement_root.trim().is_empty()
            || self.cross_rollup_message_root.trim().is_empty()
            || self.monero_anchor_commitment.trim().is_empty()
            || self.pq_receipt_authorization.trim().is_empty()
        {
            return Err("receipt commitments cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_cross_rollup_mev_receipt",
            "receipt_id": self.receipt_id,
            "intent_id": self.intent_id,
            "bid_id": self.bid_id,
            "solver_id": self.solver_id,
            "settlement_root": self.settlement_root,
            "cross_rollup_message_root": self.cross_rollup_message_root,
            "monero_anchor_commitment": self.monero_anchor_commitment,
            "pq_receipt_authorization": self.pq_receipt_authorization,
            "settled_height": self.settled_height,
        })
    }

    pub fn root(&self) -> String {
        private_cross_rollup_mev_resistant_intent_auction_payload_root(
            "RECEIPT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuctionChallenge {
    pub challenge_id: String,
    pub intent_id: String,
    pub bid_id: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub opened_height: u64,
    pub expiry_height: u64,
    pub lifecycle: ChallengeLifecycle,
}

impl AuctionChallenge {
    pub fn new(
        intent_id: &str,
        bid_id: &str,
        challenger_commitment: &str,
        evidence_root: &str,
        opened_height: u64,
        challenge_blocks: u64,
    ) -> PrivateCrossRollupMevResistantIntentAuctionResult<Self> {
        let challenge_id = private_cross_rollup_mev_resistant_intent_auction_id(
            "CHALLENGE",
            &[intent_id, bid_id, challenger_commitment, evidence_root],
        );
        let challenge = Self {
            challenge_id,
            intent_id: intent_id.to_string(),
            bid_id: bid_id.to_string(),
            challenger_commitment: challenger_commitment.to_string(),
            evidence_root: evidence_root.to_string(),
            opened_height,
            expiry_height: opened_height.saturating_add(challenge_blocks),
            lifecycle: ChallengeLifecycle::Open,
        };
        challenge.validate()?;
        Ok(challenge)
    }

    pub fn validate(&self) -> PrivateCrossRollupMevResistantIntentAuctionResult<()> {
        if self.challenge_id.trim().is_empty()
            || self.intent_id.trim().is_empty()
            || self.bid_id.trim().is_empty()
            || self.challenger_commitment.trim().is_empty()
            || self.evidence_root.trim().is_empty()
        {
            return Err("challenge fields cannot be empty".to_string());
        }
        if self.expiry_height < self.opened_height {
            return Err("challenge expiry cannot precede open height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_cross_rollup_mev_challenge",
            "challenge_id": self.challenge_id,
            "intent_id": self.intent_id,
            "bid_id": self.bid_id,
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "opened_height": self.opened_height,
            "expiry_height": self.expiry_height,
            "lifecycle": self.lifecycle.as_str(),
        })
    }

    pub fn root(&self) -> String {
        private_cross_rollup_mev_resistant_intent_auction_payload_root(
            "CHALLENGE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub auction_blocks: u64,
    pub reveal_blocks: u64,
    pub settlement_blocks: u64,
    pub challenge_blocks: u64,
    pub max_fee_bps: u64,
    pub min_solver_rebate_bps: u64,
    pub max_solver_latency_ms: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            auction_blocks:
                PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_DEFAULT_AUCTION_BLOCKS,
            reveal_blocks: PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_DEFAULT_REVEAL_BLOCKS,
            settlement_blocks:
                PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_DEFAULT_SETTLEMENT_BLOCKS,
            challenge_blocks:
                PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_DEFAULT_CHALLENGE_BLOCKS,
            max_fee_bps: 85,
            min_solver_rebate_bps: 12,
            max_solver_latency_ms: 900,
        }
    }

    pub fn validate(&self) -> PrivateCrossRollupMevResistantIntentAuctionResult<()> {
        if self.auction_blocks == 0 || self.reveal_blocks == 0 || self.settlement_blocks == 0 {
            return Err("auction, reveal, and settlement windows must be positive".to_string());
        }
        if self.challenge_blocks == 0 {
            return Err("challenge window must be positive".to_string());
        }
        if self.max_fee_bps > PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_MAX_BPS {
            return Err("max fee exceeds bps range".to_string());
        }
        if self.min_solver_rebate_bps > PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_MAX_BPS {
            return Err("min solver rebate exceeds bps range".to_string());
        }
        if self.max_solver_latency_ms == 0 {
            return Err("max solver latency must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "auction_blocks": self.auction_blocks,
            "reveal_blocks": self.reveal_blocks,
            "settlement_blocks": self.settlement_blocks,
            "challenge_blocks": self.challenge_blocks,
            "max_fee_bps": self.max_fee_bps,
            "min_solver_rebate_bps": self.min_solver_rebate_bps,
            "max_solver_latency_ms": self.max_solver_latency_ms,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub venue_root: String,
    pub solver_root: String,
    pub intent_root: String,
    pub bid_root: String,
    pub receipt_root: String,
    pub challenge_root: String,
    pub nullifier_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "venue_root": self.venue_root,
            "solver_root": self.solver_root,
            "intent_root": self.intent_root,
            "bid_root": self.bid_root,
            "receipt_root": self.receipt_root,
            "challenge_root": self.challenge_root,
            "nullifier_root": self.nullifier_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub venue_count: u64,
    pub active_solver_count: u64,
    pub open_intent_count: u64,
    pub matched_intent_count: u64,
    pub settled_intent_count: u64,
    pub selected_bid_count: u64,
    pub open_challenge_count: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "venue_count": self.venue_count,
            "active_solver_count": self.active_solver_count,
            "open_intent_count": self.open_intent_count,
            "matched_intent_count": self.matched_intent_count,
            "settled_intent_count": self.settled_intent_count,
            "selected_bid_count": self.selected_bid_count,
            "open_challenge_count": self.open_challenge_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub venues: BTreeMap<String, RollupVenue>,
    pub solvers: BTreeMap<String, SolverProfile>,
    pub intents: BTreeMap<String, PrivateIntentCommitment>,
    pub bids: BTreeMap<String, SealedSolverBid>,
    pub selected_bids: BTreeMap<String, String>,
    pub receipts: BTreeMap<String, SettlementReceipt>,
    pub challenges: BTreeMap<String, AuctionChallenge>,
    pub spent_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> PrivateCrossRollupMevResistantIntentAuctionResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height: 0,
            venues: BTreeMap::new(),
            solvers: BTreeMap::new(),
            intents: BTreeMap::new(),
            bids: BTreeMap::new(),
            selected_bids: BTreeMap::new(),
            receipts: BTreeMap::new(),
            challenges: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        })
    }

    pub fn devnet() -> PrivateCrossRollupMevResistantIntentAuctionResult<Self> {
        let mut state = Self::new(Config::devnet())?;
        state.insert_venue(RollupVenue::new(
            "monero-anchor-rollup",
            RollupSettlementKind::MoneroAnchor,
            "monero-chain-commitment:devnet",
            "committee-root:monero:devnet",
            "monero-anchor:height:0",
            700,
            9,
        )?)?;
        state.insert_venue(RollupVenue::new(
            "zk-defi-rollup",
            RollupSettlementKind::ZkRollup,
            "zk-chain-commitment:devnet",
            "committee-root:zk-defi:devnet",
            "monero-anchor:mirror:0",
            500,
            6,
        )?)?;
        state.insert_venue(RollupVenue::new(
            "private-appchain",
            RollupSettlementKind::Appchain,
            "appchain-commitment:private:devnet",
            "committee-root:appchain:devnet",
            "monero-anchor:appchain:0",
            850,
            4,
        )?)?;
        state.insert_solver(SolverProfile::new(
            "solver:pq:batch:0",
            "pq-identity:solver:0",
            "stake-commitment:solver:0",
            BTreeSet::from([
                "monero-anchor-rollup".to_string(),
                "zk-defi-rollup".to_string(),
                "private-appchain".to_string(),
            ]),
            64,
            18,
        )?)?;
        state.insert_solver(SolverProfile::new(
            "solver:low-fee:1",
            "pq-identity:solver:1",
            "stake-commitment:solver:1",
            BTreeSet::from([
                "monero-anchor-rollup".to_string(),
                "zk-defi-rollup".to_string(),
            ]),
            48,
            16,
        )?)?;
        let intent = PrivateIntentCommitment::new(
            "owner-commitment:wallet:0",
            "monero-anchor-rollup",
            "zk-defi-rollup",
            "asset-pair:xmr-private-token",
            "amount-bucket:pow2:16",
            55,
            75,
            "nullifier:intent:0",
            "encrypted-payload-root:intent:0",
            state.height,
            state.config.reveal_blocks,
            state.config.settlement_blocks,
        )?;
        let intent_id = state.submit_intent(intent)?;
        let bid_id = state.submit_bid(
            &intent_id,
            "solver:pq:batch:0",
            "sealed-bid-root:0",
            "route-root:monero-to-zk:0",
            31,
            22,
            420,
            "pq-bid-auth:0",
        )?;
        state.reveal_bid(&bid_id)?;
        state.select_best_bid(&intent_id)?;
        state.record_receipt(
            &intent_id,
            &bid_id,
            "settlement-root:0",
            "cross-rollup-message-root:0",
            "monero-anchor-commitment:0",
            "pq-receipt-auth:0",
        )?;
        state.validate()?;
        Ok(state)
    }

    pub fn insert_venue(
        &mut self,
        venue: RollupVenue,
    ) -> PrivateCrossRollupMevResistantIntentAuctionResult<()> {
        if self.venues.len() >= PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_MAX_ROLLUPS
            && !self.venues.contains_key(&venue.rollup_id)
        {
            return Err("rollup venue capacity reached".to_string());
        }
        venue.validate()?;
        self.venues.insert(venue.rollup_id.clone(), venue);
        Ok(())
    }

    pub fn insert_solver(
        &mut self,
        solver: SolverProfile,
    ) -> PrivateCrossRollupMevResistantIntentAuctionResult<()> {
        if self.solvers.len() >= PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_MAX_SOLVERS
            && !self.solvers.contains_key(&solver.solver_id)
        {
            return Err("solver capacity reached".to_string());
        }
        solver.validate()?;
        for rollup_id in &solver.supported_rollup_ids {
            if !self.venues.contains_key(rollup_id) {
                return Err("solver references missing rollup venue".to_string());
            }
        }
        self.solvers.insert(solver.solver_id.clone(), solver);
        Ok(())
    }

    pub fn submit_intent(
        &mut self,
        mut intent: PrivateIntentCommitment,
    ) -> PrivateCrossRollupMevResistantIntentAuctionResult<String> {
        if self.intents.len() >= PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_MAX_INTENTS {
            return Err("intent capacity reached".to_string());
        }
        intent.validate()?;
        if self.spent_nullifiers.contains(&intent.privacy_nullifier) {
            return Err("intent nullifier already spent".to_string());
        }
        let source = self
            .venues
            .get(&intent.source_rollup_id)
            .ok_or_else(|| "intent source rollup missing".to_string())?;
        let target = self
            .venues
            .get(&intent.target_rollup_id)
            .ok_or_else(|| "intent target rollup missing".to_string())?;
        if !source.active || !target.active {
            return Err("intent rollup venue inactive".to_string());
        }
        if intent.max_fee_bps > self.config.max_fee_bps {
            return Err("intent max fee exceeds auction policy".to_string());
        }
        intent.lifecycle = IntentLifecycle::Bidding;
        let intent_id = intent.intent_id.clone();
        self.spent_nullifiers
            .insert(intent.privacy_nullifier.clone());
        self.intents.insert(intent_id.clone(), intent);
        Ok(intent_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_bid(
        &mut self,
        intent_id: &str,
        solver_id: &str,
        sealed_bid_root: &str,
        route_commitment_root: &str,
        fee_bps: u64,
        rebate_bps: u64,
        latency_ms: u64,
        pq_bid_authorization: &str,
    ) -> PrivateCrossRollupMevResistantIntentAuctionResult<String> {
        if self.bids.len() >= PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_MAX_BIDS {
            return Err("bid capacity reached".to_string());
        }
        let intent = self
            .intents
            .get(intent_id)
            .ok_or_else(|| "bid intent missing".to_string())?;
        if !intent.accepts_bid(self.height) {
            return Err("intent is not accepting bids".to_string());
        }
        if fee_bps > intent.max_fee_bps || fee_bps > self.config.max_fee_bps {
            return Err("bid fee exceeds policy".to_string());
        }
        if rebate_bps < self.config.min_solver_rebate_bps {
            return Err("bid rebate below policy".to_string());
        }
        if latency_ms > self.config.max_solver_latency_ms {
            return Err("bid latency exceeds policy".to_string());
        }
        let solver = self
            .solvers
            .get(solver_id)
            .ok_or_else(|| "bid solver missing".to_string())?;
        if !solver.active {
            return Err("bid solver inactive".to_string());
        }
        if !solver
            .supported_rollup_ids
            .contains(&intent.source_rollup_id)
            || !solver
                .supported_rollup_ids
                .contains(&intent.target_rollup_id)
        {
            return Err("bid solver does not support route".to_string());
        }
        if rebate_bps < solver.min_rebate_bps {
            return Err("bid rebate below solver minimum".to_string());
        }
        let bid = SealedSolverBid::new(
            intent_id,
            solver_id,
            sealed_bid_root,
            route_commitment_root,
            fee_bps,
            rebate_bps,
            latency_ms,
            pq_bid_authorization,
        )?;
        let bid_id = bid.bid_id.clone();
        self.bids.insert(bid_id.clone(), bid);
        Ok(bid_id)
    }

    pub fn reveal_bid(
        &mut self,
        bid_id: &str,
    ) -> PrivateCrossRollupMevResistantIntentAuctionResult<()> {
        let bid = self
            .bids
            .get_mut(bid_id)
            .ok_or_else(|| "reveal bid missing".to_string())?;
        if bid.lifecycle != BidLifecycle::Sealed {
            return Err("bid is not sealed".to_string());
        }
        bid.lifecycle = BidLifecycle::Revealed;
        if let Some(intent) = self.intents.get_mut(&bid.intent_id) {
            if intent.lifecycle == IntentLifecycle::Bidding {
                intent.lifecycle = IntentLifecycle::Revealing;
            }
        }
        Ok(())
    }

    pub fn select_best_bid(
        &mut self,
        intent_id: &str,
    ) -> PrivateCrossRollupMevResistantIntentAuctionResult<String> {
        let intent = self
            .intents
            .get(intent_id)
            .ok_or_else(|| "select intent missing".to_string())?;
        if !matches!(
            intent.lifecycle,
            IntentLifecycle::Bidding | IntentLifecycle::Revealing
        ) {
            return Err("intent is not selectable".to_string());
        }
        let mut candidates = self
            .bids
            .values()
            .filter(|bid| bid.intent_id == intent_id)
            .filter(|bid| bid.lifecycle == BidLifecycle::Revealed)
            .map(|bid| (bid.score(intent.mev_budget_bps), bid.bid_id.clone()))
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| right.cmp(left));
        let selected_bid_id = candidates
            .first()
            .map(|(_, bid_id)| bid_id.clone())
            .ok_or_else(|| "no revealed bids available".to_string())?;
        for bid in self
            .bids
            .values_mut()
            .filter(|bid| bid.intent_id == intent_id)
        {
            if bid.bid_id == selected_bid_id {
                bid.lifecycle = BidLifecycle::Selected;
            } else if bid.lifecycle == BidLifecycle::Revealed {
                bid.lifecycle = BidLifecycle::Rejected;
            }
        }
        if let Some(intent) = self.intents.get_mut(intent_id) {
            intent.lifecycle = IntentLifecycle::Matched;
        }
        self.selected_bids
            .insert(intent_id.to_string(), selected_bid_id.clone());
        Ok(selected_bid_id)
    }

    pub fn record_receipt(
        &mut self,
        intent_id: &str,
        bid_id: &str,
        settlement_root: &str,
        cross_rollup_message_root: &str,
        monero_anchor_commitment: &str,
        pq_receipt_authorization: &str,
    ) -> PrivateCrossRollupMevResistantIntentAuctionResult<String> {
        if self.receipts.len() >= PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_MAX_RECEIPTS {
            return Err("receipt capacity reached".to_string());
        }
        let intent = self
            .intents
            .get_mut(intent_id)
            .ok_or_else(|| "receipt intent missing".to_string())?;
        if !intent.can_settle(self.height) {
            return Err("intent cannot settle".to_string());
        }
        let bid = self
            .bids
            .get(bid_id)
            .ok_or_else(|| "receipt bid missing".to_string())?;
        if bid.intent_id != intent_id || bid.lifecycle != BidLifecycle::Selected {
            return Err("receipt bid is not selected for intent".to_string());
        }
        let receipt = SettlementReceipt::new(
            intent_id,
            bid_id,
            &bid.solver_id,
            settlement_root,
            cross_rollup_message_root,
            monero_anchor_commitment,
            pq_receipt_authorization,
            self.height,
        )?;
        let receipt_id = receipt.receipt_id.clone();
        intent.lifecycle = IntentLifecycle::Settled;
        self.receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn open_challenge(
        &mut self,
        intent_id: &str,
        bid_id: &str,
        challenger_commitment: &str,
        evidence_root: &str,
    ) -> PrivateCrossRollupMevResistantIntentAuctionResult<String> {
        if self.challenges.len() >= PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_MAX_CHALLENGES
        {
            return Err("challenge capacity reached".to_string());
        }
        if !self.intents.contains_key(intent_id) {
            return Err("challenge intent missing".to_string());
        }
        if !self.bids.contains_key(bid_id) {
            return Err("challenge bid missing".to_string());
        }
        let challenge = AuctionChallenge::new(
            intent_id,
            bid_id,
            challenger_commitment,
            evidence_root,
            self.height,
            self.config.challenge_blocks,
        )?;
        let challenge_id = challenge.challenge_id.clone();
        if let Some(intent) = self.intents.get_mut(intent_id) {
            intent.lifecycle = IntentLifecycle::Challenged;
        }
        self.challenges.insert(challenge_id.clone(), challenge);
        Ok(challenge_id)
    }

    pub fn set_height(
        &mut self,
        height: u64,
    ) -> PrivateCrossRollupMevResistantIntentAuctionResult<()> {
        if height < self.height {
            return Err("private cross-rollup auction height cannot decrease".to_string());
        }
        self.height = height;
        for intent in self.intents.values_mut() {
            if matches!(
                intent.lifecycle,
                IntentLifecycle::Committed
                    | IntentLifecycle::Bidding
                    | IntentLifecycle::Revealing
                    | IntentLifecycle::Matched
            ) && height > intent.expiry_height
            {
                intent.lifecycle = IntentLifecycle::Expired;
            }
        }
        for bid in self.bids.values_mut() {
            if bid.lifecycle == BidLifecycle::Sealed {
                if let Some(intent) = self.intents.get(&bid.intent_id) {
                    if height > intent.reveal_height {
                        bid.lifecycle = BidLifecycle::Expired;
                    }
                }
            }
        }
        for challenge in self.challenges.values_mut() {
            if challenge.lifecycle == ChallengeLifecycle::Open && height > challenge.expiry_height {
                challenge.lifecycle = ChallengeLifecycle::Expired;
            }
        }
        Ok(())
    }

    pub fn update_height(
        &mut self,
        height: u64,
    ) -> PrivateCrossRollupMevResistantIntentAuctionResult<()> {
        self.set_height(height)
    }

    pub fn validate(&self) -> PrivateCrossRollupMevResistantIntentAuctionResult<()> {
        self.config.validate()?;
        if self.venues.len() > PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_MAX_ROLLUPS {
            return Err("too many rollup venues".to_string());
        }
        if self.solvers.len() > PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_MAX_SOLVERS {
            return Err("too many solvers".to_string());
        }
        if self.intents.len() > PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_MAX_INTENTS {
            return Err("too many intents".to_string());
        }
        if self.bids.len() > PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_MAX_BIDS {
            return Err("too many bids".to_string());
        }
        for venue in self.venues.values() {
            venue.validate()?;
        }
        for solver in self.solvers.values() {
            solver.validate()?;
            for rollup_id in &solver.supported_rollup_ids {
                if !self.venues.contains_key(rollup_id) {
                    return Err("solver references unknown rollup".to_string());
                }
            }
        }
        for intent in self.intents.values() {
            intent.validate()?;
            if !self.venues.contains_key(&intent.source_rollup_id)
                || !self.venues.contains_key(&intent.target_rollup_id)
            {
                return Err("intent references unknown rollup".to_string());
            }
        }
        for bid in self.bids.values() {
            bid.validate()?;
            if !self.intents.contains_key(&bid.intent_id) {
                return Err("bid references unknown intent".to_string());
            }
            if !self.solvers.contains_key(&bid.solver_id) {
                return Err("bid references unknown solver".to_string());
            }
        }
        for (intent_id, bid_id) in &self.selected_bids {
            if !self.intents.contains_key(intent_id) || !self.bids.contains_key(bid_id) {
                return Err("selected bid index is inconsistent".to_string());
            }
        }
        for receipt in self.receipts.values() {
            receipt.validate()?;
        }
        for challenge in self.challenges.values() {
            challenge.validate()?;
        }
        Ok(())
    }

    pub fn roots(&self) -> Roots {
        Roots {
            venue_root: private_cross_rollup_mev_resistant_intent_auction_record_root(
                "VENUES",
                self.venues
                    .values()
                    .map(RollupVenue::public_record)
                    .collect(),
            ),
            solver_root: private_cross_rollup_mev_resistant_intent_auction_record_root(
                "SOLVERS",
                self.solvers
                    .values()
                    .map(SolverProfile::public_record)
                    .collect(),
            ),
            intent_root: private_cross_rollup_mev_resistant_intent_auction_record_root(
                "INTENTS",
                self.intents
                    .values()
                    .map(PrivateIntentCommitment::public_record)
                    .collect(),
            ),
            bid_root: private_cross_rollup_mev_resistant_intent_auction_record_root(
                "BIDS",
                self.bids
                    .values()
                    .map(SealedSolverBid::public_record)
                    .collect(),
            ),
            receipt_root: private_cross_rollup_mev_resistant_intent_auction_record_root(
                "RECEIPTS",
                self.receipts
                    .values()
                    .map(SettlementReceipt::public_record)
                    .collect(),
            ),
            challenge_root: private_cross_rollup_mev_resistant_intent_auction_record_root(
                "CHALLENGES",
                self.challenges
                    .values()
                    .map(AuctionChallenge::public_record)
                    .collect(),
            ),
            nullifier_root: private_cross_rollup_mev_resistant_intent_auction_string_set_root(
                "NULLIFIERS",
                &self.spent_nullifiers.iter().cloned().collect::<Vec<_>>(),
            ),
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            venue_count: self.venues.len() as u64,
            active_solver_count: self.solvers.values().filter(|solver| solver.active).count()
                as u64,
            open_intent_count: self
                .intents
                .values()
                .filter(|intent| {
                    matches!(
                        intent.lifecycle,
                        IntentLifecycle::Committed
                            | IntentLifecycle::Bidding
                            | IntentLifecycle::Revealing
                    )
                })
                .count() as u64,
            matched_intent_count: self
                .intents
                .values()
                .filter(|intent| intent.lifecycle == IntentLifecycle::Matched)
                .count() as u64,
            settled_intent_count: self
                .intents
                .values()
                .filter(|intent| intent.lifecycle == IntentLifecycle::Settled)
                .count() as u64,
            selected_bid_count: self
                .bids
                .values()
                .filter(|bid| bid.lifecycle == BidLifecycle::Selected)
                .count() as u64,
            open_challenge_count: self
                .challenges
                .values()
                .filter(|challenge| challenge.lifecycle == ChallengeLifecycle::Open)
                .count() as u64,
        }
    }

    pub fn active_intent_ids(&self) -> Vec<String> {
        self.intents
            .values()
            .filter(|intent| {
                matches!(
                    intent.lifecycle,
                    IntentLifecycle::Committed
                        | IntentLifecycle::Bidding
                        | IntentLifecycle::Revealing
                        | IntentLifecycle::Matched
                )
            })
            .map(|intent| intent.intent_id.clone())
            .collect()
    }

    pub fn selected_bid_ids(&self) -> Vec<String> {
        self.selected_bids.values().cloned().collect()
    }

    pub fn open_challenge_ids(&self) -> Vec<String> {
        self.challenges
            .values()
            .filter(|challenge| challenge.lifecycle == ChallengeLifecycle::Open)
            .map(|challenge| challenge.challenge_id.clone())
            .collect()
    }

    pub fn rollup_pressure_map(&self) -> BTreeMap<String, u64> {
        let mut pressure = BTreeMap::new();
        for intent in self.intents.values() {
            if matches!(
                intent.lifecycle,
                IntentLifecycle::Committed
                    | IntentLifecycle::Bidding
                    | IntentLifecycle::Revealing
                    | IntentLifecycle::Matched
            ) {
                let source_entry = pressure
                    .entry(intent.source_rollup_id.clone())
                    .or_insert(0_u64);
                *source_entry = source_entry.saturating_add(1);
                let target_entry = pressure
                    .entry(intent.target_rollup_id.clone())
                    .or_insert(0_u64);
                *target_entry = target_entry.saturating_add(1);
            }
        }
        pressure
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "private_cross_rollup_mev_resistant_intent_auction_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_PROTOCOL_VERSION,
            "hash_suite": PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_HASH_SUITE,
            "pq_auth_suite": PRIVATE_CROSS_ROLLUP_MEV_RESISTANT_INTENT_AUCTION_PQ_AUTH_SUITE,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "active_intent_ids": self.active_intent_ids(),
            "selected_bid_ids": self.selected_bid_ids(),
            "open_challenge_ids": self.open_challenge_ids(),
            "rollup_pressure_map": self.rollup_pressure_map(),
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

pub fn root_from_record(record: &Value) -> String {
    private_cross_rollup_mev_resistant_intent_auction_payload_root("STATE", record)
}

pub fn private_cross_rollup_mev_resistant_intent_auction_payload_root(
    domain: &str,
    payload: &Value,
) -> String {
    domain_hash(
        &format!("PRIVATE-CROSS-ROLLUP-MEV-RESISTANT-INTENT-AUCTION-{domain}"),
        &[HashPart::Json(payload)],
        32,
    )
}

pub fn private_cross_rollup_mev_resistant_intent_auction_record_root(
    domain: &str,
    records: Vec<Value>,
) -> String {
    merkle_root(
        &format!("PRIVATE-CROSS-ROLLUP-MEV-RESISTANT-INTENT-AUCTION-{domain}"),
        &records,
    )
}

pub fn private_cross_rollup_mev_resistant_intent_auction_string_set_root(
    domain: &str,
    values: &[String],
) -> String {
    merkle_root(
        &format!("PRIVATE-CROSS-ROLLUP-MEV-RESISTANT-INTENT-AUCTION-{domain}"),
        &values
            .iter()
            .map(|value| json!({ "value": value }))
            .collect::<Vec<_>>(),
    )
}

pub fn private_cross_rollup_mev_resistant_intent_auction_id(
    domain: &str,
    parts: &[&str],
) -> String {
    domain_hash(
        &format!("PRIVATE-CROSS-ROLLUP-MEV-RESISTANT-INTENT-AUCTION-ID-{domain}"),
        &[HashPart::Json(&json!({ "parts": parts }))],
        32,
    )
}

pub fn devnet() -> PrivateCrossRollupMevResistantIntentAuctionResult<State> {
    State::devnet()
}
