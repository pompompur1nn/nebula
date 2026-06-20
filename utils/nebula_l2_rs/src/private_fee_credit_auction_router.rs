use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateFeeCreditAuctionRouterResult<T> = Result<T, String>;

pub const PRIVATE_FEE_CREDIT_AUCTION_ROUTER_PROTOCOL_VERSION: &str =
    "nebula-private-fee-credit-auction-router-v1";
pub const PRIVATE_FEE_CREDIT_AUCTION_ROUTER_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVATE_FEE_CREDIT_AUCTION_ROUTER_PQ_AUTH_SUITE: &str =
    "ML-DSA-65+SLH-DSA-SHAKE-128s-private-fee-credit-auction";
pub const PRIVATE_FEE_CREDIT_AUCTION_ROUTER_CREDIT_SUITE: &str = "zk-private-fee-credit-note-v1";
pub const PRIVATE_FEE_CREDIT_AUCTION_ROUTER_DEVNET_HEIGHT: u64 = 2_048;
pub const PRIVATE_FEE_CREDIT_AUCTION_ROUTER_DEFAULT_EPOCH_BLOCKS: u64 = 360;
pub const PRIVATE_FEE_CREDIT_AUCTION_ROUTER_DEFAULT_COMMIT_BLOCKS: u64 = 6;
pub const PRIVATE_FEE_CREDIT_AUCTION_ROUTER_DEFAULT_REVEAL_BLOCKS: u64 = 4;
pub const PRIVATE_FEE_CREDIT_AUCTION_ROUTER_DEFAULT_SETTLE_BLOCKS: u64 = 12;
pub const PRIVATE_FEE_CREDIT_AUCTION_ROUTER_DEFAULT_CHALLENGE_BLOCKS: u64 = 18;
pub const PRIVATE_FEE_CREDIT_AUCTION_ROUTER_DEFAULT_MIN_BID_UNITS: u64 = 20;
pub const PRIVATE_FEE_CREDIT_AUCTION_ROUTER_DEFAULT_MAX_CLEARING_BPS: u64 = 8_500;
pub const PRIVATE_FEE_CREDIT_AUCTION_ROUTER_MAX_BPS: u64 = 10_000;
pub const PRIVATE_FEE_CREDIT_AUCTION_ROUTER_MAX_LANES: usize = 64;
pub const PRIVATE_FEE_CREDIT_AUCTION_ROUTER_MAX_ROUNDS: usize = 256;
pub const PRIVATE_FEE_CREDIT_AUCTION_ROUTER_MAX_BIDS: usize = 2_048;
pub const PRIVATE_FEE_CREDIT_AUCTION_ROUTER_MAX_RECEIPTS: usize = 2_048;
pub const PRIVATE_FEE_CREDIT_AUCTION_ROUTER_MAX_ATTESTATIONS: usize = 2_048;
pub const PRIVATE_FEE_CREDIT_AUCTION_ROUTER_MAX_CHALLENGES: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeCreditAuctionClass {
    WalletTransfer,
    MoneroExit,
    PrivateSwap,
    ContractCall,
    ProofJob,
    OracleUpdate,
    Emergency,
}

impl FeeCreditAuctionClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletTransfer => "wallet_transfer",
            Self::MoneroExit => "monero_exit",
            Self::PrivateSwap => "private_swap",
            Self::ContractCall => "contract_call",
            Self::ProofJob => "proof_job",
            Self::OracleUpdate => "oracle_update",
            Self::Emergency => "emergency",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Emergency => 100,
            Self::MoneroExit => 92,
            Self::ContractCall => 82,
            Self::PrivateSwap => 78,
            Self::WalletTransfer => 74,
            Self::ProofJob => 64,
            Self::OracleUpdate => 58,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionRoundStatus {
    Commit,
    Reveal,
    Clearing,
    Settled,
    Challenged,
    Expired,
}

impl AuctionRoundStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Reveal => "reveal",
            Self::Clearing => "clearing",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Commit | Self::Reveal | Self::Clearing | Self::Challenged
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Committed,
    Revealed,
    Accepted,
    Rejected,
    Settled,
    Slashed,
    Expired,
}

impl BidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Revealed => "revealed",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Settled => "settled",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Committed | Self::Revealed | Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    Accepted,
    Rejected,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn open(self) -> bool {
        matches!(self, Self::Open)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateFeeCreditAuctionRouterConfig {
    pub epoch_blocks: u64,
    pub commit_blocks: u64,
    pub reveal_blocks: u64,
    pub settlement_blocks: u64,
    pub challenge_blocks: u64,
    pub min_bid_units: u64,
    pub max_clearing_bps: u64,
    pub pq_auth_suite: String,
    pub credit_suite: String,
    pub hash_suite: String,
}

impl PrivateFeeCreditAuctionRouterConfig {
    pub fn devnet() -> Self {
        Self {
            epoch_blocks: PRIVATE_FEE_CREDIT_AUCTION_ROUTER_DEFAULT_EPOCH_BLOCKS,
            commit_blocks: PRIVATE_FEE_CREDIT_AUCTION_ROUTER_DEFAULT_COMMIT_BLOCKS,
            reveal_blocks: PRIVATE_FEE_CREDIT_AUCTION_ROUTER_DEFAULT_REVEAL_BLOCKS,
            settlement_blocks: PRIVATE_FEE_CREDIT_AUCTION_ROUTER_DEFAULT_SETTLE_BLOCKS,
            challenge_blocks: PRIVATE_FEE_CREDIT_AUCTION_ROUTER_DEFAULT_CHALLENGE_BLOCKS,
            min_bid_units: PRIVATE_FEE_CREDIT_AUCTION_ROUTER_DEFAULT_MIN_BID_UNITS,
            max_clearing_bps: PRIVATE_FEE_CREDIT_AUCTION_ROUTER_DEFAULT_MAX_CLEARING_BPS,
            pq_auth_suite: PRIVATE_FEE_CREDIT_AUCTION_ROUTER_PQ_AUTH_SUITE.to_string(),
            credit_suite: PRIVATE_FEE_CREDIT_AUCTION_ROUTER_CREDIT_SUITE.to_string(),
            hash_suite: PRIVATE_FEE_CREDIT_AUCTION_ROUTER_HASH_SUITE.to_string(),
        }
    }

    pub fn validate(&self) -> PrivateFeeCreditAuctionRouterResult<()> {
        if self.epoch_blocks == 0
            || self.commit_blocks == 0
            || self.reveal_blocks == 0
            || self.settlement_blocks == 0
            || self.challenge_blocks == 0
        {
            return Err("fee credit auction windows must be positive".to_string());
        }
        if self.min_bid_units == 0 {
            return Err("fee credit auction min bid must be positive".to_string());
        }
        if self.max_clearing_bps > PRIVATE_FEE_CREDIT_AUCTION_ROUTER_MAX_BPS {
            return Err("fee credit auction clearing bps exceeds max".to_string());
        }
        if self.pq_auth_suite.is_empty()
            || self.credit_suite.is_empty()
            || self.hash_suite.is_empty()
        {
            return Err("fee credit auction suites cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "epoch_blocks": self.epoch_blocks,
            "commit_blocks": self.commit_blocks,
            "reveal_blocks": self.reveal_blocks,
            "settlement_blocks": self.settlement_blocks,
            "challenge_blocks": self.challenge_blocks,
            "min_bid_units": self.min_bid_units,
            "max_clearing_bps": self.max_clearing_bps,
            "pq_auth_suite": self.pq_auth_suite,
            "credit_suite": self.credit_suite,
            "hash_suite": self.hash_suite,
        })
    }

    pub fn config_root(&self) -> String {
        private_fee_credit_auction_router_payload_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeCreditAuctionLane {
    pub lane_id: String,
    pub class: FeeCreditAuctionClass,
    pub lane_label: String,
    pub fee_asset_id: String,
    pub max_credit_units: u64,
    pub target_fee_bps: u64,
    pub priority_weight: u64,
    pub admission_policy_root: String,
    pub enabled: bool,
}

impl FeeCreditAuctionLane {
    pub fn new(
        class: FeeCreditAuctionClass,
        lane_label: &str,
        fee_asset_id: &str,
        max_credit_units: u64,
        target_fee_bps: u64,
        admission_policy: &Value,
        enabled: bool,
    ) -> Self {
        let admission_policy_root =
            private_fee_credit_auction_router_payload_root("LANE-POLICY", admission_policy);
        let lane_id = private_fee_credit_auction_router_id(
            "LANE",
            &[
                class.as_str(),
                lane_label,
                fee_asset_id,
                &max_credit_units.to_string(),
                &target_fee_bps.to_string(),
                &admission_policy_root,
            ],
        );
        Self {
            lane_id,
            class,
            lane_label: lane_label.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            max_credit_units,
            target_fee_bps,
            priority_weight: class.priority_weight(),
            admission_policy_root,
            enabled,
        }
    }

    pub fn validate(&self) -> PrivateFeeCreditAuctionRouterResult<()> {
        if self.lane_id.is_empty()
            || self.lane_label.is_empty()
            || self.fee_asset_id.is_empty()
            || self.admission_policy_root.is_empty()
        {
            return Err("fee credit auction lane identifiers cannot be empty".to_string());
        }
        if self.max_credit_units == 0 || self.priority_weight == 0 {
            return Err(
                "fee credit auction lane capacity and priority must be positive".to_string(),
            );
        }
        if self.target_fee_bps > PRIVATE_FEE_CREDIT_AUCTION_ROUTER_MAX_BPS {
            return Err("fee credit auction lane target bps exceeds max".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_credit_auction_lane",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_FEE_CREDIT_AUCTION_ROUTER_PROTOCOL_VERSION,
            "lane_id": self.lane_id,
            "class": self.class.as_str(),
            "lane_label": self.lane_label,
            "fee_asset_id": self.fee_asset_id,
            "max_credit_units": self.max_credit_units,
            "target_fee_bps": self.target_fee_bps,
            "priority_weight": self.priority_weight,
            "admission_policy_root": self.admission_policy_root,
            "enabled": self.enabled,
        })
    }

    pub fn state_root(&self) -> String {
        private_fee_credit_auction_router_payload_root("LANE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeCreditAuctionRound {
    pub round_id: String,
    pub lane_id: String,
    pub epoch: u64,
    pub commit_start_height: u64,
    pub commit_end_height: u64,
    pub reveal_end_height: u64,
    pub settle_after_height: u64,
    pub expires_at_height: u64,
    pub available_credit_units: u64,
    pub status: AuctionRoundStatus,
    pub privacy_seed_commitment: String,
}

impl FeeCreditAuctionRound {
    pub fn new(
        lane_id: &str,
        epoch: u64,
        start_height: u64,
        available_credit_units: u64,
        privacy_seed: &Value,
        config: &PrivateFeeCreditAuctionRouterConfig,
    ) -> Self {
        let commit_end_height = start_height.saturating_add(config.commit_blocks);
        let reveal_end_height = commit_end_height.saturating_add(config.reveal_blocks);
        let settle_after_height = reveal_end_height.saturating_add(config.settlement_blocks);
        let expires_at_height = settle_after_height.saturating_add(config.challenge_blocks);
        let privacy_seed_commitment =
            private_fee_credit_auction_router_payload_root("ROUND-SEED", privacy_seed);
        let round_id = private_fee_credit_auction_router_id(
            "ROUND",
            &[
                lane_id,
                &epoch.to_string(),
                &start_height.to_string(),
                &available_credit_units.to_string(),
                &privacy_seed_commitment,
            ],
        );
        Self {
            round_id,
            lane_id: lane_id.to_string(),
            epoch,
            commit_start_height: start_height,
            commit_end_height,
            reveal_end_height,
            settle_after_height,
            expires_at_height,
            available_credit_units,
            status: AuctionRoundStatus::Commit,
            privacy_seed_commitment,
        }
    }

    pub fn validate(&self) -> PrivateFeeCreditAuctionRouterResult<()> {
        if self.round_id.is_empty()
            || self.lane_id.is_empty()
            || self.privacy_seed_commitment.is_empty()
        {
            return Err("fee credit auction round identifiers cannot be empty".to_string());
        }
        if self.commit_start_height >= self.commit_end_height
            || self.commit_end_height >= self.reveal_end_height
            || self.reveal_end_height >= self.settle_after_height
            || self.settle_after_height >= self.expires_at_height
        {
            return Err("fee credit auction round windows are invalid".to_string());
        }
        if self.available_credit_units == 0 {
            return Err("fee credit auction round must expose positive credit".to_string());
        }
        Ok(())
    }

    pub fn refresh_status(&mut self, height: u64) {
        self.status = if height > self.expires_at_height {
            AuctionRoundStatus::Expired
        } else if self.status == AuctionRoundStatus::Challenged
            || self.status == AuctionRoundStatus::Settled
        {
            self.status
        } else if height > self.settle_after_height {
            AuctionRoundStatus::Clearing
        } else if height > self.commit_end_height {
            AuctionRoundStatus::Reveal
        } else {
            AuctionRoundStatus::Commit
        };
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_credit_auction_round",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_FEE_CREDIT_AUCTION_ROUTER_PROTOCOL_VERSION,
            "round_id": self.round_id,
            "lane_id": self.lane_id,
            "epoch": self.epoch,
            "commit_start_height": self.commit_start_height,
            "commit_end_height": self.commit_end_height,
            "reveal_end_height": self.reveal_end_height,
            "settle_after_height": self.settle_after_height,
            "expires_at_height": self.expires_at_height,
            "available_credit_units": self.available_credit_units,
            "status": self.status.as_str(),
            "privacy_seed_commitment": self.privacy_seed_commitment,
        })
    }

    pub fn state_root(&self) -> String {
        private_fee_credit_auction_router_payload_root("ROUND", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateFeeCreditBid {
    pub bid_id: String,
    pub round_id: String,
    pub bidder_commitment: String,
    pub bid_commitment: String,
    pub max_fee_bps: u64,
    pub requested_credit_units: u64,
    pub bond_units: u64,
    pub pq_auth_root: String,
    pub nullifier: String,
    pub status: BidStatus,
    pub committed_at_height: u64,
}

impl PrivateFeeCreditBid {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        round_id: &str,
        bidder_label: &str,
        bid_payload: &Value,
        max_fee_bps: u64,
        requested_credit_units: u64,
        bond_units: u64,
        pq_auth: &Value,
        committed_at_height: u64,
    ) -> Self {
        let bidder_commitment = private_fee_credit_auction_router_payload_root(
            "BIDDER",
            &json!({"label": bidder_label}),
        );
        let bid_commitment = private_fee_credit_auction_router_payload_root("BID", bid_payload);
        let pq_auth_root = private_fee_credit_auction_router_payload_root("BID-PQ-AUTH", pq_auth);
        let nullifier = private_fee_credit_auction_router_id(
            "BID-NULLIFIER",
            &[round_id, &bidder_commitment, &bid_commitment, &pq_auth_root],
        );
        let bid_id = private_fee_credit_auction_router_id(
            "BID",
            &[
                round_id,
                &bidder_commitment,
                &bid_commitment,
                &max_fee_bps.to_string(),
                &requested_credit_units.to_string(),
                &bond_units.to_string(),
                &committed_at_height.to_string(),
            ],
        );
        Self {
            bid_id,
            round_id: round_id.to_string(),
            bidder_commitment,
            bid_commitment,
            max_fee_bps,
            requested_credit_units,
            bond_units,
            pq_auth_root,
            nullifier,
            status: BidStatus::Committed,
            committed_at_height,
        }
    }

    pub fn validate(
        &self,
        config: &PrivateFeeCreditAuctionRouterConfig,
    ) -> PrivateFeeCreditAuctionRouterResult<()> {
        if self.bid_id.is_empty()
            || self.round_id.is_empty()
            || self.bidder_commitment.is_empty()
            || self.bid_commitment.is_empty()
            || self.pq_auth_root.is_empty()
            || self.nullifier.is_empty()
        {
            return Err("fee credit bid identifiers cannot be empty".to_string());
        }
        if self.max_fee_bps > config.max_clearing_bps {
            return Err("fee credit bid exceeds clearing bps cap".to_string());
        }
        if self.requested_credit_units < config.min_bid_units {
            return Err("fee credit bid below minimum units".to_string());
        }
        if self.bond_units == 0 {
            return Err("fee credit bid bond must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_fee_credit_bid",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_FEE_CREDIT_AUCTION_ROUTER_PROTOCOL_VERSION,
            "bid_id": self.bid_id,
            "round_id": self.round_id,
            "bidder_commitment": self.bidder_commitment,
            "bid_commitment": self.bid_commitment,
            "max_fee_bps": self.max_fee_bps,
            "requested_credit_units": self.requested_credit_units,
            "bond_units": self.bond_units,
            "pq_auth_root": self.pq_auth_root,
            "nullifier": self.nullifier,
            "status": self.status.as_str(),
            "committed_at_height": self.committed_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        private_fee_credit_auction_router_payload_root("BID", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeCreditClearingReceipt {
    pub receipt_id: String,
    pub round_id: String,
    pub accepted_bid_root: String,
    pub rejected_bid_root: String,
    pub clearing_fee_bps: u64,
    pub cleared_credit_units: u64,
    pub surplus_rebate_units: u64,
    pub settled_at_height: u64,
    pub settlement_root: String,
}

impl FeeCreditClearingReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        round_id: &str,
        accepted_bid_ids: &[String],
        rejected_bid_ids: &[String],
        clearing_fee_bps: u64,
        cleared_credit_units: u64,
        surplus_rebate_units: u64,
        settled_at_height: u64,
        settlement_payload: &Value,
    ) -> Self {
        let accepted_bid_root =
            private_fee_credit_auction_router_string_set_root("ACCEPTED-BIDS", accepted_bid_ids);
        let rejected_bid_root =
            private_fee_credit_auction_router_string_set_root("REJECTED-BIDS", rejected_bid_ids);
        let settlement_root = private_fee_credit_auction_router_payload_root(
            "CLEARING-SETTLEMENT",
            settlement_payload,
        );
        let receipt_id = private_fee_credit_auction_router_id(
            "RECEIPT",
            &[
                round_id,
                &accepted_bid_root,
                &rejected_bid_root,
                &clearing_fee_bps.to_string(),
                &cleared_credit_units.to_string(),
                &settled_at_height.to_string(),
                &settlement_root,
            ],
        );
        Self {
            receipt_id,
            round_id: round_id.to_string(),
            accepted_bid_root,
            rejected_bid_root,
            clearing_fee_bps,
            cleared_credit_units,
            surplus_rebate_units,
            settled_at_height,
            settlement_root,
        }
    }

    pub fn validate(
        &self,
        config: &PrivateFeeCreditAuctionRouterConfig,
    ) -> PrivateFeeCreditAuctionRouterResult<()> {
        if self.receipt_id.is_empty()
            || self.round_id.is_empty()
            || self.accepted_bid_root.is_empty()
            || self.rejected_bid_root.is_empty()
            || self.settlement_root.is_empty()
        {
            return Err("fee credit clearing receipt identifiers cannot be empty".to_string());
        }
        if self.clearing_fee_bps > config.max_clearing_bps {
            return Err("fee credit clearing receipt exceeds fee cap".to_string());
        }
        if self.cleared_credit_units == 0 {
            return Err("fee credit clearing receipt must clear positive credit".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_credit_clearing_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_FEE_CREDIT_AUCTION_ROUTER_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "round_id": self.round_id,
            "accepted_bid_root": self.accepted_bid_root,
            "rejected_bid_root": self.rejected_bid_root,
            "clearing_fee_bps": self.clearing_fee_bps,
            "cleared_credit_units": self.cleared_credit_units,
            "surplus_rebate_units": self.surplus_rebate_units,
            "settled_at_height": self.settled_at_height,
            "settlement_root": self.settlement_root,
        })
    }

    pub fn state_root(&self) -> String {
        private_fee_credit_auction_router_payload_root("RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqFeeCreditAuctionAttestation {
    pub attestation_id: String,
    pub round_id: String,
    pub committee_id: String,
    pub signer_set_root: String,
    pub attestation_root: String,
    pub security_bits: u16,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
}

impl PqFeeCreditAuctionAttestation {
    pub fn new(
        round_id: &str,
        committee_id: &str,
        signer_ids: &[String],
        attestation_payload: &Value,
        security_bits: u16,
        signed_at_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let signer_set_root =
            private_fee_credit_auction_router_string_set_root("SIGNERS", signer_ids);
        let attestation_root =
            private_fee_credit_auction_router_payload_root("PQ-ATTESTATION", attestation_payload);
        let expires_at_height = signed_at_height.saturating_add(ttl_blocks);
        let attestation_id = private_fee_credit_auction_router_id(
            "PQ-ATTESTATION",
            &[
                round_id,
                committee_id,
                &signer_set_root,
                &attestation_root,
                &security_bits.to_string(),
                &signed_at_height.to_string(),
            ],
        );
        Self {
            attestation_id,
            round_id: round_id.to_string(),
            committee_id: committee_id.to_string(),
            signer_set_root,
            attestation_root,
            security_bits,
            signed_at_height,
            expires_at_height,
        }
    }

    pub fn validate(&self) -> PrivateFeeCreditAuctionRouterResult<()> {
        if self.attestation_id.is_empty()
            || self.round_id.is_empty()
            || self.committee_id.is_empty()
            || self.signer_set_root.is_empty()
            || self.attestation_root.is_empty()
        {
            return Err("fee credit auction attestation identifiers cannot be empty".to_string());
        }
        if self.security_bits < 128 {
            return Err("fee credit auction attestation security too low".to_string());
        }
        if self.signed_at_height >= self.expires_at_height {
            return Err("fee credit auction attestation expiry invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_fee_credit_auction_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_FEE_CREDIT_AUCTION_ROUTER_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "round_id": self.round_id,
            "committee_id": self.committee_id,
            "signer_set_root": self.signer_set_root,
            "attestation_root": self.attestation_root,
            "security_bits": self.security_bits,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        private_fee_credit_auction_router_payload_root("PQ-ATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeCreditAuctionChallenge {
    pub challenge_id: String,
    pub round_id: String,
    pub evidence_root: String,
    pub challenger_commitment: String,
    pub challenged_at_height: u64,
    pub expires_at_height: u64,
    pub slash_bps: u64,
    pub status: ChallengeStatus,
}

impl FeeCreditAuctionChallenge {
    pub fn new(
        round_id: &str,
        challenger_label: &str,
        evidence: &Value,
        challenged_at_height: u64,
        challenge_blocks: u64,
        slash_bps: u64,
    ) -> Self {
        let evidence_root = private_fee_credit_auction_router_payload_root("CHALLENGE", evidence);
        let challenger_commitment = private_fee_credit_auction_router_payload_root(
            "CHALLENGER",
            &json!({"label": challenger_label}),
        );
        let expires_at_height = challenged_at_height.saturating_add(challenge_blocks);
        let challenge_id = private_fee_credit_auction_router_id(
            "CHALLENGE",
            &[
                round_id,
                &challenger_commitment,
                &evidence_root,
                &challenged_at_height.to_string(),
                &slash_bps.to_string(),
            ],
        );
        Self {
            challenge_id,
            round_id: round_id.to_string(),
            evidence_root,
            challenger_commitment,
            challenged_at_height,
            expires_at_height,
            slash_bps,
            status: ChallengeStatus::Open,
        }
    }

    pub fn validate(&self) -> PrivateFeeCreditAuctionRouterResult<()> {
        if self.challenge_id.is_empty()
            || self.round_id.is_empty()
            || self.evidence_root.is_empty()
            || self.challenger_commitment.is_empty()
        {
            return Err("fee credit auction challenge identifiers cannot be empty".to_string());
        }
        if self.challenged_at_height >= self.expires_at_height {
            return Err("fee credit auction challenge expiry invalid".to_string());
        }
        if self.slash_bps > PRIVATE_FEE_CREDIT_AUCTION_ROUTER_MAX_BPS {
            return Err("fee credit auction challenge slash exceeds max".to_string());
        }
        Ok(())
    }

    pub fn refresh_status(&mut self, height: u64) {
        if self.status == ChallengeStatus::Open && height > self.expires_at_height {
            self.status = ChallengeStatus::Expired;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_credit_auction_challenge",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_FEE_CREDIT_AUCTION_ROUTER_PROTOCOL_VERSION,
            "challenge_id": self.challenge_id,
            "round_id": self.round_id,
            "evidence_root": self.evidence_root,
            "challenger_commitment": self.challenger_commitment,
            "challenged_at_height": self.challenged_at_height,
            "expires_at_height": self.expires_at_height,
            "slash_bps": self.slash_bps,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        private_fee_credit_auction_router_payload_root("CHALLENGE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateFeeCreditAuctionRouterRoots {
    pub config_root: String,
    pub lane_root: String,
    pub round_root: String,
    pub bid_root: String,
    pub receipt_root: String,
    pub attestation_root: String,
    pub challenge_root: String,
}

impl PrivateFeeCreditAuctionRouterRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "lane_root": self.lane_root,
            "round_root": self.round_root,
            "bid_root": self.bid_root,
            "receipt_root": self.receipt_root,
            "attestation_root": self.attestation_root,
            "challenge_root": self.challenge_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateFeeCreditAuctionRouterCounters {
    pub height: u64,
    pub lanes: u64,
    pub active_lanes: u64,
    pub rounds: u64,
    pub live_rounds: u64,
    pub bids: u64,
    pub active_bids: u64,
    pub receipts: u64,
    pub attestations: u64,
    pub challenges: u64,
    pub open_challenges: u64,
    pub total_available_credit_units: u64,
}

impl PrivateFeeCreditAuctionRouterCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "height": self.height,
            "lanes": self.lanes,
            "active_lanes": self.active_lanes,
            "rounds": self.rounds,
            "live_rounds": self.live_rounds,
            "bids": self.bids,
            "active_bids": self.active_bids,
            "receipts": self.receipts,
            "attestations": self.attestations,
            "challenges": self.challenges,
            "open_challenges": self.open_challenges,
            "total_available_credit_units": self.total_available_credit_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateFeeCreditAuctionRouterState {
    pub height: u64,
    pub epoch: u64,
    pub config: PrivateFeeCreditAuctionRouterConfig,
    pub lanes: BTreeMap<String, FeeCreditAuctionLane>,
    pub rounds: BTreeMap<String, FeeCreditAuctionRound>,
    pub bids: BTreeMap<String, PrivateFeeCreditBid>,
    pub receipts: BTreeMap<String, FeeCreditClearingReceipt>,
    pub attestations: BTreeMap<String, PqFeeCreditAuctionAttestation>,
    pub challenges: BTreeMap<String, FeeCreditAuctionChallenge>,
    pub spent_nullifiers: BTreeSet<String>,
}

impl PrivateFeeCreditAuctionRouterState {
    pub fn new(height: u64, config: PrivateFeeCreditAuctionRouterConfig) -> Self {
        let epoch = height / config.epoch_blocks.max(1);
        Self {
            height,
            epoch,
            config,
            lanes: BTreeMap::new(),
            rounds: BTreeMap::new(),
            bids: BTreeMap::new(),
            receipts: BTreeMap::new(),
            attestations: BTreeMap::new(),
            challenges: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        }
    }

    pub fn devnet() -> PrivateFeeCreditAuctionRouterResult<Self> {
        let config = PrivateFeeCreditAuctionRouterConfig::devnet();
        let mut state = Self::new(PRIVATE_FEE_CREDIT_AUCTION_ROUTER_DEVNET_HEIGHT, config);
        let lane_a = FeeCreditAuctionLane::new(
            FeeCreditAuctionClass::MoneroExit,
            "monero-exit-fee-credit",
            "wxmr-devnet",
            180_000,
            2_000,
            &json!({"privacy": "sealed_bid", "target": "monero_exit"}),
            true,
        );
        let lane_b = FeeCreditAuctionLane::new(
            FeeCreditAuctionClass::ContractCall,
            "private-contract-fee-credit",
            "dnero-devnet",
            120_000,
            2_600,
            &json!({"privacy": "sealed_bid", "target": "contract_call"}),
            true,
        );
        let lane_a_id = state.insert_lane(lane_a)?;
        let lane_b_id = state.insert_lane(lane_b)?;
        let round_a = FeeCreditAuctionRound::new(
            &lane_a_id,
            state.epoch,
            state.height,
            75_000,
            &json!({"round": "monero-exit", "seed": "devnet"}),
            &state.config,
        );
        let round_b = FeeCreditAuctionRound::new(
            &lane_b_id,
            state.epoch,
            state.height,
            45_000,
            &json!({"round": "contract-call", "seed": "devnet"}),
            &state.config,
        );
        let round_a_id = state.insert_round(round_a)?;
        let round_b_id = state.insert_round(round_b)?;
        let bid_a = PrivateFeeCreditBid::new(
            &round_a_id,
            "wallet-sponsor-alpha",
            &json!({"max_fee": 1400, "class": "monero_exit"}),
            1_400,
            12_000,
            300,
            &json!({"scheme": state.config.pq_auth_suite, "signer": "alpha"}),
            state.height,
        );
        let bid_b = PrivateFeeCreditBid::new(
            &round_b_id,
            "contract-sponsor-beta",
            &json!({"max_fee": 2100, "class": "contract_call"}),
            2_100,
            9_000,
            250,
            &json!({"scheme": state.config.pq_auth_suite, "signer": "beta"}),
            state.height,
        );
        let bid_a_id = state.insert_bid(bid_a)?;
        let bid_b_id = state.insert_bid(bid_b)?;
        let receipt = FeeCreditClearingReceipt::new(
            &round_a_id,
            &[bid_a_id],
            &[bid_b_id],
            1_350,
            12_000,
            180,
            state.height.saturating_add(state.config.settlement_blocks),
            &json!({"settlement": "devnet-clearing"}),
        );
        state.insert_receipt(receipt)?;
        let attestation = PqFeeCreditAuctionAttestation::new(
            &round_a_id,
            "devnet-fee-credit-committee",
            &["pq-signer-a".to_string(), "pq-signer-b".to_string()],
            &json!({"verdict": "clearing_valid"}),
            192,
            state.height,
            state.config.challenge_blocks,
        );
        state.insert_attestation(attestation)?;
        let challenge = FeeCreditAuctionChallenge::new(
            &round_b_id,
            "watchtower-alpha",
            &json!({"claim": "bid_reveal_missing"}),
            state.height,
            state.config.challenge_blocks,
            500,
        );
        state.insert_challenge(challenge)?;
        state.validate()?;
        Ok(state)
    }

    pub fn update_height(&mut self, next_height: u64) -> PrivateFeeCreditAuctionRouterResult<()> {
        if next_height < self.height {
            return Err("fee credit auction router height cannot move backwards".to_string());
        }
        self.height = next_height;
        self.epoch = self.height / self.config.epoch_blocks.max(1);
        for round in self.rounds.values_mut() {
            round.refresh_status(self.height);
        }
        for challenge in self.challenges.values_mut() {
            challenge.refresh_status(self.height);
        }
        Ok(())
    }

    pub fn insert_lane(
        &mut self,
        lane: FeeCreditAuctionLane,
    ) -> PrivateFeeCreditAuctionRouterResult<String> {
        if self.lanes.len() >= PRIVATE_FEE_CREDIT_AUCTION_ROUTER_MAX_LANES
            && !self.lanes.contains_key(&lane.lane_id)
        {
            return Err("fee credit auction lane capacity exceeded".to_string());
        }
        lane.validate()?;
        let lane_id = lane.lane_id.clone();
        self.lanes.insert(lane_id.clone(), lane);
        Ok(lane_id)
    }

    pub fn insert_round(
        &mut self,
        round: FeeCreditAuctionRound,
    ) -> PrivateFeeCreditAuctionRouterResult<String> {
        if self.rounds.len() >= PRIVATE_FEE_CREDIT_AUCTION_ROUTER_MAX_ROUNDS
            && !self.rounds.contains_key(&round.round_id)
        {
            return Err("fee credit auction round capacity exceeded".to_string());
        }
        round.validate()?;
        if !self.lanes.contains_key(&round.lane_id) {
            return Err("fee credit auction round references unknown lane".to_string());
        }
        let round_id = round.round_id.clone();
        self.rounds.insert(round_id.clone(), round);
        Ok(round_id)
    }

    pub fn insert_bid(
        &mut self,
        bid: PrivateFeeCreditBid,
    ) -> PrivateFeeCreditAuctionRouterResult<String> {
        if self.bids.len() >= PRIVATE_FEE_CREDIT_AUCTION_ROUTER_MAX_BIDS
            && !self.bids.contains_key(&bid.bid_id)
        {
            return Err("fee credit auction bid capacity exceeded".to_string());
        }
        bid.validate(&self.config)?;
        if !self.rounds.contains_key(&bid.round_id) {
            return Err("fee credit auction bid references unknown round".to_string());
        }
        if self.spent_nullifiers.contains(&bid.nullifier) {
            return Err("fee credit auction bid nullifier already spent".to_string());
        }
        let bid_id = bid.bid_id.clone();
        self.spent_nullifiers.insert(bid.nullifier.clone());
        self.bids.insert(bid_id.clone(), bid);
        Ok(bid_id)
    }

    pub fn insert_receipt(
        &mut self,
        receipt: FeeCreditClearingReceipt,
    ) -> PrivateFeeCreditAuctionRouterResult<String> {
        if self.receipts.len() >= PRIVATE_FEE_CREDIT_AUCTION_ROUTER_MAX_RECEIPTS
            && !self.receipts.contains_key(&receipt.receipt_id)
        {
            return Err("fee credit auction receipt capacity exceeded".to_string());
        }
        receipt.validate(&self.config)?;
        if !self.rounds.contains_key(&receipt.round_id) {
            return Err("fee credit auction receipt references unknown round".to_string());
        }
        let receipt_id = receipt.receipt_id.clone();
        self.receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn insert_attestation(
        &mut self,
        attestation: PqFeeCreditAuctionAttestation,
    ) -> PrivateFeeCreditAuctionRouterResult<String> {
        if self.attestations.len() >= PRIVATE_FEE_CREDIT_AUCTION_ROUTER_MAX_ATTESTATIONS
            && !self.attestations.contains_key(&attestation.attestation_id)
        {
            return Err("fee credit auction attestation capacity exceeded".to_string());
        }
        attestation.validate()?;
        if !self.rounds.contains_key(&attestation.round_id) {
            return Err("fee credit auction attestation references unknown round".to_string());
        }
        let attestation_id = attestation.attestation_id.clone();
        self.attestations
            .insert(attestation_id.clone(), attestation);
        Ok(attestation_id)
    }

    pub fn insert_challenge(
        &mut self,
        challenge: FeeCreditAuctionChallenge,
    ) -> PrivateFeeCreditAuctionRouterResult<String> {
        if self.challenges.len() >= PRIVATE_FEE_CREDIT_AUCTION_ROUTER_MAX_CHALLENGES
            && !self.challenges.contains_key(&challenge.challenge_id)
        {
            return Err("fee credit auction challenge capacity exceeded".to_string());
        }
        challenge.validate()?;
        if !self.rounds.contains_key(&challenge.round_id) {
            return Err("fee credit auction challenge references unknown round".to_string());
        }
        let challenge_id = challenge.challenge_id.clone();
        self.challenges.insert(challenge_id.clone(), challenge);
        Ok(challenge_id)
    }

    pub fn validate(&self) -> PrivateFeeCreditAuctionRouterResult<()> {
        self.config.validate()?;
        if self.lanes.len() > PRIVATE_FEE_CREDIT_AUCTION_ROUTER_MAX_LANES
            || self.rounds.len() > PRIVATE_FEE_CREDIT_AUCTION_ROUTER_MAX_ROUNDS
            || self.bids.len() > PRIVATE_FEE_CREDIT_AUCTION_ROUTER_MAX_BIDS
            || self.receipts.len() > PRIVATE_FEE_CREDIT_AUCTION_ROUTER_MAX_RECEIPTS
            || self.attestations.len() > PRIVATE_FEE_CREDIT_AUCTION_ROUTER_MAX_ATTESTATIONS
            || self.challenges.len() > PRIVATE_FEE_CREDIT_AUCTION_ROUTER_MAX_CHALLENGES
        {
            return Err("fee credit auction router capacity exceeded".to_string());
        }
        let mut nullifiers = BTreeSet::new();
        for lane in self.lanes.values() {
            lane.validate()?;
        }
        for round in self.rounds.values() {
            round.validate()?;
            if !self.lanes.contains_key(&round.lane_id) {
                return Err("fee credit auction round references missing lane".to_string());
            }
        }
        for bid in self.bids.values() {
            bid.validate(&self.config)?;
            if !self.rounds.contains_key(&bid.round_id) {
                return Err("fee credit auction bid references missing round".to_string());
            }
            if !nullifiers.insert(bid.nullifier.clone()) {
                return Err("duplicate fee credit auction bid nullifier".to_string());
            }
        }
        for receipt in self.receipts.values() {
            receipt.validate(&self.config)?;
            if !self.rounds.contains_key(&receipt.round_id) {
                return Err("fee credit auction receipt references missing round".to_string());
            }
        }
        for attestation in self.attestations.values() {
            attestation.validate()?;
            if !self.rounds.contains_key(&attestation.round_id) {
                return Err("fee credit auction attestation references missing round".to_string());
            }
        }
        for challenge in self.challenges.values() {
            challenge.validate()?;
            if !self.rounds.contains_key(&challenge.round_id) {
                return Err("fee credit auction challenge references missing round".to_string());
            }
        }
        Ok(())
    }

    pub fn roots(&self) -> PrivateFeeCreditAuctionRouterRoots {
        PrivateFeeCreditAuctionRouterRoots {
            config_root: self.config.config_root(),
            lane_root: merkle_root(
                "PRIVATE-FEE-CREDIT-AUCTION-LANES",
                &self
                    .lanes
                    .values()
                    .map(FeeCreditAuctionLane::public_record)
                    .collect::<Vec<_>>(),
            ),
            round_root: merkle_root(
                "PRIVATE-FEE-CREDIT-AUCTION-ROUNDS",
                &self
                    .rounds
                    .values()
                    .map(FeeCreditAuctionRound::public_record)
                    .collect::<Vec<_>>(),
            ),
            bid_root: merkle_root(
                "PRIVATE-FEE-CREDIT-AUCTION-BIDS",
                &self
                    .bids
                    .values()
                    .map(PrivateFeeCreditBid::public_record)
                    .collect::<Vec<_>>(),
            ),
            receipt_root: merkle_root(
                "PRIVATE-FEE-CREDIT-AUCTION-RECEIPTS",
                &self
                    .receipts
                    .values()
                    .map(FeeCreditClearingReceipt::public_record)
                    .collect::<Vec<_>>(),
            ),
            attestation_root: merkle_root(
                "PRIVATE-FEE-CREDIT-AUCTION-ATTESTATIONS",
                &self
                    .attestations
                    .values()
                    .map(PqFeeCreditAuctionAttestation::public_record)
                    .collect::<Vec<_>>(),
            ),
            challenge_root: merkle_root(
                "PRIVATE-FEE-CREDIT-AUCTION-CHALLENGES",
                &self
                    .challenges
                    .values()
                    .map(FeeCreditAuctionChallenge::public_record)
                    .collect::<Vec<_>>(),
            ),
        }
    }

    pub fn counters(&self) -> PrivateFeeCreditAuctionRouterCounters {
        PrivateFeeCreditAuctionRouterCounters {
            height: self.height,
            lanes: self.lanes.len() as u64,
            active_lanes: self.lanes.values().filter(|lane| lane.enabled).count() as u64,
            rounds: self.rounds.len() as u64,
            live_rounds: self
                .rounds
                .values()
                .filter(|round| round.status.live())
                .count() as u64,
            bids: self.bids.len() as u64,
            active_bids: self.bids.values().filter(|bid| bid.status.active()).count() as u64,
            receipts: self.receipts.len() as u64,
            attestations: self.attestations.len() as u64,
            challenges: self.challenges.len() as u64,
            open_challenges: self
                .challenges
                .values()
                .filter(|challenge| challenge.status.open())
                .count() as u64,
            total_available_credit_units: self
                .rounds
                .values()
                .filter(|round| round.status.live())
                .map(|round| round.available_credit_units)
                .sum(),
        }
    }

    pub fn live_round_ids(&self) -> Vec<String> {
        self.rounds
            .values()
            .filter(|round| round.status.live())
            .map(|round| round.round_id.clone())
            .collect()
    }

    pub fn open_challenge_ids(&self) -> Vec<String> {
        self.challenges
            .values()
            .filter(|challenge| challenge.status.open())
            .map(|challenge| challenge.challenge_id.clone())
            .collect()
    }

    pub fn lane_credit_pressure(&self) -> BTreeMap<String, Value> {
        let mut pressure = BTreeMap::new();
        for lane in self.lanes.values() {
            let requested_units = self
                .rounds
                .values()
                .filter(|round| round.lane_id == lane.lane_id && round.status.live())
                .map(|round| {
                    self.bids
                        .values()
                        .filter(|bid| bid.round_id == round.round_id && bid.status.active())
                        .map(|bid| bid.requested_credit_units)
                        .sum::<u64>()
                })
                .sum::<u64>();
            let capacity = lane.max_credit_units.max(1);
            let pressure_bps = requested_units
                .saturating_mul(PRIVATE_FEE_CREDIT_AUCTION_ROUTER_MAX_BPS)
                / capacity;
            pressure.insert(
                lane.lane_id.clone(),
                json!({
                    "lane_label": lane.lane_label,
                    "class": lane.class.as_str(),
                    "requested_units": requested_units,
                    "capacity_units": lane.max_credit_units,
                    "pressure_bps": pressure_bps,
                }),
            );
        }
        pressure
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_fee_credit_auction_router_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_FEE_CREDIT_AUCTION_ROUTER_PROTOCOL_VERSION,
            "height": self.height,
            "epoch": self.epoch,
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "live_round_ids": self.live_round_ids(),
            "open_challenge_ids": self.open_challenge_ids(),
            "lane_credit_pressure": self.lane_credit_pressure(),
        })
    }

    pub fn state_root(&self) -> String {
        private_fee_credit_auction_router_state_root_from_record(&self.public_record())
    }
}

pub fn private_fee_credit_auction_router_state_root_from_record(record: &Value) -> String {
    private_fee_credit_auction_router_payload_root("STATE", record)
}

pub fn private_fee_credit_auction_router_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-FEE-CREDIT-AUCTION-ROUTER-{domain}"),
        &[HashPart::Json(payload)],
        32,
    )
}

pub fn private_fee_credit_auction_router_string_set_root(
    domain: &str,
    values: &[String],
) -> String {
    merkle_root(
        &format!("PRIVATE-FEE-CREDIT-AUCTION-ROUTER-{domain}"),
        &values
            .iter()
            .map(|value| json!({"value": value}))
            .collect::<Vec<_>>(),
    )
}

pub fn private_fee_credit_auction_router_id(domain: &str, parts: &[&str]) -> String {
    let values = parts
        .iter()
        .map(|part| json!({"part": part}))
        .collect::<Vec<_>>();
    domain_hash(
        &format!("PRIVATE-FEE-CREDIT-AUCTION-ROUTER-ID-{domain}"),
        &[HashPart::Json(&json!({ "parts": values }))],
        32,
    )
}

pub fn devnet() -> PrivateFeeCreditAuctionRouterResult<PrivateFeeCreditAuctionRouterState> {
    PrivateFeeCreditAuctionRouterState::devnet()
}
