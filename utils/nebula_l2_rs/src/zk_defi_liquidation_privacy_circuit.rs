use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};

pub type ZkDefiLiquidationPrivacyCircuitResult<T> = Result<T, String>;

pub const ZK_DEFI_LIQUIDATION_PRIVACY_CIRCUIT_PROTOCOL_VERSION: &str =
    "nebula-zk-defi-liquidation-privacy-circuit-v1";
pub const ZK_DEFI_LIQUIDATION_MAX_MARKETS: usize = 32;
pub const ZK_DEFI_LIQUIDATION_MAX_POSITIONS: usize = 256;
pub const ZK_DEFI_LIQUIDATION_MAX_AUCTIONS: usize = 192;
pub const ZK_DEFI_LIQUIDATION_MAX_PROOFS: usize = 256;
pub const ZK_DEFI_LIQUIDATION_DEFAULT_CHALLENGE_BLOCKS: u64 = 96;
pub const ZK_DEFI_LIQUIDATION_DEFAULT_AUCTION_BLOCKS: u64 = 24;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum CollateralClass {
    PrivateStablecoin,
    ConfidentialVaultShare,
    MoneroBridgeReceipt,
    PrivateLpToken,
    TokenizedTreasuryNote,
}

impl CollateralClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateStablecoin => "private_stablecoin",
            Self::ConfidentialVaultShare => "confidential_vault_share",
            Self::MoneroBridgeReceipt => "monero_bridge_receipt",
            Self::PrivateLpToken => "private_lp_token",
            Self::TokenizedTreasuryNote => "tokenized_treasury_note",
        }
    }

    fn haircut_bps(self) -> u64 {
        match self {
            Self::PrivateStablecoin => 550,
            Self::ConfidentialVaultShare => 1_200,
            Self::MoneroBridgeReceipt => 1_750,
            Self::PrivateLpToken => 2_100,
            Self::TokenizedTreasuryNote => 800,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum LiquidationPositionStatus {
    Healthy,
    Watch,
    Liquidatable,
    Auctioning,
    Settled,
    Challenged,
}

impl LiquidationPositionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Watch => "watch",
            Self::Liquidatable => "liquidatable",
            Self::Auctioning => "auctioning",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuctionStatus {
    Collecting,
    Proving,
    ReadyToSettle,
    Settled,
    Challenged,
    Expired,
}

impl AuctionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Proving => "proving",
            Self::ReadyToSettle => "ready_to_settle",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProofStatus {
    Queued,
    Generated,
    Verified,
    Rejected,
    Challenged,
}

impl ProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Generated => "generated",
            Self::Verified => "verified",
            Self::Rejected => "rejected",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub challenge_blocks: u64,
    pub auction_blocks: u64,
    pub min_health_factor_bps: u64,
    pub max_markets: usize,
    pub max_positions: usize,
    pub max_auctions: usize,
    pub max_proofs: usize,
    pub zk_proof_system: String,
    pub pq_oracle_scheme: String,
    pub privacy_policy_root: String,
}

impl Config {
    pub fn devnet() -> Self {
        let privacy_policy_root = zk_defi_liquidation_string_root(
            "privacy-policy",
            &[
                "sealed-liquidation-bids",
                "private-collateral-nullifiers",
                "selective-disclosure-for-watchtowers",
            ],
        );
        Self {
            challenge_blocks: ZK_DEFI_LIQUIDATION_DEFAULT_CHALLENGE_BLOCKS,
            auction_blocks: ZK_DEFI_LIQUIDATION_DEFAULT_AUCTION_BLOCKS,
            min_health_factor_bps: 11_500,
            max_markets: ZK_DEFI_LIQUIDATION_MAX_MARKETS,
            max_positions: ZK_DEFI_LIQUIDATION_MAX_POSITIONS,
            max_auctions: ZK_DEFI_LIQUIDATION_MAX_AUCTIONS,
            max_proofs: ZK_DEFI_LIQUIDATION_MAX_PROOFS,
            zk_proof_system: "plonkish-recursive-liquidation-v1".to_string(),
            pq_oracle_scheme: "ml-dsa-87-oracle-quorum".to_string(),
            privacy_policy_root,
        }
    }

    pub fn validate(&self) -> ZkDefiLiquidationPrivacyCircuitResult<()> {
        if self.challenge_blocks == 0 || self.auction_blocks == 0 {
            return Err("liquidation privacy circuit windows must be non-zero".to_string());
        }
        if self.auction_blocks >= self.challenge_blocks {
            return Err("liquidation auction window must fit inside challenge window".to_string());
        }
        if self.min_health_factor_bps <= 10_000 {
            return Err("liquidation minimum health factor must exceed 100%".to_string());
        }
        if self.max_markets == 0
            || self.max_positions == 0
            || self.max_auctions == 0
            || self.max_proofs == 0
        {
            return Err("liquidation privacy circuit capacities must be non-zero".to_string());
        }
        if self.zk_proof_system.trim().is_empty() {
            return Err("liquidation zk proof system cannot be empty".to_string());
        }
        if self.pq_oracle_scheme.trim().is_empty() {
            return Err("liquidation pq oracle scheme cannot be empty".to_string());
        }
        if self.privacy_policy_root.trim().is_empty() {
            return Err("liquidation privacy policy root cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "challenge_blocks": self.challenge_blocks,
            "auction_blocks": self.auction_blocks,
            "min_health_factor_bps": self.min_health_factor_bps,
            "max_markets": self.max_markets,
            "max_positions": self.max_positions,
            "max_auctions": self.max_auctions,
            "max_proofs": self.max_proofs,
            "zk_proof_system": self.zk_proof_system,
            "pq_oracle_scheme": self.pq_oracle_scheme,
            "privacy_policy_root": self.privacy_policy_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LendingMarket {
    pub market_id: String,
    pub collateral_class: CollateralClass,
    pub private_market_commitment: String,
    pub oracle_feed_root: String,
    pub liquidation_threshold_bps: u64,
    pub close_factor_bps: u64,
    pub sponsor_pool_commitment: String,
}

impl LendingMarket {
    pub fn new(
        label: &str,
        collateral_class: CollateralClass,
        liquidation_threshold_bps: u64,
        close_factor_bps: u64,
    ) -> Self {
        let class = collateral_class.as_str();
        let private_market_commitment =
            zk_defi_liquidation_commitment("market", &format!("{label}:{class}"));
        let market_id =
            zk_defi_liquidation_id("market", &[label, class, &private_market_commitment]);
        let oracle_feed_root =
            zk_defi_liquidation_string_root("oracle-feed", &[label, class, "pq-quorum"]);
        let sponsor_pool_commitment =
            zk_defi_liquidation_commitment("sponsor-pool", &format!("{label}:fees"));
        Self {
            market_id,
            collateral_class,
            private_market_commitment,
            oracle_feed_root,
            liquidation_threshold_bps,
            close_factor_bps,
            sponsor_pool_commitment,
        }
    }

    pub fn validate(&self) -> ZkDefiLiquidationPrivacyCircuitResult<()> {
        if self.market_id.trim().is_empty() || self.private_market_commitment.trim().is_empty() {
            return Err("liquidation market ids cannot be empty".to_string());
        }
        if self.oracle_feed_root.trim().is_empty() || self.sponsor_pool_commitment.trim().is_empty()
        {
            return Err("liquidation market roots cannot be empty".to_string());
        }
        if self.liquidation_threshold_bps <= 10_000 || self.liquidation_threshold_bps > 20_000 {
            return Err("liquidation threshold is outside expected range".to_string());
        }
        if self.close_factor_bps == 0 || self.close_factor_bps > 10_000 {
            return Err("liquidation close factor is invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "market_id": self.market_id,
            "collateral_class": self.collateral_class.as_str(),
            "private_market_commitment": self.private_market_commitment,
            "oracle_feed_root": self.oracle_feed_root,
            "liquidation_threshold_bps": self.liquidation_threshold_bps,
            "close_factor_bps": self.close_factor_bps,
            "sponsor_pool_commitment": self.sponsor_pool_commitment,
            "haircut_bps": self.collateral_class.haircut_bps(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivatePosition {
    pub position_id: String,
    pub market_id: String,
    pub borrower_commitment: String,
    pub collateral_commitment: String,
    pub debt_commitment: String,
    pub collateral_value_units: u64,
    pub debt_value_units: u64,
    pub health_factor_bps: u64,
    pub status: LiquidationPositionStatus,
    pub nullifier_root: String,
}

impl PrivatePosition {
    pub fn new(
        market_id: &str,
        borrower_label: &str,
        collateral_value_units: u64,
        debt_value_units: u64,
    ) -> Self {
        let borrower_commitment = zk_defi_liquidation_commitment("borrower", borrower_label);
        let collateral_commitment = zk_defi_liquidation_string_root(
            "collateral",
            &[
                market_id,
                borrower_commitment.as_str(),
                &collateral_value_units.to_string(),
            ],
        );
        let debt_commitment = zk_defi_liquidation_string_root(
            "debt",
            &[
                market_id,
                borrower_commitment.as_str(),
                &debt_value_units.to_string(),
            ],
        );
        let position_id = zk_defi_liquidation_id(
            "position",
            &[
                market_id,
                borrower_commitment.as_str(),
                collateral_commitment.as_str(),
            ],
        );
        let health_factor_bps = if debt_value_units == 0 {
            20_000
        } else {
            collateral_value_units.saturating_mul(10_000) / debt_value_units
        };
        let status = if health_factor_bps < 10_500 {
            LiquidationPositionStatus::Liquidatable
        } else if health_factor_bps < 11_500 {
            LiquidationPositionStatus::Watch
        } else {
            LiquidationPositionStatus::Healthy
        };
        let nullifier_root =
            zk_defi_liquidation_string_root("position-nullifier", &[position_id.as_str()]);
        Self {
            position_id,
            market_id: market_id.to_string(),
            borrower_commitment,
            collateral_commitment,
            debt_commitment,
            collateral_value_units,
            debt_value_units,
            health_factor_bps,
            status,
            nullifier_root,
        }
    }

    pub fn validate(&self) -> ZkDefiLiquidationPrivacyCircuitResult<()> {
        if self.position_id.trim().is_empty()
            || self.market_id.trim().is_empty()
            || self.borrower_commitment.trim().is_empty()
        {
            return Err("liquidation position ids cannot be empty".to_string());
        }
        if self.collateral_commitment.trim().is_empty()
            || self.debt_commitment.trim().is_empty()
            || self.nullifier_root.trim().is_empty()
        {
            return Err("liquidation position commitments cannot be empty".to_string());
        }
        if self.collateral_value_units == 0 || self.debt_value_units == 0 {
            return Err("liquidation position values must be non-zero".to_string());
        }
        Ok(())
    }

    pub fn liquidatable(&self, config: &Config) -> bool {
        self.health_factor_bps < config.min_health_factor_bps
            || matches!(self.status, LiquidationPositionStatus::Liquidatable)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "position_id": self.position_id,
            "market_id": self.market_id,
            "borrower_commitment": self.borrower_commitment,
            "collateral_commitment": self.collateral_commitment,
            "debt_commitment": self.debt_commitment,
            "collateral_value_units": self.collateral_value_units,
            "debt_value_units": self.debt_value_units,
            "health_factor_bps": self.health_factor_bps,
            "status": self.status.as_str(),
            "nullifier_root": self.nullifier_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OracleSnapshot {
    pub snapshot_id: String,
    pub market_id: String,
    pub price_root: String,
    pub volatility_bps: u64,
    pub pq_signature_root: String,
    pub observed_height: u64,
}

impl OracleSnapshot {
    pub fn new(
        market_id: &str,
        price_label: &str,
        volatility_bps: u64,
        observed_height: u64,
    ) -> Self {
        let price_root = zk_defi_liquidation_string_root("oracle-price", &[market_id, price_label]);
        let pq_signature_root = zk_defi_liquidation_string_root(
            "oracle-pq-signature",
            &[market_id, price_root.as_str(), &observed_height.to_string()],
        );
        let snapshot_id = zk_defi_liquidation_id(
            "oracle-snapshot",
            &[market_id, price_root.as_str(), pq_signature_root.as_str()],
        );
        Self {
            snapshot_id,
            market_id: market_id.to_string(),
            price_root,
            volatility_bps,
            pq_signature_root,
            observed_height,
        }
    }

    pub fn validate(&self) -> ZkDefiLiquidationPrivacyCircuitResult<()> {
        if self.snapshot_id.trim().is_empty() || self.market_id.trim().is_empty() {
            return Err("liquidation oracle snapshot ids cannot be empty".to_string());
        }
        if self.price_root.trim().is_empty() || self.pq_signature_root.trim().is_empty() {
            return Err("liquidation oracle snapshot roots cannot be empty".to_string());
        }
        if self.volatility_bps > 20_000 {
            return Err("liquidation oracle volatility is out of range".to_string());
        }
        if self.observed_height == 0 {
            return Err("liquidation oracle observed height must be non-zero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "market_id": self.market_id,
            "price_root": self.price_root,
            "volatility_bps": self.volatility_bps,
            "pq_signature_root": self.pq_signature_root,
            "observed_height": self.observed_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedLiquidationBid {
    pub bid_id: String,
    pub auction_id: String,
    pub bidder_commitment: String,
    pub sealed_bid_root: String,
    pub repay_units: u64,
    pub bonus_bps: u64,
    pub sponsor_fee_units: u64,
}

impl SealedLiquidationBid {
    pub fn new(
        auction_id: &str,
        bidder_label: &str,
        repay_units: u64,
        bonus_bps: u64,
        sponsor_fee_units: u64,
    ) -> Self {
        let bidder_commitment = zk_defi_liquidation_commitment("liquidator", bidder_label);
        let sealed_bid_root = zk_defi_liquidation_string_root(
            "sealed-bid",
            &[
                auction_id,
                bidder_commitment.as_str(),
                &repay_units.to_string(),
                &bonus_bps.to_string(),
            ],
        );
        let bid_id = zk_defi_liquidation_id(
            "bid",
            &[
                auction_id,
                bidder_commitment.as_str(),
                sealed_bid_root.as_str(),
            ],
        );
        Self {
            bid_id,
            auction_id: auction_id.to_string(),
            bidder_commitment,
            sealed_bid_root,
            repay_units,
            bonus_bps,
            sponsor_fee_units,
        }
    }

    pub fn validate(&self) -> ZkDefiLiquidationPrivacyCircuitResult<()> {
        if self.bid_id.trim().is_empty()
            || self.auction_id.trim().is_empty()
            || self.bidder_commitment.trim().is_empty()
            || self.sealed_bid_root.trim().is_empty()
        {
            return Err("liquidation bid identifiers cannot be empty".to_string());
        }
        if self.repay_units == 0 {
            return Err("liquidation bid repay units must be non-zero".to_string());
        }
        if self.bonus_bps > 5_000 {
            return Err("liquidation bid bonus is too large".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "auction_id": self.auction_id,
            "bidder_commitment": self.bidder_commitment,
            "sealed_bid_root": self.sealed_bid_root,
            "repay_units": self.repay_units,
            "bonus_bps": self.bonus_bps,
            "sponsor_fee_units": self.sponsor_fee_units,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LiquidationAuction {
    pub auction_id: String,
    pub position_id: String,
    pub market_id: String,
    pub oracle_snapshot_id: String,
    pub bid_root: String,
    pub opened_height: u64,
    pub bid_deadline: u64,
    pub challenge_deadline: u64,
    pub status: AuctionStatus,
}

impl LiquidationAuction {
    pub fn new(
        position: &PrivatePosition,
        oracle_snapshot_id: &str,
        opened_height: u64,
        auction_blocks: u64,
        challenge_blocks: u64,
    ) -> Self {
        let auction_id = zk_defi_liquidation_id(
            "auction",
            &[
                position.position_id.as_str(),
                position.market_id.as_str(),
                oracle_snapshot_id,
                &opened_height.to_string(),
            ],
        );
        let bid_root = merkle_root("ZK-DEFI-LIQUIDATION:empty-bids", &[]);
        Self {
            auction_id,
            position_id: position.position_id.clone(),
            market_id: position.market_id.clone(),
            oracle_snapshot_id: oracle_snapshot_id.to_string(),
            bid_root,
            opened_height,
            bid_deadline: opened_height.saturating_add(auction_blocks),
            challenge_deadline: opened_height.saturating_add(challenge_blocks),
            status: AuctionStatus::Collecting,
        }
    }

    pub fn validate(&self) -> ZkDefiLiquidationPrivacyCircuitResult<()> {
        if self.auction_id.trim().is_empty()
            || self.position_id.trim().is_empty()
            || self.market_id.trim().is_empty()
            || self.oracle_snapshot_id.trim().is_empty()
        {
            return Err("liquidation auction ids cannot be empty".to_string());
        }
        if self.bid_root.trim().is_empty() {
            return Err("liquidation auction bid root cannot be empty".to_string());
        }
        if self.bid_deadline <= self.opened_height || self.challenge_deadline <= self.bid_deadline {
            return Err("liquidation auction deadlines are invalid".to_string());
        }
        Ok(())
    }

    pub fn refresh(&mut self, height: u64) {
        if matches!(self.status, AuctionStatus::Collecting) && height >= self.bid_deadline {
            self.status = AuctionStatus::Proving;
        }
        if matches!(self.status, AuctionStatus::Proving) && height >= self.challenge_deadline {
            self.status = AuctionStatus::ReadyToSettle;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "auction_id": self.auction_id,
            "position_id": self.position_id,
            "market_id": self.market_id,
            "oracle_snapshot_id": self.oracle_snapshot_id,
            "bid_root": self.bid_root,
            "opened_height": self.opened_height,
            "bid_deadline": self.bid_deadline,
            "challenge_deadline": self.challenge_deadline,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyProof {
    pub proof_id: String,
    pub auction_id: String,
    pub position_id: String,
    pub collateral_proof_root: String,
    pub debt_proof_root: String,
    pub winning_bid_nullifier: String,
    pub recursive_proof_root: String,
    pub generated_height: u64,
    pub status: ProofStatus,
}

impl PrivacyProof {
    pub fn new(auction: &LiquidationAuction, winning_bid_id: &str, generated_height: u64) -> Self {
        let collateral_proof_root = zk_defi_liquidation_string_root(
            "collateral-proof",
            &[auction.auction_id.as_str(), auction.position_id.as_str()],
        );
        let debt_proof_root = zk_defi_liquidation_string_root(
            "debt-proof",
            &[auction.auction_id.as_str(), auction.market_id.as_str()],
        );
        let winning_bid_nullifier =
            zk_defi_liquidation_string_root("winning-bid-nullifier", &[winning_bid_id]);
        let recursive_proof_root = zk_defi_liquidation_string_root(
            "recursive-proof",
            &[
                collateral_proof_root.as_str(),
                debt_proof_root.as_str(),
                winning_bid_nullifier.as_str(),
            ],
        );
        let proof_id = zk_defi_liquidation_id(
            "privacy-proof",
            &[auction.auction_id.as_str(), recursive_proof_root.as_str()],
        );
        Self {
            proof_id,
            auction_id: auction.auction_id.clone(),
            position_id: auction.position_id.clone(),
            collateral_proof_root,
            debt_proof_root,
            winning_bid_nullifier,
            recursive_proof_root,
            generated_height,
            status: ProofStatus::Generated,
        }
    }

    pub fn validate(&self) -> ZkDefiLiquidationPrivacyCircuitResult<()> {
        if self.proof_id.trim().is_empty()
            || self.auction_id.trim().is_empty()
            || self.position_id.trim().is_empty()
        {
            return Err("liquidation proof ids cannot be empty".to_string());
        }
        if self.collateral_proof_root.trim().is_empty()
            || self.debt_proof_root.trim().is_empty()
            || self.winning_bid_nullifier.trim().is_empty()
            || self.recursive_proof_root.trim().is_empty()
        {
            return Err("liquidation proof roots cannot be empty".to_string());
        }
        if self.generated_height == 0 {
            return Err("liquidation proof generated height must be non-zero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "auction_id": self.auction_id,
            "position_id": self.position_id,
            "collateral_proof_root": self.collateral_proof_root,
            "debt_proof_root": self.debt_proof_root,
            "winning_bid_nullifier": self.winning_bid_nullifier,
            "recursive_proof_root": self.recursive_proof_root,
            "generated_height": self.generated_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SponsorReceipt {
    pub receipt_id: String,
    pub auction_id: String,
    pub sponsor_commitment: String,
    pub sponsored_fee_units: u64,
    pub rebate_commitment: String,
}

impl SponsorReceipt {
    pub fn new(auction_id: &str, sponsor_label: &str, sponsored_fee_units: u64) -> Self {
        let sponsor_commitment = zk_defi_liquidation_commitment("sponsor", sponsor_label);
        let rebate_commitment = zk_defi_liquidation_string_root(
            "sponsor-rebate",
            &[
                auction_id,
                sponsor_commitment.as_str(),
                &sponsored_fee_units.to_string(),
            ],
        );
        let receipt_id = zk_defi_liquidation_id(
            "sponsor-receipt",
            &[
                auction_id,
                sponsor_commitment.as_str(),
                rebate_commitment.as_str(),
            ],
        );
        Self {
            receipt_id,
            auction_id: auction_id.to_string(),
            sponsor_commitment,
            sponsored_fee_units,
            rebate_commitment,
        }
    }

    pub fn validate(&self) -> ZkDefiLiquidationPrivacyCircuitResult<()> {
        if self.receipt_id.trim().is_empty()
            || self.auction_id.trim().is_empty()
            || self.sponsor_commitment.trim().is_empty()
            || self.rebate_commitment.trim().is_empty()
        {
            return Err("liquidation sponsor receipt fields cannot be empty".to_string());
        }
        if self.sponsored_fee_units == 0 {
            return Err("liquidation sponsor fee units must be non-zero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "auction_id": self.auction_id,
            "sponsor_commitment": self.sponsor_commitment,
            "sponsored_fee_units": self.sponsored_fee_units,
            "rebate_commitment": self.rebate_commitment,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub market_root: String,
    pub position_root: String,
    pub oracle_snapshot_root: String,
    pub auction_root: String,
    pub bid_root: String,
    pub proof_root: String,
    pub sponsor_root: String,
    pub challenge_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "market_root": self.market_root,
            "position_root": self.position_root,
            "oracle_snapshot_root": self.oracle_snapshot_root,
            "auction_root": self.auction_root,
            "bid_root": self.bid_root,
            "proof_root": self.proof_root,
            "sponsor_root": self.sponsor_root,
            "challenge_root": self.challenge_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Counters {
    pub market_count: u64,
    pub position_count: u64,
    pub liquidatable_position_count: u64,
    pub auction_count: u64,
    pub collecting_auction_count: u64,
    pub ready_auction_count: u64,
    pub bid_count: u64,
    pub proof_count: u64,
    pub verified_proof_count: u64,
    pub sponsor_receipt_count: u64,
    pub sponsored_fee_units: u64,
    pub challenged_item_count: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "market_count": self.market_count,
            "position_count": self.position_count,
            "liquidatable_position_count": self.liquidatable_position_count,
            "auction_count": self.auction_count,
            "collecting_auction_count": self.collecting_auction_count,
            "ready_auction_count": self.ready_auction_count,
            "bid_count": self.bid_count,
            "proof_count": self.proof_count,
            "verified_proof_count": self.verified_proof_count,
            "sponsor_receipt_count": self.sponsor_receipt_count,
            "sponsored_fee_units": self.sponsored_fee_units,
            "challenged_item_count": self.challenged_item_count,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub markets: BTreeMap<String, LendingMarket>,
    pub positions: BTreeMap<String, PrivatePosition>,
    pub oracle_snapshots: BTreeMap<String, OracleSnapshot>,
    pub auctions: BTreeMap<String, LiquidationAuction>,
    pub bids: BTreeMap<String, SealedLiquidationBid>,
    pub proofs: BTreeMap<String, PrivacyProof>,
    pub sponsor_receipts: BTreeMap<String, SponsorReceipt>,
    pub challenges: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> ZkDefiLiquidationPrivacyCircuitResult<Self> {
        let config = Config::devnet();
        config.validate()?;
        let mut state = Self {
            height: 64,
            config,
            markets: BTreeMap::new(),
            positions: BTreeMap::new(),
            oracle_snapshots: BTreeMap::new(),
            auctions: BTreeMap::new(),
            bids: BTreeMap::new(),
            proofs: BTreeMap::new(),
            sponsor_receipts: BTreeMap::new(),
            challenges: BTreeSet::new(),
        };

        let market_a = LendingMarket::new(
            "private-xmr-receipt-market",
            CollateralClass::MoneroBridgeReceipt,
            12_500,
            5_000,
        );
        let market_b = LendingMarket::new(
            "private-lp-token-market",
            CollateralClass::PrivateLpToken,
            13_250,
            4_500,
        );
        state.insert_market(market_a.clone())?;
        state.insert_market(market_b.clone())?;

        let mut position_a =
            PrivatePosition::new(&market_a.market_id, "borrower-alpha", 900_000, 880_000);
        let position_b =
            PrivatePosition::new(&market_b.market_id, "borrower-beta", 1_800_000, 1_260_000);
        position_a.status = LiquidationPositionStatus::Liquidatable;
        state.insert_position(position_a.clone())?;
        state.insert_position(position_b)?;

        let snapshot = OracleSnapshot::new(
            &market_a.market_id,
            "xmr-bridge-receipt-price-64",
            1_350,
            64,
        );
        state.insert_oracle_snapshot(snapshot.clone())?;

        let auction = LiquidationAuction::new(
            &position_a,
            &snapshot.snapshot_id,
            state.height,
            state.config.auction_blocks,
            state.config.challenge_blocks,
        );
        state.insert_auction(auction.clone())?;

        let bid_a =
            SealedLiquidationBid::new(&auction.auction_id, "liquidator-alpha", 440_000, 420, 380);
        let bid_b =
            SealedLiquidationBid::new(&auction.auction_id, "liquidator-beta", 460_000, 390, 420);
        state.insert_bid(bid_a.clone())?;
        state.insert_bid(bid_b)?;

        let proof = PrivacyProof::new(&auction, &bid_a.bid_id, state.height + 2);
        state.insert_proof(proof)?;
        state.insert_sponsor_receipt(SponsorReceipt::new(
            &auction.auction_id,
            "zk-liquidation-fee-sponsor-alpha",
            800,
        ))?;
        state.validate()?;
        Ok(state)
    }

    pub fn insert_market(
        &mut self,
        market: LendingMarket,
    ) -> ZkDefiLiquidationPrivacyCircuitResult<()> {
        if self.markets.len() >= self.config.max_markets {
            return Err("liquidation market capacity exceeded".to_string());
        }
        market.validate()?;
        self.markets.insert(market.market_id.clone(), market);
        Ok(())
    }

    pub fn insert_position(
        &mut self,
        position: PrivatePosition,
    ) -> ZkDefiLiquidationPrivacyCircuitResult<()> {
        if self.positions.len() >= self.config.max_positions {
            return Err("liquidation position capacity exceeded".to_string());
        }
        if !self.markets.contains_key(&position.market_id) {
            return Err("liquidation position references unknown market".to_string());
        }
        position.validate()?;
        self.positions
            .insert(position.position_id.clone(), position);
        Ok(())
    }

    pub fn insert_oracle_snapshot(
        &mut self,
        snapshot: OracleSnapshot,
    ) -> ZkDefiLiquidationPrivacyCircuitResult<()> {
        if !self.markets.contains_key(&snapshot.market_id) {
            return Err("liquidation oracle snapshot references unknown market".to_string());
        }
        snapshot.validate()?;
        self.oracle_snapshots
            .insert(snapshot.snapshot_id.clone(), snapshot);
        Ok(())
    }

    pub fn insert_auction(
        &mut self,
        auction: LiquidationAuction,
    ) -> ZkDefiLiquidationPrivacyCircuitResult<()> {
        if self.auctions.len() >= self.config.max_auctions {
            return Err("liquidation auction capacity exceeded".to_string());
        }
        if !self.positions.contains_key(&auction.position_id) {
            return Err("liquidation auction references unknown position".to_string());
        }
        if !self
            .oracle_snapshots
            .contains_key(&auction.oracle_snapshot_id)
        {
            return Err("liquidation auction references unknown oracle snapshot".to_string());
        }
        auction.validate()?;
        self.auctions.insert(auction.auction_id.clone(), auction);
        Ok(())
    }

    pub fn insert_bid(
        &mut self,
        bid: SealedLiquidationBid,
    ) -> ZkDefiLiquidationPrivacyCircuitResult<()> {
        if !self.auctions.contains_key(&bid.auction_id) {
            return Err("liquidation bid references unknown auction".to_string());
        }
        bid.validate()?;
        self.bids.insert(bid.bid_id.clone(), bid);
        self.refresh_bid_roots();
        Ok(())
    }

    pub fn insert_proof(
        &mut self,
        proof: PrivacyProof,
    ) -> ZkDefiLiquidationPrivacyCircuitResult<()> {
        if self.proofs.len() >= self.config.max_proofs {
            return Err("liquidation proof capacity exceeded".to_string());
        }
        if !self.auctions.contains_key(&proof.auction_id) {
            return Err("liquidation proof references unknown auction".to_string());
        }
        proof.validate()?;
        self.proofs.insert(proof.proof_id.clone(), proof);
        Ok(())
    }

    pub fn insert_sponsor_receipt(
        &mut self,
        receipt: SponsorReceipt,
    ) -> ZkDefiLiquidationPrivacyCircuitResult<()> {
        if !self.auctions.contains_key(&receipt.auction_id) {
            return Err("liquidation sponsor receipt references unknown auction".to_string());
        }
        receipt.validate()?;
        self.sponsor_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        Ok(())
    }

    pub fn challenge(&mut self, item_id: &str) -> ZkDefiLiquidationPrivacyCircuitResult<()> {
        if item_id.trim().is_empty() {
            return Err("liquidation challenge item id cannot be empty".to_string());
        }
        self.challenges.insert(item_id.to_string());
        if let Some(auction) = self.auctions.get_mut(item_id) {
            auction.status = AuctionStatus::Challenged;
        }
        if let Some(proof) = self.proofs.get_mut(item_id) {
            proof.status = ProofStatus::Challenged;
        }
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> ZkDefiLiquidationPrivacyCircuitResult<()> {
        if height < self.height {
            return Err("liquidation privacy circuit height cannot move backwards".to_string());
        }
        self.height = height;
        self.refresh_height();
        Ok(())
    }

    pub fn update_height(&mut self, delta: u64) -> ZkDefiLiquidationPrivacyCircuitResult<()> {
        self.set_height(self.height.saturating_add(delta))
    }

    fn refresh_height(&mut self) {
        for auction in self.auctions.values_mut() {
            auction.refresh(self.height);
        }
        for proof in self.proofs.values_mut() {
            if matches!(proof.status, ProofStatus::Generated)
                && proof.generated_height <= self.height
            {
                proof.status = ProofStatus::Verified;
            }
        }
    }

    fn refresh_bid_roots(&mut self) {
        let mut bids_by_auction: BTreeMap<String, Vec<Value>> = BTreeMap::new();
        for bid in self.bids.values() {
            bids_by_auction
                .entry(bid.auction_id.clone())
                .or_default()
                .push(bid.public_record());
        }
        for (auction_id, bids) in bids_by_auction {
            if let Some(auction) = self.auctions.get_mut(&auction_id) {
                auction.bid_root = merkle_root("ZK-DEFI-LIQUIDATION:auction-bids", &bids);
            }
        }
    }

    pub fn validate(&self) -> ZkDefiLiquidationPrivacyCircuitResult<()> {
        self.config.validate()?;
        if self.markets.len() > self.config.max_markets
            || self.positions.len() > self.config.max_positions
            || self.auctions.len() > self.config.max_auctions
            || self.proofs.len() > self.config.max_proofs
        {
            return Err("liquidation privacy circuit capacity exceeded".to_string());
        }
        for market in self.markets.values() {
            market.validate()?;
        }
        for position in self.positions.values() {
            position.validate()?;
            if !self.markets.contains_key(&position.market_id) {
                return Err("liquidation position references missing market".to_string());
            }
        }
        for snapshot in self.oracle_snapshots.values() {
            snapshot.validate()?;
            if !self.markets.contains_key(&snapshot.market_id) {
                return Err("liquidation oracle snapshot references missing market".to_string());
            }
        }
        for auction in self.auctions.values() {
            auction.validate()?;
            if !self.positions.contains_key(&auction.position_id) {
                return Err("liquidation auction references missing position".to_string());
            }
        }
        for bid in self.bids.values() {
            bid.validate()?;
            if !self.auctions.contains_key(&bid.auction_id) {
                return Err("liquidation bid references missing auction".to_string());
            }
        }
        for proof in self.proofs.values() {
            proof.validate()?;
            if !self.auctions.contains_key(&proof.auction_id) {
                return Err("liquidation proof references missing auction".to_string());
            }
        }
        for receipt in self.sponsor_receipts.values() {
            receipt.validate()?;
            if !self.auctions.contains_key(&receipt.auction_id) {
                return Err("liquidation sponsor receipt references missing auction".to_string());
            }
        }
        Ok(())
    }

    pub fn roots(&self) -> Roots {
        let market_leaves = self
            .markets
            .values()
            .map(LendingMarket::public_record)
            .collect::<Vec<_>>();
        let position_leaves = self
            .positions
            .values()
            .map(PrivatePosition::public_record)
            .collect::<Vec<_>>();
        let oracle_leaves = self
            .oracle_snapshots
            .values()
            .map(OracleSnapshot::public_record)
            .collect::<Vec<_>>();
        let auction_leaves = self
            .auctions
            .values()
            .map(LiquidationAuction::public_record)
            .collect::<Vec<_>>();
        let bid_leaves = self
            .bids
            .values()
            .map(SealedLiquidationBid::public_record)
            .collect::<Vec<_>>();
        let proof_leaves = self
            .proofs
            .values()
            .map(PrivacyProof::public_record)
            .collect::<Vec<_>>();
        let sponsor_leaves = self
            .sponsor_receipts
            .values()
            .map(SponsorReceipt::public_record)
            .collect::<Vec<_>>();
        let challenge_leaves = self
            .challenges
            .iter()
            .map(|item| json!({"challenge_item_id": item}))
            .collect::<Vec<_>>();
        Roots {
            market_root: merkle_root("ZK-DEFI-LIQUIDATION:markets", &market_leaves),
            position_root: merkle_root("ZK-DEFI-LIQUIDATION:positions", &position_leaves),
            oracle_snapshot_root: merkle_root("ZK-DEFI-LIQUIDATION:oracles", &oracle_leaves),
            auction_root: merkle_root("ZK-DEFI-LIQUIDATION:auctions", &auction_leaves),
            bid_root: merkle_root("ZK-DEFI-LIQUIDATION:bids", &bid_leaves),
            proof_root: merkle_root("ZK-DEFI-LIQUIDATION:proofs", &proof_leaves),
            sponsor_root: merkle_root("ZK-DEFI-LIQUIDATION:sponsors", &sponsor_leaves),
            challenge_root: merkle_root("ZK-DEFI-LIQUIDATION:challenges", &challenge_leaves),
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            market_count: self.markets.len() as u64,
            position_count: self.positions.len() as u64,
            liquidatable_position_count: self
                .positions
                .values()
                .filter(|position| position.liquidatable(&self.config))
                .count() as u64,
            auction_count: self.auctions.len() as u64,
            collecting_auction_count: self
                .auctions
                .values()
                .filter(|auction| matches!(auction.status, AuctionStatus::Collecting))
                .count() as u64,
            ready_auction_count: self
                .auctions
                .values()
                .filter(|auction| matches!(auction.status, AuctionStatus::ReadyToSettle))
                .count() as u64,
            bid_count: self.bids.len() as u64,
            proof_count: self.proofs.len() as u64,
            verified_proof_count: self
                .proofs
                .values()
                .filter(|proof| matches!(proof.status, ProofStatus::Verified))
                .count() as u64,
            sponsor_receipt_count: self.sponsor_receipts.len() as u64,
            sponsored_fee_units: self
                .sponsor_receipts
                .values()
                .map(|receipt| receipt.sponsored_fee_units)
                .sum::<u64>(),
            challenged_item_count: self.challenges.len() as u64,
        }
    }

    pub fn live_auction_ids(&self) -> Vec<String> {
        self.auctions
            .values()
            .filter(|auction| {
                matches!(
                    auction.status,
                    AuctionStatus::Collecting
                        | AuctionStatus::Proving
                        | AuctionStatus::ReadyToSettle
                )
            })
            .map(|auction| auction.auction_id.clone())
            .collect()
    }

    pub fn liquidatable_position_ids(&self) -> Vec<String> {
        self.positions
            .values()
            .filter(|position| position.liquidatable(&self.config))
            .map(|position| position.position_id.clone())
            .collect()
    }

    pub fn state_root(&self) -> String {
        root_from_record(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "zk_defi_liquidation_privacy_circuit",
            "version": ZK_DEFI_LIQUIDATION_PRIVACY_CIRCUIT_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "markets": self.markets.values().map(LendingMarket::public_record).collect::<Vec<_>>(),
            "positions": self.positions.values().map(PrivatePosition::public_record).collect::<Vec<_>>(),
            "oracle_snapshots": self.oracle_snapshots.values().map(OracleSnapshot::public_record).collect::<Vec<_>>(),
            "auctions": self.auctions.values().map(LiquidationAuction::public_record).collect::<Vec<_>>(),
            "bids": self.bids.values().map(SealedLiquidationBid::public_record).collect::<Vec<_>>(),
            "proofs": self.proofs.values().map(PrivacyProof::public_record).collect::<Vec<_>>(),
            "sponsor_receipts": self.sponsor_receipts.values().map(SponsorReceipt::public_record).collect::<Vec<_>>(),
            "challenges": self.challenges.iter().cloned().collect::<Vec<_>>(),
            "live_auction_ids": self.live_auction_ids(),
            "liquidatable_position_ids": self.liquidatable_position_ids(),
        })
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "ZK-DEFI-LIQUIDATION:state-root",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn devnet() -> ZkDefiLiquidationPrivacyCircuitResult<State> {
    State::devnet()
}

fn zk_defi_liquidation_id(domain: &str, parts: &[&str]) -> String {
    let leaves = parts
        .iter()
        .map(|part| json!({"part": part}))
        .collect::<Vec<_>>();
    let root = merkle_root(&format!("ZK-DEFI-LIQUIDATION:{domain}:id"), &leaves);
    domain_hash(
        &format!("ZK-DEFI-LIQUIDATION:{domain}:id-final"),
        &[HashPart::Str(root.as_str())],
        16,
    )
}

fn zk_defi_liquidation_commitment(domain: &str, label: &str) -> String {
    domain_hash(
        &format!("ZK-DEFI-LIQUIDATION:{domain}:commitment"),
        &[HashPart::Str(label)],
        32,
    )
}

fn zk_defi_liquidation_string_root(domain: &str, parts: &[&str]) -> String {
    let leaves = parts
        .iter()
        .map(|part| json!({"value": part}))
        .collect::<Vec<_>>();
    merkle_root(&format!("ZK-DEFI-LIQUIDATION:{domain}"), &leaves)
}
