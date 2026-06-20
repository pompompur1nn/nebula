use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateLiquidationAuctionRouterResult<T> = Result<T, String>;

pub const PRIVATE_LIQUIDATION_AUCTION_ROUTER_PROTOCOL_VERSION: &str =
    "nebula-private-liquidation-auction-router-v1";
pub const PRIVATE_LIQUIDATION_AUCTION_ROUTER_ENCRYPTION_SCHEME: &str =
    "ml-kem-1024+shake256-private-liquidation-lot-v1";
pub const PRIVATE_LIQUIDATION_AUCTION_ROUTER_PQ_AUTH_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-128f-liquidation-authority-v1";
pub const PRIVATE_LIQUIDATION_AUCTION_ROUTER_BID_PROOF_SCHEME: &str =
    "zk-sealed-liquidation-bid-proof-v1";
pub const PRIVATE_LIQUIDATION_AUCTION_ROUTER_DISCLOSURE_SCHEME: &str =
    "zk-selective-liquidation-disclosure-v1";
pub const PRIVATE_LIQUIDATION_AUCTION_ROUTER_DEVNET_HEIGHT: u64 = 704;
pub const PRIVATE_LIQUIDATION_AUCTION_ROUTER_DEFAULT_AUCTION_TTL_BLOCKS: u64 = 36;
pub const PRIVATE_LIQUIDATION_AUCTION_ROUTER_DEFAULT_BID_TTL_BLOCKS: u64 = 18;
pub const PRIVATE_LIQUIDATION_AUCTION_ROUTER_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 96;
pub const PRIVATE_LIQUIDATION_AUCTION_ROUTER_DEFAULT_AUTH_TTL_BLOCKS: u64 = 7_200;
pub const PRIVATE_LIQUIDATION_AUCTION_ROUTER_DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 14_400;
pub const PRIVATE_LIQUIDATION_AUCTION_ROUTER_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 128;
pub const PRIVATE_LIQUIDATION_AUCTION_ROUTER_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_LIQUIDATION_AUCTION_ROUTER_DEFAULT_MAX_BID_COUNT: usize = 96;
pub const PRIVATE_LIQUIDATION_AUCTION_ROUTER_DEFAULT_MAX_FEE_UNITS: u64 = 25_000;
pub const PRIVATE_LIQUIDATION_AUCTION_ROUTER_DEFAULT_SPONSOR_BUDGET_UNITS: u64 = 350_000;
pub const PRIVATE_LIQUIDATION_AUCTION_ROUTER_MAX_BPS: u64 = 10_000;
pub const PRIVATE_LIQUIDATION_AUCTION_ROUTER_MAX_AUCTIONS: usize = 131_072;
pub const PRIVATE_LIQUIDATION_AUCTION_ROUTER_MAX_BIDS: usize = 524_288;
pub const PRIVATE_LIQUIDATION_AUCTION_ROUTER_MAX_AUTHORIZATIONS: usize = 65_536;
pub const PRIVATE_LIQUIDATION_AUCTION_ROUTER_MAX_SPONSORS: usize = 65_536;
pub const PRIVATE_LIQUIDATION_AUCTION_ROUTER_MAX_RECEIPTS: usize = 131_072;
pub const PRIVATE_LIQUIDATION_AUCTION_ROUTER_MAX_DISCLOSURES: usize = 65_536;
pub const PRIVATE_LIQUIDATION_AUCTION_ROUTER_MAX_EVENTS: usize = 131_072;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidationVenueKind {
    ConfidentialLending,
    ConfidentialPerps,
    PrivateStablecoin,
    PrivateGasFutures,
    CrossMarginVault,
    Custom(String),
}

impl LiquidationVenueKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::ConfidentialLending => "confidential_lending".to_string(),
            Self::ConfidentialPerps => "confidential_perps".to_string(),
            Self::PrivateStablecoin => "private_stablecoin".to_string(),
            Self::PrivateGasFutures => "private_gas_futures".to_string(),
            Self::CrossMarginVault => "cross_margin_vault".to_string(),
            Self::Custom(value) => value.clone(),
        }
    }

    pub fn default_priority(&self) -> u64 {
        match self {
            Self::ConfidentialPerps => 110,
            Self::PrivateStablecoin => 100,
            Self::ConfidentialLending => 92,
            Self::CrossMarginVault => 88,
            Self::PrivateGasFutures => 78,
            Self::Custom(_) => 70,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidationTriggerKind {
    HealthFactorBreach,
    MarginRatioBreach,
    OracleDeviation,
    ExpiredDebt,
    GovernanceEmergency,
    BridgeReserveRisk,
    Custom(String),
}

impl LiquidationTriggerKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::HealthFactorBreach => "health_factor_breach".to_string(),
            Self::MarginRatioBreach => "margin_ratio_breach".to_string(),
            Self::OracleDeviation => "oracle_deviation".to_string(),
            Self::ExpiredDebt => "expired_debt".to_string(),
            Self::GovernanceEmergency => "governance_emergency".to_string(),
            Self::BridgeReserveRisk => "bridge_reserve_risk".to_string(),
            Self::Custom(value) => value.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Queued,
    Open,
    Sealed,
    Clearing,
    Settled,
    Cancelled,
    Expired,
    Disputed,
}

impl AuctionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Clearing => "clearing",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Queued | Self::Open | Self::Sealed | Self::Clearing
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Submitted,
    Eligible,
    Outbid,
    Winning,
    Settled,
    Rejected,
    Expired,
}

impl BidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Eligible => "eligible",
            Self::Outbid => "outbid",
            Self::Winning => "winning",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Submitted | Self::Eligible | Self::Winning)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityStatus {
    Active,
    Suspended,
    Revoked,
    Expired,
}

impl AuthorityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorStatus {
    Active,
    Exhausted,
    Frozen,
    Expired,
}

impl SponsorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Exhausted => "exhausted",
            Self::Frozen => "frozen",
            Self::Expired => "expired",
        }
    }

    pub fn can_spend(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Posted,
    Finalized,
    Disputed,
    Reverted,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Reverted => "reverted",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterEventKind {
    AuthorityRegistered,
    AuctionQueued,
    AuctionOpened,
    BidAccepted,
    BidRejected,
    AuctionCleared,
    SettlementPosted,
    SponsorDebited,
    DisclosureIssued,
    AuctionDisputed,
}

impl RouterEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuthorityRegistered => "authority_registered",
            Self::AuctionQueued => "auction_queued",
            Self::AuctionOpened => "auction_opened",
            Self::BidAccepted => "bid_accepted",
            Self::BidRejected => "bid_rejected",
            Self::AuctionCleared => "auction_cleared",
            Self::SettlementPosted => "settlement_posted",
            Self::SponsorDebited => "sponsor_debited",
            Self::DisclosureIssued => "disclosure_issued",
            Self::AuctionDisputed => "auction_disputed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateLiquidationAuctionRouterConfig {
    pub protocol_version: String,
    pub encryption_scheme: String,
    pub pq_auth_scheme: String,
    pub bid_proof_scheme: String,
    pub disclosure_scheme: String,
    pub auction_ttl_blocks: u64,
    pub bid_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub auth_ttl_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_bid_count: usize,
    pub max_fee_units: u64,
    pub default_sponsor_budget_units: u64,
    pub max_public_leakage_bps: u64,
}

impl PrivateLiquidationAuctionRouterConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_LIQUIDATION_AUCTION_ROUTER_PROTOCOL_VERSION.to_string(),
            encryption_scheme: PRIVATE_LIQUIDATION_AUCTION_ROUTER_ENCRYPTION_SCHEME.to_string(),
            pq_auth_scheme: PRIVATE_LIQUIDATION_AUCTION_ROUTER_PQ_AUTH_SCHEME.to_string(),
            bid_proof_scheme: PRIVATE_LIQUIDATION_AUCTION_ROUTER_BID_PROOF_SCHEME.to_string(),
            disclosure_scheme: PRIVATE_LIQUIDATION_AUCTION_ROUTER_DISCLOSURE_SCHEME.to_string(),
            auction_ttl_blocks: PRIVATE_LIQUIDATION_AUCTION_ROUTER_DEFAULT_AUCTION_TTL_BLOCKS,
            bid_ttl_blocks: PRIVATE_LIQUIDATION_AUCTION_ROUTER_DEFAULT_BID_TTL_BLOCKS,
            receipt_ttl_blocks: PRIVATE_LIQUIDATION_AUCTION_ROUTER_DEFAULT_RECEIPT_TTL_BLOCKS,
            auth_ttl_blocks: PRIVATE_LIQUIDATION_AUCTION_ROUTER_DEFAULT_AUTH_TTL_BLOCKS,
            sponsor_ttl_blocks: PRIVATE_LIQUIDATION_AUCTION_ROUTER_DEFAULT_SPONSOR_TTL_BLOCKS,
            min_privacy_set_size: PRIVATE_LIQUIDATION_AUCTION_ROUTER_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: PRIVATE_LIQUIDATION_AUCTION_ROUTER_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_bid_count: PRIVATE_LIQUIDATION_AUCTION_ROUTER_DEFAULT_MAX_BID_COUNT,
            max_fee_units: PRIVATE_LIQUIDATION_AUCTION_ROUTER_DEFAULT_MAX_FEE_UNITS,
            default_sponsor_budget_units:
                PRIVATE_LIQUIDATION_AUCTION_ROUTER_DEFAULT_SPONSOR_BUDGET_UNITS,
            max_public_leakage_bps: 1_500,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_liquidation_auction_router_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "encryption_scheme": self.encryption_scheme,
            "pq_auth_scheme": self.pq_auth_scheme,
            "bid_proof_scheme": self.bid_proof_scheme,
            "disclosure_scheme": self.disclosure_scheme,
            "auction_ttl_blocks": self.auction_ttl_blocks,
            "bid_ttl_blocks": self.bid_ttl_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "auth_ttl_blocks": self.auth_ttl_blocks,
            "sponsor_ttl_blocks": self.sponsor_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_bid_count": self.max_bid_count as u64,
            "max_fee_units": self.max_fee_units,
            "default_sponsor_budget_units": self.default_sponsor_budget_units,
            "max_public_leakage_bps": self.max_public_leakage_bps,
        })
    }

    pub fn validate(&self) -> PrivateLiquidationAuctionRouterResult<()> {
        ensure_non_empty(&self.protocol_version, "protocol version")?;
        ensure_non_empty(&self.encryption_scheme, "encryption scheme")?;
        ensure_non_empty(&self.pq_auth_scheme, "pq auth scheme")?;
        ensure_non_empty(&self.bid_proof_scheme, "bid proof scheme")?;
        ensure_non_empty(&self.disclosure_scheme, "disclosure scheme")?;
        ensure_positive(self.auction_ttl_blocks, "auction ttl")?;
        ensure_positive(self.bid_ttl_blocks, "bid ttl")?;
        ensure_positive(self.receipt_ttl_blocks, "receipt ttl")?;
        ensure_positive(self.auth_ttl_blocks, "auth ttl")?;
        ensure_positive(self.sponsor_ttl_blocks, "sponsor ttl")?;
        ensure_positive(self.min_privacy_set_size, "min privacy set")?;
        ensure_positive(self.min_pq_security_bits as u64, "min pq security bits")?;
        ensure_positive(self.max_bid_count as u64, "max bid count")?;
        ensure_positive(self.max_fee_units, "max fee units")?;
        ensure_positive(self.default_sponsor_budget_units, "default sponsor budget")?;
        ensure_bps(self.max_public_leakage_bps, "max public leakage bps")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqLiquidationAuthority {
    pub authority_id: String,
    pub venue: LiquidationVenueKind,
    pub authority_commitment: String,
    pub pq_public_key_commitment: String,
    pub scope_root: String,
    pub signature_root: String,
    pub status: AuthorityStatus,
    pub quorum_weight_bps: u64,
    pub min_privacy_set_size: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl PqLiquidationAuthority {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        venue: LiquidationVenueKind,
        authority_commitment: &str,
        pq_public_key_commitment: &str,
        scope: &Value,
        signature: &Value,
        quorum_weight_bps: u64,
        min_privacy_set_size: u64,
        issued_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateLiquidationAuctionRouterResult<Self> {
        ensure_non_empty(authority_commitment, "authority commitment")?;
        ensure_non_empty(pq_public_key_commitment, "pq public key commitment")?;
        ensure_bps(quorum_weight_bps, "quorum weight")?;
        ensure_positive(min_privacy_set_size, "min privacy set size")?;
        validate_height_window(issued_at_height, expires_at_height, "authority")?;
        let scope_root = private_liquidation_auction_payload_root("AUTHORITY-SCOPE", scope);
        let signature_root =
            private_liquidation_auction_payload_root("AUTHORITY-SIGNATURE", signature);
        let authority_id = pq_liquidation_authority_id(
            &venue,
            authority_commitment,
            pq_public_key_commitment,
            &scope_root,
            issued_at_height,
        );
        let authority = Self {
            authority_id,
            venue,
            authority_commitment: authority_commitment.to_string(),
            pq_public_key_commitment: pq_public_key_commitment.to_string(),
            scope_root,
            signature_root,
            status: AuthorityStatus::Active,
            quorum_weight_bps,
            min_privacy_set_size,
            issued_at_height,
            expires_at_height,
        };
        authority.validate()?;
        Ok(authority)
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.expires_at_height && self.status.usable() {
            self.status = AuthorityStatus::Expired;
        }
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.usable() && self.issued_at_height <= height && height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_liquidation_authority",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_LIQUIDATION_AUCTION_ROUTER_PROTOCOL_VERSION,
            "authority_id": self.authority_id,
            "venue": self.venue.as_str(),
            "authority_commitment": self.authority_commitment,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "scope_root": self.scope_root,
            "signature_root": self.signature_root,
            "status": self.status.as_str(),
            "quorum_weight_bps": self.quorum_weight_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        private_liquidation_auction_payload_root("PQ-LIQUIDATION-AUTHORITY", &self.public_record())
    }

    pub fn validate(&self) -> PrivateLiquidationAuctionRouterResult<()> {
        ensure_non_empty(&self.authority_id, "authority id")?;
        ensure_non_empty(&self.authority_commitment, "authority commitment")?;
        ensure_non_empty(&self.pq_public_key_commitment, "pq public key commitment")?;
        ensure_non_empty(&self.scope_root, "scope root")?;
        ensure_non_empty(&self.signature_root, "signature root")?;
        ensure_bps(self.quorum_weight_bps, "quorum weight")?;
        ensure_positive(self.min_privacy_set_size, "min privacy set size")?;
        validate_height_window(self.issued_at_height, self.expires_at_height, "authority")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedLiquidationLot {
    pub auction_id: String,
    pub venue: LiquidationVenueKind,
    pub trigger: LiquidationTriggerKind,
    pub authority_id: String,
    pub borrower_commitment: String,
    pub collateral_asset_commitment: String,
    pub debt_asset_commitment: String,
    pub encrypted_terms_root: String,
    pub risk_evidence_root: String,
    pub oracle_snapshot_root: String,
    pub privacy_nullifier: String,
    pub status: AuctionStatus,
    pub min_recovery_units: u64,
    pub max_discount_bps: u64,
    pub max_fee_units: u64,
    pub privacy_set_size: u64,
    pub priority_weight: u64,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
    pub sponsor_id: Option<String>,
}

impl EncryptedLiquidationLot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        venue: LiquidationVenueKind,
        trigger: LiquidationTriggerKind,
        authority_id: &str,
        borrower_commitment: &str,
        collateral_asset_commitment: &str,
        debt_asset_commitment: &str,
        encrypted_terms: &Value,
        risk_evidence: &Value,
        oracle_snapshot: &Value,
        min_recovery_units: u64,
        max_discount_bps: u64,
        max_fee_units: u64,
        privacy_set_size: u64,
        opened_at_height: u64,
        closes_at_height: u64,
        sponsor_id: Option<String>,
    ) -> PrivateLiquidationAuctionRouterResult<Self> {
        ensure_non_empty(authority_id, "authority id")?;
        ensure_non_empty(borrower_commitment, "borrower commitment")?;
        ensure_non_empty(collateral_asset_commitment, "collateral asset commitment")?;
        ensure_non_empty(debt_asset_commitment, "debt asset commitment")?;
        ensure_positive(min_recovery_units, "min recovery units")?;
        ensure_bps(max_discount_bps, "max discount bps")?;
        ensure_positive(max_fee_units, "max fee units")?;
        ensure_positive(privacy_set_size, "privacy set size")?;
        validate_height_window(opened_at_height, closes_at_height, "auction")?;
        let encrypted_terms_root =
            private_liquidation_auction_payload_root("ENCRYPTED-TERMS", encrypted_terms);
        let risk_evidence_root =
            private_liquidation_auction_payload_root("RISK-EVIDENCE", risk_evidence);
        let oracle_snapshot_root =
            private_liquidation_auction_payload_root("ORACLE-SNAPSHOT", oracle_snapshot);
        let privacy_nullifier = liquidation_lot_privacy_nullifier(
            borrower_commitment,
            collateral_asset_commitment,
            debt_asset_commitment,
            &risk_evidence_root,
            opened_at_height,
        );
        let auction_id = encrypted_liquidation_lot_id(
            &venue,
            &trigger,
            authority_id,
            borrower_commitment,
            &encrypted_terms_root,
            &privacy_nullifier,
        );
        let priority_weight = venue.default_priority().saturating_add(
            if matches!(trigger, LiquidationTriggerKind::GovernanceEmergency) {
                25
            } else {
                0
            },
        );
        let lot = Self {
            auction_id,
            venue,
            trigger,
            authority_id: authority_id.to_string(),
            borrower_commitment: borrower_commitment.to_string(),
            collateral_asset_commitment: collateral_asset_commitment.to_string(),
            debt_asset_commitment: debt_asset_commitment.to_string(),
            encrypted_terms_root,
            risk_evidence_root,
            oracle_snapshot_root,
            privacy_nullifier,
            status: AuctionStatus::Open,
            min_recovery_units,
            max_discount_bps,
            max_fee_units,
            privacy_set_size,
            priority_weight,
            opened_at_height,
            closes_at_height,
            sponsor_id,
        };
        lot.validate()?;
        Ok(lot)
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.closes_at_height && self.status.live() {
            self.status = AuctionStatus::Expired;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_liquidation_lot",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_LIQUIDATION_AUCTION_ROUTER_PROTOCOL_VERSION,
            "auction_id": self.auction_id,
            "venue": self.venue.as_str(),
            "trigger": self.trigger.as_str(),
            "authority_id": self.authority_id,
            "borrower_commitment": self.borrower_commitment,
            "collateral_asset_commitment": self.collateral_asset_commitment,
            "debt_asset_commitment": self.debt_asset_commitment,
            "encrypted_terms_root": self.encrypted_terms_root,
            "risk_evidence_root": self.risk_evidence_root,
            "oracle_snapshot_root": self.oracle_snapshot_root,
            "privacy_nullifier": self.privacy_nullifier,
            "status": self.status.as_str(),
            "min_recovery_units": self.min_recovery_units,
            "max_discount_bps": self.max_discount_bps,
            "max_fee_units": self.max_fee_units,
            "privacy_set_size": self.privacy_set_size,
            "priority_weight": self.priority_weight,
            "opened_at_height": self.opened_at_height,
            "closes_at_height": self.closes_at_height,
            "sponsor_id": self.sponsor_id,
        })
    }

    pub fn state_root(&self) -> String {
        private_liquidation_auction_payload_root("ENCRYPTED-LIQUIDATION-LOT", &self.public_record())
    }

    pub fn validate(&self) -> PrivateLiquidationAuctionRouterResult<()> {
        ensure_non_empty(&self.auction_id, "auction id")?;
        ensure_non_empty(&self.authority_id, "authority id")?;
        ensure_non_empty(&self.borrower_commitment, "borrower commitment")?;
        ensure_non_empty(
            &self.collateral_asset_commitment,
            "collateral asset commitment",
        )?;
        ensure_non_empty(&self.debt_asset_commitment, "debt asset commitment")?;
        ensure_non_empty(&self.encrypted_terms_root, "encrypted terms root")?;
        ensure_non_empty(&self.risk_evidence_root, "risk evidence root")?;
        ensure_non_empty(&self.oracle_snapshot_root, "oracle snapshot root")?;
        ensure_non_empty(&self.privacy_nullifier, "privacy nullifier")?;
        ensure_positive(self.min_recovery_units, "min recovery units")?;
        ensure_bps(self.max_discount_bps, "max discount bps")?;
        ensure_positive(self.max_fee_units, "max fee units")?;
        ensure_positive(self.privacy_set_size, "privacy set size")?;
        ensure_positive(self.priority_weight, "priority weight")?;
        validate_height_window(self.opened_at_height, self.closes_at_height, "auction")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedLiquidationBid {
    pub bid_id: String,
    pub auction_id: String,
    pub bidder_commitment: String,
    pub solver_commitment: String,
    pub bid_ciphertext_root: String,
    pub bid_commitment_root: String,
    pub bid_proof_root: String,
    pub status: BidStatus,
    pub recovery_units: u64,
    pub discount_bps: u64,
    pub fee_units: u64,
    pub privacy_set_size: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl SealedLiquidationBid {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction_id: &str,
        bidder_commitment: &str,
        solver_commitment: &str,
        bid_ciphertext: &Value,
        bid_commitment: &Value,
        bid_proof: &Value,
        recovery_units: u64,
        discount_bps: u64,
        fee_units: u64,
        privacy_set_size: u64,
        submitted_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateLiquidationAuctionRouterResult<Self> {
        ensure_non_empty(auction_id, "auction id")?;
        ensure_non_empty(bidder_commitment, "bidder commitment")?;
        ensure_non_empty(solver_commitment, "solver commitment")?;
        ensure_positive(recovery_units, "recovery units")?;
        ensure_bps(discount_bps, "discount bps")?;
        ensure_positive(fee_units, "fee units")?;
        ensure_positive(privacy_set_size, "privacy set size")?;
        validate_height_window(submitted_at_height, expires_at_height, "bid")?;
        let bid_ciphertext_root =
            private_liquidation_auction_payload_root("BID-CIPHERTEXT", bid_ciphertext);
        let bid_commitment_root =
            private_liquidation_auction_payload_root("BID-COMMITMENT", bid_commitment);
        let bid_proof_root = private_liquidation_auction_payload_root("BID-PROOF", bid_proof);
        let bid_id = sealed_liquidation_bid_id(
            auction_id,
            bidder_commitment,
            solver_commitment,
            &bid_commitment_root,
            submitted_at_height,
        );
        let bid = Self {
            bid_id,
            auction_id: auction_id.to_string(),
            bidder_commitment: bidder_commitment.to_string(),
            solver_commitment: solver_commitment.to_string(),
            bid_ciphertext_root,
            bid_commitment_root,
            bid_proof_root,
            status: BidStatus::Submitted,
            recovery_units,
            discount_bps,
            fee_units,
            privacy_set_size,
            submitted_at_height,
            expires_at_height,
        };
        bid.validate()?;
        Ok(bid)
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.expires_at_height && self.status.active() {
            self.status = BidStatus::Expired;
        }
    }

    pub fn score(&self) -> u64 {
        self.recovery_units
            .saturating_sub(
                self.recovery_units.saturating_mul(self.discount_bps)
                    / PRIVATE_LIQUIDATION_AUCTION_ROUTER_MAX_BPS,
            )
            .saturating_sub(self.fee_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sealed_liquidation_bid",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_LIQUIDATION_AUCTION_ROUTER_PROTOCOL_VERSION,
            "bid_id": self.bid_id,
            "auction_id": self.auction_id,
            "bidder_commitment": self.bidder_commitment,
            "solver_commitment": self.solver_commitment,
            "bid_ciphertext_root": self.bid_ciphertext_root,
            "bid_commitment_root": self.bid_commitment_root,
            "bid_proof_root": self.bid_proof_root,
            "status": self.status.as_str(),
            "recovery_units": self.recovery_units,
            "discount_bps": self.discount_bps,
            "fee_units": self.fee_units,
            "privacy_set_size": self.privacy_set_size,
            "score": self.score(),
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        private_liquidation_auction_payload_root("SEALED-LIQUIDATION-BID", &self.public_record())
    }

    pub fn validate(&self) -> PrivateLiquidationAuctionRouterResult<()> {
        ensure_non_empty(&self.bid_id, "bid id")?;
        ensure_non_empty(&self.auction_id, "auction id")?;
        ensure_non_empty(&self.bidder_commitment, "bidder commitment")?;
        ensure_non_empty(&self.solver_commitment, "solver commitment")?;
        ensure_non_empty(&self.bid_ciphertext_root, "bid ciphertext root")?;
        ensure_non_empty(&self.bid_commitment_root, "bid commitment root")?;
        ensure_non_empty(&self.bid_proof_root, "bid proof root")?;
        ensure_positive(self.recovery_units, "recovery units")?;
        ensure_bps(self.discount_bps, "discount bps")?;
        ensure_positive(self.fee_units, "fee units")?;
        ensure_positive(self.privacy_set_size, "privacy set size")?;
        validate_height_window(self.submitted_at_height, self.expires_at_height, "bid")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidationSponsorPool {
    pub sponsor_id: String,
    pub sponsor_commitment: String,
    pub venue_allowlist_root: String,
    pub fee_asset_id: String,
    pub budget_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub max_fee_units_per_auction: u64,
    pub status: SponsorStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub policy_root: String,
}

impl LiquidationSponsorPool {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_commitment: &str,
        venue_allowlist: &[String],
        fee_asset_id: &str,
        budget_units: u64,
        max_fee_units_per_auction: u64,
        opened_at_height: u64,
        expires_at_height: u64,
        policy: &Value,
    ) -> PrivateLiquidationAuctionRouterResult<Self> {
        ensure_non_empty(sponsor_commitment, "sponsor commitment")?;
        ensure_string_set(venue_allowlist, "venue allowlist")?;
        ensure_non_empty(fee_asset_id, "fee asset id")?;
        ensure_positive(budget_units, "budget units")?;
        ensure_positive(max_fee_units_per_auction, "max fee units per auction")?;
        validate_height_window(opened_at_height, expires_at_height, "sponsor")?;
        let venue_allowlist_root =
            private_liquidation_auction_string_set_root("SPONSOR-VENUE-ALLOWLIST", venue_allowlist);
        let policy_root = private_liquidation_auction_payload_root("SPONSOR-POLICY", policy);
        let sponsor_id = liquidation_sponsor_pool_id(
            sponsor_commitment,
            &venue_allowlist_root,
            fee_asset_id,
            &policy_root,
        );
        let pool = Self {
            sponsor_id,
            sponsor_commitment: sponsor_commitment.to_string(),
            venue_allowlist_root,
            fee_asset_id: fee_asset_id.to_string(),
            budget_units,
            reserved_units: 0,
            spent_units: 0,
            max_fee_units_per_auction,
            status: SponsorStatus::Active,
            opened_at_height,
            expires_at_height,
            policy_root,
        };
        pool.validate()?;
        Ok(pool)
    }

    pub fn available_units(&self) -> u64 {
        self.budget_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
    }

    pub fn can_pay(&self, fee_units: u64, height: u64) -> bool {
        self.status.can_spend()
            && self.opened_at_height <= height
            && height < self.expires_at_height
            && fee_units <= self.max_fee_units_per_auction
            && fee_units <= self.available_units()
    }

    pub fn reserve(
        &mut self,
        fee_units: u64,
        height: u64,
    ) -> PrivateLiquidationAuctionRouterResult<()> {
        if !self.can_pay(fee_units, height) {
            return Err("liquidation sponsor cannot cover fee".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_add(fee_units);
        Ok(())
    }

    pub fn settle(&mut self, fee_units: u64) -> PrivateLiquidationAuctionRouterResult<()> {
        if fee_units > self.reserved_units {
            return Err("liquidation sponsor settlement exceeds reserved units".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_sub(fee_units);
        self.spent_units = self.spent_units.saturating_add(fee_units);
        if self.available_units() == 0 {
            self.status = SponsorStatus::Exhausted;
        }
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.expires_at_height {
            self.status = SponsorStatus::Expired;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "liquidation_sponsor_pool",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_LIQUIDATION_AUCTION_ROUTER_PROTOCOL_VERSION,
            "sponsor_id": self.sponsor_id,
            "sponsor_commitment": self.sponsor_commitment,
            "venue_allowlist_root": self.venue_allowlist_root,
            "fee_asset_id": self.fee_asset_id,
            "budget_units": self.budget_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "available_units": self.available_units(),
            "max_fee_units_per_auction": self.max_fee_units_per_auction,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "policy_root": self.policy_root,
        })
    }

    pub fn state_root(&self) -> String {
        private_liquidation_auction_payload_root("LIQUIDATION-SPONSOR-POOL", &self.public_record())
    }

    pub fn validate(&self) -> PrivateLiquidationAuctionRouterResult<()> {
        ensure_non_empty(&self.sponsor_id, "sponsor id")?;
        ensure_non_empty(&self.sponsor_commitment, "sponsor commitment")?;
        ensure_non_empty(&self.venue_allowlist_root, "venue allowlist root")?;
        ensure_non_empty(&self.fee_asset_id, "fee asset id")?;
        ensure_positive(self.budget_units, "budget units")?;
        ensure_positive(self.max_fee_units_per_auction, "max fee units per auction")?;
        validate_height_window(self.opened_at_height, self.expires_at_height, "sponsor")?;
        if self.reserved_units.saturating_add(self.spent_units) > self.budget_units {
            return Err("liquidation sponsor accounting exceeds budget".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidationSettlementReceipt {
    pub receipt_id: String,
    pub auction_id: String,
    pub winning_bid_id: String,
    pub settlement_status: SettlementStatus,
    pub recovered_units: u64,
    pub fee_units: u64,
    pub surplus_commitment_root: String,
    pub state_transition_root: String,
    pub fee_debit_root: String,
    pub settled_at_height: u64,
    pub finalizes_at_height: u64,
}

impl LiquidationSettlementReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction_id: &str,
        winning_bid_id: &str,
        recovered_units: u64,
        fee_units: u64,
        surplus_commitment: &Value,
        state_transition: &Value,
        fee_debit: &Value,
        settled_at_height: u64,
        finalizes_at_height: u64,
    ) -> PrivateLiquidationAuctionRouterResult<Self> {
        ensure_non_empty(auction_id, "auction id")?;
        ensure_non_empty(winning_bid_id, "winning bid id")?;
        ensure_positive(recovered_units, "recovered units")?;
        ensure_positive(fee_units, "fee units")?;
        validate_height_window(settled_at_height, finalizes_at_height, "settlement")?;
        let surplus_commitment_root =
            private_liquidation_auction_payload_root("SURPLUS-COMMITMENT", surplus_commitment);
        let state_transition_root =
            private_liquidation_auction_payload_root("STATE-TRANSITION", state_transition);
        let fee_debit_root = private_liquidation_auction_payload_root("FEE-DEBIT", fee_debit);
        let receipt_id = liquidation_settlement_receipt_id(
            auction_id,
            winning_bid_id,
            &state_transition_root,
            settled_at_height,
        );
        let receipt = Self {
            receipt_id,
            auction_id: auction_id.to_string(),
            winning_bid_id: winning_bid_id.to_string(),
            settlement_status: SettlementStatus::Posted,
            recovered_units,
            fee_units,
            surplus_commitment_root,
            state_transition_root,
            fee_debit_root,
            settled_at_height,
            finalizes_at_height,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.finalizes_at_height && self.settlement_status == SettlementStatus::Posted
        {
            self.settlement_status = SettlementStatus::Finalized;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "liquidation_settlement_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_LIQUIDATION_AUCTION_ROUTER_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "auction_id": self.auction_id,
            "winning_bid_id": self.winning_bid_id,
            "settlement_status": self.settlement_status.as_str(),
            "recovered_units": self.recovered_units,
            "fee_units": self.fee_units,
            "surplus_commitment_root": self.surplus_commitment_root,
            "state_transition_root": self.state_transition_root,
            "fee_debit_root": self.fee_debit_root,
            "settled_at_height": self.settled_at_height,
            "finalizes_at_height": self.finalizes_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        private_liquidation_auction_payload_root(
            "LIQUIDATION-SETTLEMENT-RECEIPT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateLiquidationAuctionRouterResult<()> {
        ensure_non_empty(&self.receipt_id, "receipt id")?;
        ensure_non_empty(&self.auction_id, "auction id")?;
        ensure_non_empty(&self.winning_bid_id, "winning bid id")?;
        ensure_positive(self.recovered_units, "recovered units")?;
        ensure_positive(self.fee_units, "fee units")?;
        ensure_non_empty(&self.surplus_commitment_root, "surplus commitment root")?;
        ensure_non_empty(&self.state_transition_root, "state transition root")?;
        ensure_non_empty(&self.fee_debit_root, "fee debit root")?;
        validate_height_window(
            self.settled_at_height,
            self.finalizes_at_height,
            "settlement",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidationDisclosureReceipt {
    pub disclosure_id: String,
    pub auction_id: String,
    pub requester_commitment: String,
    pub scope_root: String,
    pub proof_root: String,
    pub max_disclosure_bps: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl LiquidationDisclosureReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction_id: &str,
        requester_commitment: &str,
        scope: &Value,
        proof: &Value,
        max_disclosure_bps: u64,
        issued_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateLiquidationAuctionRouterResult<Self> {
        ensure_non_empty(auction_id, "auction id")?;
        ensure_non_empty(requester_commitment, "requester commitment")?;
        ensure_bps(max_disclosure_bps, "max disclosure bps")?;
        validate_height_window(issued_at_height, expires_at_height, "disclosure")?;
        let scope_root = private_liquidation_auction_payload_root("DISCLOSURE-SCOPE", scope);
        let proof_root = private_liquidation_auction_payload_root("DISCLOSURE-PROOF", proof);
        let disclosure_id = liquidation_disclosure_receipt_id(
            auction_id,
            requester_commitment,
            &scope_root,
            &proof_root,
            issued_at_height,
        );
        let disclosure = Self {
            disclosure_id,
            auction_id: auction_id.to_string(),
            requester_commitment: requester_commitment.to_string(),
            scope_root,
            proof_root,
            max_disclosure_bps,
            issued_at_height,
            expires_at_height,
        };
        disclosure.validate()?;
        Ok(disclosure)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "liquidation_disclosure_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_LIQUIDATION_AUCTION_ROUTER_PROTOCOL_VERSION,
            "disclosure_id": self.disclosure_id,
            "auction_id": self.auction_id,
            "requester_commitment": self.requester_commitment,
            "scope_root": self.scope_root,
            "proof_root": self.proof_root,
            "max_disclosure_bps": self.max_disclosure_bps,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        private_liquidation_auction_payload_root(
            "LIQUIDATION-DISCLOSURE-RECEIPT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateLiquidationAuctionRouterResult<()> {
        ensure_non_empty(&self.disclosure_id, "disclosure id")?;
        ensure_non_empty(&self.auction_id, "auction id")?;
        ensure_non_empty(&self.requester_commitment, "requester commitment")?;
        ensure_non_empty(&self.scope_root, "scope root")?;
        ensure_non_empty(&self.proof_root, "proof root")?;
        ensure_bps(self.max_disclosure_bps, "max disclosure bps")?;
        validate_height_window(self.issued_at_height, self.expires_at_height, "disclosure")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidationRouterEvent {
    pub event_id: String,
    pub event_kind: RouterEventKind,
    pub subject_id: String,
    pub emitted_at_height: u64,
    pub payload_root: String,
}

impl LiquidationRouterEvent {
    pub fn new(
        event_kind: RouterEventKind,
        subject_id: &str,
        emitted_at_height: u64,
        payload: &Value,
    ) -> PrivateLiquidationAuctionRouterResult<Self> {
        ensure_non_empty(subject_id, "event subject")?;
        let payload_root = private_liquidation_auction_payload_root("EVENT-PAYLOAD", payload);
        let event_id =
            liquidation_router_event_id(event_kind, subject_id, emitted_at_height, &payload_root);
        let event = Self {
            event_id,
            event_kind,
            subject_id: subject_id.to_string(),
            emitted_at_height,
            payload_root,
        };
        event.validate()?;
        Ok(event)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "liquidation_router_event",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_LIQUIDATION_AUCTION_ROUTER_PROTOCOL_VERSION,
            "event_id": self.event_id,
            "event_kind": self.event_kind.as_str(),
            "subject_id": self.subject_id,
            "emitted_at_height": self.emitted_at_height,
            "payload_root": self.payload_root,
        })
    }

    pub fn validate(&self) -> PrivateLiquidationAuctionRouterResult<()> {
        ensure_non_empty(&self.event_id, "event id")?;
        ensure_non_empty(&self.subject_id, "event subject")?;
        ensure_non_empty(&self.payload_root, "event payload root")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateLiquidationAuctionRouterRoots {
    pub authority_root: String,
    pub auction_root: String,
    pub bid_root: String,
    pub sponsor_root: String,
    pub settlement_root: String,
    pub disclosure_root: String,
    pub event_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

impl PrivateLiquidationAuctionRouterRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_liquidation_auction_router_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_LIQUIDATION_AUCTION_ROUTER_PROTOCOL_VERSION,
            "authority_root": self.authority_root,
            "auction_root": self.auction_root,
            "bid_root": self.bid_root,
            "sponsor_root": self.sponsor_root,
            "settlement_root": self.settlement_root,
            "disclosure_root": self.disclosure_root,
            "event_root": self.event_root,
            "nullifier_root": self.nullifier_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateLiquidationAuctionRouterCounters {
    pub height: u64,
    pub authority_count: u64,
    pub active_authority_count: u64,
    pub auction_count: u64,
    pub live_auction_count: u64,
    pub bid_count: u64,
    pub active_bid_count: u64,
    pub sponsor_count: u64,
    pub active_sponsor_count: u64,
    pub settlement_count: u64,
    pub finalized_settlement_count: u64,
    pub disclosure_count: u64,
    pub event_count: u64,
    pub total_available_sponsor_units: u64,
    pub total_recovered_units: u64,
}

impl PrivateLiquidationAuctionRouterCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_liquidation_auction_router_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_LIQUIDATION_AUCTION_ROUTER_PROTOCOL_VERSION,
            "height": self.height,
            "authority_count": self.authority_count,
            "active_authority_count": self.active_authority_count,
            "auction_count": self.auction_count,
            "live_auction_count": self.live_auction_count,
            "bid_count": self.bid_count,
            "active_bid_count": self.active_bid_count,
            "sponsor_count": self.sponsor_count,
            "active_sponsor_count": self.active_sponsor_count,
            "settlement_count": self.settlement_count,
            "finalized_settlement_count": self.finalized_settlement_count,
            "disclosure_count": self.disclosure_count,
            "event_count": self.event_count,
            "total_available_sponsor_units": self.total_available_sponsor_units,
            "total_recovered_units": self.total_recovered_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateLiquidationAuctionRouterState {
    pub config: PrivateLiquidationAuctionRouterConfig,
    pub height: u64,
    pub authorities: BTreeMap<String, PqLiquidationAuthority>,
    pub auctions: BTreeMap<String, EncryptedLiquidationLot>,
    pub bids: BTreeMap<String, SealedLiquidationBid>,
    pub sponsors: BTreeMap<String, LiquidationSponsorPool>,
    pub settlements: BTreeMap<String, LiquidationSettlementReceipt>,
    pub disclosures: BTreeMap<String, LiquidationDisclosureReceipt>,
    pub events: BTreeMap<String, LiquidationRouterEvent>,
    pub nullifiers: BTreeSet<String>,
}

impl PrivateLiquidationAuctionRouterState {
    pub fn new(
        config: PrivateLiquidationAuctionRouterConfig,
    ) -> PrivateLiquidationAuctionRouterResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height: PRIVATE_LIQUIDATION_AUCTION_ROUTER_DEVNET_HEIGHT,
            authorities: BTreeMap::new(),
            auctions: BTreeMap::new(),
            bids: BTreeMap::new(),
            sponsors: BTreeMap::new(),
            settlements: BTreeMap::new(),
            disclosures: BTreeMap::new(),
            events: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
        })
    }

    pub fn devnet() -> PrivateLiquidationAuctionRouterResult<Self> {
        let config = PrivateLiquidationAuctionRouterConfig::devnet();
        let mut state = Self::new(config.clone())?;
        let authority = PqLiquidationAuthority::new(
            LiquidationVenueKind::ConfidentialLending,
            &private_liquidation_auction_string_root("DEVNET-AUTHORITY", "lending-liquidator"),
            &private_liquidation_auction_string_root(
                "DEVNET-PQ-KEY",
                "ml-dsa-liquidation-authority",
            ),
            &json!({"venues": ["confidential_lending", "private_stablecoin"]}),
            &json!({"scheme": config.pq_auth_scheme, "signature": "devnet"}),
            6_700,
            config.min_privacy_set_size,
            state.height,
            state.height + config.auth_ttl_blocks,
        )?;
        let authority_id = authority.authority_id.clone();
        state.insert_authority(authority)?;
        let sponsor = LiquidationSponsorPool::new(
            &private_liquidation_auction_string_root("DEVNET-SPONSOR", "low-fee-liquidation"),
            &[
                "confidential_lending".to_string(),
                "private_stablecoin".to_string(),
            ],
            "piconero-fee-credit",
            config.default_sponsor_budget_units,
            config.max_fee_units,
            state.height,
            state.height + config.sponsor_ttl_blocks,
            &json!({"covers": ["health_factor_breach", "expired_debt"]}),
        )?;
        let sponsor_id = sponsor.sponsor_id.clone();
        state.insert_sponsor(sponsor)?;
        let auction = EncryptedLiquidationLot::new(
            LiquidationVenueKind::ConfidentialLending,
            LiquidationTriggerKind::HealthFactorBreach,
            &authority_id,
            &private_liquidation_auction_string_root("DEVNET-BORROWER", "private-borrower-alpha"),
            &private_liquidation_auction_string_root("DEVNET-COLLATERAL", "wxmr-collateral"),
            &private_liquidation_auction_string_root("DEVNET-DEBT", "private-usd-debt"),
            &json!({"ciphertext": "devnet-liquidation-terms"}),
            &json!({"health_bucket": "liquidatable"}),
            &json!({"xmr_usd": "private-oracle-bucket"}),
            250_000,
            850,
            9_000,
            192,
            state.height,
            state.height + config.auction_ttl_blocks,
            Some(sponsor_id),
        )?;
        let auction_id = auction.auction_id.clone();
        state.insert_auction(auction)?;
        state.insert_bid(SealedLiquidationBid::new(
            &auction_id,
            &private_liquidation_auction_string_root("DEVNET-BIDDER", "solver-alpha"),
            &private_liquidation_auction_string_root("DEVNET-SOLVER", "solver-alpha"),
            &json!({"sealed_bid": "ciphertext"}),
            &json!({"recovery_units": 260000, "discount_bps": 400}),
            &json!({"proof": config.bid_proof_scheme}),
            260_000,
            400,
            6_000,
            192,
            state.height,
            state.height + config.bid_ttl_blocks,
        )?)?;
        state.insert_event(LiquidationRouterEvent::new(
            RouterEventKind::AuctionQueued,
            &auction_id,
            state.height,
            &json!({"auction_id": auction_id}),
        )?)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivateLiquidationAuctionRouterResult<()> {
        if height < self.height {
            return Err("private liquidation router height cannot go backwards".to_string());
        }
        self.height = height;
        for authority in self.authorities.values_mut() {
            authority.set_height(height);
        }
        for auction in self.auctions.values_mut() {
            auction.set_height(height);
        }
        for bid in self.bids.values_mut() {
            bid.set_height(height);
        }
        for sponsor in self.sponsors.values_mut() {
            sponsor.set_height(height);
        }
        for settlement in self.settlements.values_mut() {
            settlement.set_height(height);
        }
        self.validate()
    }

    pub fn insert_authority(
        &mut self,
        authority: PqLiquidationAuthority,
    ) -> PrivateLiquidationAuctionRouterResult<()> {
        authority.validate()?;
        insert_unique(
            &mut self.authorities,
            authority.authority_id.clone(),
            authority,
            "authority",
        )
    }

    pub fn insert_auction(
        &mut self,
        auction: EncryptedLiquidationLot,
    ) -> PrivateLiquidationAuctionRouterResult<()> {
        let authority = self
            .authorities
            .get(&auction.authority_id)
            .ok_or_else(|| "auction references unknown authority".to_string())?;
        if !authority.active_at(self.height) {
            return Err("auction authority is not active".to_string());
        }
        if auction.privacy_set_size < self.config.min_privacy_set_size {
            return Err("auction privacy set below config floor".to_string());
        }
        if auction.max_fee_units > self.config.max_fee_units {
            return Err("auction fee exceeds config limit".to_string());
        }
        if self.nullifiers.contains(&auction.privacy_nullifier) {
            return Err("auction privacy nullifier already used".to_string());
        }
        if let Some(sponsor_id) = &auction.sponsor_id {
            let sponsor = self
                .sponsors
                .get_mut(sponsor_id)
                .ok_or_else(|| "auction references unknown sponsor".to_string())?;
            sponsor.reserve(auction.max_fee_units, self.height)?;
        }
        auction.validate()?;
        self.nullifiers.insert(auction.privacy_nullifier.clone());
        insert_unique(
            &mut self.auctions,
            auction.auction_id.clone(),
            auction,
            "auction",
        )
    }

    pub fn insert_bid(
        &mut self,
        bid: SealedLiquidationBid,
    ) -> PrivateLiquidationAuctionRouterResult<()> {
        let auction = self
            .auctions
            .get(&bid.auction_id)
            .ok_or_else(|| "bid references unknown auction".to_string())?;
        if !matches!(auction.status, AuctionStatus::Open | AuctionStatus::Sealed) {
            return Err("auction is not accepting bids".to_string());
        }
        if bid.recovery_units < auction.min_recovery_units {
            return Err("bid recovery below auction floor".to_string());
        }
        if bid.discount_bps > auction.max_discount_bps {
            return Err("bid discount exceeds auction max".to_string());
        }
        if bid.fee_units > auction.max_fee_units {
            return Err("bid fee exceeds auction max".to_string());
        }
        if bid.privacy_set_size < self.config.min_privacy_set_size {
            return Err("bid privacy set below config floor".to_string());
        }
        if self
            .bids
            .values()
            .filter(|existing| existing.auction_id == bid.auction_id)
            .count()
            >= self.config.max_bid_count
        {
            return Err("auction bid capacity exceeded".to_string());
        }
        bid.validate()?;
        insert_unique(&mut self.bids, bid.bid_id.clone(), bid, "bid")
    }

    pub fn insert_sponsor(
        &mut self,
        sponsor: LiquidationSponsorPool,
    ) -> PrivateLiquidationAuctionRouterResult<()> {
        sponsor.validate()?;
        insert_unique(
            &mut self.sponsors,
            sponsor.sponsor_id.clone(),
            sponsor,
            "sponsor",
        )
    }

    pub fn settle_auction(
        &mut self,
        auction_id: &str,
        winning_bid_id: &str,
        settlement: LiquidationSettlementReceipt,
    ) -> PrivateLiquidationAuctionRouterResult<()> {
        require_map_key("settlement auction", auction_id, &self.auctions)?;
        require_map_key("settlement bid", winning_bid_id, &self.bids)?;
        if settlement.auction_id != auction_id || settlement.winning_bid_id != winning_bid_id {
            return Err("settlement does not match selected auction and bid".to_string());
        }
        if let Some(auction) = self.auctions.get_mut(auction_id) {
            auction.status = AuctionStatus::Settled;
            if let Some(sponsor_id) = &auction.sponsor_id {
                if let Some(sponsor) = self.sponsors.get_mut(sponsor_id) {
                    sponsor.settle(auction.max_fee_units)?;
                }
            }
        }
        if let Some(bid) = self.bids.get_mut(winning_bid_id) {
            bid.status = BidStatus::Settled;
        }
        settlement.validate()?;
        insert_unique(
            &mut self.settlements,
            settlement.receipt_id.clone(),
            settlement,
            "settlement",
        )
    }

    pub fn insert_disclosure(
        &mut self,
        disclosure: LiquidationDisclosureReceipt,
    ) -> PrivateLiquidationAuctionRouterResult<()> {
        require_map_key("disclosure", &disclosure.auction_id, &self.auctions)?;
        disclosure.validate()?;
        insert_unique(
            &mut self.disclosures,
            disclosure.disclosure_id.clone(),
            disclosure,
            "disclosure",
        )
    }

    pub fn insert_event(
        &mut self,
        event: LiquidationRouterEvent,
    ) -> PrivateLiquidationAuctionRouterResult<()> {
        event.validate()?;
        insert_unique(&mut self.events, event.event_id.clone(), event, "event")
    }

    pub fn live_auction_ids(&self) -> Vec<String> {
        self.auctions
            .values()
            .filter(|auction| auction.status.live())
            .map(|auction| auction.auction_id.clone())
            .collect()
    }

    pub fn active_bid_ids(&self) -> Vec<String> {
        self.bids
            .values()
            .filter(|bid| bid.status.active())
            .map(|bid| bid.bid_id.clone())
            .collect()
    }

    pub fn best_bid_for_auction(&self, auction_id: &str) -> Option<&SealedLiquidationBid> {
        self.bids
            .values()
            .filter(|bid| bid.auction_id == auction_id && bid.status.active())
            .max_by_key(|bid| bid.score())
    }

    pub fn total_available_sponsor_units(&self) -> u64 {
        self.sponsors
            .values()
            .map(LiquidationSponsorPool::available_units)
            .sum()
    }

    pub fn roots(&self) -> PrivateLiquidationAuctionRouterRoots {
        let authority_root = private_liquidation_auction_record_root(
            "AUTHORITY",
            self.authorities
                .values()
                .map(PqLiquidationAuthority::public_record)
                .collect(),
        );
        let auction_root = private_liquidation_auction_record_root(
            "AUCTION",
            self.auctions
                .values()
                .map(EncryptedLiquidationLot::public_record)
                .collect(),
        );
        let bid_root = private_liquidation_auction_record_root(
            "BID",
            self.bids
                .values()
                .map(SealedLiquidationBid::public_record)
                .collect(),
        );
        let sponsor_root = private_liquidation_auction_record_root(
            "SPONSOR",
            self.sponsors
                .values()
                .map(LiquidationSponsorPool::public_record)
                .collect(),
        );
        let settlement_root = private_liquidation_auction_record_root(
            "SETTLEMENT",
            self.settlements
                .values()
                .map(LiquidationSettlementReceipt::public_record)
                .collect(),
        );
        let disclosure_root = private_liquidation_auction_record_root(
            "DISCLOSURE",
            self.disclosures
                .values()
                .map(LiquidationDisclosureReceipt::public_record)
                .collect(),
        );
        let event_root = private_liquidation_auction_record_root(
            "EVENT",
            self.events
                .values()
                .map(LiquidationRouterEvent::public_record)
                .collect(),
        );
        let nullifiers = self.nullifiers.iter().cloned().collect::<Vec<_>>();
        let nullifier_root = private_liquidation_auction_string_set_root("NULLIFIER", &nullifiers);
        let state_record = json!({
            "authority_root": authority_root,
            "auction_root": auction_root,
            "bid_root": bid_root,
            "sponsor_root": sponsor_root,
            "settlement_root": settlement_root,
            "disclosure_root": disclosure_root,
            "event_root": event_root,
            "nullifier_root": nullifier_root,
            "height": self.height,
        });
        let state_root = private_liquidation_auction_router_state_root_from_record(&state_record);
        PrivateLiquidationAuctionRouterRoots {
            authority_root,
            auction_root,
            bid_root,
            sponsor_root,
            settlement_root,
            disclosure_root,
            event_root,
            nullifier_root,
            state_root,
        }
    }

    pub fn counters(&self) -> PrivateLiquidationAuctionRouterCounters {
        PrivateLiquidationAuctionRouterCounters {
            height: self.height,
            authority_count: self.authorities.len() as u64,
            active_authority_count: self
                .authorities
                .values()
                .filter(|authority| authority.active_at(self.height))
                .count() as u64,
            auction_count: self.auctions.len() as u64,
            live_auction_count: self
                .auctions
                .values()
                .filter(|auction| auction.status.live())
                .count() as u64,
            bid_count: self.bids.len() as u64,
            active_bid_count: self.bids.values().filter(|bid| bid.status.active()).count() as u64,
            sponsor_count: self.sponsors.len() as u64,
            active_sponsor_count: self
                .sponsors
                .values()
                .filter(|sponsor| sponsor.status.can_spend())
                .count() as u64,
            settlement_count: self.settlements.len() as u64,
            finalized_settlement_count: self
                .settlements
                .values()
                .filter(|receipt| receipt.settlement_status == SettlementStatus::Finalized)
                .count() as u64,
            disclosure_count: self.disclosures.len() as u64,
            event_count: self.events.len() as u64,
            total_available_sponsor_units: self.total_available_sponsor_units(),
            total_recovered_units: self
                .settlements
                .values()
                .map(|receipt| receipt.recovered_units)
                .sum(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_liquidation_auction_router_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_LIQUIDATION_AUCTION_ROUTER_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "live_auction_ids": self.live_auction_ids(),
            "active_bid_ids": self.active_bid_ids(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn validate(&self) -> PrivateLiquidationAuctionRouterResult<()> {
        self.config.validate()?;
        if self.authorities.len() > PRIVATE_LIQUIDATION_AUCTION_ROUTER_MAX_AUTHORIZATIONS {
            return Err("liquidation authority capacity exceeded".to_string());
        }
        if self.auctions.len() > PRIVATE_LIQUIDATION_AUCTION_ROUTER_MAX_AUCTIONS {
            return Err("liquidation auction capacity exceeded".to_string());
        }
        if self.bids.len() > PRIVATE_LIQUIDATION_AUCTION_ROUTER_MAX_BIDS {
            return Err("liquidation bid capacity exceeded".to_string());
        }
        if self.sponsors.len() > PRIVATE_LIQUIDATION_AUCTION_ROUTER_MAX_SPONSORS {
            return Err("liquidation sponsor capacity exceeded".to_string());
        }
        if self.settlements.len() > PRIVATE_LIQUIDATION_AUCTION_ROUTER_MAX_RECEIPTS {
            return Err("liquidation receipt capacity exceeded".to_string());
        }
        if self.disclosures.len() > PRIVATE_LIQUIDATION_AUCTION_ROUTER_MAX_DISCLOSURES {
            return Err("liquidation disclosure capacity exceeded".to_string());
        }
        if self.events.len() > PRIVATE_LIQUIDATION_AUCTION_ROUTER_MAX_EVENTS {
            return Err("liquidation event capacity exceeded".to_string());
        }
        for authority in self.authorities.values() {
            authority.validate()?;
            if authority.min_privacy_set_size < self.config.min_privacy_set_size {
                return Err("authority privacy floor below config".to_string());
            }
        }
        for auction in self.auctions.values() {
            auction.validate()?;
            require_map_key("auction", &auction.authority_id, &self.authorities)?;
            if auction.privacy_set_size < self.config.min_privacy_set_size {
                return Err("auction privacy set below config".to_string());
            }
            if auction.max_fee_units > self.config.max_fee_units {
                return Err("auction fee exceeds config".to_string());
            }
        }
        for bid in self.bids.values() {
            bid.validate()?;
            require_map_key("bid", &bid.auction_id, &self.auctions)?;
            if bid.privacy_set_size < self.config.min_privacy_set_size {
                return Err("bid privacy set below config".to_string());
            }
        }
        for sponsor in self.sponsors.values() {
            sponsor.validate()?;
        }
        for settlement in self.settlements.values() {
            settlement.validate()?;
            require_map_key("settlement", &settlement.auction_id, &self.auctions)?;
            require_map_key("settlement", &settlement.winning_bid_id, &self.bids)?;
        }
        for disclosure in self.disclosures.values() {
            disclosure.validate()?;
            require_map_key("disclosure", &disclosure.auction_id, &self.auctions)?;
        }
        for event in self.events.values() {
            event.validate()?;
        }
        Ok(())
    }
}

pub fn private_liquidation_auction_router_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-LIQUIDATION-AUCTION-ROUTER-STATE",
        &[
            HashPart::Str(PRIVATE_LIQUIDATION_AUCTION_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn private_liquidation_auction_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-LIQUIDATION-AUCTION-ROUTER-{domain}"),
        &[
            HashPart::Str(PRIVATE_LIQUIDATION_AUCTION_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn private_liquidation_auction_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        &format!("PRIVATE-LIQUIDATION-AUCTION-ROUTER-{domain}"),
        &[
            HashPart::Str(PRIVATE_LIQUIDATION_AUCTION_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn private_liquidation_auction_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(Value::String)
        .collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-LIQUIDATION-AUCTION-ROUTER-{domain}"),
        &leaves,
    )
}

pub fn private_liquidation_auction_record_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(
        &format!("PRIVATE-LIQUIDATION-AUCTION-ROUTER-{domain}"),
        &records,
    )
}

pub fn pq_liquidation_authority_id(
    venue: &LiquidationVenueKind,
    authority_commitment: &str,
    pq_public_key_commitment: &str,
    scope_root: &str,
    issued_at_height: u64,
) -> String {
    let venue = venue.as_str();
    domain_hash(
        "PRIVATE-LIQUIDATION-AUCTION-AUTHORITY-ID",
        &[
            HashPart::Str(PRIVATE_LIQUIDATION_AUCTION_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&venue),
            HashPart::Str(authority_commitment),
            HashPart::Str(pq_public_key_commitment),
            HashPart::Str(scope_root),
            HashPart::Int(issued_at_height as i128),
        ],
        32,
    )
}

pub fn liquidation_lot_privacy_nullifier(
    borrower_commitment: &str,
    collateral_asset_commitment: &str,
    debt_asset_commitment: &str,
    risk_evidence_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-LIQUIDATION-AUCTION-LOT-NULLIFIER",
        &[
            HashPart::Str(PRIVATE_LIQUIDATION_AUCTION_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(borrower_commitment),
            HashPart::Str(collateral_asset_commitment),
            HashPart::Str(debt_asset_commitment),
            HashPart::Str(risk_evidence_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn encrypted_liquidation_lot_id(
    venue: &LiquidationVenueKind,
    trigger: &LiquidationTriggerKind,
    authority_id: &str,
    borrower_commitment: &str,
    encrypted_terms_root: &str,
    privacy_nullifier: &str,
) -> String {
    let venue = venue.as_str();
    let trigger = trigger.as_str();
    domain_hash(
        "PRIVATE-LIQUIDATION-AUCTION-LOT-ID",
        &[
            HashPart::Str(PRIVATE_LIQUIDATION_AUCTION_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&venue),
            HashPart::Str(&trigger),
            HashPart::Str(authority_id),
            HashPart::Str(borrower_commitment),
            HashPart::Str(encrypted_terms_root),
            HashPart::Str(privacy_nullifier),
        ],
        32,
    )
}

pub fn sealed_liquidation_bid_id(
    auction_id: &str,
    bidder_commitment: &str,
    solver_commitment: &str,
    bid_commitment_root: &str,
    submitted_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-LIQUIDATION-AUCTION-BID-ID",
        &[
            HashPart::Str(PRIVATE_LIQUIDATION_AUCTION_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(bidder_commitment),
            HashPart::Str(solver_commitment),
            HashPart::Str(bid_commitment_root),
            HashPart::Int(submitted_at_height as i128),
        ],
        32,
    )
}

pub fn liquidation_sponsor_pool_id(
    sponsor_commitment: &str,
    venue_allowlist_root: &str,
    fee_asset_id: &str,
    policy_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-LIQUIDATION-AUCTION-SPONSOR-ID",
        &[
            HashPart::Str(PRIVATE_LIQUIDATION_AUCTION_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(venue_allowlist_root),
            HashPart::Str(fee_asset_id),
            HashPart::Str(policy_root),
        ],
        32,
    )
}

pub fn liquidation_settlement_receipt_id(
    auction_id: &str,
    winning_bid_id: &str,
    state_transition_root: &str,
    settled_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-LIQUIDATION-AUCTION-SETTLEMENT-ID",
        &[
            HashPart::Str(PRIVATE_LIQUIDATION_AUCTION_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(winning_bid_id),
            HashPart::Str(state_transition_root),
            HashPart::Int(settled_at_height as i128),
        ],
        32,
    )
}

pub fn liquidation_disclosure_receipt_id(
    auction_id: &str,
    requester_commitment: &str,
    scope_root: &str,
    proof_root: &str,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-LIQUIDATION-AUCTION-DISCLOSURE-ID",
        &[
            HashPart::Str(PRIVATE_LIQUIDATION_AUCTION_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(requester_commitment),
            HashPart::Str(scope_root),
            HashPart::Str(proof_root),
            HashPart::Int(issued_at_height as i128),
        ],
        32,
    )
}

pub fn liquidation_router_event_id(
    event_kind: RouterEventKind,
    subject_id: &str,
    emitted_at_height: u64,
    payload_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-LIQUIDATION-AUCTION-EVENT-ID",
        &[
            HashPart::Str(PRIVATE_LIQUIDATION_AUCTION_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Int(emitted_at_height as i128),
            HashPart::Str(payload_root),
        ],
        32,
    )
}

fn ensure_non_empty(value: &str, label: &str) -> PrivateLiquidationAuctionRouterResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn ensure_positive(value: u64, label: &str) -> PrivateLiquidationAuctionRouterResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_bps(value: u64, label: &str) -> PrivateLiquidationAuctionRouterResult<()> {
    if value > PRIVATE_LIQUIDATION_AUCTION_ROUTER_MAX_BPS {
        return Err(format!("{label} exceeds 10000 bps"));
    }
    Ok(())
}

fn ensure_string_set(values: &[String], label: &str) -> PrivateLiquidationAuctionRouterResult<()> {
    if values.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(value, label)?;
        if !seen.insert(value) {
            return Err(format!("{label} contains duplicate value"));
        }
    }
    Ok(())
}

fn validate_height_window(
    start: u64,
    end: u64,
    label: &str,
) -> PrivateLiquidationAuctionRouterResult<()> {
    if end <= start {
        return Err(format!("{label} height window is invalid"));
    }
    Ok(())
}

fn require_map_key<T>(
    label: &str,
    key: &str,
    map: &BTreeMap<String, T>,
) -> PrivateLiquidationAuctionRouterResult<()> {
    if !map.contains_key(key) {
        return Err(format!("{label} references unknown id"));
    }
    Ok(())
}

fn insert_unique<T>(
    map: &mut BTreeMap<String, T>,
    id: String,
    value: T,
    label: &str,
) -> PrivateLiquidationAuctionRouterResult<()> {
    if map.contains_key(&id) {
        return Err(format!("{label} already exists"));
    }
    map.insert(id, value);
    Ok(())
}
