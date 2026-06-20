use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedCatastropheBondAuctionRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-tokenized-catastrophe-bond-auction-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_PROTOCOL_VERSION;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_SCHEMA_VERSION:
    u64 = 1;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_PQ_AUTH_SUITE:
    &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-cat-bond-auction-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_AUCTION_SCHEME:
    &str = "sealed-uniform-price-confidential-cat-bond-batch-auction-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_SETTLEMENT_SCHEME:
    &str = "zk-pq-confidential-claim-risk-settlement-batch-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_DEVNET_HEIGHT: u64 =
    1_248_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_MAX_BPS: u64 =
    10_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_DEFAULT_MIN_PRIVACY_SET:
    u64 = 65_536;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_DEFAULT_BATCH_PRIVACY_SET:
    u64 = 524_288;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS:
    u16 = 256;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_DEFAULT_MAX_AUCTION_FEE_BPS:
    u64 = 8;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_DEFAULT_LOW_FEE_BPS:
    u64 = 3;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_DEFAULT_REBATE_BPS:
    u64 = 4;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_DEFAULT_ORACLE_QUORUM:
    u16 = 5;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_DEFAULT_NOTE_TTL_BLOCKS:
    u64 = 604_800;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_DEFAULT_AUCTION_TTL_BLOCKS:
    u64 = 72;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS:
    u64 = 144;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_DEFAULT_TRIGGER_FINALITY_BLOCKS:
    u64 = 36;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CatastrophePeril {
    NamedStorm,
    Earthquake,
    Wildfire,
    Flood,
    SevereConvectiveStorm,
    WinterStorm,
    Drought,
    Pandemic,
    CyberCatastrophe,
    MultiPeril,
}

impl CatastrophePeril {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NamedStorm => "named_storm",
            Self::Earthquake => "earthquake",
            Self::Wildfire => "wildfire",
            Self::Flood => "flood",
            Self::SevereConvectiveStorm => "severe_convective_storm",
            Self::WinterStorm => "winter_storm",
            Self::Drought => "drought",
            Self::Pandemic => "pandemic",
            Self::CyberCatastrophe => "cyber_catastrophe",
            Self::MultiPeril => "multi_peril",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteStatus {
    Draft,
    Offered,
    Auctioning,
    Tokenized,
    Seasoning,
    ActiveRisk,
    Triggered,
    Settling,
    Matured,
    Defaulted,
    Retired,
}

impl NoteStatus {
    pub fn accepts_auction(self) -> bool {
        matches!(self, Self::Offered | Self::Auctioning | Self::Tokenized)
    }

    pub fn risk_bearing(self) -> bool {
        matches!(self, Self::Seasoning | Self::ActiveRisk | Self::Triggered)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Open,
    Sealed,
    Revealing,
    Cleared,
    SettlementQueued,
    Settled,
    Expired,
    Cancelled,
    Disputed,
}

impl AuctionStatus {
    pub fn can_accept_bids(self) -> bool {
        matches!(self, Self::Open | Self::Sealed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidSide {
    BuyProtectionYield,
    SellRiskCapital,
    MarketMakerBackstop,
    LiquidityRebateSponsor,
}

impl BidSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BuyProtectionYield => "buy_protection_yield",
            Self::SellRiskCapital => "sell_risk_capital",
            Self::MarketMakerBackstop => "market_maker_backstop",
            Self::LiquidityRebateSponsor => "liquidity_rebate_sponsor",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Committed,
    RiskChecked,
    Revealed,
    Eligible,
    Selected,
    Settled,
    Rejected,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleAttestationKind {
    RiskModel,
    ExposureSnapshot,
    ParametricObservation,
    LossIndex,
    ClaimAdjudication,
    CollateralReserve,
    ComplianceScreen,
}

impl OracleAttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RiskModel => "risk_model",
            Self::ExposureSnapshot => "exposure_snapshot",
            Self::ParametricObservation => "parametric_observation",
            Self::LossIndex => "loss_index",
            Self::ClaimAdjudication => "claim_adjudication",
            Self::CollateralReserve => "collateral_reserve",
            Self::ComplianceScreen => "compliance_screen",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerStatus {
    Watching,
    Candidate,
    QuorumReached,
    Finalized,
    Rejected,
    Settled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrancheSeniority {
    Equity,
    Mezzanine,
    Senior,
    SuperSenior,
    SponsorRetained,
}

impl TrancheSeniority {
    pub fn loss_priority(self) -> u64 {
        match self {
            Self::Equity => 100,
            Self::Mezzanine => 70,
            Self::Senior => 35,
            Self::SuperSenior => 10,
            Self::SponsorRetained => 95,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Draft,
    Netting,
    Posted,
    ClaimLocked,
    PayoutComputed,
    Settled,
    Disputed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceScope {
    PublicIssuer,
    QualifiedInvestor,
    SanctionsSafeHarbor,
    InsuranceRegulator,
    Auditor,
    Operator,
}

impl ComplianceScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublicIssuer => "public_issuer",
            Self::QualifiedInvestor => "qualified_investor",
            Self::SanctionsSafeHarbor => "sanctions_safe_harbor",
            Self::InsuranceRegulator => "insurance_regulator",
            Self::Auditor => "auditor",
            Self::Operator => "operator",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub settlement_asset_id: String,
    pub premium_asset_id: String,
    pub fee_asset_id: String,
    pub governance_asset_id: String,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub auction_scheme: String,
    pub settlement_scheme: String,
    pub min_privacy_set: u64,
    pub batch_privacy_set: u64,
    pub min_pq_security_bits: u16,
    pub oracle_quorum: u16,
    pub note_ttl_blocks: u64,
    pub auction_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub trigger_finality_blocks: u64,
    pub max_auction_fee_bps: u64,
    pub low_fee_bps: u64,
    pub rebate_bps: u64,
    pub max_notes: usize,
    pub max_auctions: usize,
    pub max_bids: usize,
    pub max_attestations: usize,
    pub max_trigger_proofs: usize,
    pub max_tranches: usize,
    pub max_settlement_batches: usize,
    pub max_compliance_views: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: "nebula-private-l2-devnet".to_string(),
            settlement_asset_id: "dcat-devnet-risk-capital".to_string(),
            premium_asset_id: "dusd-devnet-premium".to_string(),
            fee_asset_id: "piconero-devnet-fee".to_string(),
            governance_asset_id: "nebula-devnet-governance".to_string(),
            hash_suite: PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_HASH_SUITE.to_string(),
            pq_auth_suite: PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_PQ_AUTH_SUITE.to_string(),
            auction_scheme: PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_AUCTION_SCHEME.to_string(),
            settlement_scheme: PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_SETTLEMENT_SCHEME.to_string(),
            min_privacy_set: PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
            batch_privacy_set: PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_DEFAULT_BATCH_PRIVACY_SET,
            min_pq_security_bits: PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            oracle_quorum: PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_DEFAULT_ORACLE_QUORUM,
            note_ttl_blocks: PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_DEFAULT_NOTE_TTL_BLOCKS,
            auction_ttl_blocks: PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_DEFAULT_AUCTION_TTL_BLOCKS,
            settlement_ttl_blocks: PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            trigger_finality_blocks: PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_DEFAULT_TRIGGER_FINALITY_BLOCKS,
            max_auction_fee_bps: PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_DEFAULT_MAX_AUCTION_FEE_BPS,
            low_fee_bps: PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_DEFAULT_LOW_FEE_BPS,
            rebate_bps: PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_DEFAULT_REBATE_BPS,
            max_notes: 262_144,
            max_auctions: 262_144,
            max_bids: 2_097_152,
            max_attestations: 1_048_576,
            max_trigger_proofs: 524_288,
            max_tranches: 1_048_576,
            max_settlement_batches: 262_144,
            max_compliance_views: 524_288,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("protocol_version", &self.protocol_version)?;
        require_non_empty("chain_id", &self.chain_id)?;
        require_bps("max_auction_fee_bps", self.max_auction_fee_bps)?;
        require_bps("low_fee_bps", self.low_fee_bps)?;
        require_bps("rebate_bps", self.rebate_bps)?;
        if self.low_fee_bps > self.max_auction_fee_bps {
            return Err("low_fee_bps cannot exceed max_auction_fee_bps".to_string());
        }
        if self.oracle_quorum == 0 {
            return Err("oracle_quorum must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "auction_scheme": self.auction_scheme,
            "auction_ttl_blocks": self.auction_ttl_blocks,
            "batch_privacy_set": self.batch_privacy_set,
            "chain_id": self.chain_id,
            "fee_asset_id": self.fee_asset_id,
            "governance_asset_id": self.governance_asset_id,
            "hash_suite": self.hash_suite,
            "l2_network": self.l2_network,
            "low_fee_bps": self.low_fee_bps,
            "max_auction_fee_bps": self.max_auction_fee_bps,
            "max_auctions": self.max_auctions,
            "max_attestations": self.max_attestations,
            "max_bids": self.max_bids,
            "max_compliance_views": self.max_compliance_views,
            "max_notes": self.max_notes,
            "max_settlement_batches": self.max_settlement_batches,
            "max_tranches": self.max_tranches,
            "max_trigger_proofs": self.max_trigger_proofs,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set": self.min_privacy_set,
            "note_ttl_blocks": self.note_ttl_blocks,
            "oracle_quorum": self.oracle_quorum,
            "premium_asset_id": self.premium_asset_id,
            "protocol_version": self.protocol_version,
            "pq_auth_suite": self.pq_auth_suite,
            "rebate_bps": self.rebate_bps,
            "schema_version": self.schema_version,
            "settlement_asset_id": self.settlement_asset_id,
            "settlement_scheme": self.settlement_scheme,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "trigger_finality_blocks": self.trigger_finality_blocks
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub next_note_sequence: u64,
    pub next_auction_sequence: u64,
    pub next_bid_sequence: u64,
    pub next_attestation_sequence: u64,
    pub next_trigger_sequence: u64,
    pub next_tranche_sequence: u64,
    pub next_settlement_sequence: u64,
    pub next_rebate_sequence: u64,
    pub next_compliance_view_sequence: u64,
    pub notes_issued: u64,
    pub auctions_cleared: u64,
    pub confidential_bids_received: u64,
    pub risk_attestations_accepted: u64,
    pub event_triggers_finalized: u64,
    pub settlement_batches_posted: u64,
    pub fee_rebates_accrued: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "auctions_cleared": self.auctions_cleared,
            "confidential_bids_received": self.confidential_bids_received,
            "event_triggers_finalized": self.event_triggers_finalized,
            "fee_rebates_accrued": self.fee_rebates_accrued,
            "next_attestation_sequence": self.next_attestation_sequence,
            "next_auction_sequence": self.next_auction_sequence,
            "next_bid_sequence": self.next_bid_sequence,
            "next_compliance_view_sequence": self.next_compliance_view_sequence,
            "next_note_sequence": self.next_note_sequence,
            "next_rebate_sequence": self.next_rebate_sequence,
            "next_settlement_sequence": self.next_settlement_sequence,
            "next_tranche_sequence": self.next_tranche_sequence,
            "next_trigger_sequence": self.next_trigger_sequence,
            "notes_issued": self.notes_issued,
            "risk_attestations_accepted": self.risk_attestations_accepted,
            "settlement_batches_posted": self.settlement_batches_posted
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub note_root: String,
    pub auction_root: String,
    pub bid_root: String,
    pub attestation_root: String,
    pub trigger_root: String,
    pub tranche_root: String,
    pub settlement_root: String,
    pub rebate_root: String,
    pub compliance_view_root: String,
    pub nullifier_root: String,
    pub operator_summary_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            config_root: empty_root("CONFIG"),
            note_root: empty_root("NOTE"),
            auction_root: empty_root("AUCTION"),
            bid_root: empty_root("BID"),
            attestation_root: empty_root("ATTESTATION"),
            trigger_root: empty_root("TRIGGER"),
            tranche_root: empty_root("TRANCHE"),
            settlement_root: empty_root("SETTLEMENT"),
            rebate_root: empty_root("REBATE"),
            compliance_view_root: empty_root("COMPLIANCE-VIEW"),
            nullifier_root: empty_root("NULLIFIER"),
            operator_summary_root: empty_root("OPERATOR-SUMMARY"),
            state_root: String::new(),
        }
    }

    pub fn without_state_root(&self) -> Value {
        json!({
            "attestation_root": self.attestation_root,
            "auction_root": self.auction_root,
            "bid_root": self.bid_root,
            "compliance_view_root": self.compliance_view_root,
            "config_root": self.config_root,
            "note_root": self.note_root,
            "nullifier_root": self.nullifier_root,
            "operator_summary_root": self.operator_summary_root,
            "rebate_root": self.rebate_root,
            "settlement_root": self.settlement_root,
            "tranche_root": self.tranche_root,
            "trigger_root": self.trigger_root
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.without_state_root();
        if let Some(map) = record.as_object_mut() {
            map.insert("state_root".to_string(), json!(self.state_root));
        }
        record
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CatastropheBondNote {
    pub note_id: String,
    pub issuer_commitment: String,
    pub sponsor_commitment: String,
    pub peril: CatastrophePeril,
    pub geography_commitment: String,
    pub risk_model_root: String,
    pub exposure_root: String,
    pub attachment_point_bps: u64,
    pub exhaustion_point_bps: u64,
    pub coupon_rate_bps: u64,
    pub notional_commitment: String,
    pub settlement_asset_id: String,
    pub premium_asset_id: String,
    pub term_start_height: u64,
    pub term_end_height: u64,
    pub token_supply_commitment: String,
    pub token_metadata_root: String,
    pub compliance_root: String,
    pub pq_issuer_attestation_root: String,
    pub status: NoteStatus,
    pub created_height: u64,
    pub note_nonce: String,
}

impl CatastropheBondNote {
    pub fn loss_band_bps(&self) -> u64 {
        self.exhaustion_point_bps
            .saturating_sub(self.attachment_point_bps)
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("note_id", &self.note_id)?;
        require_root("risk_model_root", &self.risk_model_root)?;
        require_root("exposure_root", &self.exposure_root)?;
        require_bps("attachment_point_bps", self.attachment_point_bps)?;
        require_bps("exhaustion_point_bps", self.exhaustion_point_bps)?;
        require_bps("coupon_rate_bps", self.coupon_rate_bps)?;
        if self.attachment_point_bps >= self.exhaustion_point_bps {
            return Err("attachment point must be below exhaustion point".to_string());
        }
        if self.term_start_height >= self.term_end_height {
            return Err("term_start_height must be below term_end_height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attachment_point_bps": self.attachment_point_bps,
            "compliance_root": self.compliance_root,
            "coupon_rate_bps": self.coupon_rate_bps,
            "created_height": self.created_height,
            "exhaustion_point_bps": self.exhaustion_point_bps,
            "exposure_root": self.exposure_root,
            "geography_commitment": self.geography_commitment,
            "issuer_commitment": self.issuer_commitment,
            "loss_band_bps": self.loss_band_bps(),
            "notional_commitment": self.notional_commitment,
            "note_id": self.note_id,
            "note_nonce": self.note_nonce,
            "peril": self.peril,
            "pq_issuer_attestation_root": self.pq_issuer_attestation_root,
            "premium_asset_id": self.premium_asset_id,
            "risk_model_root": self.risk_model_root,
            "settlement_asset_id": self.settlement_asset_id,
            "sponsor_commitment": self.sponsor_commitment,
            "status": self.status,
            "term_end_height": self.term_end_height,
            "term_start_height": self.term_start_height,
            "token_metadata_root": self.token_metadata_root,
            "token_supply_commitment": self.token_supply_commitment
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SealedAuction {
    pub auction_id: String,
    pub note_id: String,
    pub lane: String,
    pub status: AuctionStatus,
    pub sealed_order_root: String,
    pub encrypted_book_root: String,
    pub clearing_price_commitment: String,
    pub capacity_commitment: String,
    pub min_fill_commitment: String,
    pub premium_token_id: String,
    pub risk_token_id: String,
    pub open_height: u64,
    pub seal_height: u64,
    pub reveal_height: u64,
    pub settle_before_height: u64,
    pub max_fee_bps: u64,
    pub low_fee_eligible: bool,
    pub privacy_set_size: u64,
    pub pq_auctioneer_attestation_root: String,
    pub replay_nullifier: String,
    pub auction_nonce: String,
}

impl SealedAuction {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("auction_id", &self.auction_id)?;
        require_non_empty("note_id", &self.note_id)?;
        require_root("sealed_order_root", &self.sealed_order_root)?;
        require_root("encrypted_book_root", &self.encrypted_book_root)?;
        require_bps("max_fee_bps", self.max_fee_bps)?;
        if self.max_fee_bps > config.max_auction_fee_bps {
            return Err("auction fee exceeds configured maximum".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set {
            return Err("auction privacy set is below configured minimum".to_string());
        }
        if !(self.open_height < self.seal_height
            && self.seal_height <= self.reveal_height
            && self.reveal_height <= self.settle_before_height)
        {
            return Err("auction height schedule is not monotonic".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "auction_id": self.auction_id,
            "auction_nonce": self.auction_nonce,
            "capacity_commitment": self.capacity_commitment,
            "clearing_price_commitment": self.clearing_price_commitment,
            "encrypted_book_root": self.encrypted_book_root,
            "lane": self.lane,
            "low_fee_eligible": self.low_fee_eligible,
            "max_fee_bps": self.max_fee_bps,
            "min_fill_commitment": self.min_fill_commitment,
            "note_id": self.note_id,
            "open_height": self.open_height,
            "pq_auctioneer_attestation_root": self.pq_auctioneer_attestation_root,
            "premium_token_id": self.premium_token_id,
            "privacy_set_size": self.privacy_set_size,
            "replay_nullifier": self.replay_nullifier,
            "reveal_height": self.reveal_height,
            "risk_token_id": self.risk_token_id,
            "seal_height": self.seal_height,
            "sealed_order_root": self.sealed_order_root,
            "settle_before_height": self.settle_before_height,
            "status": self.status
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConfidentialBid {
    pub bid_id: String,
    pub auction_id: String,
    pub bidder_commitment: String,
    pub side: BidSide,
    pub status: BidStatus,
    pub encrypted_terms_root: String,
    pub price_commitment: String,
    pub quantity_commitment: String,
    pub collateral_commitment: String,
    pub max_slippage_bps: u64,
    pub fee_cap_bps: u64,
    pub rebate_hint_commitment: String,
    pub pq_bid_attestation_root: String,
    pub eligibility_proof_root: String,
    pub bid_nullifier: String,
    pub created_height: u64,
    pub expires_height: u64,
    pub bid_nonce: String,
}

impl ConfidentialBid {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("bid_id", &self.bid_id)?;
        require_non_empty("auction_id", &self.auction_id)?;
        require_root("encrypted_terms_root", &self.encrypted_terms_root)?;
        require_bps("max_slippage_bps", self.max_slippage_bps)?;
        require_bps("fee_cap_bps", self.fee_cap_bps)?;
        if self.fee_cap_bps > config.max_auction_fee_bps {
            return Err("bid fee cap exceeds configured maximum".to_string());
        }
        if self.created_height >= self.expires_height {
            return Err("bid expiry must be after creation".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "auction_id": self.auction_id,
            "bid_id": self.bid_id,
            "bid_nonce": self.bid_nonce,
            "bid_nullifier": self.bid_nullifier,
            "bidder_commitment": self.bidder_commitment,
            "collateral_commitment": self.collateral_commitment,
            "created_height": self.created_height,
            "eligibility_proof_root": self.eligibility_proof_root,
            "encrypted_terms_root": self.encrypted_terms_root,
            "expires_height": self.expires_height,
            "fee_cap_bps": self.fee_cap_bps,
            "max_slippage_bps": self.max_slippage_bps,
            "pq_bid_attestation_root": self.pq_bid_attestation_root,
            "price_commitment": self.price_commitment,
            "quantity_commitment": self.quantity_commitment,
            "rebate_hint_commitment": self.rebate_hint_commitment,
            "side": self.side,
            "status": self.status
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RiskOracleAttestation {
    pub attestation_id: String,
    pub subject_id: String,
    pub kind: OracleAttestationKind,
    pub oracle_commitment: String,
    pub observation_root: String,
    pub model_version_root: String,
    pub confidence_bps: u64,
    pub pq_signature_root: String,
    pub quorum_weight: u16,
    pub privacy_set_size: u64,
    pub observed_height: u64,
    pub expires_height: u64,
    pub attestation_nonce: String,
}

impl RiskOracleAttestation {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("attestation_id", &self.attestation_id)?;
        require_root("observation_root", &self.observation_root)?;
        require_bps("confidence_bps", self.confidence_bps)?;
        if self.quorum_weight == 0 {
            return Err("quorum_weight must be positive".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set {
            return Err("attestation privacy set is below configured minimum".to_string());
        }
        if self.observed_height >= self.expires_height {
            return Err("attestation expiry must be after observation".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "attestation_nonce": self.attestation_nonce,
            "confidence_bps": self.confidence_bps,
            "expires_height": self.expires_height,
            "kind": self.kind,
            "model_version_root": self.model_version_root,
            "observation_root": self.observation_root,
            "observed_height": self.observed_height,
            "oracle_commitment": self.oracle_commitment,
            "pq_signature_root": self.pq_signature_root,
            "privacy_set_size": self.privacy_set_size,
            "quorum_weight": self.quorum_weight,
            "subject_id": self.subject_id
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EventTriggerProof {
    pub trigger_id: String,
    pub note_id: String,
    pub peril: CatastrophePeril,
    pub status: TriggerStatus,
    pub event_window_root: String,
    pub parametric_index_root: String,
    pub loss_estimate_commitment: String,
    pub claim_root: String,
    pub oracle_attestation_ids: Vec<String>,
    pub quorum_root: String,
    pub finality_height: u64,
    pub payout_ratio_bps: u64,
    pub dispute_window_blocks: u64,
    pub pq_trigger_proof_root: String,
    pub trigger_nonce: String,
}

impl EventTriggerProof {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("trigger_id", &self.trigger_id)?;
        require_non_empty("note_id", &self.note_id)?;
        require_root("event_window_root", &self.event_window_root)?;
        require_root("parametric_index_root", &self.parametric_index_root)?;
        require_unique("oracle_attestation_ids", &self.oracle_attestation_ids)?;
        require_bps("payout_ratio_bps", self.payout_ratio_bps)?;
        if self.oracle_attestation_ids.len() < config.oracle_quorum as usize {
            return Err("trigger proof does not meet oracle quorum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "claim_root": self.claim_root,
            "dispute_window_blocks": self.dispute_window_blocks,
            "event_window_root": self.event_window_root,
            "finality_height": self.finality_height,
            "loss_estimate_commitment": self.loss_estimate_commitment,
            "note_id": self.note_id,
            "oracle_attestation_ids": self.oracle_attestation_ids,
            "parametric_index_root": self.parametric_index_root,
            "payout_ratio_bps": self.payout_ratio_bps,
            "peril": self.peril,
            "pq_trigger_proof_root": self.pq_trigger_proof_root,
            "quorum_root": self.quorum_root,
            "status": self.status,
            "trigger_id": self.trigger_id,
            "trigger_nonce": self.trigger_nonce
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PayoutTranche {
    pub tranche_id: String,
    pub note_id: String,
    pub seniority: TrancheSeniority,
    pub token_id: String,
    pub holder_set_root: String,
    pub notional_commitment: String,
    pub premium_claim_commitment: String,
    pub loss_absorption_bps: u64,
    pub payout_waterfall_bps: u64,
    pub residual_claim_bps: u64,
    pub tokenized_supply_commitment: String,
    pub transfer_hook_root: String,
    pub tranche_nonce: String,
}

impl PayoutTranche {
    pub fn validate(&self) -> Result<()> {
        require_non_empty("tranche_id", &self.tranche_id)?;
        require_non_empty("note_id", &self.note_id)?;
        require_bps("loss_absorption_bps", self.loss_absorption_bps)?;
        require_bps("payout_waterfall_bps", self.payout_waterfall_bps)?;
        require_bps("residual_claim_bps", self.residual_claim_bps)?;
        Ok(())
    }

    pub fn weighted_loss_priority(&self) -> u64 {
        self.seniority
            .loss_priority()
            .saturating_mul(self.loss_absorption_bps.max(1))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "holder_set_root": self.holder_set_root,
            "loss_absorption_bps": self.loss_absorption_bps,
            "note_id": self.note_id,
            "notional_commitment": self.notional_commitment,
            "payout_waterfall_bps": self.payout_waterfall_bps,
            "premium_claim_commitment": self.premium_claim_commitment,
            "residual_claim_bps": self.residual_claim_bps,
            "seniority": self.seniority,
            "token_id": self.token_id,
            "tokenized_supply_commitment": self.tokenized_supply_commitment,
            "tranche_id": self.tranche_id,
            "tranche_nonce": self.tranche_nonce,
            "transfer_hook_root": self.transfer_hook_root,
            "weighted_loss_priority": self.weighted_loss_priority()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementBatch {
    pub settlement_id: String,
    pub auction_ids: Vec<String>,
    pub note_ids: Vec<String>,
    pub trigger_ids: Vec<String>,
    pub status: SettlementStatus,
    pub netted_premium_root: String,
    pub netted_collateral_root: String,
    pub claim_payout_root: String,
    pub tranche_waterfall_root: String,
    pub token_transfer_root: String,
    pub fee_root: String,
    pub rebate_root: String,
    pub nullifier_root: String,
    pub batch_privacy_set_size: u64,
    pub settlement_height: u64,
    pub settlement_proof_root: String,
    pub operator_commitment: String,
    pub batch_nonce: String,
}

impl SettlementBatch {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("settlement_id", &self.settlement_id)?;
        require_unique("auction_ids", &self.auction_ids)?;
        require_unique("note_ids", &self.note_ids)?;
        require_unique("trigger_ids", &self.trigger_ids)?;
        require_root("netted_premium_root", &self.netted_premium_root)?;
        require_root("netted_collateral_root", &self.netted_collateral_root)?;
        require_root("settlement_proof_root", &self.settlement_proof_root)?;
        if self.batch_privacy_set_size < config.batch_privacy_set {
            return Err("settlement batch privacy set is below configured target".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "auction_ids": self.auction_ids,
            "batch_nonce": self.batch_nonce,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "claim_payout_root": self.claim_payout_root,
            "fee_root": self.fee_root,
            "netted_collateral_root": self.netted_collateral_root,
            "netted_premium_root": self.netted_premium_root,
            "note_ids": self.note_ids,
            "nullifier_root": self.nullifier_root,
            "operator_commitment": self.operator_commitment,
            "rebate_root": self.rebate_root,
            "settlement_height": self.settlement_height,
            "settlement_id": self.settlement_id,
            "settlement_proof_root": self.settlement_proof_root,
            "status": self.status,
            "token_transfer_root": self.token_transfer_root,
            "tranche_waterfall_root": self.tranche_waterfall_root,
            "trigger_ids": self.trigger_ids
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub settlement_id: String,
    pub auction_id: String,
    pub beneficiary_commitment: String,
    pub fee_asset_id: String,
    pub gross_fee_commitment: String,
    pub rebate_commitment: String,
    pub rebate_bps: u64,
    pub low_fee_reason_root: String,
    pub rebate_nullifier: String,
    pub created_height: u64,
    pub rebate_nonce: String,
}

impl FeeRebate {
    pub fn validate(&self) -> Result<()> {
        require_non_empty("rebate_id", &self.rebate_id)?;
        require_non_empty("settlement_id", &self.settlement_id)?;
        require_bps("rebate_bps", self.rebate_bps)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "auction_id": self.auction_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "created_height": self.created_height,
            "fee_asset_id": self.fee_asset_id,
            "gross_fee_commitment": self.gross_fee_commitment,
            "low_fee_reason_root": self.low_fee_reason_root,
            "rebate_bps": self.rebate_bps,
            "rebate_commitment": self.rebate_commitment,
            "rebate_id": self.rebate_id,
            "rebate_nonce": self.rebate_nonce,
            "rebate_nullifier": self.rebate_nullifier,
            "settlement_id": self.settlement_id
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedactedComplianceView {
    pub view_id: String,
    pub subject_id: String,
    pub scope: ComplianceScope,
    pub viewer_commitment: String,
    pub disclosed_fields_root: String,
    pub redacted_record_root: String,
    pub policy_root: String,
    pub jurisdiction_commitment: String,
    pub expiry_height: u64,
    pub pq_disclosure_attestation_root: String,
    pub view_nonce: String,
}

impl RedactedComplianceView {
    pub fn validate(&self) -> Result<()> {
        require_non_empty("view_id", &self.view_id)?;
        require_non_empty("subject_id", &self.subject_id)?;
        require_root("disclosed_fields_root", &self.disclosed_fields_root)?;
        require_root("redacted_record_root", &self.redacted_record_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "disclosed_fields_root": self.disclosed_fields_root,
            "expiry_height": self.expiry_height,
            "jurisdiction_commitment": self.jurisdiction_commitment,
            "policy_root": self.policy_root,
            "pq_disclosure_attestation_root": self.pq_disclosure_attestation_root,
            "redacted_record_root": self.redacted_record_root,
            "scope": self.scope,
            "subject_id": self.subject_id,
            "view_id": self.view_id,
            "view_nonce": self.view_nonce,
            "viewer_commitment": self.viewer_commitment
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorSummary {
    pub operator_id: String,
    pub height: u64,
    pub active_note_count: usize,
    pub open_auction_count: usize,
    pub sealed_bid_count: usize,
    pub aggregate_notional_root: String,
    pub aggregate_premium_root: String,
    pub aggregate_claim_root: String,
    pub liquidity_fee_bps: u64,
    pub median_clearing_spread_bps: u64,
    pub oracle_quorum_health_bps: u64,
    pub pq_security_floor_bits: u16,
    pub low_fee_batch_ratio_bps: u64,
    pub summary_root: String,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "active_note_count": self.active_note_count,
            "aggregate_claim_root": self.aggregate_claim_root,
            "aggregate_notional_root": self.aggregate_notional_root,
            "aggregate_premium_root": self.aggregate_premium_root,
            "height": self.height,
            "liquidity_fee_bps": self.liquidity_fee_bps,
            "low_fee_batch_ratio_bps": self.low_fee_batch_ratio_bps,
            "median_clearing_spread_bps": self.median_clearing_spread_bps,
            "open_auction_count": self.open_auction_count,
            "operator_id": self.operator_id,
            "oracle_quorum_health_bps": self.oracle_quorum_health_bps,
            "pq_security_floor_bits": self.pq_security_floor_bits,
            "sealed_bid_count": self.sealed_bid_count,
            "summary_root": self.summary_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IssueCatBondNoteRequest {
    pub issuer_commitment: String,
    pub sponsor_commitment: String,
    pub peril: CatastrophePeril,
    pub geography_commitment: String,
    pub risk_model_root: String,
    pub exposure_root: String,
    pub attachment_point_bps: u64,
    pub exhaustion_point_bps: u64,
    pub coupon_rate_bps: u64,
    pub notional_commitment: String,
    pub settlement_asset_id: String,
    pub premium_asset_id: String,
    pub term_start_height: u64,
    pub term_end_height: u64,
    pub token_supply_commitment: String,
    pub token_metadata_root: String,
    pub compliance_root: String,
    pub pq_issuer_attestation_root: String,
    pub note_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpenSealedAuctionRequest {
    pub note_id: String,
    pub lane: String,
    pub sealed_order_root: String,
    pub encrypted_book_root: String,
    pub clearing_price_commitment: String,
    pub capacity_commitment: String,
    pub min_fill_commitment: String,
    pub premium_token_id: String,
    pub risk_token_id: String,
    pub max_fee_bps: u64,
    pub low_fee_eligible: bool,
    pub privacy_set_size: u64,
    pub pq_auctioneer_attestation_root: String,
    pub replay_nullifier: String,
    pub auction_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SubmitConfidentialBidRequest {
    pub auction_id: String,
    pub bidder_commitment: String,
    pub side: BidSide,
    pub encrypted_terms_root: String,
    pub price_commitment: String,
    pub quantity_commitment: String,
    pub collateral_commitment: String,
    pub max_slippage_bps: u64,
    pub fee_cap_bps: u64,
    pub rebate_hint_commitment: String,
    pub pq_bid_attestation_root: String,
    pub eligibility_proof_root: String,
    pub bid_nullifier: String,
    pub bid_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PostRiskOracleAttestationRequest {
    pub subject_id: String,
    pub kind: OracleAttestationKind,
    pub oracle_commitment: String,
    pub observation_root: String,
    pub model_version_root: String,
    pub confidence_bps: u64,
    pub pq_signature_root: String,
    pub quorum_weight: u16,
    pub privacy_set_size: u64,
    pub observed_height: u64,
    pub expires_height: u64,
    pub attestation_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FinalizeEventTriggerRequest {
    pub note_id: String,
    pub peril: CatastrophePeril,
    pub event_window_root: String,
    pub parametric_index_root: String,
    pub loss_estimate_commitment: String,
    pub claim_root: String,
    pub oracle_attestation_ids: Vec<String>,
    pub finality_height: u64,
    pub payout_ratio_bps: u64,
    pub dispute_window_blocks: u64,
    pub pq_trigger_proof_root: String,
    pub trigger_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RegisterPayoutTrancheRequest {
    pub note_id: String,
    pub seniority: TrancheSeniority,
    pub token_id: String,
    pub holder_set_root: String,
    pub notional_commitment: String,
    pub premium_claim_commitment: String,
    pub loss_absorption_bps: u64,
    pub payout_waterfall_bps: u64,
    pub residual_claim_bps: u64,
    pub tokenized_supply_commitment: String,
    pub transfer_hook_root: String,
    pub tranche_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PostSettlementBatchRequest {
    pub auction_ids: Vec<String>,
    pub note_ids: Vec<String>,
    pub trigger_ids: Vec<String>,
    pub netted_premium_root: String,
    pub netted_collateral_root: String,
    pub claim_payout_root: String,
    pub tranche_waterfall_root: String,
    pub token_transfer_root: String,
    pub fee_root: String,
    pub rebate_root: String,
    pub nullifier_root: String,
    pub batch_privacy_set_size: u64,
    pub settlement_height: u64,
    pub settlement_proof_root: String,
    pub operator_commitment: String,
    pub batch_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublishFeeRebateRequest {
    pub settlement_id: String,
    pub auction_id: String,
    pub beneficiary_commitment: String,
    pub fee_asset_id: String,
    pub gross_fee_commitment: String,
    pub rebate_commitment: String,
    pub rebate_bps: u64,
    pub low_fee_reason_root: String,
    pub rebate_nullifier: String,
    pub rebate_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateComplianceViewRequest {
    pub subject_id: String,
    pub scope: ComplianceScope,
    pub viewer_commitment: String,
    pub disclosed_fields_root: String,
    pub redacted_record_root: String,
    pub policy_root: String,
    pub jurisdiction_commitment: String,
    pub expiry_height: u64,
    pub pq_disclosure_attestation_root: String,
    pub view_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub notes: BTreeMap<String, CatastropheBondNote>,
    pub auctions: BTreeMap<String, SealedAuction>,
    pub bids: BTreeMap<String, ConfidentialBid>,
    pub risk_attestations: BTreeMap<String, RiskOracleAttestation>,
    pub event_triggers: BTreeMap<String, EventTriggerProof>,
    pub payout_tranches: BTreeMap<String, PayoutTranche>,
    pub settlement_batches: BTreeMap<String, SettlementBatch>,
    pub fee_rebates: BTreeMap<String, FeeRebate>,
    pub compliance_views: BTreeMap<String, RedactedComplianceView>,
    pub nullifiers: BTreeSet<String>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::empty(),
            notes: BTreeMap::new(),
            auctions: BTreeMap::new(),
            bids: BTreeMap::new(),
            risk_attestations: BTreeMap::new(),
            event_triggers: BTreeMap::new(),
            payout_tranches: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            compliance_views: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            operator_summaries: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        demo()
    }

    pub fn issue_note(&mut self, request: IssueCatBondNoteRequest) -> Result<String> {
        self.config.validate()?;
        if self.notes.len() >= self.config.max_notes {
            return Err("note capacity exceeded".to_string());
        }
        let sequence = self.counters.next_note_sequence;
        let note_id = catastrophe_bond_note_id(&request, sequence);
        let note = CatastropheBondNote {
            note_id: note_id.clone(),
            issuer_commitment: request.issuer_commitment,
            sponsor_commitment: request.sponsor_commitment,
            peril: request.peril,
            geography_commitment: request.geography_commitment,
            risk_model_root: request.risk_model_root,
            exposure_root: request.exposure_root,
            attachment_point_bps: request.attachment_point_bps,
            exhaustion_point_bps: request.exhaustion_point_bps,
            coupon_rate_bps: request.coupon_rate_bps,
            notional_commitment: request.notional_commitment,
            settlement_asset_id: request.settlement_asset_id,
            premium_asset_id: request.premium_asset_id,
            term_start_height: request.term_start_height,
            term_end_height: request.term_end_height,
            token_supply_commitment: request.token_supply_commitment,
            token_metadata_root: request.token_metadata_root,
            compliance_root: request.compliance_root,
            pq_issuer_attestation_root: request.pq_issuer_attestation_root,
            status: NoteStatus::Offered,
            created_height:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_DEVNET_HEIGHT,
            note_nonce: request.note_nonce,
        };
        note.validate()?;
        self.counters.next_note_sequence = self.counters.next_note_sequence.saturating_add(1);
        self.counters.notes_issued = self.counters.notes_issued.saturating_add(1);
        self.notes.insert(note_id.clone(), note);
        self.refresh_roots();
        Ok(note_id)
    }

    pub fn open_sealed_auction(&mut self, request: OpenSealedAuctionRequest) -> Result<String> {
        if self.auctions.len() >= self.config.max_auctions {
            return Err("auction capacity exceeded".to_string());
        }
        let note = self
            .notes
            .get(&request.note_id)
            .ok_or_else(|| "auction note not found".to_string())?;
        if !note.status.accepts_auction() {
            return Err("note is not auctionable".to_string());
        }
        if !self.nullifiers.insert(request.replay_nullifier.clone()) {
            return Err("auction replay nullifier already used".to_string());
        }
        let sequence = self.counters.next_auction_sequence;
        let auction_id = sealed_auction_id(&request, sequence);
        let open_height =
            PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_DEVNET_HEIGHT
                + sequence;
        let auction = SealedAuction {
            auction_id: auction_id.clone(),
            note_id: request.note_id,
            lane: request.lane,
            status: AuctionStatus::Sealed,
            sealed_order_root: request.sealed_order_root,
            encrypted_book_root: request.encrypted_book_root,
            clearing_price_commitment: request.clearing_price_commitment,
            capacity_commitment: request.capacity_commitment,
            min_fill_commitment: request.min_fill_commitment,
            premium_token_id: request.premium_token_id,
            risk_token_id: request.risk_token_id,
            open_height,
            seal_height: open_height + self.config.auction_ttl_blocks / 2,
            reveal_height: open_height + self.config.auction_ttl_blocks,
            settle_before_height: open_height
                + self.config.auction_ttl_blocks
                + self.config.settlement_ttl_blocks,
            max_fee_bps: request.max_fee_bps,
            low_fee_eligible: request.low_fee_eligible,
            privacy_set_size: request.privacy_set_size,
            pq_auctioneer_attestation_root: request.pq_auctioneer_attestation_root,
            replay_nullifier: request.replay_nullifier,
            auction_nonce: request.auction_nonce,
        };
        auction.validate(&self.config)?;
        self.counters.next_auction_sequence = self.counters.next_auction_sequence.saturating_add(1);
        self.auctions.insert(auction_id.clone(), auction);
        self.refresh_roots();
        Ok(auction_id)
    }

    pub fn submit_confidential_bid(
        &mut self,
        request: SubmitConfidentialBidRequest,
    ) -> Result<String> {
        if self.bids.len() >= self.config.max_bids {
            return Err("bid capacity exceeded".to_string());
        }
        let auction = self
            .auctions
            .get(&request.auction_id)
            .ok_or_else(|| "auction not found".to_string())?;
        if !auction.status.can_accept_bids() {
            return Err("auction cannot accept bids".to_string());
        }
        if !self.nullifiers.insert(request.bid_nullifier.clone()) {
            return Err("bid nullifier already used".to_string());
        }
        let sequence = self.counters.next_bid_sequence;
        let bid_id = confidential_bid_id(&request, sequence);
        let bid = ConfidentialBid {
            bid_id: bid_id.clone(),
            auction_id: request.auction_id,
            bidder_commitment: request.bidder_commitment,
            side: request.side,
            status: BidStatus::Committed,
            encrypted_terms_root: request.encrypted_terms_root,
            price_commitment: request.price_commitment,
            quantity_commitment: request.quantity_commitment,
            collateral_commitment: request.collateral_commitment,
            max_slippage_bps: request.max_slippage_bps,
            fee_cap_bps: request.fee_cap_bps,
            rebate_hint_commitment: request.rebate_hint_commitment,
            pq_bid_attestation_root: request.pq_bid_attestation_root,
            eligibility_proof_root: request.eligibility_proof_root,
            bid_nullifier: request.bid_nullifier,
            created_height: auction.open_height,
            expires_height: auction.settle_before_height,
            bid_nonce: request.bid_nonce,
        };
        bid.validate(&self.config)?;
        self.counters.next_bid_sequence = self.counters.next_bid_sequence.saturating_add(1);
        self.counters.confidential_bids_received =
            self.counters.confidential_bids_received.saturating_add(1);
        self.bids.insert(bid_id.clone(), bid);
        self.refresh_roots();
        Ok(bid_id)
    }

    pub fn post_risk_oracle_attestation(
        &mut self,
        request: PostRiskOracleAttestationRequest,
    ) -> Result<String> {
        if self.risk_attestations.len() >= self.config.max_attestations {
            return Err("attestation capacity exceeded".to_string());
        }
        let sequence = self.counters.next_attestation_sequence;
        let attestation_id = risk_oracle_attestation_id(&request, sequence);
        let attestation = RiskOracleAttestation {
            attestation_id: attestation_id.clone(),
            subject_id: request.subject_id,
            kind: request.kind,
            oracle_commitment: request.oracle_commitment,
            observation_root: request.observation_root,
            model_version_root: request.model_version_root,
            confidence_bps: request.confidence_bps,
            pq_signature_root: request.pq_signature_root,
            quorum_weight: request.quorum_weight,
            privacy_set_size: request.privacy_set_size,
            observed_height: request.observed_height,
            expires_height: request.expires_height,
            attestation_nonce: request.attestation_nonce,
        };
        attestation.validate(&self.config)?;
        self.counters.next_attestation_sequence =
            self.counters.next_attestation_sequence.saturating_add(1);
        self.counters.risk_attestations_accepted =
            self.counters.risk_attestations_accepted.saturating_add(1);
        self.risk_attestations
            .insert(attestation_id.clone(), attestation);
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn finalize_event_trigger(
        &mut self,
        request: FinalizeEventTriggerRequest,
    ) -> Result<String> {
        if self.event_triggers.len() >= self.config.max_trigger_proofs {
            return Err("trigger proof capacity exceeded".to_string());
        }
        if !self.notes.contains_key(&request.note_id) {
            return Err("trigger note not found".to_string());
        }
        for attestation_id in &request.oracle_attestation_ids {
            if !self.risk_attestations.contains_key(attestation_id) {
                return Err(format!("oracle attestation {attestation_id} not found"));
            }
        }
        let sequence = self.counters.next_trigger_sequence;
        let trigger_id = event_trigger_id(&request, sequence);
        let trigger = EventTriggerProof {
            trigger_id: trigger_id.clone(),
            note_id: request.note_id,
            peril: request.peril,
            status: TriggerStatus::Finalized,
            event_window_root: request.event_window_root,
            parametric_index_root: request.parametric_index_root,
            loss_estimate_commitment: request.loss_estimate_commitment,
            claim_root: request.claim_root,
            quorum_root: id_list_root("TRIGGER-QUORUM", &request.oracle_attestation_ids),
            oracle_attestation_ids: request.oracle_attestation_ids,
            finality_height: request.finality_height,
            payout_ratio_bps: request.payout_ratio_bps,
            dispute_window_blocks: request.dispute_window_blocks,
            pq_trigger_proof_root: request.pq_trigger_proof_root,
            trigger_nonce: request.trigger_nonce,
        };
        trigger.validate(&self.config)?;
        self.counters.next_trigger_sequence = self.counters.next_trigger_sequence.saturating_add(1);
        self.counters.event_triggers_finalized =
            self.counters.event_triggers_finalized.saturating_add(1);
        self.event_triggers.insert(trigger_id.clone(), trigger);
        self.refresh_roots();
        Ok(trigger_id)
    }

    pub fn register_payout_tranche(
        &mut self,
        request: RegisterPayoutTrancheRequest,
    ) -> Result<String> {
        if self.payout_tranches.len() >= self.config.max_tranches {
            return Err("tranche capacity exceeded".to_string());
        }
        if !self.notes.contains_key(&request.note_id) {
            return Err("tranche note not found".to_string());
        }
        let sequence = self.counters.next_tranche_sequence;
        let tranche_id = payout_tranche_id(&request, sequence);
        let tranche = PayoutTranche {
            tranche_id: tranche_id.clone(),
            note_id: request.note_id,
            seniority: request.seniority,
            token_id: request.token_id,
            holder_set_root: request.holder_set_root,
            notional_commitment: request.notional_commitment,
            premium_claim_commitment: request.premium_claim_commitment,
            loss_absorption_bps: request.loss_absorption_bps,
            payout_waterfall_bps: request.payout_waterfall_bps,
            residual_claim_bps: request.residual_claim_bps,
            tokenized_supply_commitment: request.tokenized_supply_commitment,
            transfer_hook_root: request.transfer_hook_root,
            tranche_nonce: request.tranche_nonce,
        };
        tranche.validate()?;
        self.counters.next_tranche_sequence = self.counters.next_tranche_sequence.saturating_add(1);
        self.payout_tranches.insert(tranche_id.clone(), tranche);
        self.refresh_roots();
        Ok(tranche_id)
    }

    pub fn post_settlement_batch(&mut self, request: PostSettlementBatchRequest) -> Result<String> {
        if self.settlement_batches.len() >= self.config.max_settlement_batches {
            return Err("settlement batch capacity exceeded".to_string());
        }
        let sequence = self.counters.next_settlement_sequence;
        let settlement_id = settlement_batch_id(&request, sequence);
        let settlement = SettlementBatch {
            settlement_id: settlement_id.clone(),
            auction_ids: request.auction_ids,
            note_ids: request.note_ids,
            trigger_ids: request.trigger_ids,
            status: SettlementStatus::Posted,
            netted_premium_root: request.netted_premium_root,
            netted_collateral_root: request.netted_collateral_root,
            claim_payout_root: request.claim_payout_root,
            tranche_waterfall_root: request.tranche_waterfall_root,
            token_transfer_root: request.token_transfer_root,
            fee_root: request.fee_root,
            rebate_root: request.rebate_root,
            nullifier_root: request.nullifier_root,
            batch_privacy_set_size: request.batch_privacy_set_size,
            settlement_height: request.settlement_height,
            settlement_proof_root: request.settlement_proof_root,
            operator_commitment: request.operator_commitment,
            batch_nonce: request.batch_nonce,
        };
        settlement.validate(&self.config)?;
        self.counters.next_settlement_sequence =
            self.counters.next_settlement_sequence.saturating_add(1);
        self.counters.settlement_batches_posted =
            self.counters.settlement_batches_posted.saturating_add(1);
        self.settlement_batches
            .insert(settlement_id.clone(), settlement);
        self.refresh_roots();
        Ok(settlement_id)
    }

    pub fn publish_fee_rebate(&mut self, request: PublishFeeRebateRequest) -> Result<String> {
        if !self.settlement_batches.contains_key(&request.settlement_id) {
            return Err("rebate settlement batch not found".to_string());
        }
        if !self.nullifiers.insert(request.rebate_nullifier.clone()) {
            return Err("rebate nullifier already used".to_string());
        }
        let sequence = self.counters.next_rebate_sequence;
        let rebate_id = fee_rebate_id(&request, sequence);
        let rebate = FeeRebate {
            rebate_id: rebate_id.clone(),
            settlement_id: request.settlement_id,
            auction_id: request.auction_id,
            beneficiary_commitment: request.beneficiary_commitment,
            fee_asset_id: request.fee_asset_id,
            gross_fee_commitment: request.gross_fee_commitment,
            rebate_commitment: request.rebate_commitment,
            rebate_bps: request.rebate_bps,
            low_fee_reason_root: request.low_fee_reason_root,
            rebate_nullifier: request.rebate_nullifier,
            created_height:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_DEVNET_HEIGHT
                    + sequence,
            rebate_nonce: request.rebate_nonce,
        };
        rebate.validate()?;
        self.counters.next_rebate_sequence = self.counters.next_rebate_sequence.saturating_add(1);
        self.counters.fee_rebates_accrued = self.counters.fee_rebates_accrued.saturating_add(1);
        self.fee_rebates.insert(rebate_id.clone(), rebate);
        self.refresh_roots();
        Ok(rebate_id)
    }

    pub fn create_compliance_view(
        &mut self,
        request: CreateComplianceViewRequest,
    ) -> Result<String> {
        if self.compliance_views.len() >= self.config.max_compliance_views {
            return Err("compliance view capacity exceeded".to_string());
        }
        let sequence = self.counters.next_compliance_view_sequence;
        let view_id = compliance_view_id(&request, sequence);
        let view = RedactedComplianceView {
            view_id: view_id.clone(),
            subject_id: request.subject_id,
            scope: request.scope,
            viewer_commitment: request.viewer_commitment,
            disclosed_fields_root: request.disclosed_fields_root,
            redacted_record_root: request.redacted_record_root,
            policy_root: request.policy_root,
            jurisdiction_commitment: request.jurisdiction_commitment,
            expiry_height: request.expiry_height,
            pq_disclosure_attestation_root: request.pq_disclosure_attestation_root,
            view_nonce: request.view_nonce,
        };
        view.validate()?;
        self.counters.next_compliance_view_sequence = self
            .counters
            .next_compliance_view_sequence
            .saturating_add(1);
        self.compliance_views.insert(view_id.clone(), view);
        self.refresh_roots();
        Ok(view_id)
    }

    pub fn refresh_operator_summary(&mut self, operator_id: &str) {
        let active_note_count = self
            .notes
            .values()
            .filter(|note| note.status.risk_bearing() || note.status.accepts_auction())
            .count();
        let open_auction_count = self
            .auctions
            .values()
            .filter(|auction| auction.status.can_accept_bids())
            .count();
        let sealed_bid_count = self.bids.len();
        let summary_record = json!({
            "active_note_count": active_note_count,
            "bid_root": self.roots.bid_root,
            "note_root": self.roots.note_root,
            "operator_id": operator_id,
            "settlement_root": self.roots.settlement_root
        });
        let summary = OperatorSummary {
            operator_id: operator_id.to_string(),
            height:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_DEVNET_HEIGHT,
            active_note_count,
            open_auction_count,
            sealed_bid_count,
            aggregate_notional_root: self.roots.note_root.clone(),
            aggregate_premium_root: self.roots.auction_root.clone(),
            aggregate_claim_root: self.roots.trigger_root.clone(),
            liquidity_fee_bps: self.config.low_fee_bps,
            median_clearing_spread_bps: 225,
            oracle_quorum_health_bps: 9_800,
            pq_security_floor_bits: self.config.min_pq_security_bits,
            low_fee_batch_ratio_bps: 8_750,
            summary_root: root_from_record("OPERATOR-SUMMARY", &summary_record),
        };
        self.operator_summaries
            .insert(operator_id.to_string(), summary);
        self.refresh_roots();
    }

    pub fn roots(&self) -> Roots {
        let mut roots = Roots {
            config_root: root_from_record("CONFIG", &self.config.public_record()),
            note_root: public_record_root(
                "NOTE",
                &self
                    .notes
                    .values()
                    .map(CatastropheBondNote::public_record)
                    .collect::<Vec<_>>(),
            ),
            auction_root: public_record_root(
                "AUCTION",
                &self
                    .auctions
                    .values()
                    .map(SealedAuction::public_record)
                    .collect::<Vec<_>>(),
            ),
            bid_root: public_record_root(
                "BID",
                &self
                    .bids
                    .values()
                    .map(ConfidentialBid::public_record)
                    .collect::<Vec<_>>(),
            ),
            attestation_root: public_record_root(
                "ATTESTATION",
                &self
                    .risk_attestations
                    .values()
                    .map(RiskOracleAttestation::public_record)
                    .collect::<Vec<_>>(),
            ),
            trigger_root: public_record_root(
                "TRIGGER",
                &self
                    .event_triggers
                    .values()
                    .map(EventTriggerProof::public_record)
                    .collect::<Vec<_>>(),
            ),
            tranche_root: public_record_root(
                "TRANCHE",
                &self
                    .payout_tranches
                    .values()
                    .map(PayoutTranche::public_record)
                    .collect::<Vec<_>>(),
            ),
            settlement_root: public_record_root(
                "SETTLEMENT",
                &self
                    .settlement_batches
                    .values()
                    .map(SettlementBatch::public_record)
                    .collect::<Vec<_>>(),
            ),
            rebate_root: public_record_root(
                "REBATE",
                &self
                    .fee_rebates
                    .values()
                    .map(FeeRebate::public_record)
                    .collect::<Vec<_>>(),
            ),
            compliance_view_root: public_record_root(
                "COMPLIANCE-VIEW",
                &self
                    .compliance_views
                    .values()
                    .map(RedactedComplianceView::public_record)
                    .collect::<Vec<_>>(),
            ),
            nullifier_root: public_record_root(
                "NULLIFIER",
                &self
                    .nullifiers
                    .iter()
                    .map(|id| json!(id))
                    .collect::<Vec<_>>(),
            ),
            operator_summary_root: public_record_root(
                "OPERATOR-SUMMARY",
                &self
                    .operator_summaries
                    .values()
                    .map(OperatorSummary::public_record)
                    .collect::<Vec<_>>(),
            ),
            state_root: String::new(),
        };
        roots.state_root = state_root_from_record(&self.public_record_without_roots_state(&roots));
        roots
    }

    pub fn refresh_roots(&mut self) {
        self.roots = self.roots();
    }

    pub fn public_record_without_state_root(&self) -> Value {
        self.public_record_without_roots_state(&self.roots)
    }

    fn public_record_without_roots_state(&self, roots: &Roots) -> Value {
        json!({
            "auctions": sorted_records(self.auctions.values().map(SealedAuction::public_record).collect()),
            "bids": sorted_records(self.bids.values().map(ConfidentialBid::public_record).collect()),
            "compliance_views": sorted_records(self.compliance_views.values().map(RedactedComplianceView::public_record).collect()),
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "event_triggers": sorted_records(self.event_triggers.values().map(EventTriggerProof::public_record).collect()),
            "fee_rebates": sorted_records(self.fee_rebates.values().map(FeeRebate::public_record).collect()),
            "notes": sorted_records(self.notes.values().map(CatastropheBondNote::public_record).collect()),
            "operator_summaries": sorted_records(self.operator_summaries.values().map(OperatorSummary::public_record).collect()),
            "payout_tranches": sorted_records(self.payout_tranches.values().map(PayoutTranche::public_record).collect()),
            "protocol_version": PROTOCOL_VERSION,
            "risk_attestations": sorted_records(self.risk_attestations.values().map(RiskOracleAttestation::public_record).collect()),
            "roots": roots.without_state_root(),
            "settlement_batches": sorted_records(self.settlement_batches.values().map(SettlementBatch::public_record).collect())
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(map) = record.as_object_mut() {
            map.insert("state_root".to_string(), json!(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn redacted_operator_view(&self) -> Value {
        json!({
            "auction_count": self.auctions.len(),
            "bid_count": self.bids.len(),
            "compliance_view_root": self.roots.compliance_view_root,
            "low_fee_bps": self.config.low_fee_bps,
            "note_count": self.notes.len(),
            "operator_summary_root": self.roots.operator_summary_root,
            "protocol_version": PROTOCOL_VERSION,
            "settlement_batch_count": self.settlement_batches.len(),
            "state_root": self.state_root()
        })
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    let mut state = State::new(Config::devnet());
    let note_id = state
        .issue_note(IssueCatBondNoteRequest {
            issuer_commitment: commitment("issuer", 0),
            sponsor_commitment: commitment("sponsor", 0),
            peril: CatastrophePeril::NamedStorm,
            geography_commitment: commitment("gulf-coast-geography", 0),
            risk_model_root: fixture_root("risk-model", 0),
            exposure_root: fixture_root("exposure", 0),
            attachment_point_bps: 2_500,
            exhaustion_point_bps: 8_500,
            coupon_rate_bps: 925,
            notional_commitment: commitment("notional-250m", 0),
            settlement_asset_id: state.config.settlement_asset_id.clone(),
            premium_asset_id: state.config.premium_asset_id.clone(),
            term_start_height:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_DEVNET_HEIGHT
                    + 720,
            term_end_height:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_DEVNET_HEIGHT
                    + 525_600,
            token_supply_commitment: commitment("token-supply", 0),
            token_metadata_root: fixture_root("token-metadata", 0),
            compliance_root: fixture_root("compliance", 0),
            pq_issuer_attestation_root: fixture_root("pq-issuer", 0),
            note_nonce: "devnet-note-0".to_string(),
        })
        .expect("devnet note fixture must be valid");
    let auction_id = state
        .open_sealed_auction(OpenSealedAuctionRequest {
            note_id: note_id.clone(),
            lane: "low_fee_cat_risk_primary".to_string(),
            sealed_order_root: fixture_root("sealed-order", 0),
            encrypted_book_root: fixture_root("encrypted-book", 0),
            clearing_price_commitment: commitment("clearing-price", 0),
            capacity_commitment: commitment("capacity", 0),
            min_fill_commitment: commitment("min-fill", 0),
            premium_token_id: "dusd-cat-premium-devnet".to_string(),
            risk_token_id: "dcat-gulf-wind-2026-senior".to_string(),
            max_fee_bps: state.config.low_fee_bps,
            low_fee_eligible: true,
            privacy_set_size: state.config.batch_privacy_set,
            pq_auctioneer_attestation_root: fixture_root("pq-auctioneer", 0),
            replay_nullifier: fixture_root("auction-nullifier", 0),
            auction_nonce: "devnet-auction-0".to_string(),
        })
        .expect("devnet auction fixture must be valid");
    for index in 0..6 {
        state
            .submit_confidential_bid(SubmitConfidentialBidRequest {
                auction_id: auction_id.clone(),
                bidder_commitment: commitment("bidder", index),
                side: if index % 3 == 0 {
                    BidSide::MarketMakerBackstop
                } else {
                    BidSide::SellRiskCapital
                },
                encrypted_terms_root: fixture_root("encrypted-bid-terms", index),
                price_commitment: commitment("bid-price", index),
                quantity_commitment: commitment("bid-quantity", index),
                collateral_commitment: commitment("bid-collateral", index),
                max_slippage_bps: 35,
                fee_cap_bps: state.config.low_fee_bps,
                rebate_hint_commitment: commitment("rebate-hint", index),
                pq_bid_attestation_root: fixture_root("pq-bid", index),
                eligibility_proof_root: fixture_root("eligibility", index),
                bid_nullifier: fixture_root("bid-nullifier", index),
                bid_nonce: format!("devnet-bid-{index}"),
            })
            .expect("devnet bid fixture must be valid");
    }
    let mut attestation_ids = Vec::new();
    for index in 0..5 {
        let attestation_id = state
            .post_risk_oracle_attestation(PostRiskOracleAttestationRequest {
                subject_id: note_id.clone(),
                kind: if index < 3 {
                    OracleAttestationKind::ParametricObservation
                } else {
                    OracleAttestationKind::LossIndex
                },
                oracle_commitment: commitment("oracle", index),
                observation_root: fixture_root("observation", index),
                model_version_root: fixture_root("model-version", index),
                confidence_bps: 9_250 + index * 20,
                pq_signature_root: fixture_root("pq-oracle-signature", index),
                quorum_weight: 1,
                privacy_set_size: state.config.min_privacy_set,
                observed_height: PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_DEVNET_HEIGHT + 96 + index,
                expires_height: PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_DEVNET_HEIGHT + 8_640 + index,
                attestation_nonce: format!("devnet-attestation-{index}"),
            })
            .expect("devnet attestation fixture must be valid");
        attestation_ids.push(attestation_id);
    }
    let trigger_id = state
        .finalize_event_trigger(FinalizeEventTriggerRequest {
            note_id: note_id.clone(),
            peril: CatastrophePeril::NamedStorm,
            event_window_root: fixture_root("event-window", 0),
            parametric_index_root: fixture_root("parametric-index", 0),
            loss_estimate_commitment: commitment("loss-estimate", 0),
            claim_root: fixture_root("claim", 0),
            oracle_attestation_ids: attestation_ids,
            finality_height:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_DEVNET_HEIGHT
                    + 10_080,
            payout_ratio_bps: 3_750,
            dispute_window_blocks: 720,
            pq_trigger_proof_root: fixture_root("pq-trigger-proof", 0),
            trigger_nonce: "devnet-trigger-0".to_string(),
        })
        .expect("devnet trigger fixture must be valid");
    for (index, seniority) in [
        TrancheSeniority::Equity,
        TrancheSeniority::Mezzanine,
        TrancheSeniority::Senior,
        TrancheSeniority::SuperSenior,
    ]
    .into_iter()
    .enumerate()
    {
        state
            .register_payout_tranche(RegisterPayoutTrancheRequest {
                note_id: note_id.clone(),
                seniority,
                token_id: format!("dcat-gulf-wind-2026-{}", seniority.loss_priority()),
                holder_set_root: fixture_root("holder-set", index as u64),
                notional_commitment: commitment("tranche-notional", index as u64),
                premium_claim_commitment: commitment("tranche-premium", index as u64),
                loss_absorption_bps: 2_500,
                payout_waterfall_bps: 2_500 + index as u64 * 500,
                residual_claim_bps: 7_500 - index as u64 * 500,
                tokenized_supply_commitment: commitment("tranche-supply", index as u64),
                transfer_hook_root: fixture_root("transfer-hook", index as u64),
                tranche_nonce: format!("devnet-tranche-{index}"),
            })
            .expect("devnet tranche fixture must be valid");
    }
    let settlement_id = state
        .post_settlement_batch(PostSettlementBatchRequest {
            auction_ids: vec![auction_id.clone()],
            note_ids: vec![note_id.clone()],
            trigger_ids: vec![trigger_id],
            netted_premium_root: fixture_root("netted-premium", 0),
            netted_collateral_root: fixture_root("netted-collateral", 0),
            claim_payout_root: fixture_root("claim-payout", 0),
            tranche_waterfall_root: fixture_root("tranche-waterfall", 0),
            token_transfer_root: fixture_root("token-transfer", 0),
            fee_root: fixture_root("fee", 0),
            rebate_root: fixture_root("settlement-rebate", 0),
            nullifier_root: fixture_root("settlement-nullifier", 0),
            batch_privacy_set_size: state.config.batch_privacy_set,
            settlement_height:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_DEVNET_HEIGHT
                    + 10_200,
            settlement_proof_root: fixture_root("settlement-proof", 0),
            operator_commitment: commitment("operator", 0),
            batch_nonce: "devnet-settlement-0".to_string(),
        })
        .expect("devnet settlement fixture must be valid");
    state
        .publish_fee_rebate(PublishFeeRebateRequest {
            settlement_id: settlement_id.clone(),
            auction_id,
            beneficiary_commitment: commitment("rebate-beneficiary", 0),
            fee_asset_id: state.config.fee_asset_id.clone(),
            gross_fee_commitment: commitment("gross-fee", 0),
            rebate_commitment: commitment("rebate", 0),
            rebate_bps: state.config.rebate_bps,
            low_fee_reason_root: fixture_root("low-fee-reason", 0),
            rebate_nullifier: fixture_root("rebate-nullifier", 0),
            rebate_nonce: "devnet-rebate-0".to_string(),
        })
        .expect("devnet rebate fixture must be valid");
    state
        .create_compliance_view(CreateComplianceViewRequest {
            subject_id: note_id,
            scope: ComplianceScope::InsuranceRegulator,
            viewer_commitment: commitment("regulator", 0),
            disclosed_fields_root: fixture_root("disclosed-fields", 0),
            redacted_record_root: fixture_root("redacted-record", 0),
            policy_root: fixture_root("policy", 0),
            jurisdiction_commitment: commitment("jurisdiction", 0),
            expiry_height:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_DEVNET_HEIGHT
                    + 86_400,
            pq_disclosure_attestation_root: fixture_root("pq-disclosure", 0),
            view_nonce: "devnet-view-0".to_string(),
        })
        .expect("devnet compliance view fixture must be valid");
    state.refresh_operator_summary("devnet-cat-bond-operator-0");
    state.refresh_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn catastrophe_bond_note_id(request: &IssueCatBondNoteRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-CATASTROPHE-BOND-AUCTION-NOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(request.peril.as_str()),
            HashPart::Str(&request.issuer_commitment),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.risk_model_root),
            HashPart::Str(&request.note_nonce),
        ],
        32,
    )
}

pub fn sealed_auction_id(request: &OpenSealedAuctionRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-CATASTROPHE-BOND-AUCTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.note_id),
            HashPart::Str(&request.sealed_order_root),
            HashPart::Str(&request.encrypted_book_root),
            HashPart::Str(&request.replay_nullifier),
            HashPart::Str(&request.auction_nonce),
        ],
        32,
    )
}

pub fn confidential_bid_id(request: &SubmitConfidentialBidRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-CATASTROPHE-BOND-AUCTION-BID-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.auction_id),
            HashPart::Str(request.side.as_str()),
            HashPart::Str(&request.bidder_commitment),
            HashPart::Str(&request.encrypted_terms_root),
            HashPart::Str(&request.bid_nullifier),
            HashPart::Str(&request.bid_nonce),
        ],
        32,
    )
}

pub fn risk_oracle_attestation_id(
    request: &PostRiskOracleAttestationRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-CATASTROPHE-BOND-AUCTION-ORACLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.subject_id),
            HashPart::Str(request.kind.as_str()),
            HashPart::Str(&request.oracle_commitment),
            HashPart::Str(&request.observation_root),
            HashPart::Str(&request.attestation_nonce),
        ],
        32,
    )
}

pub fn event_trigger_id(request: &FinalizeEventTriggerRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-CATASTROPHE-BOND-AUCTION-TRIGGER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.note_id),
            HashPart::Str(request.peril.as_str()),
            HashPart::Str(&request.event_window_root),
            HashPart::Str(&request.parametric_index_root),
            HashPart::Str(&id_list_root(
                "TRIGGER-ATTESTATIONS",
                &request.oracle_attestation_ids,
            )),
            HashPart::Str(&request.trigger_nonce),
        ],
        32,
    )
}

pub fn payout_tranche_id(request: &RegisterPayoutTrancheRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-CATASTROPHE-BOND-AUCTION-TRANCHE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.note_id),
            HashPart::Str(&request.token_id),
            HashPart::Str(&request.holder_set_root),
            HashPart::Str(&request.tranche_nonce),
        ],
        32,
    )
}

pub fn settlement_batch_id(request: &PostSettlementBatchRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-CATASTROPHE-BOND-AUCTION-SETTLEMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&id_list_root("SETTLEMENT-AUCTIONS", &request.auction_ids)),
            HashPart::Str(&id_list_root("SETTLEMENT-NOTES", &request.note_ids)),
            HashPart::Str(&id_list_root("SETTLEMENT-TRIGGERS", &request.trigger_ids)),
            HashPart::Str(&request.settlement_proof_root),
            HashPart::Str(&request.batch_nonce),
        ],
        32,
    )
}

pub fn fee_rebate_id(request: &PublishFeeRebateRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-CATASTROPHE-BOND-AUCTION-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.settlement_id),
            HashPart::Str(&request.auction_id),
            HashPart::Str(&request.beneficiary_commitment),
            HashPart::Str(&request.rebate_nullifier),
            HashPart::Str(&request.rebate_nonce),
        ],
        32,
    )
}

pub fn compliance_view_id(request: &CreateComplianceViewRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-CATASTROPHE-BOND-AUCTION-COMPLIANCE-VIEW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.subject_id),
            HashPart::Str(request.scope.as_str()),
            HashPart::Str(&request.viewer_commitment),
            HashPart::Str(&request.redacted_record_root),
            HashPart::Str(&request.view_nonce),
        ],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-CATASTROPHE-BOND-AUCTION-{domain}"),
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-CATASTROPHE-BOND-AUCTION-{domain}"),
        records,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("STATE", record)
}

fn empty_root(domain: &str) -> String {
    public_record_root(domain, &[])
}

fn id_list_root(domain: &str, ids: &[String]) -> String {
    public_record_root(domain, &ids.iter().map(|id| json!(id)).collect::<Vec<_>>())
}

fn sorted_records(mut records: Vec<Value>) -> Vec<Value> {
    records.sort_by(|left, right| left.to_string().cmp(&right.to_string()));
    records
}

fn fixture_root(label: &str, index: u64) -> String {
    root_from_record(
        "FIXTURE",
        &json!({
            "index": index,
            "label": label,
            "protocol_version": PROTOCOL_VERSION
        }),
    )
}

fn commitment(label: &str, index: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-CATASTROPHE-BOND-AUCTION-COMMITMENT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(index as i128),
        ],
        32,
    )
}

fn require_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

fn require_root(field: &str, value: &str) -> Result<()> {
    require_non_empty(field, value)?;
    if value.len() < 16 {
        return Err(format!("{field} must look like a commitment root"));
    }
    Ok(())
}

fn require_bps(field: &str, value: u64) -> Result<()> {
    if value > PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_CATASTROPHE_BOND_AUCTION_RUNTIME_MAX_BPS {
        Err(format!("{field} exceeds basis point maximum"))
    } else {
        Ok(())
    }
}

fn require_unique(field: &str, values: &[String]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_non_empty(field, value)?;
        if !seen.insert(value) {
            return Err(format!("{field} contains duplicate value {value}"));
        }
    }
    Ok(())
}
