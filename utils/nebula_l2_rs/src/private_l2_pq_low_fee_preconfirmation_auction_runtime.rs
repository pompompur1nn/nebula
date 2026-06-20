use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqLowFeePreconfirmationAuctionRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_LOW_FEE_PRECONFIRMATION_AUCTION_RUNTIME_PROTOCOL_VERSION: &str =
    "private-l2-pq-low-fee-preconfirmation-auction-runtime-v1";
pub const PRIVATE_L2_PQ_LOW_FEE_PRECONFIRMATION_AUCTION_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_LOW_FEE_PRECONFIRMATION_AUCTION_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_LOW_FEE_PRECONFIRMATION_AUCTION_RUNTIME_SIGNATURE_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const PRIVATE_L2_PQ_LOW_FEE_PRECONFIRMATION_AUCTION_RUNTIME_KEM_SUITE: &str =
    "ML-KEM-1024-envelope";
pub const PRIVATE_L2_PQ_LOW_FEE_PRECONFIRMATION_AUCTION_RUNTIME_PRIVACY_FENCE_SUITE: &str =
    "zk-nullifier-fence-v1";
pub const PRIVATE_L2_PQ_LOW_FEE_PRECONFIRMATION_AUCTION_RUNTIME_DEVNET_HEIGHT: u64 = 1_730_000;
pub const DEFAULT_AUCTION_TTL_BLOCKS: u64 = 8;
pub const DEFAULT_INTENT_TTL_BLOCKS: u64 = 12;
pub const DEFAULT_CERTIFICATE_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 16;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 32;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 20;
pub const DEFAULT_TARGET_USER_FEE_BPS: u64 = 8;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 5;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 18;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 512;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 4_096;
pub const DEFAULT_MAX_LATENCY_MS: u64 = 1_200;
pub const DEFAULT_MAX_AUCTIONS: usize = 2_097_152;
pub const DEFAULT_MAX_INTENTS: usize = 16_777_216;
pub const DEFAULT_MAX_BIDS: usize = 16_777_216;
pub const DEFAULT_MAX_CERTIFICATES: usize = 4_194_304;
pub const DEFAULT_MAX_SPONSOR_RESERVATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_RECEIPTS: usize = 4_194_304;
pub const DEFAULT_MAX_REBATES: usize = 4_194_304;
pub const DEFAULT_MAX_FENCES: usize = 8_388_608;
pub const DEFAULT_MAX_SLASHING_EVENTS: usize = 1_048_576;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuctionLane {
    PrivateContractCall,
    ConfidentialDefiSwap,
    TokenMintBurn,
    MoneroBridgeExit,
    PaymentChannelSettle,
    OracleUpdate,
    GovernanceAction,
    EmergencyCircuitBreak,
}

impl AuctionLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateContractCall => "private_contract_call",
            Self::ConfidentialDefiSwap => "confidential_defi_swap",
            Self::TokenMintBurn => "token_mint_burn",
            Self::MoneroBridgeExit => "monero_bridge_exit",
            Self::PaymentChannelSettle => "payment_channel_settle",
            Self::OracleUpdate => "oracle_update",
            Self::GovernanceAction => "governance_action",
            Self::EmergencyCircuitBreak => "emergency_circuit_break",
        }
    }

    pub fn latency_weight(self) -> u64 {
        match self {
            Self::EmergencyCircuitBreak => 10_000,
            Self::PaymentChannelSettle => 8_500,
            Self::PrivateContractCall => 7_500,
            Self::ConfidentialDefiSwap => 7_000,
            Self::MoneroBridgeExit => 6_500,
            Self::TokenMintBurn => 5_500,
            Self::OracleUpdate => 4_500,
            Self::GovernanceAction => 3_000,
        }
    }

    pub fn default_fee_cap_bps(self) -> u64 {
        match self {
            Self::EmergencyCircuitBreak => 40,
            Self::MoneroBridgeExit => 28,
            Self::PaymentChannelSettle => 16,
            Self::PrivateContractCall => 18,
            Self::ConfidentialDefiSwap => 18,
            Self::TokenMintBurn => 14,
            Self::OracleUpdate => 12,
            Self::GovernanceAction => 10,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuctionStatus {
    Open,
    Sealed,
    BidSelected,
    CertificateIssued,
    Settled,
    Cancelled,
    Expired,
}

impl AuctionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::BidSelected => "bid_selected",
            Self::CertificateIssued => "certificate_issued",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IntentStatus {
    Submitted,
    Batched,
    Certified,
    Settled,
    Rebated,
    Cancelled,
    Expired,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Batched => "batched",
            Self::Certified => "certified",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BidStatus {
    Posted,
    Shortlisted,
    Selected,
    Slashed,
    Expired,
    Rejected,
}

impl BidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Shortlisted => "shortlisted",
            Self::Selected => "selected",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CertificateStatus {
    PendingReveal,
    Active,
    Included,
    Challenged,
    Settled,
    Expired,
}

impl CertificateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PendingReveal => "pending_reveal",
            Self::Active => "active",
            Self::Included => "included",
            Self::Challenged => "challenged",
            Self::Settled => "settled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SponsorStatus {
    Reserved,
    Consumed,
    Released,
    Expired,
}

impl SponsorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ReceiptKind {
    L2BlockInclusion,
    MoneroBridgeAnchor,
    RecursiveProofBatch,
    ContractExecution,
    TokenSettlement,
    PaymentChannelClose,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::L2BlockInclusion => "l2_block_inclusion",
            Self::MoneroBridgeAnchor => "monero_bridge_anchor",
            Self::RecursiveProofBatch => "recursive_proof_batch",
            Self::ContractExecution => "contract_execution",
            Self::TokenSettlement => "token_settlement",
            Self::PaymentChannelClose => "payment_channel_close",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RebateStatus {
    Reserved,
    Claimable,
    Claimed,
    Expired,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Claimable => "claimable",
            Self::Claimed => "claimed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FenceKind {
    IntentNullifier,
    BidNullifier,
    CertificateReplay,
    SponsorReplay,
    RebateClaim,
    SettlementReceipt,
    SlashingEvidence,
}

impl FenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IntentNullifier => "intent_nullifier",
            Self::BidNullifier => "bid_nullifier",
            Self::CertificateReplay => "certificate_replay",
            Self::SponsorReplay => "sponsor_replay",
            Self::RebateClaim => "rebate_claim",
            Self::SettlementReceipt => "settlement_receipt",
            Self::SlashingEvidence => "slashing_evidence",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SlashingReason {
    MissedLatencySla,
    InvalidPqSignature,
    DoublePreconfirmation,
    FeeCapViolation,
    PrivacyLeak,
    StaleCertificate,
    InvalidSettlementReceipt,
}

impl SlashingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissedLatencySla => "missed_latency_sla",
            Self::InvalidPqSignature => "invalid_pq_signature",
            Self::DoublePreconfirmation => "double_preconfirmation",
            Self::FeeCapViolation => "fee_cap_violation",
            Self::PrivacyLeak => "privacy_leak",
            Self::StaleCertificate => "stale_certificate",
            Self::InvalidSettlementReceipt => "invalid_settlement_receipt",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub signature_suite: String,
    pub kem_suite: String,
    pub privacy_fence_suite: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub target_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub max_latency_ms: u64,
    pub auction_ttl_blocks: u64,
    pub intent_ttl_blocks: u64,
    pub certificate_ttl_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub settlement_window_blocks: u64,
    pub max_auctions: usize,
    pub max_intents: usize,
    pub max_bids: usize,
    pub max_certificates: usize,
    pub max_sponsor_reservations: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub max_fences: usize,
    pub max_slashing_events: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version:
                PRIVATE_L2_PQ_LOW_FEE_PRECONFIRMATION_AUCTION_RUNTIME_PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_L2_PQ_LOW_FEE_PRECONFIRMATION_AUCTION_RUNTIME_SCHEMA_VERSION,
            hash_suite: PRIVATE_L2_PQ_LOW_FEE_PRECONFIRMATION_AUCTION_RUNTIME_HASH_SUITE
                .to_string(),
            signature_suite: PRIVATE_L2_PQ_LOW_FEE_PRECONFIRMATION_AUCTION_RUNTIME_SIGNATURE_SUITE
                .to_string(),
            kem_suite: PRIVATE_L2_PQ_LOW_FEE_PRECONFIRMATION_AUCTION_RUNTIME_KEM_SUITE.to_string(),
            privacy_fence_suite:
                PRIVATE_L2_PQ_LOW_FEE_PRECONFIRMATION_AUCTION_RUNTIME_PRIVACY_FENCE_SUITE
                    .to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
            max_latency_ms: DEFAULT_MAX_LATENCY_MS,
            auction_ttl_blocks: DEFAULT_AUCTION_TTL_BLOCKS,
            intent_ttl_blocks: DEFAULT_INTENT_TTL_BLOCKS,
            certificate_ttl_blocks: DEFAULT_CERTIFICATE_TTL_BLOCKS,
            sponsor_ttl_blocks: DEFAULT_SPONSOR_TTL_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            settlement_window_blocks: DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            max_auctions: DEFAULT_MAX_AUCTIONS,
            max_intents: DEFAULT_MAX_INTENTS,
            max_bids: DEFAULT_MAX_BIDS,
            max_certificates: DEFAULT_MAX_CERTIFICATES,
            max_sponsor_reservations: DEFAULT_MAX_SPONSOR_RESERVATIONS,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_fences: DEFAULT_MAX_FENCES,
            max_slashing_events: DEFAULT_MAX_SLASHING_EVENTS,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("protocol version", &self.protocol_version)?;
        require_non_empty("hash suite", &self.hash_suite)?;
        require_non_empty("signature suite", &self.signature_suite)?;
        require_non_empty("kem suite", &self.kem_suite)?;
        require_non_empty("privacy fence suite", &self.privacy_fence_suite)?;
        require_positive_u64("min privacy set size", self.min_privacy_set_size)?;
        require_positive_u64("batch privacy set size", self.batch_privacy_set_size)?;
        require_positive_u64("auction ttl blocks", self.auction_ttl_blocks)?;
        require_positive_u64("intent ttl blocks", self.intent_ttl_blocks)?;
        require_positive_u64("certificate ttl blocks", self.certificate_ttl_blocks)?;
        require_positive_u64("sponsor ttl blocks", self.sponsor_ttl_blocks)?;
        require_positive_u64("rebate ttl blocks", self.rebate_ttl_blocks)?;
        require_positive_u64("settlement window blocks", self.settlement_window_blocks)?;
        require_positive_u64("max latency ms", self.max_latency_ms)?;
        require_positive_usize("max auctions", self.max_auctions)?;
        require_positive_usize("max intents", self.max_intents)?;
        require_positive_usize("max bids", self.max_bids)?;
        require_positive_usize("max certificates", self.max_certificates)?;
        require_positive_usize("max sponsor reservations", self.max_sponsor_reservations)?;
        require_positive_usize("max receipts", self.max_receipts)?;
        require_positive_usize("max rebates", self.max_rebates)?;
        require_positive_usize("max fences", self.max_fences)?;
        require_positive_usize("max slashing events", self.max_slashing_events)?;
        require_bps("max user fee bps", self.max_user_fee_bps)?;
        require_bps("target user fee bps", self.target_user_fee_bps)?;
        require_bps("target rebate bps", self.target_rebate_bps)?;
        require_bps("max rebate bps", self.max_rebate_bps)?;
        if self.target_user_fee_bps > self.max_user_fee_bps {
            return Err("target user fee cannot exceed max user fee".to_string());
        }
        if self.target_rebate_bps > self.max_rebate_bps {
            return Err("target rebate cannot exceed max rebate".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq security bits below runtime minimum".to_string());
        }
        if self.batch_privacy_set_size < self.min_privacy_set_size {
            return Err("batch privacy set cannot be below minimum privacy set".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_low_fee_preconfirmation_auction_runtime_config",
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "signature_suite": self.signature_suite,
            "kem_suite": self.kem_suite,
            "privacy_fence_suite": self.privacy_fence_suite,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_user_fee_bps": self.target_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "max_latency_ms": self.max_latency_ms,
            "auction_ttl_blocks": self.auction_ttl_blocks,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "certificate_ttl_blocks": self.certificate_ttl_blocks,
            "sponsor_ttl_blocks": self.sponsor_ttl_blocks,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "settlement_window_blocks": self.settlement_window_blocks,
            "max_auctions": self.max_auctions,
            "max_intents": self.max_intents,
            "max_bids": self.max_bids,
            "max_certificates": self.max_certificates,
            "max_sponsor_reservations": self.max_sponsor_reservations,
            "max_receipts": self.max_receipts,
            "max_rebates": self.max_rebates,
            "max_fences": self.max_fences,
            "max_slashing_events": self.max_slashing_events,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub auctions_opened: u64,
    pub intents_submitted: u64,
    pub bids_posted: u64,
    pub certificates_issued: u64,
    pub sponsor_reservations: u64,
    pub receipts_published: u64,
    pub rebates_issued: u64,
    pub privacy_fences: u64,
    pub slashing_events: u64,
    pub nullifiers_spent: u64,
    pub total_fee_micro_units: u128,
    pub total_rebate_micro_units: u128,
    pub total_sponsor_coverage_micro_units: u128,
    pub total_bond_micro_units: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_low_fee_preconfirmation_auction_runtime_counters",
            "auctions_opened": self.auctions_opened,
            "intents_submitted": self.intents_submitted,
            "bids_posted": self.bids_posted,
            "certificates_issued": self.certificates_issued,
            "sponsor_reservations": self.sponsor_reservations,
            "receipts_published": self.receipts_published,
            "rebates_issued": self.rebates_issued,
            "privacy_fences": self.privacy_fences,
            "slashing_events": self.slashing_events,
            "nullifiers_spent": self.nullifiers_spent,
            "total_fee_micro_units": self.total_fee_micro_units.to_string(),
            "total_rebate_micro_units": self.total_rebate_micro_units.to_string(),
            "total_sponsor_coverage_micro_units": self.total_sponsor_coverage_micro_units.to_string(),
            "total_bond_micro_units": self.total_bond_micro_units.to_string(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub counter_root: String,
    pub auction_root: String,
    pub intent_root: String,
    pub bid_root: String,
    pub certificate_root: String,
    pub sponsor_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub privacy_fence_root: String,
    pub slashing_root: String,
    pub nullifier_root: String,
    pub event_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            config_root: empty_root("CONFIG"),
            counter_root: empty_root("COUNTERS"),
            auction_root: empty_root("AUCTIONS"),
            intent_root: empty_root("INTENTS"),
            bid_root: empty_root("BIDS"),
            certificate_root: empty_root("CERTIFICATES"),
            sponsor_root: empty_root("SPONSORS"),
            receipt_root: empty_root("RECEIPTS"),
            rebate_root: empty_root("REBATES"),
            privacy_fence_root: empty_root("PRIVACY-FENCES"),
            slashing_root: empty_root("SLASHING"),
            nullifier_root: empty_root("NULLIFIERS"),
            event_root: empty_root("EVENTS"),
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_low_fee_preconfirmation_auction_runtime_roots",
            "config_root": self.config_root,
            "counter_root": self.counter_root,
            "auction_root": self.auction_root,
            "intent_root": self.intent_root,
            "bid_root": self.bid_root,
            "certificate_root": self.certificate_root,
            "sponsor_root": self.sponsor_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
            "privacy_fence_root": self.privacy_fence_root,
            "slashing_root": self.slashing_root,
            "nullifier_root": self.nullifier_root,
            "event_root": self.event_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenAuctionRequest {
    pub lane: AuctionLane,
    pub domain_label: String,
    pub encrypted_call_bundle_root: String,
    pub intent_set_root: String,
    pub fee_asset_id: String,
    pub max_user_fee_bps: u64,
    pub target_latency_ms: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub sponsor_required: bool,
    pub opens_at_height: u64,
    pub ttl_blocks: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreconfirmationAuction {
    pub auction_id: String,
    pub lane: AuctionLane,
    pub status: AuctionStatus,
    pub domain_label: String,
    pub encrypted_call_bundle_root: String,
    pub intent_set_root: String,
    pub fee_asset_id: String,
    pub max_user_fee_bps: u64,
    pub target_latency_ms: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub sponsor_required: bool,
    pub selected_bid_id: String,
    pub certificate_id: String,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
}

impl PreconfirmationAuction {
    pub fn from_request(
        request: OpenAuctionRequest,
        sequence: u64,
        config: &Config,
    ) -> Result<Self> {
        request.validate(config)?;
        let auction_id = auction_id(&request, sequence);
        Ok(Self {
            auction_id,
            lane: request.lane,
            status: AuctionStatus::Open,
            domain_label: request.domain_label,
            encrypted_call_bundle_root: request.encrypted_call_bundle_root,
            intent_set_root: request.intent_set_root,
            fee_asset_id: request.fee_asset_id,
            max_user_fee_bps: request.max_user_fee_bps,
            target_latency_ms: request.target_latency_ms,
            min_privacy_set_size: request.min_privacy_set_size,
            min_pq_security_bits: request.min_pq_security_bits,
            sponsor_required: request.sponsor_required,
            selected_bid_id: String::new(),
            certificate_id: String::new(),
            opened_at_height: request.opens_at_height,
            closes_at_height: request.opens_at_height.saturating_add(request.ttl_blocks),
        })
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("auction id", &self.auction_id)?;
        require_non_empty("domain label", &self.domain_label)?;
        require_root(
            "encrypted call bundle root",
            &self.encrypted_call_bundle_root,
        )?;
        require_root("intent set root", &self.intent_set_root)?;
        require_non_empty("fee asset id", &self.fee_asset_id)?;
        require_bps("max user fee bps", self.max_user_fee_bps)?;
        require_positive_u64("target latency ms", self.target_latency_ms)?;
        if self.max_user_fee_bps > config.max_user_fee_bps.max(self.lane.default_fee_cap_bps()) {
            return Err("auction fee cap exceeds configured maximum".to_string());
        }
        if self.target_latency_ms > config.max_latency_ms {
            return Err("auction target latency exceeds configured maximum".to_string());
        }
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("auction privacy set below configured minimum".to_string());
        }
        if self.min_pq_security_bits < config.min_pq_security_bits {
            return Err("auction pq security below configured minimum".to_string());
        }
        if self.closes_at_height <= self.opened_at_height {
            return Err("auction closes before it opens".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_low_fee_preconfirmation_auction",
            "auction_id": self.auction_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "domain_label": self.domain_label,
            "encrypted_call_bundle_root": self.encrypted_call_bundle_root,
            "intent_set_root": self.intent_set_root,
            "fee_asset_id": self.fee_asset_id,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_latency_ms": self.target_latency_ms,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "sponsor_required": self.sponsor_required,
            "selected_bid_id": self.selected_bid_id,
            "certificate_id": self.certificate_id,
            "opened_at_height": self.opened_at_height,
            "closes_at_height": self.closes_at_height,
        })
    }
}

impl OpenAuctionRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("domain label", &self.domain_label)?;
        require_root(
            "encrypted call bundle root",
            &self.encrypted_call_bundle_root,
        )?;
        require_root("intent set root", &self.intent_set_root)?;
        require_non_empty("fee asset id", &self.fee_asset_id)?;
        require_bps("max user fee bps", self.max_user_fee_bps)?;
        require_positive_u64("target latency ms", self.target_latency_ms)?;
        require_positive_u64("ttl blocks", self.ttl_blocks)?;
        if self.ttl_blocks > config.auction_ttl_blocks.saturating_mul(16) {
            return Err("auction ttl too large".to_string());
        }
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("auction request privacy set below configured minimum".to_string());
        }
        if self.min_pq_security_bits < config.min_pq_security_bits {
            return Err("auction request pq security below configured minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitIntentRequest {
    pub auction_id: String,
    pub sender_commitment: String,
    pub contract_commitment: String,
    pub encrypted_call_root: String,
    pub max_fee_micro_units: u64,
    pub priority_fee_micro_units: u64,
    pub privacy_set_size: u64,
    pub nullifier_root: String,
    pub pq_envelope_root: String,
    pub submitted_at_height: u64,
    pub ttl_blocks: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedPreconfirmationIntent {
    pub intent_id: String,
    pub auction_id: String,
    pub status: IntentStatus,
    pub sender_commitment: String,
    pub contract_commitment: String,
    pub encrypted_call_root: String,
    pub max_fee_micro_units: u64,
    pub priority_fee_micro_units: u64,
    pub privacy_set_size: u64,
    pub nullifier_root: String,
    pub pq_envelope_root: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl EncryptedPreconfirmationIntent {
    pub fn from_request(
        request: SubmitIntentRequest,
        sequence: u64,
        config: &Config,
    ) -> Result<Self> {
        request.validate(config)?;
        let intent_id = intent_id(&request, sequence);
        Ok(Self {
            intent_id,
            auction_id: request.auction_id,
            status: IntentStatus::Submitted,
            sender_commitment: request.sender_commitment,
            contract_commitment: request.contract_commitment,
            encrypted_call_root: request.encrypted_call_root,
            max_fee_micro_units: request.max_fee_micro_units,
            priority_fee_micro_units: request.priority_fee_micro_units,
            privacy_set_size: request.privacy_set_size,
            nullifier_root: request.nullifier_root,
            pq_envelope_root: request.pq_envelope_root,
            submitted_at_height: request.submitted_at_height,
            expires_at_height: request
                .submitted_at_height
                .saturating_add(request.ttl_blocks),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_low_fee_preconfirmation_intent",
            "intent_id": self.intent_id,
            "auction_id": self.auction_id,
            "status": self.status.as_str(),
            "sender_commitment": self.sender_commitment,
            "contract_commitment": self.contract_commitment,
            "encrypted_call_root": self.encrypted_call_root,
            "max_fee_micro_units": self.max_fee_micro_units,
            "priority_fee_micro_units": self.priority_fee_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "nullifier_root": self.nullifier_root,
            "pq_envelope_root": self.pq_envelope_root,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

impl SubmitIntentRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("auction id", &self.auction_id)?;
        require_non_empty("sender commitment", &self.sender_commitment)?;
        require_non_empty("contract commitment", &self.contract_commitment)?;
        require_root("encrypted call root", &self.encrypted_call_root)?;
        require_root("nullifier root", &self.nullifier_root)?;
        require_root("pq envelope root", &self.pq_envelope_root)?;
        require_positive_u64("max fee micro units", self.max_fee_micro_units)?;
        require_positive_u64("ttl blocks", self.ttl_blocks)?;
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("intent privacy set below configured minimum".to_string());
        }
        if self.priority_fee_micro_units > self.max_fee_micro_units {
            return Err("priority fee exceeds max fee".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostSequencerBidRequest {
    pub auction_id: String,
    pub sequencer_commitment: String,
    pub max_latency_ms: u64,
    pub fee_bps: u64,
    pub bond_micro_units: u64,
    pub pq_attestation_root: String,
    pub bid_ciphertext_root: String,
    pub bond_note_root: String,
    pub relay_hint_root: String,
    pub posted_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencerBid {
    pub bid_id: String,
    pub auction_id: String,
    pub status: BidStatus,
    pub sequencer_commitment: String,
    pub max_latency_ms: u64,
    pub fee_bps: u64,
    pub bond_micro_units: u64,
    pub pq_attestation_root: String,
    pub bid_ciphertext_root: String,
    pub bond_note_root: String,
    pub relay_hint_root: String,
    pub score: u64,
    pub posted_at_height: u64,
}

impl SequencerBid {
    pub fn from_request(
        request: PostSequencerBidRequest,
        auction: &PreconfirmationAuction,
        sequence: u64,
        config: &Config,
    ) -> Result<Self> {
        request.validate(auction, config)?;
        let score = bid_score(&request, auction);
        let bid_id = bid_id(&request, sequence);
        Ok(Self {
            bid_id,
            auction_id: request.auction_id,
            status: BidStatus::Posted,
            sequencer_commitment: request.sequencer_commitment,
            max_latency_ms: request.max_latency_ms,
            fee_bps: request.fee_bps,
            bond_micro_units: request.bond_micro_units,
            pq_attestation_root: request.pq_attestation_root,
            bid_ciphertext_root: request.bid_ciphertext_root,
            bond_note_root: request.bond_note_root,
            relay_hint_root: request.relay_hint_root,
            score,
            posted_at_height: request.posted_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_low_fee_preconfirmation_sequencer_bid",
            "bid_id": self.bid_id,
            "auction_id": self.auction_id,
            "status": self.status.as_str(),
            "sequencer_commitment": self.sequencer_commitment,
            "max_latency_ms": self.max_latency_ms,
            "fee_bps": self.fee_bps,
            "bond_micro_units": self.bond_micro_units,
            "pq_attestation_root": self.pq_attestation_root,
            "bid_ciphertext_root": self.bid_ciphertext_root,
            "bond_note_root": self.bond_note_root,
            "relay_hint_root": self.relay_hint_root,
            "score": self.score,
            "posted_at_height": self.posted_at_height,
        })
    }
}

impl PostSequencerBidRequest {
    pub fn validate(&self, auction: &PreconfirmationAuction, config: &Config) -> Result<()> {
        ensure_eq(&self.auction_id, &auction.auction_id, "auction id")?;
        require_non_empty("sequencer commitment", &self.sequencer_commitment)?;
        require_root("pq attestation root", &self.pq_attestation_root)?;
        require_root("bid ciphertext root", &self.bid_ciphertext_root)?;
        require_root("bond note root", &self.bond_note_root)?;
        require_root("relay hint root", &self.relay_hint_root)?;
        require_bps("fee bps", self.fee_bps)?;
        require_positive_u64("max latency ms", self.max_latency_ms)?;
        require_positive_u64("bond micro units", self.bond_micro_units)?;
        if self.fee_bps > auction.max_user_fee_bps {
            return Err("bid fee exceeds auction cap".to_string());
        }
        if self.max_latency_ms > auction.target_latency_ms.max(config.max_latency_ms) {
            return Err("bid latency exceeds runtime maximum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveSponsorRequest {
    pub auction_id: String,
    pub sponsor_commitment: String,
    pub covered_intent_ids: Vec<String>,
    pub max_coverage_micro_units: u64,
    pub coverage_bps: u64,
    pub sponsor_note_root: String,
    pub nullifier_root: String,
    pub reserved_at_height: u64,
    pub ttl_blocks: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorReservation {
    pub reservation_id: String,
    pub auction_id: String,
    pub status: SponsorStatus,
    pub sponsor_commitment: String,
    pub covered_intent_ids: Vec<String>,
    pub max_coverage_micro_units: u64,
    pub coverage_bps: u64,
    pub sponsor_note_root: String,
    pub nullifier_root: String,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl SponsorReservation {
    pub fn from_request(
        request: ReserveSponsorRequest,
        sequence: u64,
        config: &Config,
    ) -> Result<Self> {
        request.validate(config)?;
        let reservation_id = sponsor_reservation_id(&request, sequence);
        Ok(Self {
            reservation_id,
            auction_id: request.auction_id,
            status: SponsorStatus::Reserved,
            sponsor_commitment: request.sponsor_commitment,
            covered_intent_ids: request.covered_intent_ids,
            max_coverage_micro_units: request.max_coverage_micro_units,
            coverage_bps: request.coverage_bps,
            sponsor_note_root: request.sponsor_note_root,
            nullifier_root: request.nullifier_root,
            reserved_at_height: request.reserved_at_height,
            expires_at_height: request
                .reserved_at_height
                .saturating_add(request.ttl_blocks),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_low_fee_preconfirmation_sponsor_reservation",
            "reservation_id": self.reservation_id,
            "auction_id": self.auction_id,
            "status": self.status.as_str(),
            "sponsor_commitment": self.sponsor_commitment,
            "covered_intent_ids": self.covered_intent_ids,
            "max_coverage_micro_units": self.max_coverage_micro_units,
            "coverage_bps": self.coverage_bps,
            "sponsor_note_root": self.sponsor_note_root,
            "nullifier_root": self.nullifier_root,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

impl ReserveSponsorRequest {
    pub fn validate(&self, _config: &Config) -> Result<()> {
        require_non_empty("auction id", &self.auction_id)?;
        require_non_empty("sponsor commitment", &self.sponsor_commitment)?;
        require_non_empty_vec("covered intent ids", &self.covered_intent_ids)?;
        require_root("sponsor note root", &self.sponsor_note_root)?;
        require_root("nullifier root", &self.nullifier_root)?;
        require_positive_u64("max coverage micro units", self.max_coverage_micro_units)?;
        require_positive_u64("ttl blocks", self.ttl_blocks)?;
        require_bps("coverage bps", self.coverage_bps)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueCertificateRequest {
    pub auction_id: String,
    pub winning_bid_id: String,
    pub intent_ids: Vec<String>,
    pub sponsor_reservation_ids: Vec<String>,
    pub encrypted_batch_root: String,
    pub state_access_root: String,
    pub fee_schedule_root: String,
    pub pq_signature_root: String,
    pub committee_attestation_root: String,
    pub issued_at_height: u64,
    pub ttl_blocks: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreconfirmationCertificate {
    pub certificate_id: String,
    pub auction_id: String,
    pub winning_bid_id: String,
    pub status: CertificateStatus,
    pub intent_ids: Vec<String>,
    pub sponsor_reservation_ids: Vec<String>,
    pub encrypted_batch_root: String,
    pub state_access_root: String,
    pub fee_schedule_root: String,
    pub pq_signature_root: String,
    pub committee_attestation_root: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl PreconfirmationCertificate {
    pub fn from_request(request: IssueCertificateRequest, sequence: u64) -> Result<Self> {
        request.validate()?;
        let certificate_id = certificate_id(&request, sequence);
        Ok(Self {
            certificate_id,
            auction_id: request.auction_id,
            winning_bid_id: request.winning_bid_id,
            status: CertificateStatus::Active,
            intent_ids: request.intent_ids,
            sponsor_reservation_ids: request.sponsor_reservation_ids,
            encrypted_batch_root: request.encrypted_batch_root,
            state_access_root: request.state_access_root,
            fee_schedule_root: request.fee_schedule_root,
            pq_signature_root: request.pq_signature_root,
            committee_attestation_root: request.committee_attestation_root,
            issued_at_height: request.issued_at_height,
            expires_at_height: request.issued_at_height.saturating_add(request.ttl_blocks),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_low_fee_preconfirmation_certificate",
            "certificate_id": self.certificate_id,
            "auction_id": self.auction_id,
            "winning_bid_id": self.winning_bid_id,
            "status": self.status.as_str(),
            "intent_ids": self.intent_ids,
            "sponsor_reservation_ids": self.sponsor_reservation_ids,
            "encrypted_batch_root": self.encrypted_batch_root,
            "state_access_root": self.state_access_root,
            "fee_schedule_root": self.fee_schedule_root,
            "pq_signature_root": self.pq_signature_root,
            "committee_attestation_root": self.committee_attestation_root,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

impl IssueCertificateRequest {
    pub fn validate(&self) -> Result<()> {
        require_non_empty("auction id", &self.auction_id)?;
        require_non_empty("winning bid id", &self.winning_bid_id)?;
        require_non_empty_vec("intent ids", &self.intent_ids)?;
        require_root("encrypted batch root", &self.encrypted_batch_root)?;
        require_root("state access root", &self.state_access_root)?;
        require_root("fee schedule root", &self.fee_schedule_root)?;
        require_root("pq signature root", &self.pq_signature_root)?;
        require_root(
            "committee attestation root",
            &self.committee_attestation_root,
        )?;
        require_positive_u64("ttl blocks", self.ttl_blocks)?;
        ensure_unique("intent ids", &self.intent_ids)?;
        ensure_unique("sponsor reservation ids", &self.sponsor_reservation_ids)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishSettlementReceiptRequest {
    pub certificate_id: String,
    pub auction_id: String,
    pub receipt_kind: ReceiptKind,
    pub inclusion_root: String,
    pub execution_receipt_root: String,
    pub paid_fee_micro_units: u64,
    pub actual_latency_ms: u64,
    pub included_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub certificate_id: String,
    pub auction_id: String,
    pub receipt_kind: ReceiptKind,
    pub inclusion_root: String,
    pub execution_receipt_root: String,
    pub paid_fee_micro_units: u64,
    pub actual_latency_ms: u64,
    pub included_at_height: u64,
}

impl SettlementReceipt {
    pub fn from_request(request: PublishSettlementReceiptRequest, sequence: u64) -> Result<Self> {
        request.validate()?;
        let receipt_id = settlement_receipt_id(&request, sequence);
        Ok(Self {
            receipt_id,
            certificate_id: request.certificate_id,
            auction_id: request.auction_id,
            receipt_kind: request.receipt_kind,
            inclusion_root: request.inclusion_root,
            execution_receipt_root: request.execution_receipt_root,
            paid_fee_micro_units: request.paid_fee_micro_units,
            actual_latency_ms: request.actual_latency_ms,
            included_at_height: request.included_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_low_fee_preconfirmation_settlement_receipt",
            "receipt_id": self.receipt_id,
            "certificate_id": self.certificate_id,
            "auction_id": self.auction_id,
            "receipt_kind": self.receipt_kind.as_str(),
            "inclusion_root": self.inclusion_root,
            "execution_receipt_root": self.execution_receipt_root,
            "paid_fee_micro_units": self.paid_fee_micro_units,
            "actual_latency_ms": self.actual_latency_ms,
            "included_at_height": self.included_at_height,
        })
    }
}

impl PublishSettlementReceiptRequest {
    pub fn validate(&self) -> Result<()> {
        require_non_empty("certificate id", &self.certificate_id)?;
        require_non_empty("auction id", &self.auction_id)?;
        require_root("inclusion root", &self.inclusion_root)?;
        require_root("execution receipt root", &self.execution_receipt_root)?;
        require_positive_u64("paid fee micro units", self.paid_fee_micro_units)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueFeeRebateRequest {
    pub receipt_id: String,
    pub beneficiary_commitment: String,
    pub rebate_note_root: String,
    pub rebate_micro_units: u64,
    pub rebate_bps: u64,
    pub issued_at_height: u64,
    pub ttl_blocks: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub receipt_id: String,
    pub status: RebateStatus,
    pub beneficiary_commitment: String,
    pub rebate_note_root: String,
    pub rebate_micro_units: u64,
    pub rebate_bps: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl FeeRebate {
    pub fn from_request(
        request: IssueFeeRebateRequest,
        sequence: u64,
        config: &Config,
    ) -> Result<Self> {
        request.validate(config)?;
        let rebate_id = rebate_id(&request, sequence);
        Ok(Self {
            rebate_id,
            receipt_id: request.receipt_id,
            status: RebateStatus::Claimable,
            beneficiary_commitment: request.beneficiary_commitment,
            rebate_note_root: request.rebate_note_root,
            rebate_micro_units: request.rebate_micro_units,
            rebate_bps: request.rebate_bps,
            issued_at_height: request.issued_at_height,
            expires_at_height: request.issued_at_height.saturating_add(request.ttl_blocks),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_low_fee_preconfirmation_fee_rebate",
            "rebate_id": self.rebate_id,
            "receipt_id": self.receipt_id,
            "status": self.status.as_str(),
            "beneficiary_commitment": self.beneficiary_commitment,
            "rebate_note_root": self.rebate_note_root,
            "rebate_micro_units": self.rebate_micro_units,
            "rebate_bps": self.rebate_bps,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

impl IssueFeeRebateRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("receipt id", &self.receipt_id)?;
        require_non_empty("beneficiary commitment", &self.beneficiary_commitment)?;
        require_root("rebate note root", &self.rebate_note_root)?;
        require_positive_u64("rebate micro units", self.rebate_micro_units)?;
        require_positive_u64("ttl blocks", self.ttl_blocks)?;
        require_bps("rebate bps", self.rebate_bps)?;
        if self.rebate_bps > config.max_rebate_bps {
            return Err("rebate bps exceeds configured maximum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenPrivacyFenceRequest {
    pub fence_kind: FenceKind,
    pub subject_id: String,
    pub commitment_root: String,
    pub nullifier_root: String,
    pub replay_domain: String,
    pub privacy_set_size: u64,
    pub opened_at_height: u64,
    pub ttl_blocks: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub fence_kind: FenceKind,
    pub subject_id: String,
    pub commitment_root: String,
    pub nullifier_root: String,
    pub replay_domain: String,
    pub privacy_set_size: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivacyFence {
    pub fn from_request(
        request: OpenPrivacyFenceRequest,
        sequence: u64,
        config: &Config,
    ) -> Result<Self> {
        request.validate(config)?;
        let fence_id = privacy_fence_id(&request, sequence);
        Ok(Self {
            fence_id,
            fence_kind: request.fence_kind,
            subject_id: request.subject_id,
            commitment_root: request.commitment_root,
            nullifier_root: request.nullifier_root,
            replay_domain: request.replay_domain,
            privacy_set_size: request.privacy_set_size,
            opened_at_height: request.opened_at_height,
            expires_at_height: request.opened_at_height.saturating_add(request.ttl_blocks),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_low_fee_preconfirmation_privacy_fence",
            "fence_id": self.fence_id,
            "fence_kind": self.fence_kind.as_str(),
            "subject_id": self.subject_id,
            "commitment_root": self.commitment_root,
            "nullifier_root": self.nullifier_root,
            "replay_domain": self.replay_domain,
            "privacy_set_size": self.privacy_set_size,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

impl OpenPrivacyFenceRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("subject id", &self.subject_id)?;
        require_root("commitment root", &self.commitment_root)?;
        require_root("nullifier root", &self.nullifier_root)?;
        require_non_empty("replay domain", &self.replay_domain)?;
        require_positive_u64("ttl blocks", self.ttl_blocks)?;
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("privacy fence set below configured minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordSlashingEventRequest {
    pub auction_id: String,
    pub bid_id: String,
    pub certificate_id: String,
    pub reason: SlashingReason,
    pub evidence_root: String,
    pub slashed_bond_micro_units: u64,
    pub reporter_commitment: String,
    pub pq_signature_root: String,
    pub recorded_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingEvent {
    pub slash_id: String,
    pub auction_id: String,
    pub bid_id: String,
    pub certificate_id: String,
    pub reason: SlashingReason,
    pub evidence_root: String,
    pub slashed_bond_micro_units: u64,
    pub reporter_commitment: String,
    pub pq_signature_root: String,
    pub recorded_at_height: u64,
}

impl SlashingEvent {
    pub fn from_request(request: RecordSlashingEventRequest, sequence: u64) -> Result<Self> {
        request.validate()?;
        let slash_id = slashing_event_id(&request, sequence);
        Ok(Self {
            slash_id,
            auction_id: request.auction_id,
            bid_id: request.bid_id,
            certificate_id: request.certificate_id,
            reason: request.reason,
            evidence_root: request.evidence_root,
            slashed_bond_micro_units: request.slashed_bond_micro_units,
            reporter_commitment: request.reporter_commitment,
            pq_signature_root: request.pq_signature_root,
            recorded_at_height: request.recorded_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_low_fee_preconfirmation_slashing_event",
            "slash_id": self.slash_id,
            "auction_id": self.auction_id,
            "bid_id": self.bid_id,
            "certificate_id": self.certificate_id,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "slashed_bond_micro_units": self.slashed_bond_micro_units,
            "reporter_commitment": self.reporter_commitment,
            "pq_signature_root": self.pq_signature_root,
            "recorded_at_height": self.recorded_at_height,
        })
    }
}

impl RecordSlashingEventRequest {
    pub fn validate(&self) -> Result<()> {
        require_non_empty("auction id", &self.auction_id)?;
        require_non_empty("bid id", &self.bid_id)?;
        require_non_empty("certificate id", &self.certificate_id)?;
        require_root("evidence root", &self.evidence_root)?;
        require_non_empty("reporter commitment", &self.reporter_commitment)?;
        require_root("pq signature root", &self.pq_signature_root)?;
        require_positive_u64("slashed bond micro units", self.slashed_bond_micro_units)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_low_fee_preconfirmation_runtime_event",
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub current_height: u64,
    pub auctions: BTreeMap<String, PreconfirmationAuction>,
    pub intents: BTreeMap<String, EncryptedPreconfirmationIntent>,
    pub bids: BTreeMap<String, SequencerBid>,
    pub certificates: BTreeMap<String, PreconfirmationCertificate>,
    pub sponsor_reservations: BTreeMap<String, SponsorReservation>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub slashing_events: BTreeMap<String, SlashingEvent>,
    pub nullifiers: BTreeSet<String>,
    pub events: Vec<RuntimeEvent>,
}

impl State {
    pub fn new(config: Config, current_height: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            current_height,
            auctions: BTreeMap::new(),
            intents: BTreeMap::new(),
            bids: BTreeMap::new(),
            certificates: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            slashing_events: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            events: Vec::new(),
        };
        state.recompute_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let height = PRIVATE_L2_PQ_LOW_FEE_PRECONFIRMATION_AUCTION_RUNTIME_DEVNET_HEIGHT;
        let mut state = Self::new(Config::devnet(), height).expect("valid devnet config");
        let auction = state
            .open_auction(OpenAuctionRequest {
                lane: AuctionLane::PrivateContractCall,
                domain_label: "devnet-private-contract-call-auction".to_string(),
                encrypted_call_bundle_root: commitment("devnet-call-bundle"),
                intent_set_root: commitment("devnet-intent-set"),
                fee_asset_id: "xmr-private-fee-note".to_string(),
                max_user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
                target_latency_ms: 450,
                min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
                min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                sponsor_required: true,
                opens_at_height: height,
                ttl_blocks: DEFAULT_AUCTION_TTL_BLOCKS,
            })
            .expect("devnet auction");
        let intent = state
            .submit_intent(SubmitIntentRequest {
                auction_id: auction.clone(),
                sender_commitment: commitment("devnet-sender"),
                contract_commitment: commitment("devnet-contract"),
                encrypted_call_root: commitment("devnet-encrypted-call"),
                max_fee_micro_units: 18_000,
                priority_fee_micro_units: 2_000,
                privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
                nullifier_root: commitment("devnet-intent-nullifier"),
                pq_envelope_root: commitment("devnet-pq-envelope"),
                submitted_at_height: height.saturating_add(1),
                ttl_blocks: DEFAULT_INTENT_TTL_BLOCKS,
            })
            .expect("devnet intent");
        let bid = state
            .post_bid(PostSequencerBidRequest {
                auction_id: auction.clone(),
                sequencer_commitment: commitment("devnet-sequencer"),
                max_latency_ms: 320,
                fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
                bond_micro_units: 3_000_000,
                pq_attestation_root: commitment("devnet-bid-pq-attestation"),
                bid_ciphertext_root: commitment("devnet-bid-ciphertext"),
                bond_note_root: commitment("devnet-bond-note"),
                relay_hint_root: commitment("devnet-relay-hint"),
                posted_at_height: height.saturating_add(2),
            })
            .expect("devnet bid");
        let sponsor = state
            .reserve_sponsor(ReserveSponsorRequest {
                auction_id: auction.clone(),
                sponsor_commitment: commitment("devnet-sponsor"),
                covered_intent_ids: vec![intent.clone()],
                max_coverage_micro_units: 18_000,
                coverage_bps: 7_500,
                sponsor_note_root: commitment("devnet-sponsor-note"),
                nullifier_root: commitment("devnet-sponsor-nullifier"),
                reserved_at_height: height.saturating_add(2),
                ttl_blocks: DEFAULT_SPONSOR_TTL_BLOCKS,
            })
            .expect("devnet sponsor");
        let cert = state
            .issue_certificate(IssueCertificateRequest {
                auction_id: auction.clone(),
                winning_bid_id: bid,
                intent_ids: vec![intent],
                sponsor_reservation_ids: vec![sponsor],
                encrypted_batch_root: commitment("devnet-encrypted-batch"),
                state_access_root: commitment("devnet-state-access"),
                fee_schedule_root: commitment("devnet-fee-schedule"),
                pq_signature_root: commitment("devnet-certificate-pq-signature"),
                committee_attestation_root: commitment("devnet-committee-attestation"),
                issued_at_height: height.saturating_add(3),
                ttl_blocks: DEFAULT_CERTIFICATE_TTL_BLOCKS,
            })
            .expect("devnet certificate");
        let receipt = state
            .publish_settlement_receipt(PublishSettlementReceiptRequest {
                certificate_id: cert,
                auction_id: auction.clone(),
                receipt_kind: ReceiptKind::ContractExecution,
                inclusion_root: commitment("devnet-inclusion"),
                execution_receipt_root: commitment("devnet-execution-receipt"),
                paid_fee_micro_units: 13_000,
                actual_latency_ms: 310,
                included_at_height: height.saturating_add(4),
            })
            .expect("devnet receipt");
        state
            .issue_rebate(IssueFeeRebateRequest {
                receipt_id: receipt,
                beneficiary_commitment: commitment("devnet-beneficiary"),
                rebate_note_root: commitment("devnet-rebate-note"),
                rebate_micro_units: 900,
                rebate_bps: DEFAULT_TARGET_REBATE_BPS,
                issued_at_height: height.saturating_add(5),
                ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            })
            .expect("devnet rebate");
        state
    }

    pub fn open_auction(&mut self, request: OpenAuctionRequest) -> Result<String> {
        require_capacity("auctions", self.auctions.len(), self.config.max_auctions)?;
        let sequence = self.counters.auctions_opened.saturating_add(1);
        let auction = PreconfirmationAuction::from_request(request, sequence, &self.config)?;
        let auction_id = auction.auction_id.clone();
        self.auctions.insert(auction_id.clone(), auction);
        self.counters.auctions_opened = sequence;
        self.emit_event("auction_opened", &auction_id, self.current_height);
        self.recompute_roots();
        Ok(auction_id)
    }

    pub fn submit_intent(&mut self, request: SubmitIntentRequest) -> Result<String> {
        require_capacity("intents", self.intents.len(), self.config.max_intents)?;
        if !self.auctions.contains_key(&request.auction_id) {
            return Err("intent references unknown auction".to_string());
        }
        self.spend_nullifier(&request.nullifier_root)?;
        let sequence = self.counters.intents_submitted.saturating_add(1);
        let intent = EncryptedPreconfirmationIntent::from_request(request, sequence, &self.config)?;
        let intent_id = intent.intent_id.clone();
        self.intents.insert(intent_id.clone(), intent);
        self.counters.intents_submitted = sequence;
        self.emit_event("intent_submitted", &intent_id, self.current_height);
        self.recompute_roots();
        Ok(intent_id)
    }

    pub fn post_bid(&mut self, request: PostSequencerBidRequest) -> Result<String> {
        require_capacity("bids", self.bids.len(), self.config.max_bids)?;
        let auction = self
            .auctions
            .get(&request.auction_id)
            .ok_or_else(|| "bid references unknown auction".to_string())?;
        let sequence = self.counters.bids_posted.saturating_add(1);
        let bid = SequencerBid::from_request(request, auction, sequence, &self.config)?;
        let bid_id = bid.bid_id.clone();
        self.counters.total_bond_micro_units = self
            .counters
            .total_bond_micro_units
            .saturating_add(bid.bond_micro_units as u128);
        self.bids.insert(bid_id.clone(), bid);
        self.counters.bids_posted = sequence;
        self.emit_event("bid_posted", &bid_id, self.current_height);
        self.recompute_roots();
        Ok(bid_id)
    }

    pub fn reserve_sponsor(&mut self, request: ReserveSponsorRequest) -> Result<String> {
        require_capacity(
            "sponsor reservations",
            self.sponsor_reservations.len(),
            self.config.max_sponsor_reservations,
        )?;
        if !self.auctions.contains_key(&request.auction_id) {
            return Err("sponsor references unknown auction".to_string());
        }
        for intent_id in &request.covered_intent_ids {
            if !self.intents.contains_key(intent_id) {
                return Err("sponsor references unknown intent".to_string());
            }
        }
        self.spend_nullifier(&request.nullifier_root)?;
        let sequence = self.counters.sponsor_reservations.saturating_add(1);
        let reservation = SponsorReservation::from_request(request, sequence, &self.config)?;
        let reservation_id = reservation.reservation_id.clone();
        self.counters.total_sponsor_coverage_micro_units = self
            .counters
            .total_sponsor_coverage_micro_units
            .saturating_add(reservation.max_coverage_micro_units as u128);
        self.sponsor_reservations
            .insert(reservation_id.clone(), reservation);
        self.counters.sponsor_reservations = sequence;
        self.emit_event("sponsor_reserved", &reservation_id, self.current_height);
        self.recompute_roots();
        Ok(reservation_id)
    }

    pub fn issue_certificate(&mut self, request: IssueCertificateRequest) -> Result<String> {
        require_capacity(
            "certificates",
            self.certificates.len(),
            self.config.max_certificates,
        )?;
        let auction_id = request.auction_id.clone();
        let winning_bid_id = request.winning_bid_id.clone();
        if !self.auctions.contains_key(&auction_id) {
            return Err("certificate references unknown auction".to_string());
        }
        if !self.bids.contains_key(&winning_bid_id) {
            return Err("certificate references unknown bid".to_string());
        }
        for intent_id in &request.intent_ids {
            if !self.intents.contains_key(intent_id) {
                return Err("certificate references unknown intent".to_string());
            }
        }
        for reservation_id in &request.sponsor_reservation_ids {
            if !self.sponsor_reservations.contains_key(reservation_id) {
                return Err("certificate references unknown sponsor reservation".to_string());
            }
        }
        let sequence = self.counters.certificates_issued.saturating_add(1);
        let certificate = PreconfirmationCertificate::from_request(request, sequence)?;
        let certificate_id = certificate.certificate_id.clone();
        if let Some(auction) = self.auctions.get_mut(&auction_id) {
            auction.status = AuctionStatus::CertificateIssued;
            auction.selected_bid_id = winning_bid_id.clone();
            auction.certificate_id = certificate_id.clone();
        }
        if let Some(bid) = self.bids.get_mut(&winning_bid_id) {
            bid.status = BidStatus::Selected;
        }
        for intent_id in &certificate.intent_ids {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = IntentStatus::Certified;
            }
        }
        for reservation_id in &certificate.sponsor_reservation_ids {
            if let Some(reservation) = self.sponsor_reservations.get_mut(reservation_id) {
                reservation.status = SponsorStatus::Consumed;
            }
        }
        self.certificates
            .insert(certificate_id.clone(), certificate);
        self.counters.certificates_issued = sequence;
        self.emit_event("certificate_issued", &certificate_id, self.current_height);
        self.recompute_roots();
        Ok(certificate_id)
    }

    pub fn publish_settlement_receipt(
        &mut self,
        request: PublishSettlementReceiptRequest,
    ) -> Result<String> {
        require_capacity(
            "settlement receipts",
            self.settlement_receipts.len(),
            self.config.max_receipts,
        )?;
        if !self.certificates.contains_key(&request.certificate_id) {
            return Err("receipt references unknown certificate".to_string());
        }
        let certificate_id = request.certificate_id.clone();
        let auction_id = request.auction_id.clone();
        let paid_fee = request.paid_fee_micro_units;
        let sequence = self.counters.receipts_published.saturating_add(1);
        let receipt = SettlementReceipt::from_request(request, sequence)?;
        let receipt_id = receipt.receipt_id.clone();
        if let Some(certificate) = self.certificates.get_mut(&certificate_id) {
            certificate.status = CertificateStatus::Settled;
        }
        if let Some(auction) = self.auctions.get_mut(&auction_id) {
            auction.status = AuctionStatus::Settled;
        }
        self.counters.total_fee_micro_units = self
            .counters
            .total_fee_micro_units
            .saturating_add(paid_fee as u128);
        self.settlement_receipts.insert(receipt_id.clone(), receipt);
        self.counters.receipts_published = sequence;
        self.emit_event(
            "settlement_receipt_published",
            &receipt_id,
            self.current_height,
        );
        self.recompute_roots();
        Ok(receipt_id)
    }

    pub fn issue_rebate(&mut self, request: IssueFeeRebateRequest) -> Result<String> {
        require_capacity("rebates", self.rebates.len(), self.config.max_rebates)?;
        if !self.settlement_receipts.contains_key(&request.receipt_id) {
            return Err("rebate references unknown receipt".to_string());
        }
        let sequence = self.counters.rebates_issued.saturating_add(1);
        let rebate = FeeRebate::from_request(request, sequence, &self.config)?;
        let rebate_id = rebate.rebate_id.clone();
        self.counters.total_rebate_micro_units = self
            .counters
            .total_rebate_micro_units
            .saturating_add(rebate.rebate_micro_units as u128);
        self.rebates.insert(rebate_id.clone(), rebate);
        self.counters.rebates_issued = sequence;
        self.emit_event("rebate_issued", &rebate_id, self.current_height);
        self.recompute_roots();
        Ok(rebate_id)
    }

    pub fn open_privacy_fence(&mut self, request: OpenPrivacyFenceRequest) -> Result<String> {
        require_capacity(
            "privacy fences",
            self.privacy_fences.len(),
            self.config.max_fences,
        )?;
        self.spend_nullifier(&request.nullifier_root)?;
        let sequence = self.counters.privacy_fences.saturating_add(1);
        let fence = PrivacyFence::from_request(request, sequence, &self.config)?;
        let fence_id = fence.fence_id.clone();
        self.privacy_fences.insert(fence_id.clone(), fence);
        self.counters.privacy_fences = sequence;
        self.emit_event("privacy_fence_opened", &fence_id, self.current_height);
        self.recompute_roots();
        Ok(fence_id)
    }

    pub fn record_slashing_event(&mut self, request: RecordSlashingEventRequest) -> Result<String> {
        require_capacity(
            "slashing events",
            self.slashing_events.len(),
            self.config.max_slashing_events,
        )?;
        if !self.auctions.contains_key(&request.auction_id) {
            return Err("slash references unknown auction".to_string());
        }
        if !self.bids.contains_key(&request.bid_id) {
            return Err("slash references unknown bid".to_string());
        }
        if !self.certificates.contains_key(&request.certificate_id) {
            return Err("slash references unknown certificate".to_string());
        }
        let bid_id = request.bid_id.clone();
        let sequence = self.counters.slashing_events.saturating_add(1);
        let slash = SlashingEvent::from_request(request, sequence)?;
        let slash_id = slash.slash_id.clone();
        if let Some(bid) = self.bids.get_mut(&bid_id) {
            bid.status = BidStatus::Slashed;
        }
        self.slashing_events.insert(slash_id.clone(), slash);
        self.counters.slashing_events = sequence;
        self.emit_event("slashing_event_recorded", &slash_id, self.current_height);
        self.recompute_roots();
        Ok(slash_id)
    }

    pub fn spend_nullifier(&mut self, nullifier_root: &str) -> Result<()> {
        require_root("nullifier root", nullifier_root)?;
        if !self.nullifiers.insert(nullifier_root.to_string()) {
            return Err("nullifier already spent".to_string());
        }
        self.counters.nullifiers_spent = self.counters.nullifiers_spent.saturating_add(1);
        Ok(())
    }

    pub fn recompute_counters(&mut self) {
        self.counters.auctions_opened = self.auctions.len() as u64;
        self.counters.intents_submitted = self.intents.len() as u64;
        self.counters.bids_posted = self.bids.len() as u64;
        self.counters.certificates_issued = self.certificates.len() as u64;
        self.counters.sponsor_reservations = self.sponsor_reservations.len() as u64;
        self.counters.receipts_published = self.settlement_receipts.len() as u64;
        self.counters.rebates_issued = self.rebates.len() as u64;
        self.counters.privacy_fences = self.privacy_fences.len() as u64;
        self.counters.slashing_events = self.slashing_events.len() as u64;
        self.counters.nullifiers_spent = self.nullifiers.len() as u64;
        self.counters.total_fee_micro_units = self
            .settlement_receipts
            .values()
            .map(|receipt| receipt.paid_fee_micro_units as u128)
            .sum();
        self.counters.total_rebate_micro_units = self
            .rebates
            .values()
            .map(|rebate| rebate.rebate_micro_units as u128)
            .sum();
        self.counters.total_sponsor_coverage_micro_units = self
            .sponsor_reservations
            .values()
            .map(|reservation| reservation.max_coverage_micro_units as u128)
            .sum();
        self.counters.total_bond_micro_units = self
            .bids
            .values()
            .map(|bid| bid.bond_micro_units as u128)
            .sum();
    }

    pub fn recompute_roots(&mut self) {
        self.roots = Roots {
            config_root: root_from_record("CONFIG", &self.config.public_record()),
            counter_root: root_from_record("COUNTERS", &self.counters.public_record()),
            auction_root: map_root(
                "AUCTIONS",
                self.auctions
                    .values()
                    .map(PreconfirmationAuction::public_record),
            ),
            intent_root: map_root(
                "INTENTS",
                self.intents
                    .values()
                    .map(EncryptedPreconfirmationIntent::public_record),
            ),
            bid_root: map_root("BIDS", self.bids.values().map(SequencerBid::public_record)),
            certificate_root: map_root(
                "CERTIFICATES",
                self.certificates
                    .values()
                    .map(PreconfirmationCertificate::public_record),
            ),
            sponsor_root: map_root(
                "SPONSORS",
                self.sponsor_reservations
                    .values()
                    .map(SponsorReservation::public_record),
            ),
            receipt_root: map_root(
                "RECEIPTS",
                self.settlement_receipts
                    .values()
                    .map(SettlementReceipt::public_record),
            ),
            rebate_root: map_root(
                "REBATES",
                self.rebates.values().map(FeeRebate::public_record),
            ),
            privacy_fence_root: map_root(
                "PRIVACY-FENCES",
                self.privacy_fences
                    .values()
                    .map(PrivacyFence::public_record),
            ),
            slashing_root: map_root(
                "SLASHING",
                self.slashing_events
                    .values()
                    .map(SlashingEvent::public_record),
            ),
            nullifier_root: set_root("NULLIFIERS", &self.nullifiers),
            event_root: map_root(
                "EVENTS",
                self.events.iter().map(RuntimeEvent::public_record),
            ),
        };
    }

    pub fn emit_event(&mut self, event_kind: &str, subject_id: &str, height: u64) {
        let sequence = self.events.len() as u64 + 1;
        let payload = json!({
            "event_kind": event_kind,
            "subject_id": subject_id,
            "height": height,
            "sequence": sequence,
        });
        let event = RuntimeEvent {
            event_id: runtime_event_id(event_kind, subject_id, &payload, height, sequence),
            event_kind: event_kind.to_string(),
            subject_id: subject_id.to_string(),
            payload_root: payload_root("RUNTIME-EVENT-PAYLOAD", &payload),
            height,
            sequence,
        };
        self.events.push(event);
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_low_fee_preconfirmation_auction_runtime_state",
            "chain_id": CHAIN_ID,
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn private_l2_pq_low_fee_preconfirmation_auction_runtime_public_record(state: &State) -> Value {
    state.public_record()
}

pub fn private_l2_pq_low_fee_preconfirmation_auction_runtime_state_root(state: &State) -> String {
    state.state_root()
}

pub fn auction_id(request: &OpenAuctionRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-LOW-FEE-PRECONFIRMATION-AUCTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.lane.as_str()),
            HashPart::Str(&request.domain_label),
            HashPart::Str(&request.encrypted_call_bundle_root),
            HashPart::Str(&request.intent_set_root),
            HashPart::U64(request.opens_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn intent_id(request: &SubmitIntentRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-LOW-FEE-PRECONFIRMATION-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.auction_id),
            HashPart::Str(&request.sender_commitment),
            HashPart::Str(&request.contract_commitment),
            HashPart::Str(&request.encrypted_call_root),
            HashPart::Str(&request.nullifier_root),
            HashPart::U64(request.submitted_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn bid_id(request: &PostSequencerBidRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-LOW-FEE-PRECONFIRMATION-BID-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.auction_id),
            HashPart::Str(&request.sequencer_commitment),
            HashPart::Str(&request.bid_ciphertext_root),
            HashPart::Str(&request.bond_note_root),
            HashPart::U64(request.fee_bps),
            HashPart::U64(request.max_latency_ms),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn sponsor_reservation_id(request: &ReserveSponsorRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-LOW-FEE-PRECONFIRMATION-SPONSOR-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.auction_id),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&id_list_root(
                "SPONSOR-COVERED-INTENTS",
                &request.covered_intent_ids,
            )),
            HashPart::Str(&request.sponsor_note_root),
            HashPart::Str(&request.nullifier_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn certificate_id(request: &IssueCertificateRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-LOW-FEE-PRECONFIRMATION-CERTIFICATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.auction_id),
            HashPart::Str(&request.winning_bid_id),
            HashPart::Str(&id_list_root("CERTIFICATE-INTENTS", &request.intent_ids)),
            HashPart::Str(&request.encrypted_batch_root),
            HashPart::Str(&request.pq_signature_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn settlement_receipt_id(request: &PublishSettlementReceiptRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-LOW-FEE-PRECONFIRMATION-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.certificate_id),
            HashPart::Str(&request.auction_id),
            HashPart::Str(request.receipt_kind.as_str()),
            HashPart::Str(&request.inclusion_root),
            HashPart::Str(&request.execution_receipt_root),
            HashPart::U64(request.included_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn rebate_id(request: &IssueFeeRebateRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-LOW-FEE-PRECONFIRMATION-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.receipt_id),
            HashPart::Str(&request.beneficiary_commitment),
            HashPart::Str(&request.rebate_note_root),
            HashPart::U64(request.rebate_micro_units),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn privacy_fence_id(request: &OpenPrivacyFenceRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-LOW-FEE-PRECONFIRMATION-PRIVACY-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.fence_kind.as_str()),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.commitment_root),
            HashPart::Str(&request.nullifier_root),
            HashPart::Str(&request.replay_domain),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn slashing_event_id(request: &RecordSlashingEventRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-LOW-FEE-PRECONFIRMATION-SLASHING-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.auction_id),
            HashPart::Str(&request.bid_id),
            HashPart::Str(&request.certificate_id),
            HashPart::Str(request.reason.as_str()),
            HashPart::Str(&request.evidence_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn runtime_event_id(
    event_kind: &str,
    subject_id: &str,
    payload: &Value,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-LOW-FEE-PRECONFIRMATION-RUNTIME-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind),
            HashPart::Str(subject_id),
            HashPart::Json(payload),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn commitment(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-LOW-FEE-PRECONFIRMATION-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-LOW-FEE-PRECONFIRMATION-{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    payload_root(&format!("{domain}-ROOT"), record)
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(
        &format!("PRIVATE-L2-PQ-LOW-FEE-PRECONFIRMATION-{domain}"),
        records,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("STATE", record)
}

pub fn empty_root(domain: &str) -> String {
    public_record_root(domain, &[])
}

pub fn id_list_root(domain: &str, ids: &[String]) -> String {
    let records = ids.iter().map(|id| json!({ "id": id })).collect::<Vec<_>>();
    public_record_root(domain, &records)
}

fn map_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let records = records.into_iter().collect::<Vec<_>>();
    public_record_root(domain, &records)
}

fn set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let records = values
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    public_record_root(domain, &records)
}

fn bid_score(request: &PostSequencerBidRequest, auction: &PreconfirmationAuction) -> u64 {
    let latency_score = auction
        .target_latency_ms
        .saturating_mul(10_000)
        .checked_div(request.max_latency_ms.max(1))
        .unwrap_or(0);
    let fee_score = auction
        .max_user_fee_bps
        .saturating_sub(request.fee_bps)
        .saturating_mul(1_000);
    let bond_score = request.bond_micro_units / 10_000;
    auction
        .lane
        .latency_weight()
        .saturating_add(latency_score)
        .saturating_add(fee_score)
        .saturating_add(bond_score)
}

fn ensure_eq(actual: &str, expected: &str, label: &str) -> Result<()> {
    if actual != expected {
        Err(format!(
            "{label} mismatch: expected {expected}, got {actual}"
        ))
    } else {
        Ok(())
    }
}

fn ensure_unique(field: &str, values: &[String]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_non_empty(field, value)?;
        if !seen.insert(value) {
            return Err(format!("{field} contains duplicate value {value}"));
        }
    }
    Ok(())
}

fn require_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

fn require_non_empty_vec(field: &str, values: &[String]) -> Result<()> {
    if values.is_empty() {
        return Err(format!("{field} cannot be empty"));
    }
    for value in values {
        require_non_empty(field, value)?;
    }
    Ok(())
}

fn require_root(field: &str, value: &str) -> Result<()> {
    require_non_empty(field, value)?;
    if value.len() < 32 {
        Err(format!("{field} must look like a commitment root"))
    } else {
        Ok(())
    }
}

fn require_positive_u64(field: &str, value: u64) -> Result<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn require_positive_usize(field: &str, value: usize) -> Result<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn require_bps(field: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{field} exceeds basis point maximum"))
    } else {
        Ok(())
    }
}

fn require_capacity(field: &str, len: usize, max: usize) -> Result<()> {
    if len >= max {
        Err(format!("{field} capacity exceeded"))
    } else {
        Ok(())
    }
}
