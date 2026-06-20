use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type FastWithdrawalResult<T> = Result<T, String>;

pub const PROTOCOL_VERSION: &str = "nebula-fast-withdrawals-v1";
pub const FAST_WITHDRAWAL_DEVNET_HEIGHT: u64 = 128;
pub const FAST_WITHDRAWAL_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const FAST_WITHDRAWAL_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const FAST_WITHDRAWAL_DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const FAST_WITHDRAWAL_PQ_SUITE: &str = "ML-KEM-768+ML-DSA-65+SLH-DSA-SHAKE-128s-devnet";
pub const FAST_WITHDRAWAL_ATTESTATION_SCHEME: &str = "ML-DSA-65-devnet-withdrawal-intent";
pub const FAST_WITHDRAWAL_RECEIPT_SCHEME: &str = "shake256-private-receipt-nullifier";
pub const FAST_WITHDRAWAL_RESERVE_PROOF_SCHEME: &str = "devnet-monero-reserve-attestation";
pub const FAST_WITHDRAWAL_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 8;
pub const FAST_WITHDRAWAL_DEFAULT_INTENT_TTL_BLOCKS: u64 = 24;
pub const FAST_WITHDRAWAL_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 18;
pub const FAST_WITHDRAWAL_DEFAULT_RECEIPT_REVEAL_DELAY_BLOCKS: u64 = 4;
pub const FAST_WITHDRAWAL_DEFAULT_MAX_OPERATOR_EXPOSURE_UNITS: u64 = 2_000_000;
pub const FAST_WITHDRAWAL_DEFAULT_MAX_MAKER_EXPOSURE_UNITS: u64 = 750_000;
pub const FAST_WITHDRAWAL_DEFAULT_MAX_PENDING_INTENTS: usize = 512;
pub const FAST_WITHDRAWAL_DEFAULT_MAX_OPEN_QUOTES_PER_MAKER: usize = 64;
pub const FAST_WITHDRAWAL_DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 11_000;
pub const FAST_WITHDRAWAL_DEFAULT_WARN_RESERVE_COVERAGE_BPS: u64 = 12_000;
pub const FAST_WITHDRAWAL_DEFAULT_MAX_QUOTE_PREMIUM_BPS: u64 = 250;
pub const FAST_WITHDRAWAL_DEFAULT_MAX_SPONSOR_REBATE_BPS: u64 = 9_500;
pub const FAST_WITHDRAWAL_DEFAULT_SETTLEMENT_FINALITY_BLOCKS: u64 = 10;
pub const FAST_WITHDRAWAL_DEFAULT_FEE_FLOOR_UNITS: u64 = 2;
pub const FAST_WITHDRAWAL_DEFAULT_SPONSOR_POOL_UNITS: u64 = 50_000;
pub const FAST_WITHDRAWAL_DEFAULT_OPERATOR_DAILY_LIMIT_UNITS: u64 = 5_000_000;
pub const FAST_WITHDRAWAL_DEFAULT_MAKER_DAILY_LIMIT_UNITS: u64 = 1_500_000;
pub const FAST_WITHDRAWAL_DEFAULT_PRIVACY_SET_SIZE: u64 = 256;
pub const FAST_WITHDRAWAL_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitPriority {
    Normal,
    Fast,
    Urgent,
    Sponsored,
    Emergency,
}

impl ExitPriority {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Fast => "fast",
            Self::Urgent => "urgent",
            Self::Sponsored => "sponsored",
            Self::Emergency => "emergency",
        }
    }

    pub fn default_quote_ttl_blocks(&self) -> u64 {
        match self {
            Self::Normal => 16,
            Self::Fast => FAST_WITHDRAWAL_DEFAULT_QUOTE_TTL_BLOCKS,
            Self::Urgent => 4,
            Self::Sponsored => 12,
            Self::Emergency => 2,
        }
    }

    pub fn risk_weight_bps(&self) -> u64 {
        match self {
            Self::Normal => 10_000,
            Self::Fast => 11_000,
            Self::Urgent => 13_000,
            Self::Sponsored => 10_500,
            Self::Emergency => 15_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementRail {
    MoneroHotWallet,
    MoneroWarmWallet,
    MakerInventory,
    InternalNetting,
    DelayedReserve,
    SponsoredBatch,
}

impl SettlementRail {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MoneroHotWallet => "monero_hot_wallet",
            Self::MoneroWarmWallet => "monero_warm_wallet",
            Self::MakerInventory => "maker_inventory",
            Self::InternalNetting => "internal_netting",
            Self::DelayedReserve => "delayed_reserve",
            Self::SponsoredBatch => "sponsored_batch",
        }
    }

    pub fn is_instant(&self) -> bool {
        matches!(
            self,
            Self::MoneroHotWallet | Self::MakerInventory | Self::InternalNetting
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalIntentStatus {
    Submitted,
    Attested,
    QuoteBound,
    Funded,
    Challenged,
    Settled,
    Cancelled,
    Expired,
    Rejected,
}

impl WithdrawalIntentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Attested => "attested",
            Self::QuoteBound => "quote_bound",
            Self::Funded => "funded",
            Self::Challenged => "challenged",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn is_open(&self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::Attested | Self::QuoteBound | Self::Funded | Self::Challenged
        )
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Cancelled | Self::Expired | Self::Rejected
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAttestationRole {
    Wallet,
    Operator,
    Maker,
    Watchtower,
    Sponsor,
    ReserveCommittee,
}

impl PqAttestationRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Wallet => "wallet",
            Self::Operator => "operator",
            Self::Maker => "maker",
            Self::Watchtower => "watchtower",
            Self::Sponsor => "sponsor",
            Self::ReserveCommittee => "reserve_committee",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MakerKind {
    InternalDesk,
    ExternalMarketMaker,
    CommunityVault,
    OperatorBackstop,
    InsuranceFund,
}

impl MakerKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InternalDesk => "internal_desk",
            Self::ExternalMarketMaker => "external_market_maker",
            Self::CommunityVault => "community_vault",
            Self::OperatorBackstop => "operator_backstop",
            Self::InsuranceFund => "insurance_fund",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MakerStatus {
    Active,
    Throttled,
    Paused,
    Draining,
    Retired,
    Slashed,
}

impl MakerStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }

    pub fn accepts_flow(&self) -> bool {
        matches!(self, Self::Active | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Open,
    Reserved,
    Filled,
    Cancelled,
    Expired,
    Challenged,
}

impl QuoteStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Filled => "filled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }

    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Open | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    DoubleSpend,
    InvalidPqAttestation,
    StaleReserveProof,
    MakerInventoryShortfall,
    QuoteMispricing,
    ReceiptLinkability,
    SponsorshipAbuse,
    OperatorLimitBreach,
    SettlementTimeout,
}

impl ChallengeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DoubleSpend => "double_spend",
            Self::InvalidPqAttestation => "invalid_pq_attestation",
            Self::StaleReserveProof => "stale_reserve_proof",
            Self::MakerInventoryShortfall => "maker_inventory_shortfall",
            Self::QuoteMispricing => "quote_mispricing",
            Self::ReceiptLinkability => "receipt_linkability",
            Self::SponsorshipAbuse => "sponsorship_abuse",
            Self::OperatorLimitBreach => "operator_limit_breach",
            Self::SettlementTimeout => "settlement_timeout",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    EvidenceSubmitted,
    Accepted,
    Rejected,
    Expired,
    Resolved,
    Slashed,
}

impl ChallengeStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceSubmitted => "evidence_submitted",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Resolved => "resolved",
            Self::Slashed => "slashed",
        }
    }

    pub fn is_open(&self) -> bool {
        matches!(self, Self::Open | Self::EvidenceSubmitted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveProofStatus {
    Fresh,
    Watch,
    Stale,
    Challenged,
    Revoked,
}

impl ReserveProofStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Watch => "watch",
            Self::Stale => "stale",
            Self::Challenged => "challenged",
            Self::Revoked => "revoked",
        }
    }

    pub fn counts_as_live(&self) -> bool {
        matches!(self, Self::Fresh | Self::Watch | Self::Challenged)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptVisibility {
    Shielded,
    AggregateOnly,
    WatchtowerReveal,
    PublicAudit,
}

impl ReceiptVisibility {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Shielded => "shielded",
            Self::AggregateOnly => "aggregate_only",
            Self::WatchtowerReveal => "watchtower_reveal",
            Self::PublicAudit => "public_audit",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Committed,
    Revealed,
    Settled,
    Challenged,
    Revoked,
}

impl ReceiptStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Revealed => "revealed",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Reserved,
    Applied,
    Reclaimed,
    Expired,
    Slashed,
}

impl SponsorshipStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Reclaimed => "reclaimed",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Pending,
    Broadcast,
    Confirmed,
    Finalized,
    Failed,
    Reorged,
}

impl SettlementStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Broadcast => "broadcast",
            Self::Confirmed => "confirmed",
            Self::Finalized => "finalized",
            Self::Failed => "failed",
            Self::Reorged => "reorged",
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Finalized | Self::Failed | Self::Reorged)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorRiskMode {
    Normal,
    Cautious,
    MakerOnly,
    SponsorOnly,
    Halted,
}

impl OperatorRiskMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Cautious => "cautious",
            Self::MakerOnly => "maker_only",
            Self::SponsorOnly => "sponsor_only",
            Self::Halted => "halted",
        }
    }

    pub fn accepts_new_intents(&self) -> bool {
        !matches!(self, Self::Halted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLimitStatus {
    Healthy,
    Watch,
    Limited,
    Breached,
    Halted,
}

impl RiskLimitStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Watch => "watch",
            Self::Limited => "limited",
            Self::Breached => "breached",
            Self::Halted => "halted",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastWithdrawalConfig {
    pub protocol_version: String,
    pub asset_id: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub pq_suite: String,
    pub attestation_scheme: String,
    pub receipt_scheme: String,
    pub reserve_proof_scheme: String,
    pub default_intent_ttl_blocks: u64,
    pub default_quote_ttl_blocks: u64,
    pub default_challenge_window_blocks: u64,
    pub default_receipt_reveal_delay_blocks: u64,
    pub settlement_finality_blocks: u64,
    pub max_operator_exposure_units: u64,
    pub max_maker_exposure_units: u64,
    pub max_pending_intents: usize,
    pub max_open_quotes_per_maker: usize,
    pub min_reserve_coverage_bps: u64,
    pub warn_reserve_coverage_bps: u64,
    pub max_quote_premium_bps: u64,
    pub max_sponsor_rebate_bps: u64,
    pub default_fee_floor_units: u64,
    pub default_sponsor_pool_units: u64,
    pub operator_daily_limit_units: u64,
    pub maker_daily_limit_units: u64,
    pub default_privacy_set_size: u64,
}

impl Default for FastWithdrawalConfig {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            asset_id: FAST_WITHDRAWAL_DEVNET_ASSET_ID.to_string(),
            monero_network: FAST_WITHDRAWAL_DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: FAST_WITHDRAWAL_DEVNET_FEE_ASSET_ID.to_string(),
            pq_suite: FAST_WITHDRAWAL_PQ_SUITE.to_string(),
            attestation_scheme: FAST_WITHDRAWAL_ATTESTATION_SCHEME.to_string(),
            receipt_scheme: FAST_WITHDRAWAL_RECEIPT_SCHEME.to_string(),
            reserve_proof_scheme: FAST_WITHDRAWAL_RESERVE_PROOF_SCHEME.to_string(),
            default_intent_ttl_blocks: FAST_WITHDRAWAL_DEFAULT_INTENT_TTL_BLOCKS,
            default_quote_ttl_blocks: FAST_WITHDRAWAL_DEFAULT_QUOTE_TTL_BLOCKS,
            default_challenge_window_blocks: FAST_WITHDRAWAL_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            default_receipt_reveal_delay_blocks:
                FAST_WITHDRAWAL_DEFAULT_RECEIPT_REVEAL_DELAY_BLOCKS,
            settlement_finality_blocks: FAST_WITHDRAWAL_DEFAULT_SETTLEMENT_FINALITY_BLOCKS,
            max_operator_exposure_units: FAST_WITHDRAWAL_DEFAULT_MAX_OPERATOR_EXPOSURE_UNITS,
            max_maker_exposure_units: FAST_WITHDRAWAL_DEFAULT_MAX_MAKER_EXPOSURE_UNITS,
            max_pending_intents: FAST_WITHDRAWAL_DEFAULT_MAX_PENDING_INTENTS,
            max_open_quotes_per_maker: FAST_WITHDRAWAL_DEFAULT_MAX_OPEN_QUOTES_PER_MAKER,
            min_reserve_coverage_bps: FAST_WITHDRAWAL_DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            warn_reserve_coverage_bps: FAST_WITHDRAWAL_DEFAULT_WARN_RESERVE_COVERAGE_BPS,
            max_quote_premium_bps: FAST_WITHDRAWAL_DEFAULT_MAX_QUOTE_PREMIUM_BPS,
            max_sponsor_rebate_bps: FAST_WITHDRAWAL_DEFAULT_MAX_SPONSOR_REBATE_BPS,
            default_fee_floor_units: FAST_WITHDRAWAL_DEFAULT_FEE_FLOOR_UNITS,
            default_sponsor_pool_units: FAST_WITHDRAWAL_DEFAULT_SPONSOR_POOL_UNITS,
            operator_daily_limit_units: FAST_WITHDRAWAL_DEFAULT_OPERATOR_DAILY_LIMIT_UNITS,
            maker_daily_limit_units: FAST_WITHDRAWAL_DEFAULT_MAKER_DAILY_LIMIT_UNITS,
            default_privacy_set_size: FAST_WITHDRAWAL_DEFAULT_PRIVACY_SET_SIZE,
        }
    }
}

impl FastWithdrawalConfig {
    pub fn validate(&self) -> FastWithdrawalResult<()> {
        ensure_non_empty(&self.protocol_version, "protocol_version")?;
        ensure_non_empty(&self.asset_id, "asset_id")?;
        ensure_non_empty(&self.monero_network, "monero_network")?;
        ensure_non_empty(&self.fee_asset_id, "fee_asset_id")?;
        ensure_non_empty(&self.pq_suite, "pq_suite")?;
        ensure_non_empty(&self.attestation_scheme, "attestation_scheme")?;
        ensure_non_empty(&self.receipt_scheme, "receipt_scheme")?;
        ensure_positive(self.default_intent_ttl_blocks, "default_intent_ttl_blocks")?;
        ensure_positive(self.default_quote_ttl_blocks, "default_quote_ttl_blocks")?;
        ensure_positive(
            self.default_challenge_window_blocks,
            "default_challenge_window_blocks",
        )?;
        ensure_positive(
            self.settlement_finality_blocks,
            "settlement_finality_blocks",
        )?;
        ensure_positive(
            self.max_operator_exposure_units,
            "max_operator_exposure_units",
        )?;
        ensure_positive(self.max_maker_exposure_units, "max_maker_exposure_units")?;
        ensure_positive(self.min_reserve_coverage_bps, "min_reserve_coverage_bps")?;
        ensure_bps_at_most(
            self.max_quote_premium_bps,
            FAST_WITHDRAWAL_MAX_BPS,
            "max_quote_premium_bps",
        )?;
        ensure_bps_at_most(
            self.max_sponsor_rebate_bps,
            FAST_WITHDRAWAL_MAX_BPS,
            "max_sponsor_rebate_bps",
        )?;
        if self.max_pending_intents == 0 {
            return Err("max_pending_intents must be positive".to_string());
        }
        if self.max_open_quotes_per_maker == 0 {
            return Err("max_open_quotes_per_maker must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_withdrawal_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "asset_id": self.asset_id,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "pq_suite": self.pq_suite,
            "attestation_scheme": self.attestation_scheme,
            "receipt_scheme": self.receipt_scheme,
            "reserve_proof_scheme": self.reserve_proof_scheme,
            "default_intent_ttl_blocks": self.default_intent_ttl_blocks,
            "default_quote_ttl_blocks": self.default_quote_ttl_blocks,
            "default_challenge_window_blocks": self.default_challenge_window_blocks,
            "default_receipt_reveal_delay_blocks": self.default_receipt_reveal_delay_blocks,
            "settlement_finality_blocks": self.settlement_finality_blocks,
            "max_operator_exposure_units": self.max_operator_exposure_units,
            "max_maker_exposure_units": self.max_maker_exposure_units,
            "max_pending_intents": self.max_pending_intents as u64,
            "max_open_quotes_per_maker": self.max_open_quotes_per_maker as u64,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "warn_reserve_coverage_bps": self.warn_reserve_coverage_bps,
            "max_quote_premium_bps": self.max_quote_premium_bps,
            "max_sponsor_rebate_bps": self.max_sponsor_rebate_bps,
            "default_fee_floor_units": self.default_fee_floor_units,
            "default_sponsor_pool_units": self.default_sponsor_pool_units,
            "operator_daily_limit_units": self.operator_daily_limit_units,
            "maker_daily_limit_units": self.maker_daily_limit_units,
            "default_privacy_set_size": self.default_privacy_set_size,
        })
    }

    pub fn config_root(&self) -> String {
        fast_withdrawal_config_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqWithdrawalAttestation {
    pub attestation_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub attester_id: String,
    pub role: PqAttestationRole,
    pub key_commitment: String,
    pub signature_scheme: String,
    pub signature_root: String,
    pub transcript_root: String,
    pub weight: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl PqWithdrawalAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject_kind: &str,
        subject_id: &str,
        subject_root: &str,
        attester_id: &str,
        role: PqAttestationRole,
        key_commitment: &str,
        signature_scheme: &str,
        transcript_root: &str,
        weight: u64,
        issued_at_height: u64,
        ttl_blocks: u64,
    ) -> FastWithdrawalResult<Self> {
        ensure_non_empty(subject_kind, "subject_kind")?;
        ensure_non_empty(subject_id, "subject_id")?;
        ensure_non_empty(subject_root, "subject_root")?;
        ensure_non_empty(attester_id, "attester_id")?;
        ensure_non_empty(key_commitment, "key_commitment")?;
        ensure_non_empty(signature_scheme, "signature_scheme")?;
        ensure_non_empty(transcript_root, "transcript_root")?;
        ensure_positive(weight, "weight")?;
        ensure_positive(ttl_blocks, "ttl_blocks")?;
        let signature_root = fast_withdrawal_payload_root(
            "FAST-WITHDRAWAL-PQ-SIGNATURE",
            &json!({
                "subject_kind": subject_kind,
                "subject_id": subject_id,
                "subject_root": subject_root,
                "attester_id": attester_id,
                "role": role.as_str(),
                "key_commitment": key_commitment,
                "signature_scheme": signature_scheme,
                "transcript_root": transcript_root,
                "issued_at_height": issued_at_height,
            }),
        );
        let attestation_id = fast_withdrawal_pq_attestation_id(
            subject_kind,
            subject_id,
            subject_root,
            attester_id,
            role.as_str(),
            &signature_root,
            issued_at_height,
        );
        Ok(Self {
            attestation_id,
            subject_kind: subject_kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            attester_id: attester_id.to_string(),
            role,
            key_commitment: key_commitment.to_string(),
            signature_scheme: signature_scheme.to_string(),
            signature_root,
            transcript_root: transcript_root.to_string(),
            weight,
            issued_at_height,
            expires_at_height: issued_at_height.saturating_add(ttl_blocks),
        })
    }

    pub fn subject_matches(
        &self,
        subject_kind: &str,
        subject_id: &str,
        subject_root: &str,
    ) -> bool {
        self.subject_kind == subject_kind
            && self.subject_id == subject_id
            && self.subject_root == subject_root
    }

    pub fn is_expired_at(&self, height: u64) -> bool {
        height > self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_withdrawal_pq_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "attester_id": self.attester_id,
            "role": self.role.as_str(),
            "key_commitment": self.key_commitment,
            "signature_scheme": self.signature_scheme,
            "signature_root": self.signature_root,
            "transcript_root": self.transcript_root,
            "weight": self.weight,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn attestation_root(&self) -> String {
        fast_withdrawal_pq_attestation_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalIntent {
    pub intent_id: String,
    pub owner_commitment: String,
    pub recipient_address_commitment: String,
    pub recipient_view_tag_root: String,
    pub asset_id: String,
    pub amount_units: u64,
    pub max_fee_units: u64,
    pub min_receive_units: u64,
    pub priority: ExitPriority,
    pub settlement_rail: SettlementRail,
    pub source_note_root: String,
    pub nullifier_root: String,
    pub anti_replay_nonce: u64,
    pub pq_session_id: String,
    pub wallet_attestation_root: String,
    pub operator_attestation_root: String,
    pub requested_at_height: u64,
    pub expires_at_height: u64,
    pub challenge_window_end_height: u64,
    pub privacy_set_size: u64,
    pub status: WithdrawalIntentStatus,
    pub bound_quote_id: String,
    pub sponsorship_id: String,
    pub receipt_id: String,
    pub risk_score_bps: u64,
    pub metadata_root: String,
}

impl WithdrawalIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner_commitment: &str,
        recipient_address_commitment: &str,
        recipient_view_tag_root: &str,
        asset_id: &str,
        amount_units: u64,
        max_fee_units: u64,
        priority: ExitPriority,
        settlement_rail: SettlementRail,
        source_note_root: &str,
        nullifier_root: &str,
        anti_replay_nonce: u64,
        pq_session_id: &str,
        wallet_attestation_root: &str,
        requested_at_height: u64,
        ttl_blocks: u64,
        challenge_window_blocks: u64,
        privacy_set_size: u64,
        metadata: &Value,
    ) -> FastWithdrawalResult<Self> {
        ensure_non_empty(owner_commitment, "owner_commitment")?;
        ensure_non_empty(recipient_address_commitment, "recipient_address_commitment")?;
        ensure_non_empty(recipient_view_tag_root, "recipient_view_tag_root")?;
        ensure_non_empty(asset_id, "asset_id")?;
        ensure_positive(amount_units, "amount_units")?;
        ensure_non_empty(source_note_root, "source_note_root")?;
        ensure_non_empty(nullifier_root, "nullifier_root")?;
        ensure_non_empty(pq_session_id, "pq_session_id")?;
        ensure_non_empty(wallet_attestation_root, "wallet_attestation_root")?;
        ensure_positive(ttl_blocks, "ttl_blocks")?;
        ensure_positive(challenge_window_blocks, "challenge_window_blocks")?;
        ensure_positive(privacy_set_size, "privacy_set_size")?;
        let min_receive_units = amount_units.saturating_sub(max_fee_units);
        let metadata_root =
            fast_withdrawal_payload_root("FAST-WITHDRAWAL-INTENT-METADATA", metadata);
        let intent_id = fast_withdrawal_intent_id(
            owner_commitment,
            recipient_address_commitment,
            asset_id,
            amount_units,
            source_note_root,
            nullifier_root,
            anti_replay_nonce,
            pq_session_id,
        );
        let risk_score_bps = withdrawal_intent_risk_score_bps(
            amount_units,
            priority,
            settlement_rail,
            privacy_set_size,
        );
        Ok(Self {
            intent_id,
            owner_commitment: owner_commitment.to_string(),
            recipient_address_commitment: recipient_address_commitment.to_string(),
            recipient_view_tag_root: recipient_view_tag_root.to_string(),
            asset_id: asset_id.to_string(),
            amount_units,
            max_fee_units,
            min_receive_units,
            priority,
            settlement_rail,
            source_note_root: source_note_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            anti_replay_nonce,
            pq_session_id: pq_session_id.to_string(),
            wallet_attestation_root: wallet_attestation_root.to_string(),
            operator_attestation_root: merkle_root("FAST-WITHDRAWAL-OPERATOR-ATTESTATION", &[]),
            requested_at_height,
            expires_at_height: requested_at_height.saturating_add(ttl_blocks),
            challenge_window_end_height: requested_at_height
                .saturating_add(challenge_window_blocks),
            privacy_set_size,
            status: WithdrawalIntentStatus::Submitted,
            bound_quote_id: String::new(),
            sponsorship_id: String::new(),
            receipt_id: String::new(),
            risk_score_bps,
            metadata_root,
        })
    }

    pub fn validate(&self) -> FastWithdrawalResult<()> {
        ensure_non_empty(&self.intent_id, "intent_id")?;
        ensure_non_empty(&self.owner_commitment, "owner_commitment")?;
        ensure_non_empty(
            &self.recipient_address_commitment,
            "recipient_address_commitment",
        )?;
        ensure_non_empty(&self.asset_id, "asset_id")?;
        ensure_positive(self.amount_units, "amount_units")?;
        ensure_non_empty(&self.source_note_root, "source_note_root")?;
        ensure_non_empty(&self.nullifier_root, "nullifier_root")?;
        if self.min_receive_units > self.amount_units {
            return Err("min_receive_units exceeds amount_units".to_string());
        }
        if self.expires_at_height < self.requested_at_height {
            return Err("intent expiry precedes request height".to_string());
        }
        Ok(())
    }

    pub fn is_expired_at(&self, height: u64) -> bool {
        height > self.expires_at_height
    }

    pub fn challenge_window_open_at(&self, height: u64) -> bool {
        height <= self.challenge_window_end_height && !self.status.is_terminal()
    }

    pub fn bind_quote(&mut self, quote_id: &str, sponsorship_id: &str) -> FastWithdrawalResult<()> {
        ensure_non_empty(quote_id, "quote_id")?;
        if self.status.is_terminal() {
            return Err("cannot bind quote to terminal withdrawal intent".to_string());
        }
        self.bound_quote_id = quote_id.to_string();
        self.sponsorship_id = sponsorship_id.to_string();
        self.status = WithdrawalIntentStatus::QuoteBound;
        Ok(())
    }

    pub fn mark_funded(&mut self, receipt_id: &str) -> FastWithdrawalResult<()> {
        ensure_non_empty(receipt_id, "receipt_id")?;
        if self.bound_quote_id.is_empty() {
            return Err("cannot fund withdrawal intent before quote binding".to_string());
        }
        self.receipt_id = receipt_id.to_string();
        self.status = WithdrawalIntentStatus::Funded;
        Ok(())
    }

    pub fn mark_challenged(&mut self) -> FastWithdrawalResult<()> {
        if self.status.is_terminal() {
            return Err("cannot challenge terminal withdrawal intent".to_string());
        }
        self.status = WithdrawalIntentStatus::Challenged;
        Ok(())
    }

    pub fn mark_settled(&mut self) -> FastWithdrawalResult<()> {
        if self.status == WithdrawalIntentStatus::Cancelled {
            return Err("cannot settle cancelled withdrawal intent".to_string());
        }
        self.status = WithdrawalIntentStatus::Settled;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_withdrawal_intent",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "intent_id": self.intent_id,
            "owner_commitment": self.owner_commitment,
            "recipient_address_commitment": self.recipient_address_commitment,
            "recipient_view_tag_root": self.recipient_view_tag_root,
            "asset_id": self.asset_id,
            "amount_units": self.amount_units,
            "max_fee_units": self.max_fee_units,
            "min_receive_units": self.min_receive_units,
            "priority": self.priority.as_str(),
            "settlement_rail": self.settlement_rail.as_str(),
            "source_note_root": self.source_note_root,
            "nullifier_root": self.nullifier_root,
            "anti_replay_nonce": self.anti_replay_nonce,
            "pq_session_id": self.pq_session_id,
            "wallet_attestation_root": self.wallet_attestation_root,
            "operator_attestation_root": self.operator_attestation_root,
            "requested_at_height": self.requested_at_height,
            "expires_at_height": self.expires_at_height,
            "challenge_window_end_height": self.challenge_window_end_height,
            "privacy_set_size": self.privacy_set_size,
            "status": self.status.as_str(),
            "bound_quote_id": self.bound_quote_id,
            "sponsorship_id": self.sponsorship_id,
            "receipt_id": self.receipt_id,
            "risk_score_bps": self.risk_score_bps,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn intent_root(&self) -> String {
        fast_withdrawal_intent_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityMaker {
    pub maker_id: String,
    pub label: String,
    pub maker_kind: MakerKind,
    pub operator_commitment: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub inventory_commitment_root: String,
    pub reserve_proof_id: String,
    pub public_key_commitment: String,
    pub max_quote_units: u64,
    pub available_units: u64,
    pub reserved_units: u64,
    pub filled_units: u64,
    pub fee_floor_units: u64,
    pub max_premium_bps: u64,
    pub daily_limit_units: u64,
    pub daily_filled_units: u64,
    pub trust_weight: u64,
    pub status: MakerStatus,
    pub metadata_root: String,
}

impl LiquidityMaker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: &str,
        maker_kind: MakerKind,
        operator_commitment: &str,
        asset_id: &str,
        fee_asset_id: &str,
        inventory_commitment_root: &str,
        public_key_commitment: &str,
        max_quote_units: u64,
        available_units: u64,
        fee_floor_units: u64,
        max_premium_bps: u64,
        daily_limit_units: u64,
        trust_weight: u64,
        metadata: &Value,
    ) -> FastWithdrawalResult<Self> {
        ensure_non_empty(label, "label")?;
        ensure_non_empty(operator_commitment, "operator_commitment")?;
        ensure_non_empty(asset_id, "asset_id")?;
        ensure_non_empty(fee_asset_id, "fee_asset_id")?;
        ensure_non_empty(inventory_commitment_root, "inventory_commitment_root")?;
        ensure_non_empty(public_key_commitment, "public_key_commitment")?;
        ensure_positive(max_quote_units, "max_quote_units")?;
        ensure_bps_at_most(max_premium_bps, FAST_WITHDRAWAL_MAX_BPS, "max_premium_bps")?;
        ensure_positive(daily_limit_units, "daily_limit_units")?;
        ensure_positive(trust_weight, "trust_weight")?;
        let metadata_root =
            fast_withdrawal_payload_root("FAST-WITHDRAWAL-MAKER-METADATA", metadata);
        let maker_id = fast_withdrawal_maker_id(
            label,
            maker_kind.as_str(),
            operator_commitment,
            asset_id,
            inventory_commitment_root,
            public_key_commitment,
        );
        Ok(Self {
            maker_id,
            label: label.to_string(),
            maker_kind,
            operator_commitment: operator_commitment.to_string(),
            asset_id: asset_id.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            inventory_commitment_root: inventory_commitment_root.to_string(),
            reserve_proof_id: String::new(),
            public_key_commitment: public_key_commitment.to_string(),
            max_quote_units,
            available_units,
            reserved_units: 0,
            filled_units: 0,
            fee_floor_units,
            max_premium_bps,
            daily_limit_units,
            daily_filled_units: 0,
            trust_weight,
            status: MakerStatus::Active,
            metadata_root,
        })
    }

    pub fn validate(&self) -> FastWithdrawalResult<()> {
        ensure_non_empty(&self.maker_id, "maker_id")?;
        ensure_non_empty(&self.label, "label")?;
        ensure_non_empty(&self.operator_commitment, "operator_commitment")?;
        ensure_non_empty(&self.asset_id, "asset_id")?;
        ensure_non_empty(&self.fee_asset_id, "fee_asset_id")?;
        ensure_positive(self.max_quote_units, "max_quote_units")?;
        ensure_bps_at_most(
            self.max_premium_bps,
            FAST_WITHDRAWAL_MAX_BPS,
            "max_premium_bps",
        )?;
        Ok(())
    }

    pub fn unreserved_units(&self) -> u64 {
        self.available_units.saturating_sub(self.reserved_units)
    }

    pub fn can_quote(&self, amount_units: u64, premium_bps: u64) -> bool {
        self.status.accepts_flow()
            && amount_units <= self.max_quote_units
            && amount_units <= self.unreserved_units()
            && premium_bps <= self.max_premium_bps
            && self.daily_filled_units.saturating_add(amount_units) <= self.daily_limit_units
    }

    pub fn reserve_units(&mut self, amount_units: u64) -> FastWithdrawalResult<()> {
        ensure_positive(amount_units, "amount_units")?;
        if amount_units > self.unreserved_units() {
            return Err("maker has insufficient unreserved liquidity".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_add(amount_units);
        Ok(())
    }

    pub fn fill_reserved_units(&mut self, amount_units: u64) -> FastWithdrawalResult<()> {
        ensure_positive(amount_units, "amount_units")?;
        if amount_units > self.reserved_units {
            return Err("maker fill exceeds reserved units".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_sub(amount_units);
        self.available_units = self.available_units.saturating_sub(amount_units);
        self.filled_units = self.filled_units.saturating_add(amount_units);
        self.daily_filled_units = self.daily_filled_units.saturating_add(amount_units);
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_withdrawal_liquidity_maker",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "maker_id": self.maker_id,
            "label": self.label,
            "maker_kind": self.maker_kind.as_str(),
            "operator_commitment": self.operator_commitment,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "inventory_commitment_root": self.inventory_commitment_root,
            "reserve_proof_id": self.reserve_proof_id,
            "public_key_commitment": self.public_key_commitment,
            "max_quote_units": self.max_quote_units,
            "available_units": self.available_units,
            "reserved_units": self.reserved_units,
            "unreserved_units": self.unreserved_units(),
            "filled_units": self.filled_units,
            "fee_floor_units": self.fee_floor_units,
            "max_premium_bps": self.max_premium_bps,
            "daily_limit_units": self.daily_limit_units,
            "daily_filled_units": self.daily_filled_units,
            "trust_weight": self.trust_weight,
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root,
        })
    }

    pub fn maker_root(&self) -> String {
        fast_withdrawal_maker_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityMakerQuote {
    pub quote_id: String,
    pub maker_id: String,
    pub intent_id: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub amount_units: u64,
    pub gross_fee_units: u64,
    pub premium_bps: u64,
    pub maker_bond_units: u64,
    pub settlement_rail: SettlementRail,
    pub privacy_set_size: u64,
    pub quote_commitment_root: String,
    pub reserve_proof_id: String,
    pub sponsorship_id: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub fill_not_before_height: u64,
    pub challenge_window_end_height: u64,
    pub status: QuoteStatus,
    pub metadata_root: String,
}

impl LiquidityMakerQuote {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        maker_id: &str,
        intent_id: &str,
        asset_id: &str,
        fee_asset_id: &str,
        amount_units: u64,
        gross_fee_units: u64,
        premium_bps: u64,
        maker_bond_units: u64,
        settlement_rail: SettlementRail,
        privacy_set_size: u64,
        quote_commitment_root: &str,
        reserve_proof_id: &str,
        sponsorship_id: &str,
        created_at_height: u64,
        ttl_blocks: u64,
        challenge_window_blocks: u64,
        metadata: &Value,
    ) -> FastWithdrawalResult<Self> {
        ensure_non_empty(maker_id, "maker_id")?;
        ensure_non_empty(intent_id, "intent_id")?;
        ensure_non_empty(asset_id, "asset_id")?;
        ensure_non_empty(fee_asset_id, "fee_asset_id")?;
        ensure_positive(amount_units, "amount_units")?;
        ensure_bps_at_most(premium_bps, FAST_WITHDRAWAL_MAX_BPS, "premium_bps")?;
        ensure_positive(privacy_set_size, "privacy_set_size")?;
        ensure_non_empty(quote_commitment_root, "quote_commitment_root")?;
        ensure_positive(ttl_blocks, "ttl_blocks")?;
        ensure_positive(challenge_window_blocks, "challenge_window_blocks")?;
        let metadata_root =
            fast_withdrawal_payload_root("FAST-WITHDRAWAL-QUOTE-METADATA", metadata);
        let quote_id = fast_withdrawal_quote_id(
            maker_id,
            intent_id,
            asset_id,
            amount_units,
            gross_fee_units,
            premium_bps,
            created_at_height,
        );
        Ok(Self {
            quote_id,
            maker_id: maker_id.to_string(),
            intent_id: intent_id.to_string(),
            asset_id: asset_id.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            amount_units,
            gross_fee_units,
            premium_bps,
            maker_bond_units,
            settlement_rail,
            privacy_set_size,
            quote_commitment_root: quote_commitment_root.to_string(),
            reserve_proof_id: reserve_proof_id.to_string(),
            sponsorship_id: sponsorship_id.to_string(),
            created_at_height,
            expires_at_height: created_at_height.saturating_add(ttl_blocks),
            fill_not_before_height: created_at_height,
            challenge_window_end_height: created_at_height.saturating_add(challenge_window_blocks),
            status: QuoteStatus::Open,
            metadata_root,
        })
    }

    pub fn validate(&self) -> FastWithdrawalResult<()> {
        ensure_non_empty(&self.quote_id, "quote_id")?;
        ensure_non_empty(&self.maker_id, "maker_id")?;
        ensure_non_empty(&self.intent_id, "intent_id")?;
        ensure_positive(self.amount_units, "amount_units")?;
        ensure_bps_at_most(self.premium_bps, FAST_WITHDRAWAL_MAX_BPS, "premium_bps")?;
        if self.expires_at_height < self.created_at_height {
            return Err("quote expiry precedes creation height".to_string());
        }
        Ok(())
    }

    pub fn is_expired_at(&self, height: u64) -> bool {
        height > self.expires_at_height
    }

    pub fn net_receive_units(&self) -> u64 {
        self.amount_units.saturating_sub(self.gross_fee_units)
    }

    pub fn reserve(&mut self) -> FastWithdrawalResult<()> {
        if self.status != QuoteStatus::Open {
            return Err("quote is not open".to_string());
        }
        self.status = QuoteStatus::Reserved;
        Ok(())
    }

    pub fn fill(&mut self) -> FastWithdrawalResult<()> {
        if !matches!(self.status, QuoteStatus::Open | QuoteStatus::Reserved) {
            return Err("quote cannot be filled from current status".to_string());
        }
        self.status = QuoteStatus::Filled;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_withdrawal_liquidity_quote",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "quote_id": self.quote_id,
            "maker_id": self.maker_id,
            "intent_id": self.intent_id,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "amount_units": self.amount_units,
            "gross_fee_units": self.gross_fee_units,
            "net_receive_units": self.net_receive_units(),
            "premium_bps": self.premium_bps,
            "maker_bond_units": self.maker_bond_units,
            "settlement_rail": self.settlement_rail.as_str(),
            "privacy_set_size": self.privacy_set_size,
            "quote_commitment_root": self.quote_commitment_root,
            "reserve_proof_id": self.reserve_proof_id,
            "sponsorship_id": self.sponsorship_id,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "fill_not_before_height": self.fill_not_before_height,
            "challenge_window_end_height": self.challenge_window_end_height,
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root,
        })
    }

    pub fn quote_root(&self) -> String {
        fast_withdrawal_quote_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveProofSnapshot {
    pub proof_id: String,
    pub prover_id: String,
    pub reserve_account_commitment: String,
    pub asset_id: String,
    pub monero_network: String,
    pub reserve_view_root: String,
    pub output_set_root: String,
    pub spent_key_image_root: String,
    pub liabilities_root: String,
    pub gross_reserve_units: u64,
    pub reserved_exit_units: u64,
    pub pending_exit_units: u64,
    pub maker_inventory_units: u64,
    pub challenge_bond_units: u64,
    pub attestation_root: String,
    pub observed_at_height: u64,
    pub expires_at_height: u64,
    pub min_coverage_bps: u64,
    pub status: ReserveProofStatus,
    pub metadata_root: String,
}

impl ReserveProofSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        prover_id: &str,
        reserve_account_commitment: &str,
        asset_id: &str,
        monero_network: &str,
        reserve_view_root: &str,
        output_set_root: &str,
        spent_key_image_root: &str,
        liabilities_root: &str,
        gross_reserve_units: u64,
        reserved_exit_units: u64,
        pending_exit_units: u64,
        maker_inventory_units: u64,
        challenge_bond_units: u64,
        attestation_root: &str,
        observed_at_height: u64,
        ttl_blocks: u64,
        min_coverage_bps: u64,
        metadata: &Value,
    ) -> FastWithdrawalResult<Self> {
        ensure_non_empty(prover_id, "prover_id")?;
        ensure_non_empty(reserve_account_commitment, "reserve_account_commitment")?;
        ensure_non_empty(asset_id, "asset_id")?;
        ensure_non_empty(monero_network, "monero_network")?;
        ensure_non_empty(reserve_view_root, "reserve_view_root")?;
        ensure_non_empty(output_set_root, "output_set_root")?;
        ensure_non_empty(spent_key_image_root, "spent_key_image_root")?;
        ensure_non_empty(liabilities_root, "liabilities_root")?;
        ensure_positive(gross_reserve_units, "gross_reserve_units")?;
        ensure_positive(ttl_blocks, "ttl_blocks")?;
        ensure_positive(min_coverage_bps, "min_coverage_bps")?;
        let metadata_root =
            fast_withdrawal_payload_root("FAST-WITHDRAWAL-RESERVE-METADATA", metadata);
        let proof_id = fast_withdrawal_reserve_proof_id(
            prover_id,
            reserve_account_commitment,
            asset_id,
            output_set_root,
            liabilities_root,
            observed_at_height,
        );
        Ok(Self {
            proof_id,
            prover_id: prover_id.to_string(),
            reserve_account_commitment: reserve_account_commitment.to_string(),
            asset_id: asset_id.to_string(),
            monero_network: monero_network.to_string(),
            reserve_view_root: reserve_view_root.to_string(),
            output_set_root: output_set_root.to_string(),
            spent_key_image_root: spent_key_image_root.to_string(),
            liabilities_root: liabilities_root.to_string(),
            gross_reserve_units,
            reserved_exit_units,
            pending_exit_units,
            maker_inventory_units,
            challenge_bond_units,
            attestation_root: attestation_root.to_string(),
            observed_at_height,
            expires_at_height: observed_at_height.saturating_add(ttl_blocks),
            min_coverage_bps,
            status: ReserveProofStatus::Fresh,
            metadata_root,
        })
    }

    pub fn total_claimed_liability_units(&self) -> u64 {
        self.reserved_exit_units
            .saturating_add(self.pending_exit_units)
            .saturating_add(self.maker_inventory_units)
    }

    pub fn available_reserve_units(&self) -> u64 {
        self.gross_reserve_units
            .saturating_sub(self.total_claimed_liability_units())
    }

    pub fn coverage_bps(&self) -> u64 {
        ratio_bps(
            self.gross_reserve_units,
            self.total_claimed_liability_units(),
        )
    }

    pub fn is_expired_at(&self, height: u64) -> bool {
        height > self.expires_at_height
    }

    pub fn validate_coverage(&self) -> FastWithdrawalResult<u64> {
        let coverage_bps = self.coverage_bps();
        if coverage_bps < self.min_coverage_bps {
            return Err("reserve proof coverage is below configured minimum".to_string());
        }
        Ok(coverage_bps)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_withdrawal_reserve_proof",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "proof_id": self.proof_id,
            "prover_id": self.prover_id,
            "reserve_account_commitment": self.reserve_account_commitment,
            "asset_id": self.asset_id,
            "monero_network": self.monero_network,
            "reserve_view_root": self.reserve_view_root,
            "output_set_root": self.output_set_root,
            "spent_key_image_root": self.spent_key_image_root,
            "liabilities_root": self.liabilities_root,
            "gross_reserve_units": self.gross_reserve_units,
            "reserved_exit_units": self.reserved_exit_units,
            "pending_exit_units": self.pending_exit_units,
            "maker_inventory_units": self.maker_inventory_units,
            "total_claimed_liability_units": self.total_claimed_liability_units(),
            "available_reserve_units": self.available_reserve_units(),
            "coverage_bps": self.coverage_bps(),
            "challenge_bond_units": self.challenge_bond_units,
            "attestation_root": self.attestation_root,
            "observed_at_height": self.observed_at_height,
            "expires_at_height": self.expires_at_height,
            "min_coverage_bps": self.min_coverage_bps,
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root,
        })
    }

    pub fn proof_root(&self) -> String {
        fast_withdrawal_reserve_proof_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastWithdrawalChallenge {
    pub challenge_id: String,
    pub intent_id: String,
    pub quote_id: String,
    pub challenger_commitment: String,
    pub challenge_kind: ChallengeKind,
    pub evidence_root: String,
    pub evidence_payload_root: String,
    pub bond_units: u64,
    pub opened_at_height: u64,
    pub response_due_height: u64,
    pub resolved_at_height: u64,
    pub status: ChallengeStatus,
    pub resolution_root: String,
}

impl FastWithdrawalChallenge {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent_id: &str,
        quote_id: &str,
        challenger_commitment: &str,
        challenge_kind: ChallengeKind,
        evidence: &Value,
        bond_units: u64,
        opened_at_height: u64,
        response_window_blocks: u64,
    ) -> FastWithdrawalResult<Self> {
        ensure_non_empty(intent_id, "intent_id")?;
        ensure_non_empty(quote_id, "quote_id")?;
        ensure_non_empty(challenger_commitment, "challenger_commitment")?;
        ensure_positive(bond_units, "bond_units")?;
        ensure_positive(response_window_blocks, "response_window_blocks")?;
        let evidence_payload_root =
            fast_withdrawal_payload_root("FAST-WITHDRAWAL-CHALLENGE-EVIDENCE", evidence);
        let evidence_root = fast_withdrawal_string_root(
            "FAST-WITHDRAWAL-CHALLENGE-EVIDENCE-ROOT",
            &evidence_payload_root,
        );
        let challenge_id = fast_withdrawal_challenge_id(
            intent_id,
            quote_id,
            challenger_commitment,
            challenge_kind.as_str(),
            &evidence_root,
            opened_at_height,
        );
        Ok(Self {
            challenge_id,
            intent_id: intent_id.to_string(),
            quote_id: quote_id.to_string(),
            challenger_commitment: challenger_commitment.to_string(),
            challenge_kind,
            evidence_root,
            evidence_payload_root,
            bond_units,
            opened_at_height,
            response_due_height: opened_at_height.saturating_add(response_window_blocks),
            resolved_at_height: 0,
            status: ChallengeStatus::Open,
            resolution_root: merkle_root("FAST-WITHDRAWAL-CHALLENGE-RESOLUTION", &[]),
        })
    }

    pub fn is_expired_at(&self, height: u64) -> bool {
        self.status.is_open() && height > self.response_due_height
    }

    pub fn resolve(
        &mut self,
        accepted: bool,
        resolved_at_height: u64,
        resolution: &Value,
    ) -> FastWithdrawalResult<()> {
        if !self.status.is_open() {
            return Err("challenge is not open".to_string());
        }
        self.resolved_at_height = resolved_at_height;
        self.resolution_root =
            fast_withdrawal_payload_root("FAST-WITHDRAWAL-CHALLENGE-RESOLUTION", resolution);
        self.status = if accepted {
            ChallengeStatus::Accepted
        } else {
            ChallengeStatus::Rejected
        };
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_withdrawal_challenge",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "challenge_id": self.challenge_id,
            "intent_id": self.intent_id,
            "quote_id": self.quote_id,
            "challenger_commitment": self.challenger_commitment,
            "challenge_kind": self.challenge_kind.as_str(),
            "evidence_root": self.evidence_root,
            "evidence_payload_root": self.evidence_payload_root,
            "bond_units": self.bond_units,
            "opened_at_height": self.opened_at_height,
            "response_due_height": self.response_due_height,
            "resolved_at_height": self.resolved_at_height,
            "status": self.status.as_str(),
            "resolution_root": self.resolution_root,
        })
    }

    pub fn challenge_root(&self) -> String {
        fast_withdrawal_challenge_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyReceipt {
    pub receipt_id: String,
    pub intent_id: String,
    pub quote_id: String,
    pub maker_id: String,
    pub owner_receipt_commitment: String,
    pub recipient_receipt_commitment: String,
    pub amount_bucket: u64,
    pub fee_bucket: u64,
    pub nullifier: String,
    pub receipt_nullifier_root: String,
    pub encrypted_payload_root: String,
    pub settlement_tx_commitment: String,
    pub visibility: ReceiptVisibility,
    pub privacy_set_size: u64,
    pub issued_at_height: u64,
    pub reveal_after_height: u64,
    pub status: ReceiptStatus,
}

impl PrivacyReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent_id: &str,
        quote_id: &str,
        maker_id: &str,
        owner_receipt_commitment: &str,
        recipient_receipt_commitment: &str,
        amount_units: u64,
        fee_units: u64,
        receipt_secret: &str,
        encrypted_payload: &Value,
        settlement_tx_commitment: &str,
        visibility: ReceiptVisibility,
        privacy_set_size: u64,
        issued_at_height: u64,
        reveal_delay_blocks: u64,
    ) -> FastWithdrawalResult<Self> {
        ensure_non_empty(intent_id, "intent_id")?;
        ensure_non_empty(quote_id, "quote_id")?;
        ensure_non_empty(maker_id, "maker_id")?;
        ensure_non_empty(owner_receipt_commitment, "owner_receipt_commitment")?;
        ensure_non_empty(recipient_receipt_commitment, "recipient_receipt_commitment")?;
        ensure_positive(amount_units, "amount_units")?;
        ensure_non_empty(receipt_secret, "receipt_secret")?;
        ensure_non_empty(settlement_tx_commitment, "settlement_tx_commitment")?;
        ensure_positive(privacy_set_size, "privacy_set_size")?;
        let amount_bucket = fast_withdrawal_amount_bucket(amount_units);
        let fee_bucket = fast_withdrawal_amount_bucket(fee_units);
        let nullifier = fast_withdrawal_receipt_nullifier(
            intent_id,
            quote_id,
            owner_receipt_commitment,
            receipt_secret,
        );
        let receipt_nullifier_root =
            fast_withdrawal_string_root("FAST-WITHDRAWAL-RECEIPT-NULLIFIER", &nullifier);
        let encrypted_payload_root = fast_withdrawal_payload_root(
            "FAST-WITHDRAWAL-RECEIPT-ENCRYPTED-PAYLOAD",
            encrypted_payload,
        );
        let receipt_id = fast_withdrawal_receipt_id(
            intent_id,
            quote_id,
            maker_id,
            &receipt_nullifier_root,
            issued_at_height,
        );
        Ok(Self {
            receipt_id,
            intent_id: intent_id.to_string(),
            quote_id: quote_id.to_string(),
            maker_id: maker_id.to_string(),
            owner_receipt_commitment: owner_receipt_commitment.to_string(),
            recipient_receipt_commitment: recipient_receipt_commitment.to_string(),
            amount_bucket,
            fee_bucket,
            nullifier,
            receipt_nullifier_root,
            encrypted_payload_root,
            settlement_tx_commitment: settlement_tx_commitment.to_string(),
            visibility,
            privacy_set_size,
            issued_at_height,
            reveal_after_height: issued_at_height.saturating_add(reveal_delay_blocks),
            status: ReceiptStatus::Committed,
        })
    }

    pub fn reveal(&mut self, height: u64) -> FastWithdrawalResult<()> {
        if height < self.reveal_after_height {
            return Err("receipt reveal delay has not elapsed".to_string());
        }
        if self.status == ReceiptStatus::Revoked {
            return Err("cannot reveal revoked receipt".to_string());
        }
        self.status = ReceiptStatus::Revealed;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_withdrawal_privacy_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "intent_id": self.intent_id,
            "quote_id": self.quote_id,
            "maker_id": self.maker_id,
            "owner_receipt_commitment": self.owner_receipt_commitment,
            "recipient_receipt_commitment": self.recipient_receipt_commitment,
            "amount_bucket": self.amount_bucket,
            "fee_bucket": self.fee_bucket,
            "receipt_nullifier_root": self.receipt_nullifier_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "settlement_tx_commitment": self.settlement_tx_commitment,
            "visibility": self.visibility.as_str(),
            "privacy_set_size": self.privacy_set_size,
            "issued_at_height": self.issued_at_height,
            "reveal_after_height": self.reveal_after_height,
            "status": self.status.as_str(),
        })
    }

    pub fn receipt_root(&self) -> String {
        fast_withdrawal_receipt_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub intent_id: String,
    pub quote_id: String,
    pub fee_asset_id: String,
    pub gross_fee_units: u64,
    pub sponsored_fee_units: u64,
    pub rebate_bps: u64,
    pub sponsor_pool_id: String,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
    pub status: SponsorshipStatus,
    pub metadata_root: String,
}

impl LowFeeSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_commitment: &str,
        intent_id: &str,
        quote_id: &str,
        fee_asset_id: &str,
        gross_fee_units: u64,
        sponsored_fee_units: u64,
        sponsor_pool_id: &str,
        reserved_at_height: u64,
        ttl_blocks: u64,
        metadata: &Value,
    ) -> FastWithdrawalResult<Self> {
        ensure_non_empty(sponsor_commitment, "sponsor_commitment")?;
        ensure_non_empty(intent_id, "intent_id")?;
        ensure_non_empty(quote_id, "quote_id")?;
        ensure_non_empty(fee_asset_id, "fee_asset_id")?;
        ensure_non_empty(sponsor_pool_id, "sponsor_pool_id")?;
        ensure_positive(ttl_blocks, "ttl_blocks")?;
        if sponsored_fee_units > gross_fee_units {
            return Err("sponsored_fee_units exceeds gross_fee_units".to_string());
        }
        let rebate_bps = ratio_bps(sponsored_fee_units, gross_fee_units);
        let metadata_root =
            fast_withdrawal_payload_root("FAST-WITHDRAWAL-SPONSORSHIP-METADATA", metadata);
        let sponsorship_id = fast_withdrawal_sponsorship_id(
            sponsor_commitment,
            intent_id,
            quote_id,
            fee_asset_id,
            gross_fee_units,
            sponsored_fee_units,
            reserved_at_height,
        );
        Ok(Self {
            sponsorship_id,
            sponsor_commitment: sponsor_commitment.to_string(),
            intent_id: intent_id.to_string(),
            quote_id: quote_id.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            gross_fee_units,
            sponsored_fee_units,
            rebate_bps,
            sponsor_pool_id: sponsor_pool_id.to_string(),
            reserved_at_height,
            expires_at_height: reserved_at_height.saturating_add(ttl_blocks),
            status: SponsorshipStatus::Reserved,
            metadata_root,
        })
    }

    pub fn apply(&mut self) -> FastWithdrawalResult<()> {
        if self.status != SponsorshipStatus::Reserved {
            return Err("sponsorship is not reserved".to_string());
        }
        self.status = SponsorshipStatus::Applied;
        Ok(())
    }

    pub fn is_expired_at(&self, height: u64) -> bool {
        height > self.expires_at_height && self.status == SponsorshipStatus::Reserved
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_withdrawal_low_fee_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "intent_id": self.intent_id,
            "quote_id": self.quote_id,
            "fee_asset_id": self.fee_asset_id,
            "gross_fee_units": self.gross_fee_units,
            "sponsored_fee_units": self.sponsored_fee_units,
            "rebate_bps": self.rebate_bps,
            "sponsor_pool_id": self.sponsor_pool_id,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root,
        })
    }

    pub fn sponsorship_root(&self) -> String {
        fast_withdrawal_sponsorship_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorRiskLimits {
    pub limits_id: String,
    pub operator_commitment: String,
    pub mode: OperatorRiskMode,
    pub max_operator_exposure_units: u64,
    pub max_single_intent_units: u64,
    pub max_pending_intents: usize,
    pub max_maker_exposure_units: u64,
    pub min_reserve_coverage_bps: u64,
    pub warn_reserve_coverage_bps: u64,
    pub daily_limit_units: u64,
    pub challenge_halt_threshold: u64,
    pub sponsor_pool_limit_units: u64,
    pub updated_at_height: u64,
}

impl OperatorRiskLimits {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operator_commitment: &str,
        mode: OperatorRiskMode,
        max_operator_exposure_units: u64,
        max_single_intent_units: u64,
        max_pending_intents: usize,
        max_maker_exposure_units: u64,
        min_reserve_coverage_bps: u64,
        warn_reserve_coverage_bps: u64,
        daily_limit_units: u64,
        challenge_halt_threshold: u64,
        sponsor_pool_limit_units: u64,
        updated_at_height: u64,
    ) -> FastWithdrawalResult<Self> {
        ensure_non_empty(operator_commitment, "operator_commitment")?;
        ensure_positive(max_operator_exposure_units, "max_operator_exposure_units")?;
        ensure_positive(max_single_intent_units, "max_single_intent_units")?;
        if max_pending_intents == 0 {
            return Err("max_pending_intents must be positive".to_string());
        }
        ensure_positive(max_maker_exposure_units, "max_maker_exposure_units")?;
        ensure_positive(min_reserve_coverage_bps, "min_reserve_coverage_bps")?;
        ensure_positive(warn_reserve_coverage_bps, "warn_reserve_coverage_bps")?;
        ensure_positive(daily_limit_units, "daily_limit_units")?;
        let limits_id = fast_withdrawal_operator_limits_id(
            operator_commitment,
            mode.as_str(),
            max_operator_exposure_units,
            daily_limit_units,
            updated_at_height,
        );
        Ok(Self {
            limits_id,
            operator_commitment: operator_commitment.to_string(),
            mode,
            max_operator_exposure_units,
            max_single_intent_units,
            max_pending_intents,
            max_maker_exposure_units,
            min_reserve_coverage_bps,
            warn_reserve_coverage_bps,
            daily_limit_units,
            challenge_halt_threshold,
            sponsor_pool_limit_units,
            updated_at_height,
        })
    }

    pub fn from_config(operator_commitment: &str, config: &FastWithdrawalConfig) -> Self {
        Self::new(
            operator_commitment,
            OperatorRiskMode::Normal,
            config.max_operator_exposure_units,
            config.max_maker_exposure_units,
            config.max_pending_intents,
            config.max_maker_exposure_units,
            config.min_reserve_coverage_bps,
            config.warn_reserve_coverage_bps,
            config.operator_daily_limit_units,
            3,
            config.default_sponsor_pool_units,
            0,
        )
        .expect("default fast withdrawal risk limits")
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_withdrawal_operator_risk_limits",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "limits_id": self.limits_id,
            "operator_commitment": self.operator_commitment,
            "mode": self.mode.as_str(),
            "max_operator_exposure_units": self.max_operator_exposure_units,
            "max_single_intent_units": self.max_single_intent_units,
            "max_pending_intents": self.max_pending_intents as u64,
            "max_maker_exposure_units": self.max_maker_exposure_units,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "warn_reserve_coverage_bps": self.warn_reserve_coverage_bps,
            "daily_limit_units": self.daily_limit_units,
            "challenge_halt_threshold": self.challenge_halt_threshold,
            "sponsor_pool_limit_units": self.sponsor_pool_limit_units,
            "updated_at_height": self.updated_at_height,
        })
    }

    pub fn limits_root(&self) -> String {
        fast_withdrawal_operator_limits_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorExposureSnapshot {
    pub snapshot_id: String,
    pub operator_commitment: String,
    pub height: u64,
    pub pending_intent_count: u64,
    pub open_quote_count: u64,
    pub challenged_count: u64,
    pub pending_exposure_units: u64,
    pub maker_reserved_units: u64,
    pub maker_filled_units: u64,
    pub sponsor_reserved_units: u64,
    pub reserve_available_units: u64,
    pub reserve_coverage_bps: u64,
    pub risk_status: RiskLimitStatus,
    pub risk_root: String,
}

impl OperatorExposureSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operator_commitment: &str,
        height: u64,
        pending_intent_count: u64,
        open_quote_count: u64,
        challenged_count: u64,
        pending_exposure_units: u64,
        maker_reserved_units: u64,
        maker_filled_units: u64,
        sponsor_reserved_units: u64,
        reserve_available_units: u64,
        reserve_coverage_bps: u64,
        risk_status: RiskLimitStatus,
    ) -> FastWithdrawalResult<Self> {
        ensure_non_empty(operator_commitment, "operator_commitment")?;
        let risk_payload = json!({
            "pending_intent_count": pending_intent_count,
            "open_quote_count": open_quote_count,
            "challenged_count": challenged_count,
            "pending_exposure_units": pending_exposure_units,
            "maker_reserved_units": maker_reserved_units,
            "maker_filled_units": maker_filled_units,
            "sponsor_reserved_units": sponsor_reserved_units,
            "reserve_available_units": reserve_available_units,
            "reserve_coverage_bps": reserve_coverage_bps,
            "risk_status": risk_status.as_str(),
        });
        let risk_root =
            fast_withdrawal_payload_root("FAST-WITHDRAWAL-OPERATOR-RISK", &risk_payload);
        let snapshot_id =
            fast_withdrawal_exposure_snapshot_id(operator_commitment, height, &risk_root);
        Ok(Self {
            snapshot_id,
            operator_commitment: operator_commitment.to_string(),
            height,
            pending_intent_count,
            open_quote_count,
            challenged_count,
            pending_exposure_units,
            maker_reserved_units,
            maker_filled_units,
            sponsor_reserved_units,
            reserve_available_units,
            reserve_coverage_bps,
            risk_status,
            risk_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_withdrawal_operator_exposure_snapshot",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "snapshot_id": self.snapshot_id,
            "operator_commitment": self.operator_commitment,
            "height": self.height,
            "pending_intent_count": self.pending_intent_count,
            "open_quote_count": self.open_quote_count,
            "challenged_count": self.challenged_count,
            "pending_exposure_units": self.pending_exposure_units,
            "maker_reserved_units": self.maker_reserved_units,
            "maker_filled_units": self.maker_filled_units,
            "sponsor_reserved_units": self.sponsor_reserved_units,
            "reserve_available_units": self.reserve_available_units,
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "risk_status": self.risk_status.as_str(),
            "risk_root": self.risk_root,
        })
    }

    pub fn snapshot_root(&self) -> String {
        fast_withdrawal_exposure_snapshot_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastWithdrawalSettlement {
    pub settlement_id: String,
    pub intent_id: String,
    pub quote_id: String,
    pub receipt_id: String,
    pub maker_id: String,
    pub rail: SettlementRail,
    pub asset_id: String,
    pub amount_units: u64,
    pub fee_units: u64,
    pub settlement_tx_commitment: String,
    pub monero_tx_key_root: String,
    pub broadcast_at_height: u64,
    pub confirmed_at_height: u64,
    pub final_at_height: u64,
    pub confirmation_count: u64,
    pub status: SettlementStatus,
}

impl FastWithdrawalSettlement {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent_id: &str,
        quote_id: &str,
        receipt_id: &str,
        maker_id: &str,
        rail: SettlementRail,
        asset_id: &str,
        amount_units: u64,
        fee_units: u64,
        settlement_tx_commitment: &str,
        monero_tx_key_root: &str,
        broadcast_at_height: u64,
        finality_blocks: u64,
    ) -> FastWithdrawalResult<Self> {
        ensure_non_empty(intent_id, "intent_id")?;
        ensure_non_empty(quote_id, "quote_id")?;
        ensure_non_empty(receipt_id, "receipt_id")?;
        ensure_non_empty(maker_id, "maker_id")?;
        ensure_non_empty(asset_id, "asset_id")?;
        ensure_positive(amount_units, "amount_units")?;
        ensure_non_empty(settlement_tx_commitment, "settlement_tx_commitment")?;
        ensure_non_empty(monero_tx_key_root, "monero_tx_key_root")?;
        ensure_positive(finality_blocks, "finality_blocks")?;
        let settlement_id = fast_withdrawal_settlement_id(
            intent_id,
            quote_id,
            receipt_id,
            maker_id,
            settlement_tx_commitment,
            broadcast_at_height,
        );
        Ok(Self {
            settlement_id,
            intent_id: intent_id.to_string(),
            quote_id: quote_id.to_string(),
            receipt_id: receipt_id.to_string(),
            maker_id: maker_id.to_string(),
            rail,
            asset_id: asset_id.to_string(),
            amount_units,
            fee_units,
            settlement_tx_commitment: settlement_tx_commitment.to_string(),
            monero_tx_key_root: monero_tx_key_root.to_string(),
            broadcast_at_height,
            confirmed_at_height: 0,
            final_at_height: broadcast_at_height.saturating_add(finality_blocks),
            confirmation_count: 0,
            status: SettlementStatus::Broadcast,
        })
    }

    pub fn mark_confirmed(&mut self, height: u64, confirmations: u64) -> FastWithdrawalResult<()> {
        if self.status.is_terminal() {
            return Err("settlement already terminal".to_string());
        }
        self.confirmed_at_height = height;
        self.confirmation_count = confirmations;
        self.status = if height >= self.final_at_height {
            SettlementStatus::Finalized
        } else {
            SettlementStatus::Confirmed
        };
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_withdrawal_settlement",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "settlement_id": self.settlement_id,
            "intent_id": self.intent_id,
            "quote_id": self.quote_id,
            "receipt_id": self.receipt_id,
            "maker_id": self.maker_id,
            "rail": self.rail.as_str(),
            "asset_id": self.asset_id,
            "amount_units": self.amount_units,
            "fee_units": self.fee_units,
            "settlement_tx_commitment": self.settlement_tx_commitment,
            "monero_tx_key_root": self.monero_tx_key_root,
            "broadcast_at_height": self.broadcast_at_height,
            "confirmed_at_height": self.confirmed_at_height,
            "final_at_height": self.final_at_height,
            "confirmation_count": self.confirmation_count,
            "status": self.status.as_str(),
        })
    }

    pub fn settlement_root(&self) -> String {
        fast_withdrawal_settlement_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastWithdrawalPublicRecord {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub payload_root: String,
    pub emitted_at_height: u64,
    pub publisher_commitment: String,
}

impl FastWithdrawalPublicRecord {
    pub fn new(
        record_kind: &str,
        subject_id: &str,
        subject_root: &str,
        payload: &Value,
        emitted_at_height: u64,
        publisher_commitment: &str,
    ) -> FastWithdrawalResult<Self> {
        ensure_non_empty(record_kind, "record_kind")?;
        ensure_non_empty(subject_id, "subject_id")?;
        ensure_non_empty(subject_root, "subject_root")?;
        ensure_non_empty(publisher_commitment, "publisher_commitment")?;
        let payload_root = fast_withdrawal_payload_root("FAST-WITHDRAWAL-PUBLIC-PAYLOAD", payload);
        let record_id = fast_withdrawal_public_record_id(
            record_kind,
            subject_id,
            subject_root,
            &payload_root,
            emitted_at_height,
            publisher_commitment,
        );
        Ok(Self {
            record_id,
            record_kind: record_kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            payload_root,
            emitted_at_height,
            publisher_commitment: publisher_commitment.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_withdrawal_public_record",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "payload_root": self.payload_root,
            "emitted_at_height": self.emitted_at_height,
            "publisher_commitment": self.publisher_commitment,
        })
    }

    pub fn record_root(&self) -> String {
        fast_withdrawal_public_record_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastWithdrawalRoots {
    pub config_root: String,
    pub operator_limits_root: String,
    pub intent_root: String,
    pub maker_root: String,
    pub quote_root: String,
    pub challenge_root: String,
    pub reserve_proof_root: String,
    pub receipt_root: String,
    pub sponsorship_root: String,
    pub settlement_root: String,
    pub pq_attestation_root: String,
    pub exposure_snapshot_root: String,
    pub public_record_root: String,
}

impl FastWithdrawalRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_withdrawal_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "config_root": self.config_root,
            "operator_limits_root": self.operator_limits_root,
            "intent_root": self.intent_root,
            "maker_root": self.maker_root,
            "quote_root": self.quote_root,
            "challenge_root": self.challenge_root,
            "reserve_proof_root": self.reserve_proof_root,
            "receipt_root": self.receipt_root,
            "sponsorship_root": self.sponsorship_root,
            "settlement_root": self.settlement_root,
            "pq_attestation_root": self.pq_attestation_root,
            "exposure_snapshot_root": self.exposure_snapshot_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastWithdrawalState {
    pub height: u64,
    pub operator_commitment: String,
    pub active_reserve_proof_id: String,
    pub config: FastWithdrawalConfig,
    pub operator_limits: OperatorRiskLimits,
    pub intents: BTreeMap<String, WithdrawalIntent>,
    pub makers: BTreeMap<String, LiquidityMaker>,
    pub quotes: BTreeMap<String, LiquidityMakerQuote>,
    pub challenges: BTreeMap<String, FastWithdrawalChallenge>,
    pub reserve_proofs: BTreeMap<String, ReserveProofSnapshot>,
    pub receipts: BTreeMap<String, PrivacyReceipt>,
    pub sponsorships: BTreeMap<String, LowFeeSponsorship>,
    pub settlements: BTreeMap<String, FastWithdrawalSettlement>,
    pub pq_attestations: BTreeMap<String, PqWithdrawalAttestation>,
    pub exposure_snapshots: BTreeMap<String, OperatorExposureSnapshot>,
    pub public_records: BTreeMap<String, FastWithdrawalPublicRecord>,
}

impl FastWithdrawalState {
    pub fn new(
        config: FastWithdrawalConfig,
        operator_commitment: &str,
        height: u64,
    ) -> FastWithdrawalResult<Self> {
        config.validate()?;
        ensure_non_empty(operator_commitment, "operator_commitment")?;
        let operator_limits = OperatorRiskLimits::from_config(operator_commitment, &config);
        Ok(Self {
            height,
            operator_commitment: operator_commitment.to_string(),
            active_reserve_proof_id: String::new(),
            config,
            operator_limits,
            intents: BTreeMap::new(),
            makers: BTreeMap::new(),
            quotes: BTreeMap::new(),
            challenges: BTreeMap::new(),
            reserve_proofs: BTreeMap::new(),
            receipts: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            settlements: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            exposure_snapshots: BTreeMap::new(),
            public_records: BTreeMap::new(),
        })
    }

    pub fn devnet() -> FastWithdrawalResult<Self> {
        let mut state = Self::new(
            FastWithdrawalConfig::default(),
            &fast_withdrawal_account_commitment("devnet-fast-withdrawal-operator"),
            FAST_WITHDRAWAL_DEVNET_HEIGHT,
        )?;
        state.operator_limits = OperatorRiskLimits::new(
            &state.operator_commitment,
            OperatorRiskMode::Normal,
            3_000_000,
            500_000,
            512,
            900_000,
            11_000,
            12_000,
            6_000_000,
            4,
            75_000,
            state.height,
        )?;

        let reserve_attestation_root = fast_withdrawal_string_set_root(
            "FAST-WITHDRAWAL-DEVNET-RESERVE-ATTESTERS",
            &[
                "devnet-reserve-attester-a".to_string(),
                "devnet-reserve-attester-b".to_string(),
                "devnet-monero-watchtower".to_string(),
            ],
        );
        let reserve_proof = ReserveProofSnapshot::new(
            "devnet-reserve-prover",
            &fast_withdrawal_account_commitment("devnet-hot-reserve"),
            &state.config.asset_id,
            &state.config.monero_network,
            &fast_withdrawal_string_root("FAST-WITHDRAWAL-DEVNET-RESERVE-VIEW", "hot-wallet-view"),
            &fast_withdrawal_string_root(
                "FAST-WITHDRAWAL-DEVNET-OUTPUT-SET",
                "unspent-hot-outputs",
            ),
            &fast_withdrawal_string_root("FAST-WITHDRAWAL-DEVNET-KEY-IMAGES", "spent-key-images"),
            &fast_withdrawal_string_root("FAST-WITHDRAWAL-DEVNET-LIABILITIES", "exit-liabilities"),
            4_500_000,
            450_000,
            125_000,
            800_000,
            12_500,
            &reserve_attestation_root,
            state.height.saturating_sub(3),
            36,
            state.config.min_reserve_coverage_bps,
            &json!({"reserve_lane": "hot", "auditor": "devnet-auditor"}),
        )?;
        let reserve_proof_id = reserve_proof.proof_id.clone();
        state.insert_reserve_proof(reserve_proof)?;
        state.active_reserve_proof_id = reserve_proof_id.clone();

        let maker_a = LiquidityMaker::new(
            "devnet-maker-alpha",
            MakerKind::ExternalMarketMaker,
            &fast_withdrawal_account_commitment("maker-alpha-operator"),
            &state.config.asset_id,
            &state.config.fee_asset_id,
            &fast_withdrawal_string_root("FAST-WITHDRAWAL-DEVNET-MAKER-A-INVENTORY", "alpha-xmr"),
            &fast_withdrawal_account_commitment("maker-alpha-pq-key"),
            350_000,
            900_000,
            2,
            60,
            1_500_000,
            3,
            &json!({"latency_blocks": 1, "rail": "maker_inventory"}),
        )?;
        let maker_a_id = maker_a.maker_id.clone();
        state.insert_maker(maker_a)?;
        if let Some(maker) = state.makers.get_mut(&maker_a_id) {
            maker.reserve_proof_id = reserve_proof_id.clone();
        }

        let maker_b = LiquidityMaker::new(
            "devnet-community-vault",
            MakerKind::CommunityVault,
            &fast_withdrawal_account_commitment("community-vault-operator"),
            &state.config.asset_id,
            &state.config.fee_asset_id,
            &fast_withdrawal_string_root("FAST-WITHDRAWAL-DEVNET-MAKER-B-INVENTORY", "community"),
            &fast_withdrawal_account_commitment("community-vault-pq-key"),
            150_000,
            250_000,
            1,
            25,
            600_000,
            2,
            &json!({"latency_blocks": 2, "rail": "sponsored_batch"}),
        )?;
        let maker_b_id = maker_b.maker_id.clone();
        state.insert_maker(maker_b)?;
        if let Some(maker) = state.makers.get_mut(&maker_b_id) {
            maker.reserve_proof_id = reserve_proof_id.clone();
        }

        let alice_owner = fast_withdrawal_account_commitment("alice-devnet-wallet");
        let alice_wallet_attestation = PqWithdrawalAttestation::new(
            "withdrawal_intent_preimage",
            "alice-devnet-intent",
            &fast_withdrawal_string_root("FAST-WITHDRAWAL-DEVNET-ALICE-PREIMAGE", "intent"),
            "alice-devnet-wallet",
            PqAttestationRole::Wallet,
            &fast_withdrawal_account_commitment("alice-devnet-ml-dsa-key"),
            FAST_WITHDRAWAL_ATTESTATION_SCHEME,
            &fast_withdrawal_string_root("FAST-WITHDRAWAL-DEVNET-ALICE-TRANSCRIPT", "wallet"),
            1,
            state.height,
            state.config.default_intent_ttl_blocks,
        )?;
        let alice_attestation_root = alice_wallet_attestation.attestation_root();
        state.insert_pq_attestation(alice_wallet_attestation)?;

        let alice_intent = WithdrawalIntent::new(
            &alice_owner,
            &fast_withdrawal_account_commitment("alice-monero-recipient"),
            &fast_withdrawal_string_root("FAST-WITHDRAWAL-DEVNET-ALICE-VIEW-TAG", "view-tag"),
            &state.config.asset_id,
            125_000,
            12,
            ExitPriority::Fast,
            SettlementRail::MakerInventory,
            &fast_withdrawal_string_root("FAST-WITHDRAWAL-DEVNET-ALICE-SOURCE", "note-root"),
            &fast_withdrawal_string_root("FAST-WITHDRAWAL-DEVNET-ALICE-NULLIFIER", "nullifier"),
            7,
            "devnet-pq-session-alice",
            &alice_attestation_root,
            state.height,
            state.config.default_intent_ttl_blocks,
            state.config.default_challenge_window_blocks,
            state.config.default_privacy_set_size,
            &json!({"wallet": "alice", "path": "instant"}),
        )?;
        let alice_intent_id = alice_intent.intent_id.clone();
        state.submit_intent(alice_intent)?;

        let alice_quote = state.quote_intent(
            &maker_a_id,
            &alice_intent_id,
            125_000,
            9,
            35,
            SettlementRail::MakerInventory,
            &json!({"quote": "alpha-fast", "spread_bps": 35}),
        )?;
        state.reserve_quote(&alice_quote.quote_id)?;
        let alice_receipt = state.fund_reserved_quote(
            &alice_quote.quote_id,
            &fast_withdrawal_account_commitment("alice-receipt-owner"),
            &fast_withdrawal_account_commitment("alice-receipt-recipient"),
            "alice-devnet-receipt-secret",
            &json!({"ciphertext": "devnet-alice-receipt", "hint": "amount-bucket-only"}),
            &fast_withdrawal_string_root("FAST-WITHDRAWAL-DEVNET-ALICE-TX", "monero-tx"),
        )?;
        state.record_settlement(
            &alice_quote.quote_id,
            &alice_receipt.receipt_id,
            &fast_withdrawal_string_root("FAST-WITHDRAWAL-DEVNET-ALICE-TX-KEY", "tx-key"),
        )?;

        let bob_owner = fast_withdrawal_account_commitment("bob-devnet-wallet");
        let bob_wallet_attestation = PqWithdrawalAttestation::new(
            "withdrawal_intent_preimage",
            "bob-devnet-intent",
            &fast_withdrawal_string_root("FAST-WITHDRAWAL-DEVNET-BOB-PREIMAGE", "intent"),
            "bob-devnet-wallet",
            PqAttestationRole::Wallet,
            &fast_withdrawal_account_commitment("bob-devnet-ml-dsa-key"),
            FAST_WITHDRAWAL_ATTESTATION_SCHEME,
            &fast_withdrawal_string_root("FAST-WITHDRAWAL-DEVNET-BOB-TRANSCRIPT", "wallet"),
            1,
            state.height,
            state.config.default_intent_ttl_blocks,
        )?;
        let bob_attestation_root = bob_wallet_attestation.attestation_root();
        state.insert_pq_attestation(bob_wallet_attestation)?;

        let bob_intent = WithdrawalIntent::new(
            &bob_owner,
            &fast_withdrawal_account_commitment("bob-monero-recipient"),
            &fast_withdrawal_string_root("FAST-WITHDRAWAL-DEVNET-BOB-VIEW-TAG", "view-tag"),
            &state.config.asset_id,
            65_000,
            8,
            ExitPriority::Sponsored,
            SettlementRail::SponsoredBatch,
            &fast_withdrawal_string_root("FAST-WITHDRAWAL-DEVNET-BOB-SOURCE", "note-root"),
            &fast_withdrawal_string_root("FAST-WITHDRAWAL-DEVNET-BOB-NULLIFIER", "nullifier"),
            11,
            "devnet-pq-session-bob",
            &bob_attestation_root,
            state.height.saturating_add(1),
            state.config.default_intent_ttl_blocks,
            state.config.default_challenge_window_blocks,
            state.config.default_privacy_set_size.saturating_mul(2),
            &json!({"wallet": "bob", "path": "sponsored"}),
        )?;
        let bob_intent_id = bob_intent.intent_id.clone();
        state.submit_intent(bob_intent)?;
        let bob_quote = state.quote_intent(
            &maker_b_id,
            &bob_intent_id,
            65_000,
            6,
            20,
            SettlementRail::SponsoredBatch,
            &json!({"quote": "community-sponsored", "spread_bps": 20}),
        )?;
        let bob_sponsorship = state.reserve_sponsorship(
            "devnet-low-fee-sponsor",
            &bob_intent_id,
            &bob_quote.quote_id,
            6,
            5,
            "devnet-fast-withdrawal-sponsor-pool",
            &json!({"reason": "small-exit-fee-smoothing"}),
        )?;
        state.bind_sponsorship_to_quote(&bob_quote.quote_id, &bob_sponsorship.sponsorship_id)?;

        let challenge = state.open_challenge(
            &bob_intent_id,
            &bob_quote.quote_id,
            &fast_withdrawal_account_commitment("devnet-watchtower"),
            ChallengeKind::SettlementTimeout,
            &json!({"observed_delay_blocks": 2, "expected": "sponsor batch broadcast"}),
            4,
        )?;
        state.resolve_challenge(
            &challenge.challenge_id,
            false,
            &json!({"resolution": "batch still within quoted relay delay"}),
        )?;

        state.refresh_exposure_snapshot()?;
        let record = state.public_record_without_root();
        state.publish_public_record(
            "fast_withdrawal_devnet",
            "bootstrap",
            &fast_withdrawal_state_root_from_record(&record),
            &record,
        )?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        for intent in self.intents.values_mut() {
            if intent.is_expired_at(height) && intent.status.is_open() {
                intent.status = WithdrawalIntentStatus::Expired;
            }
        }
        for quote in self.quotes.values_mut() {
            if quote.is_expired_at(height) && quote.status == QuoteStatus::Open {
                quote.status = QuoteStatus::Expired;
            }
        }
        for challenge in self.challenges.values_mut() {
            if challenge.is_expired_at(height) {
                challenge.status = ChallengeStatus::Expired;
            }
        }
        for proof in self.reserve_proofs.values_mut() {
            if proof.is_expired_at(height) && proof.status.counts_as_live() {
                proof.status = ReserveProofStatus::Stale;
            }
        }
        for sponsorship in self.sponsorships.values_mut() {
            if sponsorship.is_expired_at(height) {
                sponsorship.status = SponsorshipStatus::Expired;
            }
        }
    }

    pub fn insert_pq_attestation(
        &mut self,
        attestation: PqWithdrawalAttestation,
    ) -> FastWithdrawalResult<PqWithdrawalAttestation> {
        if attestation.is_expired_at(self.height) {
            return Err("pq withdrawal attestation is expired".to_string());
        }
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation.clone());
        Ok(attestation)
    }

    pub fn submit_intent(
        &mut self,
        mut intent: WithdrawalIntent,
    ) -> FastWithdrawalResult<WithdrawalIntent> {
        intent.validate()?;
        if !self.operator_limits.mode.accepts_new_intents() {
            return Err("operator risk mode does not accept new intents".to_string());
        }
        if self.pending_intent_count() as usize >= self.operator_limits.max_pending_intents {
            return Err("pending fast withdrawal intent limit exceeded".to_string());
        }
        if intent.amount_units > self.operator_limits.max_single_intent_units {
            return Err("fast withdrawal intent exceeds single intent limit".to_string());
        }
        if self
            .pending_exposure_units()
            .saturating_add(intent.amount_units)
            > self.operator_limits.max_operator_exposure_units
        {
            return Err("operator exposure limit exceeded".to_string());
        }
        if self
            .intents
            .values()
            .any(|existing| existing.nullifier_root == intent.nullifier_root)
        {
            return Err("duplicate withdrawal nullifier root".to_string());
        }
        intent.status = WithdrawalIntentStatus::Attested;
        self.intents
            .insert(intent.intent_id.clone(), intent.clone());
        Ok(intent)
    }

    pub fn insert_maker(&mut self, maker: LiquidityMaker) -> FastWithdrawalResult<LiquidityMaker> {
        maker.validate()?;
        self.makers.insert(maker.maker_id.clone(), maker.clone());
        Ok(maker)
    }

    pub fn insert_reserve_proof(
        &mut self,
        proof: ReserveProofSnapshot,
    ) -> FastWithdrawalResult<ReserveProofSnapshot> {
        proof.validate_coverage()?;
        if proof.is_expired_at(self.height) {
            return Err("reserve proof is expired".to_string());
        }
        self.reserve_proofs
            .insert(proof.proof_id.clone(), proof.clone());
        if self.active_reserve_proof_id.is_empty() {
            self.active_reserve_proof_id = proof.proof_id.clone();
        }
        Ok(proof)
    }

    pub fn quote_intent(
        &mut self,
        maker_id: &str,
        intent_id: &str,
        amount_units: u64,
        gross_fee_units: u64,
        premium_bps: u64,
        settlement_rail: SettlementRail,
        metadata: &Value,
    ) -> FastWithdrawalResult<LiquidityMakerQuote> {
        let intent = self
            .intents
            .get(intent_id)
            .ok_or_else(|| format!("unknown withdrawal intent: {intent_id}"))?;
        if intent.status.is_terminal() {
            return Err("cannot quote terminal withdrawal intent".to_string());
        }
        if amount_units != intent.amount_units {
            return Err("quote amount does not match withdrawal intent".to_string());
        }
        if gross_fee_units > intent.max_fee_units {
            return Err("quote fee exceeds intent max fee".to_string());
        }
        if premium_bps > self.config.max_quote_premium_bps {
            return Err("quote premium exceeds protocol max".to_string());
        }
        let open_quotes = self
            .quotes
            .values()
            .filter(|quote| quote.maker_id == maker_id && quote.status == QuoteStatus::Open)
            .count();
        if open_quotes >= self.config.max_open_quotes_per_maker {
            return Err("maker open quote limit exceeded".to_string());
        }
        let maker = self
            .makers
            .get(maker_id)
            .ok_or_else(|| format!("unknown liquidity maker: {maker_id}"))?;
        if !maker.can_quote(amount_units, premium_bps) {
            return Err("maker cannot quote requested withdrawal".to_string());
        }
        let reserve_proof_id = if maker.reserve_proof_id.is_empty() {
            self.active_reserve_proof_id.clone()
        } else {
            maker.reserve_proof_id.clone()
        };
        if !reserve_proof_id.is_empty() {
            let proof = self
                .reserve_proofs
                .get(&reserve_proof_id)
                .ok_or_else(|| "quote references unknown reserve proof".to_string())?;
            if proof.is_expired_at(self.height) {
                return Err("quote reserve proof is expired".to_string());
            }
            proof.validate_coverage()?;
        }
        let ttl_blocks = intent.priority.default_quote_ttl_blocks();
        let quote_commitment_root = fast_withdrawal_payload_root(
            "FAST-WITHDRAWAL-QUOTE-COMMITMENT",
            &json!({
                "maker_id": maker_id,
                "intent_id": intent_id,
                "amount_units": amount_units,
                "gross_fee_units": gross_fee_units,
                "premium_bps": premium_bps,
                "settlement_rail": settlement_rail.as_str(),
                "height": self.height,
            }),
        );
        let quote = LiquidityMakerQuote::new(
            maker_id,
            intent_id,
            &intent.asset_id,
            &self.config.fee_asset_id,
            amount_units,
            gross_fee_units,
            premium_bps,
            gross_fee_units
                .saturating_mul(2)
                .max(self.config.default_fee_floor_units),
            settlement_rail,
            intent.privacy_set_size,
            &quote_commitment_root,
            &reserve_proof_id,
            "",
            self.height,
            ttl_blocks,
            self.config.default_challenge_window_blocks,
            metadata,
        )?;
        self.quotes.insert(quote.quote_id.clone(), quote.clone());
        Ok(quote)
    }

    pub fn reserve_quote(&mut self, quote_id: &str) -> FastWithdrawalResult<LiquidityMakerQuote> {
        let quote = self
            .quotes
            .get_mut(quote_id)
            .ok_or_else(|| format!("unknown quote: {quote_id}"))?;
        if quote.is_expired_at(self.height) {
            quote.status = QuoteStatus::Expired;
            return Err("quote is expired".to_string());
        }
        quote.reserve()?;
        let quote_copy = quote.clone();
        let maker = self
            .makers
            .get_mut(&quote_copy.maker_id)
            .ok_or_else(|| "quote maker is unknown".to_string())?;
        maker.reserve_units(quote_copy.amount_units)?;
        if let Some(intent) = self.intents.get_mut(&quote_copy.intent_id) {
            intent.bind_quote(&quote_copy.quote_id, &quote_copy.sponsorship_id)?;
        }
        Ok(quote_copy)
    }

    pub fn reserve_sponsorship(
        &mut self,
        sponsor_label: &str,
        intent_id: &str,
        quote_id: &str,
        gross_fee_units: u64,
        sponsored_fee_units: u64,
        sponsor_pool_id: &str,
        metadata: &Value,
    ) -> FastWithdrawalResult<LowFeeSponsorship> {
        let intent = self
            .intents
            .get(intent_id)
            .ok_or_else(|| format!("unknown withdrawal intent: {intent_id}"))?;
        let quote = self
            .quotes
            .get(quote_id)
            .ok_or_else(|| format!("unknown quote: {quote_id}"))?;
        if quote.intent_id != intent.intent_id {
            return Err("sponsorship quote does not match intent".to_string());
        }
        let rebate_bps = ratio_bps(sponsored_fee_units, gross_fee_units);
        if rebate_bps > self.config.max_sponsor_rebate_bps {
            return Err("sponsorship rebate exceeds configured maximum".to_string());
        }
        if self
            .sponsor_reserved_units()
            .saturating_add(sponsored_fee_units)
            > self.operator_limits.sponsor_pool_limit_units
        {
            return Err("sponsor pool limit exceeded".to_string());
        }
        let sponsor_commitment = fast_withdrawal_account_commitment(sponsor_label);
        let sponsorship = LowFeeSponsorship::new(
            &sponsor_commitment,
            intent_id,
            quote_id,
            &self.config.fee_asset_id,
            gross_fee_units,
            sponsored_fee_units,
            sponsor_pool_id,
            self.height,
            self.config.default_intent_ttl_blocks,
            metadata,
        )?;
        self.sponsorships
            .insert(sponsorship.sponsorship_id.clone(), sponsorship.clone());
        Ok(sponsorship)
    }

    pub fn bind_sponsorship_to_quote(
        &mut self,
        quote_id: &str,
        sponsorship_id: &str,
    ) -> FastWithdrawalResult<()> {
        let quote = self
            .quotes
            .get_mut(quote_id)
            .ok_or_else(|| format!("unknown quote: {quote_id}"))?;
        let sponsorship = self
            .sponsorships
            .get(sponsorship_id)
            .ok_or_else(|| format!("unknown sponsorship: {sponsorship_id}"))?;
        if sponsorship.quote_id != quote.quote_id {
            return Err("sponsorship does not reference quote".to_string());
        }
        quote.sponsorship_id = sponsorship_id.to_string();
        if let Some(intent) = self.intents.get_mut(&quote.intent_id) {
            intent.sponsorship_id = sponsorship_id.to_string();
        }
        Ok(())
    }

    pub fn fund_reserved_quote(
        &mut self,
        quote_id: &str,
        owner_receipt_commitment: &str,
        recipient_receipt_commitment: &str,
        receipt_secret: &str,
        encrypted_payload: &Value,
        settlement_tx_commitment: &str,
    ) -> FastWithdrawalResult<PrivacyReceipt> {
        let quote = self
            .quotes
            .get_mut(quote_id)
            .ok_or_else(|| format!("unknown quote: {quote_id}"))?;
        if quote.status != QuoteStatus::Reserved {
            return Err("quote must be reserved before funding".to_string());
        }
        let maker = self
            .makers
            .get_mut(&quote.maker_id)
            .ok_or_else(|| "quote maker is unknown".to_string())?;
        maker.fill_reserved_units(quote.amount_units)?;
        quote.fill()?;
        let receipt = PrivacyReceipt::new(
            &quote.intent_id,
            &quote.quote_id,
            &quote.maker_id,
            owner_receipt_commitment,
            recipient_receipt_commitment,
            quote.amount_units,
            quote.gross_fee_units,
            receipt_secret,
            encrypted_payload,
            settlement_tx_commitment,
            ReceiptVisibility::AggregateOnly,
            quote.privacy_set_size,
            self.height,
            self.config.default_receipt_reveal_delay_blocks,
        )?;
        if let Some(intent) = self.intents.get_mut(&quote.intent_id) {
            intent.mark_funded(&receipt.receipt_id)?;
        }
        if !quote.sponsorship_id.is_empty() {
            if let Some(sponsorship) = self.sponsorships.get_mut(&quote.sponsorship_id) {
                sponsorship.apply()?;
            }
        }
        self.receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        Ok(receipt)
    }

    pub fn record_settlement(
        &mut self,
        quote_id: &str,
        receipt_id: &str,
        monero_tx_key_root: &str,
    ) -> FastWithdrawalResult<FastWithdrawalSettlement> {
        let quote = self
            .quotes
            .get(quote_id)
            .ok_or_else(|| format!("unknown quote: {quote_id}"))?;
        let receipt = self
            .receipts
            .get(receipt_id)
            .ok_or_else(|| format!("unknown receipt: {receipt_id}"))?;
        if receipt.quote_id != quote.quote_id {
            return Err("receipt does not match quote".to_string());
        }
        let settlement = FastWithdrawalSettlement::new(
            &quote.intent_id,
            &quote.quote_id,
            receipt_id,
            &quote.maker_id,
            quote.settlement_rail,
            &quote.asset_id,
            quote.amount_units,
            quote.gross_fee_units,
            &receipt.settlement_tx_commitment,
            monero_tx_key_root,
            self.height,
            self.config.settlement_finality_blocks,
        )?;
        if let Some(intent) = self.intents.get_mut(&quote.intent_id) {
            intent.mark_settled()?;
        }
        self.settlements
            .insert(settlement.settlement_id.clone(), settlement.clone());
        Ok(settlement)
    }

    pub fn open_challenge(
        &mut self,
        intent_id: &str,
        quote_id: &str,
        challenger_commitment: &str,
        challenge_kind: ChallengeKind,
        evidence: &Value,
        bond_units: u64,
    ) -> FastWithdrawalResult<FastWithdrawalChallenge> {
        let intent = self
            .intents
            .get_mut(intent_id)
            .ok_or_else(|| format!("unknown withdrawal intent: {intent_id}"))?;
        if !intent.challenge_window_open_at(self.height) {
            return Err("intent challenge window is closed".to_string());
        }
        let quote = self
            .quotes
            .get_mut(quote_id)
            .ok_or_else(|| format!("unknown quote: {quote_id}"))?;
        if quote.intent_id != intent.intent_id {
            return Err("challenge quote does not match intent".to_string());
        }
        quote.status = QuoteStatus::Challenged;
        intent.mark_challenged()?;
        let challenge = FastWithdrawalChallenge::new(
            intent_id,
            quote_id,
            challenger_commitment,
            challenge_kind,
            evidence,
            bond_units,
            self.height,
            self.config.default_challenge_window_blocks,
        )?;
        self.challenges
            .insert(challenge.challenge_id.clone(), challenge.clone());
        Ok(challenge)
    }

    pub fn resolve_challenge(
        &mut self,
        challenge_id: &str,
        accepted: bool,
        resolution: &Value,
    ) -> FastWithdrawalResult<FastWithdrawalChallenge> {
        let challenge = self
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| format!("unknown challenge: {challenge_id}"))?;
        challenge.resolve(accepted, self.height, resolution)?;
        let challenge_copy = challenge.clone();
        if let Some(quote) = self.quotes.get_mut(&challenge_copy.quote_id) {
            quote.status = if accepted {
                QuoteStatus::Cancelled
            } else {
                QuoteStatus::Reserved
            };
        }
        if let Some(intent) = self.intents.get_mut(&challenge_copy.intent_id) {
            intent.status = if accepted {
                WithdrawalIntentStatus::Rejected
            } else if intent.receipt_id.is_empty() {
                WithdrawalIntentStatus::QuoteBound
            } else {
                WithdrawalIntentStatus::Funded
            };
        }
        Ok(challenge_copy)
    }

    pub fn publish_public_record(
        &mut self,
        record_kind: &str,
        subject_id: &str,
        subject_root: &str,
        payload: &Value,
    ) -> FastWithdrawalResult<FastWithdrawalPublicRecord> {
        let record = FastWithdrawalPublicRecord::new(
            record_kind,
            subject_id,
            subject_root,
            payload,
            self.height,
            &self.operator_commitment,
        )?;
        self.public_records
            .insert(record.record_id.clone(), record.clone());
        Ok(record)
    }

    pub fn refresh_exposure_snapshot(&mut self) -> FastWithdrawalResult<OperatorExposureSnapshot> {
        let risk_status = self.risk_status();
        let latest_reserve = self
            .active_reserve_proof()
            .map(|proof| (proof.available_reserve_units(), proof.coverage_bps()))
            .unwrap_or((0, 0));
        let snapshot = OperatorExposureSnapshot::new(
            &self.operator_commitment,
            self.height,
            self.pending_intent_count(),
            self.open_quote_count(),
            self.open_challenge_count(),
            self.pending_exposure_units(),
            self.maker_reserved_units(),
            self.maker_filled_units(),
            self.sponsor_reserved_units(),
            latest_reserve.0,
            latest_reserve.1,
            risk_status,
        )?;
        self.exposure_snapshots
            .insert(snapshot.snapshot_id.clone(), snapshot.clone());
        Ok(snapshot)
    }

    pub fn active_reserve_proof(&self) -> Option<&ReserveProofSnapshot> {
        self.reserve_proofs.get(&self.active_reserve_proof_id)
    }

    pub fn pending_intent_count(&self) -> u64 {
        self.intents
            .values()
            .filter(|intent| intent.status.is_open())
            .count() as u64
    }

    pub fn open_quote_count(&self) -> u64 {
        self.quotes
            .values()
            .filter(|quote| quote.status.is_usable())
            .count() as u64
    }

    pub fn open_challenge_count(&self) -> u64 {
        self.challenges
            .values()
            .filter(|challenge| challenge.status.is_open())
            .count() as u64
    }

    pub fn pending_exposure_units(&self) -> u64 {
        self.intents.values().fold(0_u64, |total, intent| {
            if intent.status.is_open() {
                total.saturating_add(intent.amount_units)
            } else {
                total
            }
        })
    }

    pub fn maker_reserved_units(&self) -> u64 {
        self.makers.values().fold(0_u64, |total, maker| {
            total.saturating_add(maker.reserved_units)
        })
    }

    pub fn maker_filled_units(&self) -> u64 {
        self.makers.values().fold(0_u64, |total, maker| {
            total.saturating_add(maker.filled_units)
        })
    }

    pub fn sponsor_reserved_units(&self) -> u64 {
        self.sponsorships
            .values()
            .fold(0_u64, |total, sponsorship| {
                if sponsorship.status == SponsorshipStatus::Reserved {
                    total.saturating_add(sponsorship.sponsored_fee_units)
                } else {
                    total
                }
            })
    }

    pub fn risk_status(&self) -> RiskLimitStatus {
        if self.operator_limits.mode == OperatorRiskMode::Halted {
            return RiskLimitStatus::Halted;
        }
        let pending_exposure = self.pending_exposure_units();
        if pending_exposure > self.operator_limits.max_operator_exposure_units {
            return RiskLimitStatus::Breached;
        }
        if self.open_challenge_count() >= self.operator_limits.challenge_halt_threshold {
            return RiskLimitStatus::Breached;
        }
        if let Some(proof) = self.active_reserve_proof() {
            if proof.coverage_bps() < self.operator_limits.min_reserve_coverage_bps {
                return RiskLimitStatus::Breached;
            }
            if proof.coverage_bps() < self.operator_limits.warn_reserve_coverage_bps {
                return RiskLimitStatus::Watch;
            }
        }
        let exposure_bps = ratio_bps(
            pending_exposure,
            self.operator_limits.max_operator_exposure_units,
        );
        if exposure_bps >= 9_000 {
            RiskLimitStatus::Limited
        } else if exposure_bps >= 7_000 {
            RiskLimitStatus::Watch
        } else {
            RiskLimitStatus::Healthy
        }
    }

    pub fn roots(&self) -> FastWithdrawalRoots {
        FastWithdrawalRoots {
            config_root: self.config.config_root(),
            operator_limits_root: self.operator_limits.limits_root(),
            intent_root: self.intent_root(),
            maker_root: self.maker_root(),
            quote_root: self.quote_root(),
            challenge_root: self.challenge_root(),
            reserve_proof_root: self.reserve_proof_root(),
            receipt_root: self.receipt_root(),
            sponsorship_root: self.sponsorship_root(),
            settlement_root: self.settlement_root(),
            pq_attestation_root: self.pq_attestation_root(),
            exposure_snapshot_root: self.exposure_snapshot_root(),
            public_record_root: self.public_record_root(),
        }
    }

    pub fn intent_root(&self) -> String {
        fast_withdrawal_intent_collection_root(&self.intents.values().cloned().collect::<Vec<_>>())
    }

    pub fn maker_root(&self) -> String {
        fast_withdrawal_maker_collection_root(&self.makers.values().cloned().collect::<Vec<_>>())
    }

    pub fn quote_root(&self) -> String {
        fast_withdrawal_quote_collection_root(&self.quotes.values().cloned().collect::<Vec<_>>())
    }

    pub fn challenge_root(&self) -> String {
        fast_withdrawal_challenge_collection_root(
            &self.challenges.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn reserve_proof_root(&self) -> String {
        fast_withdrawal_reserve_proof_collection_root(
            &self.reserve_proofs.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn receipt_root(&self) -> String {
        fast_withdrawal_receipt_collection_root(
            &self.receipts.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn sponsorship_root(&self) -> String {
        fast_withdrawal_sponsorship_collection_root(
            &self.sponsorships.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn settlement_root(&self) -> String {
        fast_withdrawal_settlement_collection_root(
            &self.settlements.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn pq_attestation_root(&self) -> String {
        fast_withdrawal_pq_attestation_collection_root(
            &self.pq_attestations.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn exposure_snapshot_root(&self) -> String {
        fast_withdrawal_exposure_snapshot_collection_root(
            &self
                .exposure_snapshots
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn public_record_root(&self) -> String {
        fast_withdrawal_public_record_collection_root(
            &self.public_records.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn state_root(&self) -> String {
        fast_withdrawal_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("fast withdrawal state record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "fast_withdrawal_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "height": self.height,
            "operator_commitment": self.operator_commitment,
            "active_reserve_proof_id": self.active_reserve_proof_id,
            "config_root": self.config.config_root(),
            "operator_limits_root": self.operator_limits.limits_root(),
            "roots": roots.public_record(),
            "intent_count": self.intents.len() as u64,
            "maker_count": self.makers.len() as u64,
            "quote_count": self.quotes.len() as u64,
            "challenge_count": self.challenges.len() as u64,
            "reserve_proof_count": self.reserve_proofs.len() as u64,
            "receipt_count": self.receipts.len() as u64,
            "sponsorship_count": self.sponsorships.len() as u64,
            "settlement_count": self.settlements.len() as u64,
            "pq_attestation_count": self.pq_attestations.len() as u64,
            "exposure_snapshot_count": self.exposure_snapshots.len() as u64,
            "public_record_count": self.public_records.len() as u64,
            "pending_intent_count": self.pending_intent_count(),
            "open_quote_count": self.open_quote_count(),
            "open_challenge_count": self.open_challenge_count(),
            "pending_exposure_units": self.pending_exposure_units(),
            "maker_reserved_units": self.maker_reserved_units(),
            "maker_filled_units": self.maker_filled_units(),
            "sponsor_reserved_units": self.sponsor_reserved_units(),
            "risk_status": self.risk_status().as_str(),
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub fn fast_withdrawal_intent_id(
    owner_commitment: &str,
    recipient_address_commitment: &str,
    asset_id: &str,
    amount_units: u64,
    source_note_root: &str,
    nullifier_root: &str,
    anti_replay_nonce: u64,
    pq_session_id: &str,
) -> String {
    domain_hash(
        "FAST-WITHDRAWAL-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_commitment),
            HashPart::Str(recipient_address_commitment),
            HashPart::Str(asset_id),
            HashPart::Int(amount_units as i128),
            HashPart::Str(source_note_root),
            HashPart::Str(nullifier_root),
            HashPart::Int(anti_replay_nonce as i128),
            HashPart::Str(pq_session_id),
        ],
        32,
    )
}

pub fn fast_withdrawal_maker_id(
    label: &str,
    maker_kind: &str,
    operator_commitment: &str,
    asset_id: &str,
    inventory_commitment_root: &str,
    public_key_commitment: &str,
) -> String {
    domain_hash(
        "FAST-WITHDRAWAL-MAKER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(maker_kind),
            HashPart::Str(operator_commitment),
            HashPart::Str(asset_id),
            HashPart::Str(inventory_commitment_root),
            HashPart::Str(public_key_commitment),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn fast_withdrawal_quote_id(
    maker_id: &str,
    intent_id: &str,
    asset_id: &str,
    amount_units: u64,
    gross_fee_units: u64,
    premium_bps: u64,
    created_at_height: u64,
) -> String {
    domain_hash(
        "FAST-WITHDRAWAL-QUOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(maker_id),
            HashPart::Str(intent_id),
            HashPart::Str(asset_id),
            HashPart::Int(amount_units as i128),
            HashPart::Int(gross_fee_units as i128),
            HashPart::Int(premium_bps as i128),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn fast_withdrawal_reserve_proof_id(
    prover_id: &str,
    reserve_account_commitment: &str,
    asset_id: &str,
    output_set_root: &str,
    liabilities_root: &str,
    observed_at_height: u64,
) -> String {
    domain_hash(
        "FAST-WITHDRAWAL-RESERVE-PROOF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(prover_id),
            HashPart::Str(reserve_account_commitment),
            HashPart::Str(asset_id),
            HashPart::Str(output_set_root),
            HashPart::Str(liabilities_root),
            HashPart::Int(observed_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn fast_withdrawal_challenge_id(
    intent_id: &str,
    quote_id: &str,
    challenger_commitment: &str,
    challenge_kind: &str,
    evidence_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "FAST-WITHDRAWAL-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(quote_id),
            HashPart::Str(challenger_commitment),
            HashPart::Str(challenge_kind),
            HashPart::Str(evidence_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn fast_withdrawal_receipt_id(
    intent_id: &str,
    quote_id: &str,
    maker_id: &str,
    receipt_nullifier_root: &str,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "FAST-WITHDRAWAL-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(quote_id),
            HashPart::Str(maker_id),
            HashPart::Str(receipt_nullifier_root),
            HashPart::Int(issued_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn fast_withdrawal_sponsorship_id(
    sponsor_commitment: &str,
    intent_id: &str,
    quote_id: &str,
    fee_asset_id: &str,
    gross_fee_units: u64,
    sponsored_fee_units: u64,
    reserved_at_height: u64,
) -> String {
    domain_hash(
        "FAST-WITHDRAWAL-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(intent_id),
            HashPart::Str(quote_id),
            HashPart::Str(fee_asset_id),
            HashPart::Int(gross_fee_units as i128),
            HashPart::Int(sponsored_fee_units as i128),
            HashPart::Int(reserved_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn fast_withdrawal_settlement_id(
    intent_id: &str,
    quote_id: &str,
    receipt_id: &str,
    maker_id: &str,
    settlement_tx_commitment: &str,
    broadcast_at_height: u64,
) -> String {
    domain_hash(
        "FAST-WITHDRAWAL-SETTLEMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(quote_id),
            HashPart::Str(receipt_id),
            HashPart::Str(maker_id),
            HashPart::Str(settlement_tx_commitment),
            HashPart::Int(broadcast_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn fast_withdrawal_pq_attestation_id(
    subject_kind: &str,
    subject_id: &str,
    subject_root: &str,
    attester_id: &str,
    role: &str,
    signature_root: &str,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "FAST-WITHDRAWAL-PQ-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(attester_id),
            HashPart::Str(role),
            HashPart::Str(signature_root),
            HashPart::Int(issued_at_height as i128),
        ],
        32,
    )
}

pub fn fast_withdrawal_operator_limits_id(
    operator_commitment: &str,
    mode: &str,
    max_operator_exposure_units: u64,
    daily_limit_units: u64,
    updated_at_height: u64,
) -> String {
    domain_hash(
        "FAST-WITHDRAWAL-OPERATOR-LIMITS-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_commitment),
            HashPart::Str(mode),
            HashPart::Int(max_operator_exposure_units as i128),
            HashPart::Int(daily_limit_units as i128),
            HashPart::Int(updated_at_height as i128),
        ],
        32,
    )
}

pub fn fast_withdrawal_exposure_snapshot_id(
    operator_commitment: &str,
    height: u64,
    risk_root: &str,
) -> String {
    domain_hash(
        "FAST-WITHDRAWAL-EXPOSURE-SNAPSHOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_commitment),
            HashPart::Int(height as i128),
            HashPart::Str(risk_root),
        ],
        32,
    )
}

pub fn fast_withdrawal_public_record_id(
    record_kind: &str,
    subject_id: &str,
    subject_root: &str,
    payload_root: &str,
    emitted_at_height: u64,
    publisher_commitment: &str,
) -> String {
    domain_hash(
        "FAST-WITHDRAWAL-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(record_kind),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(payload_root),
            HashPart::Int(emitted_at_height as i128),
            HashPart::Str(publisher_commitment),
        ],
        32,
    )
}

pub fn fast_withdrawal_receipt_nullifier(
    intent_id: &str,
    quote_id: &str,
    owner_receipt_commitment: &str,
    receipt_secret: &str,
) -> String {
    domain_hash(
        "FAST-WITHDRAWAL-RECEIPT-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(quote_id),
            HashPart::Str(owner_receipt_commitment),
            HashPart::Str(receipt_secret),
        ],
        32,
    )
}

pub fn fast_withdrawal_account_commitment(label: &str) -> String {
    domain_hash(
        "FAST-WITHDRAWAL-ACCOUNT-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn fast_withdrawal_config_root(config: &FastWithdrawalConfig) -> String {
    fast_withdrawal_payload_root("FAST-WITHDRAWAL-CONFIG", &config.public_record())
}

pub fn fast_withdrawal_intent_root(intent: &WithdrawalIntent) -> String {
    fast_withdrawal_payload_root("FAST-WITHDRAWAL-INTENT", &intent.public_record())
}

pub fn fast_withdrawal_maker_root(maker: &LiquidityMaker) -> String {
    fast_withdrawal_payload_root("FAST-WITHDRAWAL-MAKER", &maker.public_record())
}

pub fn fast_withdrawal_quote_root(quote: &LiquidityMakerQuote) -> String {
    fast_withdrawal_payload_root("FAST-WITHDRAWAL-QUOTE", &quote.public_record())
}

pub fn fast_withdrawal_challenge_root(challenge: &FastWithdrawalChallenge) -> String {
    fast_withdrawal_payload_root("FAST-WITHDRAWAL-CHALLENGE", &challenge.public_record())
}

pub fn fast_withdrawal_reserve_proof_root(proof: &ReserveProofSnapshot) -> String {
    fast_withdrawal_payload_root("FAST-WITHDRAWAL-RESERVE-PROOF", &proof.public_record())
}

pub fn fast_withdrawal_receipt_root(receipt: &PrivacyReceipt) -> String {
    fast_withdrawal_payload_root("FAST-WITHDRAWAL-RECEIPT", &receipt.public_record())
}

pub fn fast_withdrawal_sponsorship_root(sponsorship: &LowFeeSponsorship) -> String {
    fast_withdrawal_payload_root("FAST-WITHDRAWAL-SPONSORSHIP", &sponsorship.public_record())
}

pub fn fast_withdrawal_settlement_root(settlement: &FastWithdrawalSettlement) -> String {
    fast_withdrawal_payload_root("FAST-WITHDRAWAL-SETTLEMENT", &settlement.public_record())
}

pub fn fast_withdrawal_pq_attestation_root(attestation: &PqWithdrawalAttestation) -> String {
    fast_withdrawal_payload_root(
        "FAST-WITHDRAWAL-PQ-ATTESTATION",
        &attestation.public_record(),
    )
}

pub fn fast_withdrawal_operator_limits_root(limits: &OperatorRiskLimits) -> String {
    fast_withdrawal_payload_root("FAST-WITHDRAWAL-OPERATOR-LIMITS", &limits.public_record())
}

pub fn fast_withdrawal_exposure_snapshot_root(snapshot: &OperatorExposureSnapshot) -> String {
    fast_withdrawal_payload_root(
        "FAST-WITHDRAWAL-EXPOSURE-SNAPSHOT",
        &snapshot.public_record(),
    )
}

pub fn fast_withdrawal_public_record_root(record: &FastWithdrawalPublicRecord) -> String {
    fast_withdrawal_payload_root("FAST-WITHDRAWAL-PUBLIC-RECORD", &record.public_record())
}

pub fn fast_withdrawal_intent_collection_root(intents: &[WithdrawalIntent]) -> String {
    keyed_record_root(
        "FAST-WITHDRAWAL-INTENT-COLLECTION",
        intents
            .iter()
            .map(|intent| (intent.intent_id.clone(), intent.public_record()))
            .collect(),
    )
}

pub fn fast_withdrawal_maker_collection_root(makers: &[LiquidityMaker]) -> String {
    keyed_record_root(
        "FAST-WITHDRAWAL-MAKER-COLLECTION",
        makers
            .iter()
            .map(|maker| (maker.maker_id.clone(), maker.public_record()))
            .collect(),
    )
}

pub fn fast_withdrawal_quote_collection_root(quotes: &[LiquidityMakerQuote]) -> String {
    keyed_record_root(
        "FAST-WITHDRAWAL-QUOTE-COLLECTION",
        quotes
            .iter()
            .map(|quote| (quote.quote_id.clone(), quote.public_record()))
            .collect(),
    )
}

pub fn fast_withdrawal_challenge_collection_root(challenges: &[FastWithdrawalChallenge]) -> String {
    keyed_record_root(
        "FAST-WITHDRAWAL-CHALLENGE-COLLECTION",
        challenges
            .iter()
            .map(|challenge| (challenge.challenge_id.clone(), challenge.public_record()))
            .collect(),
    )
}

pub fn fast_withdrawal_reserve_proof_collection_root(proofs: &[ReserveProofSnapshot]) -> String {
    keyed_record_root(
        "FAST-WITHDRAWAL-RESERVE-PROOF-COLLECTION",
        proofs
            .iter()
            .map(|proof| (proof.proof_id.clone(), proof.public_record()))
            .collect(),
    )
}

pub fn fast_withdrawal_receipt_collection_root(receipts: &[PrivacyReceipt]) -> String {
    keyed_record_root(
        "FAST-WITHDRAWAL-RECEIPT-COLLECTION",
        receipts
            .iter()
            .map(|receipt| (receipt.receipt_id.clone(), receipt.public_record()))
            .collect(),
    )
}

pub fn fast_withdrawal_sponsorship_collection_root(sponsorships: &[LowFeeSponsorship]) -> String {
    keyed_record_root(
        "FAST-WITHDRAWAL-SPONSORSHIP-COLLECTION",
        sponsorships
            .iter()
            .map(|sponsorship| {
                (
                    sponsorship.sponsorship_id.clone(),
                    sponsorship.public_record(),
                )
            })
            .collect(),
    )
}

pub fn fast_withdrawal_settlement_collection_root(
    settlements: &[FastWithdrawalSettlement],
) -> String {
    keyed_record_root(
        "FAST-WITHDRAWAL-SETTLEMENT-COLLECTION",
        settlements
            .iter()
            .map(|settlement| (settlement.settlement_id.clone(), settlement.public_record()))
            .collect(),
    )
}

pub fn fast_withdrawal_pq_attestation_collection_root(
    attestations: &[PqWithdrawalAttestation],
) -> String {
    keyed_record_root(
        "FAST-WITHDRAWAL-PQ-ATTESTATION-COLLECTION",
        attestations
            .iter()
            .map(|attestation| {
                (
                    attestation.attestation_id.clone(),
                    attestation.public_record(),
                )
            })
            .collect(),
    )
}

pub fn fast_withdrawal_exposure_snapshot_collection_root(
    snapshots: &[OperatorExposureSnapshot],
) -> String {
    keyed_record_root(
        "FAST-WITHDRAWAL-EXPOSURE-SNAPSHOT-COLLECTION",
        snapshots
            .iter()
            .map(|snapshot| (snapshot.snapshot_id.clone(), snapshot.public_record()))
            .collect(),
    )
}

pub fn fast_withdrawal_public_record_collection_root(
    records: &[FastWithdrawalPublicRecord],
) -> String {
    keyed_record_root(
        "FAST-WITHDRAWAL-PUBLIC-RECORD-COLLECTION",
        records
            .iter()
            .map(|record| (record.record_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn fast_withdrawal_state_root(state: &FastWithdrawalState) -> String {
    state.state_root()
}

pub fn fast_withdrawal_state_root_from_record(record: &Value) -> String {
    fast_withdrawal_payload_root("FAST-WITHDRAWAL-STATE", record)
}

pub fn fast_withdrawal_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn fast_withdrawal_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn fast_withdrawal_string_set_root(domain: &str, values: &[String]) -> String {
    let ordered = values.iter().cloned().collect::<BTreeSet<_>>();
    merkle_root(
        domain,
        &ordered
            .into_iter()
            .map(|value| Value::String(fast_withdrawal_string_root(domain, &value)))
            .collect::<Vec<_>>(),
    )
}

pub fn fast_withdrawal_amount_bucket(amount_units: u64) -> u64 {
    if amount_units == 0 {
        0
    } else if amount_units <= 10 {
        10
    } else {
        amount_units.div_ceil(10_000) * 10_000
    }
}

pub fn withdrawal_intent_risk_score_bps(
    amount_units: u64,
    priority: ExitPriority,
    settlement_rail: SettlementRail,
    privacy_set_size: u64,
) -> u64 {
    let amount_weight: u64 = if amount_units <= 10_000 {
        100
    } else if amount_units <= 100_000 {
        350
    } else if amount_units <= 500_000 {
        750
    } else {
        1_250
    };
    let rail_weight: u64 = if settlement_rail.is_instant() {
        300
    } else {
        100
    };
    let privacy_discount: u64 = if privacy_set_size >= 512 {
        125
    } else if privacy_set_size >= 256 {
        75
    } else {
        0
    };
    amount_weight
        .saturating_add(rail_weight)
        .saturating_add(priority.risk_weight_bps().saturating_sub(10_000))
        .saturating_sub(privacy_discount)
}

pub fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return u64::MAX;
    }
    let ratio =
        (numerator as u128).saturating_mul(FAST_WITHDRAWAL_MAX_BPS as u128) / denominator as u128;
    ratio.min(u64::MAX as u128) as u64
}

pub fn ensure_non_empty(value: &str, label: &str) -> FastWithdrawalResult<()> {
    if value.is_empty() {
        return Err(format!("{label} is required"));
    }
    Ok(())
}

pub fn ensure_positive(value: u64, label: &str) -> FastWithdrawalResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

pub fn ensure_bps_at_most(value: u64, max: u64, label: &str) -> FastWithdrawalResult<()> {
    if value > max {
        return Err(format!("{label} exceeds maximum basis points"));
    }
    Ok(())
}

fn keyed_record_root(domain: &str, mut records: Vec<(String, Value)>) -> String {
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        domain,
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}
