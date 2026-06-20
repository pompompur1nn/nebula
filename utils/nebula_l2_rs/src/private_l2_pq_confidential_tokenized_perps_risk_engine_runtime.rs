use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialTokenizedPerpsRiskEngineRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialTokenizedPerpsRiskEngineRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_PERPS_RISK_ENGINE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-tokenized-perps-risk-engine-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_PERPS_RISK_ENGINE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 1_920_000;
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEFAULT_COLLATERAL_ASSET_ID: &str = "asset:wxmr";
pub const DEFAULT_QUOTE_ASSET_ID: &str = "asset:private-usd";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-perps-risk-v1";
pub const CONFIDENTIAL_POSITION_SUITE: &str =
    "RingCT-position-note+amount-commitment+range-proof+viewtag-v1";
pub const ORACLE_ATTESTATION_SUITE: &str =
    "pq-threshold-oracle-attestation+medianized-price+staleness-bound-v1";
pub const RISK_ENGINE_SUITE: &str =
    "root-only-private-perps-risk-band+liquidation-queue+insurance-backstop-v1";
pub const LOW_FEE_BATCH_SUITE: &str = "recursive-low-fee-tokenized-perps-netting+rebate-receipt-v1";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_MAX_LIQUIDATION_FEE_BPS: u64 = 75;
pub const DEFAULT_MAX_FUNDING_RATE_BPS: u64 = 1_200;
pub const DEFAULT_INITIAL_MARGIN_BPS: u64 = 1_500;
pub const DEFAULT_MAINTENANCE_MARGIN_BPS: u64 = 750;
pub const DEFAULT_LIQUIDATION_PENALTY_BPS: u64 = 350;
pub const DEFAULT_INSURANCE_FUND_TARGET_BPS: u64 = 500;
pub const DEFAULT_REBATE_BPS: u64 = 4;
pub const DEFAULT_ORACLE_STALENESS_BLOCKS: u64 = 24;
pub const DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 16;
pub const DEFAULT_AUTH_TTL_BLOCKS: u64 = 128;
pub const DEFAULT_MAX_MARKETS: usize = 131_072;
pub const DEFAULT_MAX_POSITIONS: usize = 8_388_608;
pub const DEFAULT_MAX_MARGIN_NOTES: usize = 16_777_216;
pub const DEFAULT_MAX_FUNDING_SNAPSHOTS: usize = 4_194_304;
pub const DEFAULT_MAX_RISK_BANDS: usize = 1_048_576;
pub const DEFAULT_MAX_LIQUIDATION_QUEUE_ITEMS: usize = 4_194_304;
pub const DEFAULT_MAX_INSURANCE_FUNDS: usize = 262_144;
pub const DEFAULT_MAX_ORACLE_ATTESTATIONS: usize = 8_388_608;
pub const DEFAULT_MAX_FEE_REBATES: usize = 8_388_608;
pub const DEFAULT_MAX_PRIVACY_FENCES: usize = 67_108_864;
pub const DEFAULT_MAX_SLASHING_EVIDENCE: usize = 2_097_152;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketKind {
    Linear,
    Inverse,
    Quanto,
    TokenizedIndex,
    VolatilityPerp,
    FundingOnly,
}
impl MarketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Linear => "linear",
            Self::Inverse => "inverse",
            Self::Quanto => "quanto",
            Self::TokenizedIndex => "tokenized_index",
            Self::VolatilityPerp => "volatility_perp",
            Self::FundingOnly => "funding_only",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketStatus {
    Draft,
    Open,
    FundingOnly,
    ReduceOnly,
    LiquidationOnly,
    Paused,
    Closed,
}
impl MarketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Open => "open",
            Self::FundingOnly => "funding_only",
            Self::ReduceOnly => "reduce_only",
            Self::LiquidationOnly => "liquidation_only",
            Self::Paused => "paused",
            Self::Closed => "closed",
        }
    }
    pub fn accepts_positions(self) -> bool {
        matches!(self, Self::Open)
    }
    pub fn accepts_funding(self) -> bool {
        matches!(self, Self::Open | Self::FundingOnly | Self::ReduceOnly)
    }
    pub fn accepts_liquidations(self) -> bool {
        matches!(
            self,
            Self::Open | Self::FundingOnly | Self::ReduceOnly | Self::LiquidationOnly
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionSide {
    Long,
    Short,
}
impl PositionSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Long => "long",
            Self::Short => "short",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionStatus {
    Pending,
    Open,
    ReduceOnly,
    FundingSettled,
    LiquidationQueued,
    Liquidating,
    Closed,
    Expired,
    Slashed,
}
impl PositionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Open => "open",
            Self::ReduceOnly => "reduce_only",
            Self::FundingSettled => "funding_settled",
            Self::LiquidationQueued => "liquidation_queued",
            Self::Liquidating => "liquidating",
            Self::Closed => "closed",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarginNoteKind {
    Deposit,
    Withdraw,
    TransferIn,
    TransferOut,
    FundingCredit,
    FundingDebit,
    LiquidationCredit,
    LiquidationDebit,
    InsuranceBackstop,
}
impl MarginNoteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deposit => "deposit",
            Self::Withdraw => "withdraw",
            Self::TransferIn => "transfer_in",
            Self::TransferOut => "transfer_out",
            Self::FundingCredit => "funding_credit",
            Self::FundingDebit => "funding_debit",
            Self::LiquidationCredit => "liquidation_credit",
            Self::LiquidationDebit => "liquidation_debit",
            Self::InsuranceBackstop => "insurance_backstop",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskBandKind {
    Prime,
    Standard,
    Watch,
    Deleveraging,
    Liquidatable,
    Insolvent,
}
impl RiskBandKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prime => "prime",
            Self::Standard => "standard",
            Self::Watch => "watch",
            Self::Deleveraging => "deleveraging",
            Self::Liquidatable => "liquidatable",
            Self::Insolvent => "insolvent",
        }
    }
    pub fn liquidation_candidate(self) -> bool {
        matches!(self, Self::Liquidatable | Self::Insolvent)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidationStatus {
    Queued,
    Assigned,
    Proving,
    Settled,
    Cancelled,
    Slashed,
}
impl LiquidationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Assigned => "assigned",
            Self::Proving => "proving",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleStatus {
    Fresh,
    Medianized,
    Stale,
    Disputed,
    Slashed,
}
impl OracleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Medianized => "medianized",
            Self::Stale => "stale",
            Self::Disputed => "disputed",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceKind {
    SpendNullifier,
    PositionNullifier,
    MarginNullifier,
    FundingNullifier,
    RebateNullifier,
    LiquidationNullifier,
    ViewTagFence,
    OracleReplayFence,
}
impl FenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SpendNullifier => "spend_nullifier",
            Self::PositionNullifier => "position_nullifier",
            Self::MarginNullifier => "margin_nullifier",
            Self::FundingNullifier => "funding_nullifier",
            Self::RebateNullifier => "rebate_nullifier",
            Self::LiquidationNullifier => "liquidation_nullifier",
            Self::ViewTagFence => "view_tag_fence",
            Self::OracleReplayFence => "oracle_replay_fence",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingReason {
    DoubleSpendNullifier,
    OracleEquivocation,
    InvalidRiskProof,
    LateLiquidationProof,
    InsuranceFundMisuse,
    PqSignatureFailure,
    BatchWithheld,
    FeeOvercharge,
}
impl SlashingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DoubleSpendNullifier => "double_spend_nullifier",
            Self::OracleEquivocation => "oracle_equivocation",
            Self::InvalidRiskProof => "invalid_risk_proof",
            Self::LateLiquidationProof => "late_liquidation_proof",
            Self::InsuranceFundMisuse => "insurance_fund_misuse",
            Self::PqSignatureFailure => "pq_signature_failure",
            Self::BatchWithheld => "batch_withheld",
            Self::FeeOvercharge => "fee_overcharge",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub collateral_asset_id: String,
    pub quote_asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub confidential_position_suite: String,
    pub oracle_attestation_suite: String,
    pub risk_engine_suite: String,
    pub low_fee_batch_suite: String,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_liquidation_fee_bps: u64,
    pub max_funding_rate_bps: u64,
    pub initial_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub liquidation_penalty_bps: u64,
    pub insurance_fund_target_bps: u64,
    pub rebate_bps: u64,
    pub oracle_staleness_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub auth_ttl_blocks: u64,
    pub max_markets: usize,
    pub max_positions: usize,
    pub max_margin_notes: usize,
    pub max_funding_snapshots: usize,
    pub max_risk_bands: usize,
    pub max_liquidation_queue_items: usize,
    pub max_insurance_funds: usize,
    pub max_oracle_attestations: usize,
    pub max_fee_rebates: usize,
    pub max_privacy_fences: usize,
    pub max_slashing_evidence: usize,
}
impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            collateral_asset_id: DEFAULT_COLLATERAL_ASSET_ID.to_string(),
            quote_asset_id: DEFAULT_QUOTE_ASSET_ID.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_auth_suite: PQ_AUTH_SUITE.to_string(),
            confidential_position_suite: CONFIDENTIAL_POSITION_SUITE.to_string(),
            oracle_attestation_suite: ORACLE_ATTESTATION_SUITE.to_string(),
            risk_engine_suite: RISK_ENGINE_SUITE.to_string(),
            low_fee_batch_suite: LOW_FEE_BATCH_SUITE.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_liquidation_fee_bps: DEFAULT_MAX_LIQUIDATION_FEE_BPS,
            max_funding_rate_bps: DEFAULT_MAX_FUNDING_RATE_BPS,
            initial_margin_bps: DEFAULT_INITIAL_MARGIN_BPS,
            maintenance_margin_bps: DEFAULT_MAINTENANCE_MARGIN_BPS,
            liquidation_penalty_bps: DEFAULT_LIQUIDATION_PENALTY_BPS,
            insurance_fund_target_bps: DEFAULT_INSURANCE_FUND_TARGET_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            oracle_staleness_blocks: DEFAULT_ORACLE_STALENESS_BLOCKS,
            settlement_ttl_blocks: DEFAULT_SETTLEMENT_TTL_BLOCKS,
            auth_ttl_blocks: DEFAULT_AUTH_TTL_BLOCKS,
            max_markets: DEFAULT_MAX_MARKETS,
            max_positions: DEFAULT_MAX_POSITIONS,
            max_margin_notes: DEFAULT_MAX_MARGIN_NOTES,
            max_funding_snapshots: DEFAULT_MAX_FUNDING_SNAPSHOTS,
            max_risk_bands: DEFAULT_MAX_RISK_BANDS,
            max_liquidation_queue_items: DEFAULT_MAX_LIQUIDATION_QUEUE_ITEMS,
            max_insurance_funds: DEFAULT_MAX_INSURANCE_FUNDS,
            max_oracle_attestations: DEFAULT_MAX_ORACLE_ATTESTATIONS,
            max_fee_rebates: DEFAULT_MAX_FEE_REBATES,
            max_privacy_fences: DEFAULT_MAX_PRIVACY_FENCES,
            max_slashing_evidence: DEFAULT_MAX_SLASHING_EVIDENCE,
        }
    }
    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("protocol version mismatch".to_string());
        }
        if self.min_pq_security_bits < 256 {
            return Err("pq security bits below runtime floor".to_string());
        }
        if self.initial_margin_bps < self.maintenance_margin_bps {
            return Err("initial margin must cover maintenance margin".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub markets: u64,
    pub encrypted_positions: u64,
    pub margin_notes: u64,
    pub funding_snapshots: u64,
    pub risk_bands: u64,
    pub liquidation_queue_items: u64,
    pub insurance_funds: u64,
    pub oracle_attestations: u64,
    pub fee_rebates: u64,
    pub privacy_fences: u64,
    pub slashing_evidence: u64,
    pub public_events: u64,
}
impl Counters {
    pub fn empty() -> Self {
        Self {
            markets: 0,
            encrypted_positions: 0,
            margin_notes: 0,
            funding_snapshots: 0,
            risk_bands: 0,
            liquidation_queue_items: 0,
            insurance_funds: 0,
            oracle_attestations: 0,
            fee_rebates: 0,
            privacy_fences: 0,
            slashing_evidence: 0,
            public_events: 0,
        }
    }
    pub fn total_records(&self) -> u64 {
        self.markets
            + self.encrypted_positions
            + self.margin_notes
            + self.funding_snapshots
            + self.risk_bands
            + self.liquidation_queue_items
            + self.insurance_funds
            + self.oracle_attestations
            + self.fee_rebates
            + self.privacy_fences
            + self.slashing_evidence
            + self.public_events
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub market_root: String,
    pub encrypted_position_root: String,
    pub margin_note_root: String,
    pub funding_snapshot_root: String,
    pub risk_band_root: String,
    pub liquidation_queue_root: String,
    pub insurance_fund_root: String,
    pub oracle_attestation_root: String,
    pub fee_rebate_root: String,
    pub privacy_fence_root: String,
    pub slashing_evidence_root: String,
    pub public_event_root: String,
    pub counters_root: String,
    pub state_root: String,
}
impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        let mut roots = Self {
            config_root: json_root("PERPS-RISK-CONFIG", &json!(config)),
            market_root: merkle_root("PERPS-RISK-MARKETS", &[]),
            encrypted_position_root: merkle_root("PERPS-RISK-ENCRYPTED-POSITIONS", &[]),
            margin_note_root: merkle_root("PERPS-RISK-MARGIN-NOTES", &[]),
            funding_snapshot_root: merkle_root("PERPS-RISK-FUNDING-SNAPSHOTS", &[]),
            risk_band_root: merkle_root("PERPS-RISK-RISK-BANDS", &[]),
            liquidation_queue_root: merkle_root("PERPS-RISK-LIQUIDATION-QUEUE", &[]),
            insurance_fund_root: merkle_root("PERPS-RISK-INSURANCE-FUNDS", &[]),
            oracle_attestation_root: merkle_root("PERPS-RISK-ORACLE-ATTESTATIONS", &[]),
            fee_rebate_root: merkle_root("PERPS-RISK-FEE-REBATES", &[]),
            privacy_fence_root: merkle_root("PERPS-RISK-PRIVACY-FENCES", &[]),
            slashing_evidence_root: merkle_root("PERPS-RISK-SLASHING-EVIDENCE", &[]),
            public_event_root: merkle_root("PERPS-RISK-PUBLIC-EVENTS", &[]),
            counters_root: json_root("PERPS-RISK-COUNTERS", &json!(counters)),
            state_root: String::new(),
        };
        roots.state_root = roots.compute_state_root();
        roots
    }
    pub fn public_record_without_state_root(&self) -> Value {
        json!({"config_root":self.config_root,"market_root":self.market_root,"encrypted_position_root":self.encrypted_position_root,"margin_note_root":self.margin_note_root,"funding_snapshot_root":self.funding_snapshot_root,"risk_band_root":self.risk_band_root,"liquidation_queue_root":self.liquidation_queue_root,"insurance_fund_root":self.insurance_fund_root,"oracle_attestation_root":self.oracle_attestation_root,"fee_rebate_root":self.fee_rebate_root,"privacy_fence_root":self.privacy_fence_root,"slashing_evidence_root":self.slashing_evidence_root,"public_event_root":self.public_event_root,"counters_root":self.counters_root})
    }
    pub fn compute_state_root(&self) -> String {
        domain_hash(
            "PERPS-RISK-STATE-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&self.public_record_without_state_root()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivatePerpsMarket {
    pub market_id: String,
    pub symbol: String,
    pub kind: MarketKind,
    pub status: MarketStatus,
    pub base_token_id: String,
    pub quote_token_id: String,
    pub collateral_token_id: String,
    pub oracle_feed_id: String,
    pub funding_interval_blocks: u64,
    pub max_open_interest_commitment: String,
    pub initial_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub liquidation_penalty_bps: u64,
    pub fee_bps: u64,
    pub min_privacy_set_size: u64,
    pub pq_policy_root: String,
    pub covenant_root: String,
    pub metadata_root: String,
    pub opened_at_height: u64,
}
impl PrivatePerpsMarket {
    pub fn new(
        symbol: &str,
        kind: MarketKind,
        base_token_id: &str,
        quote_token_id: &str,
        collateral_token_id: &str,
        oracle_feed_id: &str,
        opened_at_height: u64,
        nonce: u64,
    ) -> Self {
        let metadata_root = root_from_parts(
            "PERPS-RISK-MARKET-METADATA",
            &[HashPart::Str(symbol), HashPart::U64(nonce)],
        );
        let market_id = market_id(
            symbol,
            kind,
            base_token_id,
            quote_token_id,
            collateral_token_id,
            oracle_feed_id,
            opened_at_height,
            nonce,
            &metadata_root,
        );
        Self {
            market_id,
            symbol: symbol.to_string(),
            kind,
            status: MarketStatus::Open,
            base_token_id: base_token_id.to_string(),
            quote_token_id: quote_token_id.to_string(),
            collateral_token_id: collateral_token_id.to_string(),
            oracle_feed_id: oracle_feed_id.to_string(),
            funding_interval_blocks: 60,
            max_open_interest_commitment: root_from_parts(
                "PERPS-RISK-OI-CAP",
                &[HashPart::Str(symbol), HashPart::U64(nonce)],
            ),
            initial_margin_bps: DEFAULT_INITIAL_MARGIN_BPS,
            maintenance_margin_bps: DEFAULT_MAINTENANCE_MARGIN_BPS,
            liquidation_penalty_bps: DEFAULT_LIQUIDATION_PENALTY_BPS,
            fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_policy_root: root_from_parts("PERPS-RISK-PQ-POLICY", &[HashPart::Str(symbol)]),
            covenant_root: root_from_parts("PERPS-RISK-COVENANT", &[HashPart::Str(symbol)]),
            metadata_root,
            opened_at_height,
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedPosition {
    pub position_id: String,
    pub market_id: String,
    pub owner_commitment: String,
    pub side: PositionSide,
    pub status: PositionStatus,
    pub size_commitment: String,
    pub collateral_commitment: String,
    pub entry_price_commitment: String,
    pub leverage_bps: u64,
    pub encrypted_payload_root: String,
    pub range_proof_root: String,
    pub pq_authorization_root: String,
    pub view_tag: String,
    pub nullifier_hash: String,
    pub opened_at_height: u64,
    pub last_touched_height: u64,
}
impl EncryptedPosition {
    pub fn new(
        market_id: &str,
        owner_commitment: &str,
        side: PositionSide,
        size_commitment: &str,
        collateral_commitment: &str,
        opened_at_height: u64,
        nonce: u64,
    ) -> Self {
        let nullifier_hash = nullifier_hash(
            FenceKind::PositionNullifier,
            owner_commitment,
            market_id,
            nonce,
        );
        let position_id = position_id(
            market_id,
            owner_commitment,
            side,
            size_commitment,
            collateral_commitment,
            &nullifier_hash,
            opened_at_height,
            nonce,
        );
        let tag = root_from_parts(
            "PERPS-RISK-VIEW-TAG",
            &[HashPart::Str(owner_commitment), HashPart::U64(nonce)],
        );
        Self {
            position_id,
            market_id: market_id.to_string(),
            owner_commitment: owner_commitment.to_string(),
            side,
            status: PositionStatus::Open,
            size_commitment: size_commitment.to_string(),
            collateral_commitment: collateral_commitment.to_string(),
            entry_price_commitment: root_from_parts(
                "PERPS-RISK-ENTRY-PRICE",
                &[HashPart::Str(market_id), HashPart::U64(nonce)],
            ),
            leverage_bps: 300,
            encrypted_payload_root: root_from_parts(
                "PERPS-RISK-POSITION-PAYLOAD",
                &[HashPart::Str(owner_commitment), HashPart::U64(nonce)],
            ),
            range_proof_root: root_from_parts(
                "PERPS-RISK-POSITION-RANGE",
                &[
                    HashPart::Str(size_commitment),
                    HashPart::Str(collateral_commitment),
                ],
            ),
            pq_authorization_root: root_from_parts(
                "PERPS-RISK-POSITION-PQ",
                &[
                    HashPart::Str(owner_commitment),
                    HashPart::U64(opened_at_height),
                ],
            ),
            view_tag: tag[0..16].to_string(),
            nullifier_hash,
            opened_at_height,
            last_touched_height: opened_at_height,
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MarginNote {
    pub note_id: String,
    pub market_id: String,
    pub position_id: String,
    pub kind: MarginNoteKind,
    pub asset_id: String,
    pub amount_commitment: String,
    pub balance_commitment: String,
    pub spend_nullifier_hash: String,
    pub recipient_commitment: String,
    pub range_proof_root: String,
    pub pq_authorization_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}
impl MarginNote {
    pub fn new(
        market_id: &str,
        position_id: &str,
        kind: MarginNoteKind,
        asset_id: &str,
        amount_commitment: &str,
        recipient_commitment: &str,
        created_at_height: u64,
        nonce: u64,
    ) -> Self {
        let spend_nullifier_hash = nullifier_hash(
            FenceKind::MarginNullifier,
            recipient_commitment,
            position_id,
            nonce,
        );
        let note_id = margin_note_id(
            market_id,
            position_id,
            kind,
            amount_commitment,
            &spend_nullifier_hash,
            created_at_height,
            nonce,
        );
        Self {
            note_id,
            market_id: market_id.to_string(),
            position_id: position_id.to_string(),
            kind,
            asset_id: asset_id.to_string(),
            amount_commitment: amount_commitment.to_string(),
            balance_commitment: root_from_parts(
                "PERPS-RISK-MARGIN-BALANCE",
                &[HashPart::Str(position_id), HashPart::U64(nonce)],
            ),
            spend_nullifier_hash,
            recipient_commitment: recipient_commitment.to_string(),
            range_proof_root: root_from_parts(
                "PERPS-RISK-MARGIN-RANGE",
                &[HashPart::Str(amount_commitment), HashPart::Str(asset_id)],
            ),
            pq_authorization_root: root_from_parts(
                "PERPS-RISK-MARGIN-PQ",
                &[HashPart::Str(position_id), HashPart::U64(nonce)],
            ),
            created_at_height,
            expires_at_height: created_at_height + DEFAULT_SETTLEMENT_TTL_BLOCKS,
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FundingSnapshot {
    pub snapshot_id: String,
    pub market_id: String,
    pub funding_epoch: u64,
    pub funding_rate_bps: i64,
    pub premium_index_bps: i64,
    pub oracle_price_root: String,
    pub open_interest_long_commitment: String,
    pub open_interest_short_commitment: String,
    pub settlement_nullifier_root: String,
    pub previous_snapshot_id: String,
    pub captured_at_height: u64,
}
impl FundingSnapshot {
    pub fn new(
        market_id: &str,
        funding_epoch: u64,
        funding_rate_bps: i64,
        oracle_price_root: &str,
        previous_snapshot_id: &str,
        captured_at_height: u64,
    ) -> Self {
        let snapshot_id = funding_snapshot_id(
            market_id,
            funding_epoch,
            funding_rate_bps,
            oracle_price_root,
            previous_snapshot_id,
            captured_at_height,
        );
        Self {
            snapshot_id,
            market_id: market_id.to_string(),
            funding_epoch,
            funding_rate_bps,
            premium_index_bps: funding_rate_bps / 2,
            oracle_price_root: oracle_price_root.to_string(),
            open_interest_long_commitment: root_from_parts(
                "PERPS-RISK-OI-LONG",
                &[HashPart::Str(market_id), HashPart::U64(funding_epoch)],
            ),
            open_interest_short_commitment: root_from_parts(
                "PERPS-RISK-OI-SHORT",
                &[HashPart::Str(market_id), HashPart::U64(funding_epoch)],
            ),
            settlement_nullifier_root: root_from_parts(
                "PERPS-RISK-FUNDING-NULLIFIERS",
                &[HashPart::Str(market_id), HashPart::U64(funding_epoch)],
            ),
            previous_snapshot_id: previous_snapshot_id.to_string(),
            captured_at_height,
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskBand {
    pub band_id: String,
    pub market_id: String,
    pub position_id: String,
    pub kind: RiskBandKind,
    pub margin_ratio_bps: u64,
    pub notional_commitment: String,
    pub collateral_commitment: String,
    pub risk_proof_root: String,
    pub oracle_attestation_id: String,
    pub computed_at_height: u64,
}
impl RiskBand {
    pub fn new(
        market_id: &str,
        position_id: &str,
        kind: RiskBandKind,
        margin_ratio_bps: u64,
        oracle_attestation_id: &str,
        computed_at_height: u64,
        nonce: u64,
    ) -> Self {
        let risk_proof_root = root_from_parts(
            "PERPS-RISK-BAND-PROOF",
            &[HashPart::Str(position_id), HashPart::U64(nonce)],
        );
        let band_id = risk_band_id(
            market_id,
            position_id,
            kind,
            margin_ratio_bps,
            &risk_proof_root,
            computed_at_height,
            nonce,
        );
        Self {
            band_id,
            market_id: market_id.to_string(),
            position_id: position_id.to_string(),
            kind,
            margin_ratio_bps,
            notional_commitment: root_from_parts(
                "PERPS-RISK-NOTIONAL",
                &[HashPart::Str(position_id), HashPart::U64(nonce)],
            ),
            collateral_commitment: root_from_parts(
                "PERPS-RISK-COLLATERAL",
                &[HashPart::Str(position_id), HashPart::U64(nonce)],
            ),
            risk_proof_root,
            oracle_attestation_id: oracle_attestation_id.to_string(),
            computed_at_height,
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidationQueueItem {
    pub queue_id: String,
    pub market_id: String,
    pub position_id: String,
    pub risk_band_id: String,
    pub status: LiquidationStatus,
    pub priority: u64,
    pub keeper_commitment: String,
    pub sealed_bid_root: String,
    pub liquidation_proof_root: String,
    pub queued_at_height: u64,
    pub expires_at_height: u64,
}
impl LiquidationQueueItem {
    pub fn new(
        market_id: &str,
        position_id: &str,
        risk_band_id: &str,
        priority: u64,
        keeper_commitment: &str,
        queued_at_height: u64,
        nonce: u64,
    ) -> Self {
        let sealed_bid_root = root_from_parts(
            "PERPS-RISK-LIQUIDATION-BID",
            &[HashPart::Str(keeper_commitment), HashPart::U64(nonce)],
        );
        let queue_id = liquidation_queue_id(
            market_id,
            position_id,
            risk_band_id,
            priority,
            &sealed_bid_root,
            queued_at_height,
            nonce,
        );
        Self {
            queue_id,
            market_id: market_id.to_string(),
            position_id: position_id.to_string(),
            risk_band_id: risk_band_id.to_string(),
            status: LiquidationStatus::Queued,
            priority,
            keeper_commitment: keeper_commitment.to_string(),
            sealed_bid_root,
            liquidation_proof_root: root_from_parts(
                "PERPS-RISK-LIQUIDATION-PROOF",
                &[HashPart::Str(position_id), HashPart::Str(risk_band_id)],
            ),
            queued_at_height,
            expires_at_height: queued_at_height + DEFAULT_SETTLEMENT_TTL_BLOCKS,
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InsuranceFund {
    pub fund_id: String,
    pub market_id: String,
    pub asset_id: String,
    pub operator_commitment: String,
    pub reserve_commitment: String,
    pub target_reserve_bps: u64,
    pub backstop_proof_root: String,
    pub withdrawal_covenant_root: String,
    pub last_rebalanced_height: u64,
}
impl InsuranceFund {
    pub fn new(
        market_id: &str,
        asset_id: &str,
        operator_commitment: &str,
        reserve_commitment: &str,
        last_rebalanced_height: u64,
        nonce: u64,
    ) -> Self {
        let fund_id = insurance_fund_id(
            market_id,
            asset_id,
            operator_commitment,
            reserve_commitment,
            last_rebalanced_height,
            nonce,
        );
        Self {
            fund_id,
            market_id: market_id.to_string(),
            asset_id: asset_id.to_string(),
            operator_commitment: operator_commitment.to_string(),
            reserve_commitment: reserve_commitment.to_string(),
            target_reserve_bps: DEFAULT_INSURANCE_FUND_TARGET_BPS,
            backstop_proof_root: root_from_parts(
                "PERPS-RISK-INSURANCE-BACKSTOP",
                &[HashPart::Str(market_id), HashPart::U64(nonce)],
            ),
            withdrawal_covenant_root: root_from_parts(
                "PERPS-RISK-INSURANCE-COVENANT",
                &[HashPart::Str(operator_commitment)],
            ),
            last_rebalanced_height,
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleAttestation {
    pub attestation_id: String,
    pub feed_id: String,
    pub market_id: String,
    pub status: OracleStatus,
    pub price_commitment: String,
    pub confidence_bps: u64,
    pub medianized_source_root: String,
    pub pq_signature_root: String,
    pub reporter_set_root: String,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
}
impl OracleAttestation {
    pub fn new(
        feed_id: &str,
        market_id: &str,
        price_commitment: &str,
        confidence_bps: u64,
        reporter_set_root: &str,
        attested_at_height: u64,
        nonce: u64,
    ) -> Self {
        let attestation_id = oracle_attestation_id(
            feed_id,
            market_id,
            price_commitment,
            reporter_set_root,
            attested_at_height,
            nonce,
        );
        Self {
            attestation_id,
            feed_id: feed_id.to_string(),
            market_id: market_id.to_string(),
            status: OracleStatus::Medianized,
            price_commitment: price_commitment.to_string(),
            confidence_bps,
            medianized_source_root: root_from_parts(
                "PERPS-RISK-ORACLE-SOURCES",
                &[HashPart::Str(feed_id), HashPart::U64(nonce)],
            ),
            pq_signature_root: root_from_parts(
                "PERPS-RISK-ORACLE-PQ-SIG",
                &[
                    HashPart::Str(reporter_set_root),
                    HashPart::U64(attested_at_height),
                ],
            ),
            reporter_set_root: reporter_set_root.to_string(),
            attested_at_height,
            expires_at_height: attested_at_height + DEFAULT_ORACLE_STALENESS_BLOCKS,
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub market_id: String,
    pub beneficiary_commitment: String,
    pub fee_nullifier_hash: String,
    pub rebate_commitment: String,
    pub rebate_bps: u64,
    pub settlement_receipt_root: String,
    pub created_at_height: u64,
}
impl FeeRebate {
    pub fn new(
        market_id: &str,
        beneficiary_commitment: &str,
        rebate_commitment: &str,
        created_at_height: u64,
        nonce: u64,
    ) -> Self {
        let fee_nullifier_hash = nullifier_hash(
            FenceKind::RebateNullifier,
            beneficiary_commitment,
            market_id,
            nonce,
        );
        let rebate_id = fee_rebate_id(
            market_id,
            beneficiary_commitment,
            &fee_nullifier_hash,
            rebate_commitment,
            created_at_height,
            nonce,
        );
        Self {
            rebate_id,
            market_id: market_id.to_string(),
            beneficiary_commitment: beneficiary_commitment.to_string(),
            fee_nullifier_hash,
            rebate_commitment: rebate_commitment.to_string(),
            rebate_bps: DEFAULT_REBATE_BPS,
            settlement_receipt_root: root_from_parts(
                "PERPS-RISK-REBATE-RECEIPT",
                &[HashPart::Str(beneficiary_commitment), HashPart::U64(nonce)],
            ),
            created_at_height,
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub kind: FenceKind,
    pub subject_id: String,
    pub nullifier_hash: String,
    pub privacy_set_root: String,
    pub min_privacy_set_size: u64,
    pub consumed_at_height: u64,
}
impl PrivacyFence {
    pub fn new(
        kind: FenceKind,
        subject_id: &str,
        nullifier_hash: &str,
        privacy_set_root: &str,
        consumed_at_height: u64,
        nonce: u64,
    ) -> Self {
        let fence_id = privacy_fence_id(
            kind,
            subject_id,
            nullifier_hash,
            privacy_set_root,
            consumed_at_height,
            nonce,
        );
        Self {
            fence_id,
            kind,
            subject_id: subject_id.to_string(),
            nullifier_hash: nullifier_hash.to_string(),
            privacy_set_root: privacy_set_root.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            consumed_at_height,
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub offender_commitment: String,
    pub reason: SlashingReason,
    pub evidence_root: String,
    pub disputed_record_id: String,
    pub penalty_commitment: String,
    pub reporter_commitment: String,
    pub pq_signature_root: String,
    pub recorded_at_height: u64,
}
impl SlashingEvidence {
    pub fn new(
        offender_commitment: &str,
        reason: SlashingReason,
        evidence_root: &str,
        disputed_record_id: &str,
        reporter_commitment: &str,
        recorded_at_height: u64,
        nonce: u64,
    ) -> Self {
        let evidence_id = slashing_evidence_id(
            offender_commitment,
            reason,
            evidence_root,
            disputed_record_id,
            recorded_at_height,
            nonce,
        );
        Self {
            evidence_id,
            offender_commitment: offender_commitment.to_string(),
            reason,
            evidence_root: evidence_root.to_string(),
            disputed_record_id: disputed_record_id.to_string(),
            penalty_commitment: root_from_parts(
                "PERPS-RISK-SLASH-PENALTY",
                &[HashPart::Str(offender_commitment), HashPart::U64(nonce)],
            ),
            reporter_commitment: reporter_commitment.to_string(),
            pq_signature_root: root_from_parts(
                "PERPS-RISK-SLASH-PQ-SIG",
                &[HashPart::Str(reporter_commitment), HashPart::U64(nonce)],
            ),
            recorded_at_height,
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicEvent {
    pub event_id: String,
    pub event_type: String,
    pub subject_id: String,
    pub payload_root: String,
    pub height: u64,
    pub sequence: u64,
}
impl PublicEvent {
    pub fn new(
        event_type: &str,
        subject_id: &str,
        payload: &Value,
        height: u64,
        sequence: u64,
    ) -> Self {
        let payload_root = json_root("PERPS-RISK-EVENT-PAYLOAD", payload);
        let event_id = public_event_id(event_type, subject_id, &payload_root, height, sequence);
        Self {
            event_id,
            event_type: event_type.to_string(),
            subject_id: subject_id.to_string(),
            payload_root,
            height,
            sequence,
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub markets: BTreeMap<String, PrivatePerpsMarket>,
    pub encrypted_positions: BTreeMap<String, EncryptedPosition>,
    pub margin_notes: BTreeMap<String, MarginNote>,
    pub funding_snapshots: BTreeMap<String, FundingSnapshot>,
    pub risk_bands: BTreeMap<String, RiskBand>,
    pub liquidation_queue: BTreeMap<String, LiquidationQueueItem>,
    pub insurance_funds: BTreeMap<String, InsuranceFund>,
    pub oracle_attestations: BTreeMap<String, OracleAttestation>,
    pub fee_rebates: BTreeMap<String, FeeRebate>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub public_events: BTreeMap<String, PublicEvent>,
    pub consumed_nullifiers: BTreeSet<String>,
}
impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let counters = Counters::empty();
        let roots = Roots::empty(&config, &counters);
        Ok(Self {
            config,
            counters,
            roots,
            markets: BTreeMap::new(),
            encrypted_positions: BTreeMap::new(),
            margin_notes: BTreeMap::new(),
            funding_snapshots: BTreeMap::new(),
            risk_bands: BTreeMap::new(),
            liquidation_queue: BTreeMap::new(),
            insurance_funds: BTreeMap::new(),
            oracle_attestations: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            public_events: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        })
    }
    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).expect("devnet config is valid");
        state.seed_devnet();
        state.recompute_roots();
        state
    }
    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }
    pub fn public_record(&self) -> Value {
        json!({"protocol_version":self.config.protocol_version,"schema_version":self.config.schema_version,"chain_id":self.config.chain_id,"l2_network":self.config.l2_network,"monero_network":self.config.monero_network,"roots":self.roots,"counters":self.counters,"state_root":self.roots.state_root})
    }
    pub fn add_market(&mut self, market: PrivatePerpsMarket) -> Result<()> {
        if self.markets.len() >= self.config.max_markets {
            return Err("market capacity exceeded".to_string());
        }
        if self.markets.contains_key(&market.market_id) {
            return Err("duplicate market".to_string());
        }
        self.markets.insert(market.market_id.clone(), market);
        self.recompute_roots();
        Ok(())
    }
    pub fn add_encrypted_position(&mut self, position: EncryptedPosition) -> Result<()> {
        if self.encrypted_positions.len() >= self.config.max_positions {
            return Err("position capacity exceeded".to_string());
        }
        let market = self
            .markets
            .get(&position.market_id)
            .ok_or_else(|| "unknown market for position".to_string())?;
        if !market.status.accepts_positions() {
            return Err("market does not accept positions".to_string());
        }
        self.insert_nullifier(&position.nullifier_hash)?;
        self.encrypted_positions
            .insert(position.position_id.clone(), position);
        self.recompute_roots();
        Ok(())
    }
    pub fn add_margin_note(&mut self, note: MarginNote) -> Result<()> {
        if self.margin_notes.len() >= self.config.max_margin_notes {
            return Err("margin note capacity exceeded".to_string());
        }
        if !self.markets.contains_key(&note.market_id) {
            return Err("unknown market for margin note".to_string());
        }
        if !self.encrypted_positions.contains_key(&note.position_id) {
            return Err("unknown position for margin note".to_string());
        }
        self.insert_nullifier(&note.spend_nullifier_hash)?;
        self.margin_notes.insert(note.note_id.clone(), note);
        self.recompute_roots();
        Ok(())
    }
    pub fn add_funding_snapshot(&mut self, snapshot: FundingSnapshot) -> Result<()> {
        if self.funding_snapshots.len() >= self.config.max_funding_snapshots {
            return Err("funding snapshot capacity exceeded".to_string());
        }
        let market = self
            .markets
            .get(&snapshot.market_id)
            .ok_or_else(|| "unknown market for funding snapshot".to_string())?;
        if !market.status.accepts_funding() {
            return Err("market does not accept funding".to_string());
        }
        if snapshot.funding_rate_bps.unsigned_abs() > self.config.max_funding_rate_bps {
            return Err("funding rate exceeds runtime bound".to_string());
        }
        self.funding_snapshots
            .insert(snapshot.snapshot_id.clone(), snapshot);
        self.recompute_roots();
        Ok(())
    }
    pub fn add_risk_band(&mut self, band: RiskBand) -> Result<()> {
        if self.risk_bands.len() >= self.config.max_risk_bands {
            return Err("risk band capacity exceeded".to_string());
        }
        if !self.markets.contains_key(&band.market_id) {
            return Err("unknown market for risk band".to_string());
        }
        if !self.encrypted_positions.contains_key(&band.position_id) {
            return Err("unknown position for risk band".to_string());
        }
        self.risk_bands.insert(band.band_id.clone(), band);
        self.recompute_roots();
        Ok(())
    }
    pub fn add_liquidation_queue_item(&mut self, item: LiquidationQueueItem) -> Result<()> {
        if self.liquidation_queue.len() >= self.config.max_liquidation_queue_items {
            return Err("liquidation queue capacity exceeded".to_string());
        }
        let market = self
            .markets
            .get(&item.market_id)
            .ok_or_else(|| "unknown market for liquidation".to_string())?;
        if !market.status.accepts_liquidations() {
            return Err("market does not accept liquidations".to_string());
        }
        self.liquidation_queue.insert(item.queue_id.clone(), item);
        self.recompute_roots();
        Ok(())
    }
    pub fn add_insurance_fund(&mut self, fund: InsuranceFund) -> Result<()> {
        if self.insurance_funds.len() >= self.config.max_insurance_funds {
            return Err("insurance fund capacity exceeded".to_string());
        }
        if !self.markets.contains_key(&fund.market_id) {
            return Err("unknown market for insurance fund".to_string());
        }
        self.insurance_funds.insert(fund.fund_id.clone(), fund);
        self.recompute_roots();
        Ok(())
    }
    pub fn add_oracle_attestation(&mut self, attestation: OracleAttestation) -> Result<()> {
        if self.oracle_attestations.len() >= self.config.max_oracle_attestations {
            return Err("oracle attestation capacity exceeded".to_string());
        }
        if !self.markets.contains_key(&attestation.market_id) {
            return Err("unknown market for oracle attestation".to_string());
        }
        if attestation.confidence_bps > MAX_BPS {
            return Err("oracle confidence exceeds max bps".to_string());
        }
        self.oracle_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.recompute_roots();
        Ok(())
    }
    pub fn add_fee_rebate(&mut self, rebate: FeeRebate) -> Result<()> {
        if self.fee_rebates.len() >= self.config.max_fee_rebates {
            return Err("fee rebate capacity exceeded".to_string());
        }
        self.insert_nullifier(&rebate.fee_nullifier_hash)?;
        self.fee_rebates.insert(rebate.rebate_id.clone(), rebate);
        self.recompute_roots();
        Ok(())
    }
    pub fn add_privacy_fence(&mut self, fence: PrivacyFence) -> Result<()> {
        if self.privacy_fences.len() >= self.config.max_privacy_fences {
            return Err("privacy fence capacity exceeded".to_string());
        }
        if fence.min_privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy set below runtime floor".to_string());
        }
        self.insert_nullifier(&fence.nullifier_hash)?;
        self.privacy_fences.insert(fence.fence_id.clone(), fence);
        self.recompute_roots();
        Ok(())
    }
    pub fn add_slashing_evidence(&mut self, evidence: SlashingEvidence) -> Result<()> {
        if self.slashing_evidence.len() >= self.config.max_slashing_evidence {
            return Err("slashing evidence capacity exceeded".to_string());
        }
        self.slashing_evidence
            .insert(evidence.evidence_id.clone(), evidence);
        self.recompute_roots();
        Ok(())
    }
    pub fn add_public_event(&mut self, event: PublicEvent) -> Result<()> {
        self.public_events.insert(event.event_id.clone(), event);
        self.recompute_roots();
        Ok(())
    }
    pub fn recompute_roots(&mut self) {
        self.counters = Counters {
            markets: self.markets.len() as u64,
            encrypted_positions: self.encrypted_positions.len() as u64,
            margin_notes: self.margin_notes.len() as u64,
            funding_snapshots: self.funding_snapshots.len() as u64,
            risk_bands: self.risk_bands.len() as u64,
            liquidation_queue_items: self.liquidation_queue.len() as u64,
            insurance_funds: self.insurance_funds.len() as u64,
            oracle_attestations: self.oracle_attestations.len() as u64,
            fee_rebates: self.fee_rebates.len() as u64,
            privacy_fences: self.privacy_fences.len() as u64,
            slashing_evidence: self.slashing_evidence.len() as u64,
            public_events: self.public_events.len() as u64,
        };
        self.roots.config_root = json_root("PERPS-RISK-CONFIG", &json!(self.config));
        self.roots.counters_root = json_root("PERPS-RISK-COUNTERS", &json!(self.counters));
        self.roots.market_root = map_merkle_root("PERPS-RISK-MARKETS", &self.markets);
        self.roots.encrypted_position_root =
            map_merkle_root("PERPS-RISK-ENCRYPTED-POSITIONS", &self.encrypted_positions);
        self.roots.margin_note_root =
            map_merkle_root("PERPS-RISK-MARGIN-NOTES", &self.margin_notes);
        self.roots.funding_snapshot_root =
            map_merkle_root("PERPS-RISK-FUNDING-SNAPSHOTS", &self.funding_snapshots);
        self.roots.risk_band_root = map_merkle_root("PERPS-RISK-RISK-BANDS", &self.risk_bands);
        self.roots.liquidation_queue_root =
            map_merkle_root("PERPS-RISK-LIQUIDATION-QUEUE", &self.liquidation_queue);
        self.roots.insurance_fund_root =
            map_merkle_root("PERPS-RISK-INSURANCE-FUNDS", &self.insurance_funds);
        self.roots.oracle_attestation_root =
            map_merkle_root("PERPS-RISK-ORACLE-ATTESTATIONS", &self.oracle_attestations);
        self.roots.fee_rebate_root = map_merkle_root("PERPS-RISK-FEE-REBATES", &self.fee_rebates);
        self.roots.privacy_fence_root =
            map_merkle_root("PERPS-RISK-PRIVACY-FENCES", &self.privacy_fences);
        self.roots.slashing_evidence_root =
            map_merkle_root("PERPS-RISK-SLASHING-EVIDENCE", &self.slashing_evidence);
        self.roots.public_event_root =
            map_merkle_root("PERPS-RISK-PUBLIC-EVENTS", &self.public_events);
        self.roots.state_root = self.roots.compute_state_root();
    }
    fn insert_nullifier(&mut self, nullifier: &str) -> Result<()> {
        if !self.consumed_nullifiers.insert(nullifier.to_string()) {
            return Err("nullifier already consumed".to_string());
        }
        Ok(())
    }
    fn seed_devnet(&mut self) {
        let market = PrivatePerpsMarket::new(
            "pXMR-PERP",
            MarketKind::Linear,
            "asset:pxmr-index",
            "asset:private-usd",
            DEFAULT_COLLATERAL_ASSET_ID,
            "feed:pxmr-usd",
            DEVNET_HEIGHT,
            1,
        );
        let market_id = market.market_id.clone();
        self.markets.insert(market_id.clone(), market);
        let oracle = OracleAttestation::new(
            "feed:pxmr-usd",
            &market_id,
            &root_from_parts("DEVNET-PRICE", &[HashPart::Str("pxmr-usd")]),
            42,
            &root_from_parts("DEVNET-REPORTERS", &[HashPart::Str("reporters")]),
            DEVNET_HEIGHT,
            2,
        );
        let oracle_id = oracle.attestation_id.clone();
        self.oracle_attestations.insert(oracle_id.clone(), oracle);
        let position = EncryptedPosition::new(
            &market_id,
            "commit:devnet-trader",
            PositionSide::Long,
            "commit:size-10",
            "commit:collateral-3",
            DEVNET_HEIGHT + 1,
            3,
        );
        self.consumed_nullifiers
            .insert(position.nullifier_hash.clone());
        let position_id = position.position_id.clone();
        self.encrypted_positions
            .insert(position_id.clone(), position);
        let note = MarginNote::new(
            &market_id,
            &position_id,
            MarginNoteKind::Deposit,
            DEFAULT_COLLATERAL_ASSET_ID,
            "commit:deposit-3",
            "commit:devnet-trader",
            DEVNET_HEIGHT + 1,
            4,
        );
        self.consumed_nullifiers
            .insert(note.spend_nullifier_hash.clone());
        self.margin_notes.insert(note.note_id.clone(), note);
        let funding = FundingSnapshot::new(
            &market_id,
            1,
            8,
            &root_from_parts("DEVNET-ORACLE-ROOT", &[HashPart::Str(&oracle_id)]),
            "genesis",
            DEVNET_HEIGHT + 2,
        );
        self.funding_snapshots
            .insert(funding.snapshot_id.clone(), funding);
        let band = RiskBand::new(
            &market_id,
            &position_id,
            RiskBandKind::Prime,
            2_400,
            &oracle_id,
            DEVNET_HEIGHT + 2,
            5,
        );
        let band_id = band.band_id.clone();
        self.risk_bands.insert(band_id.clone(), band);
        let queue = LiquidationQueueItem::new(
            &market_id,
            &position_id,
            &band_id,
            1,
            "commit:keeper",
            DEVNET_HEIGHT + 3,
            6,
        );
        self.liquidation_queue.insert(queue.queue_id.clone(), queue);
        let fund = InsuranceFund::new(
            &market_id,
            DEFAULT_COLLATERAL_ASSET_ID,
            "commit:insurance-operator",
            "commit:reserve",
            DEVNET_HEIGHT + 3,
            7,
        );
        self.insurance_funds.insert(fund.fund_id.clone(), fund);
        let rebate = FeeRebate::new(
            &market_id,
            "commit:devnet-trader",
            "commit:rebate",
            DEVNET_HEIGHT + 4,
            8,
        );
        self.consumed_nullifiers
            .insert(rebate.fee_nullifier_hash.clone());
        self.fee_rebates.insert(rebate.rebate_id.clone(), rebate);
        let fence = PrivacyFence::new(
            FenceKind::ViewTagFence,
            &position_id,
            &root_from_parts("DEVNET-FENCE", &[HashPart::Str(&position_id)]),
            &root_from_parts("DEVNET-PRIVACY-SET", &[HashPart::Str("set")]),
            DEVNET_HEIGHT + 4,
            9,
        );
        self.consumed_nullifiers
            .insert(fence.nullifier_hash.clone());
        self.privacy_fences.insert(fence.fence_id.clone(), fence);
        let slash = SlashingEvidence::new(
            "commit:bad-oracle",
            SlashingReason::OracleEquivocation,
            &root_from_parts("DEVNET-SLASH-EVIDENCE", &[HashPart::Str("oracle")]),
            &oracle_id,
            "commit:watchtower",
            DEVNET_HEIGHT + 5,
            10,
        );
        self.slashing_evidence
            .insert(slash.evidence_id.clone(), slash);
        let event = PublicEvent::new(
            "devnet_initialized",
            &market_id,
            &json!({"market_id":market_id,"height":DEVNET_HEIGHT}),
            DEVNET_HEIGHT + 5,
            0,
        );
        self.public_events.insert(event.event_id.clone(), event);
    }
}

pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}
pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}
pub fn state_root_from_public_record(record: &Value) -> String {
    domain_hash(
        "PERPS-RISK-PUBLIC-RECORD-STATE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}
pub fn market_id(
    symbol: &str,
    kind: MarketKind,
    base_token_id: &str,
    quote_token_id: &str,
    collateral_token_id: &str,
    oracle_feed_id: &str,
    opened_at_height: u64,
    nonce: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "PERPS-RISK-MARKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(symbol),
            HashPart::Str(kind.as_str()),
            HashPart::Str(base_token_id),
            HashPart::Str(quote_token_id),
            HashPart::Str(collateral_token_id),
            HashPart::Str(oracle_feed_id),
            HashPart::U64(opened_at_height),
            HashPart::U64(nonce),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}
pub fn position_id(
    market_id: &str,
    owner_commitment: &str,
    side: PositionSide,
    size_commitment: &str,
    collateral_commitment: &str,
    nullifier_hash: &str,
    opened_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PERPS-RISK-POSITION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(market_id),
            HashPart::Str(owner_commitment),
            HashPart::Str(side.as_str()),
            HashPart::Str(size_commitment),
            HashPart::Str(collateral_commitment),
            HashPart::Str(nullifier_hash),
            HashPart::U64(opened_at_height),
            HashPart::U64(nonce),
        ],
        32,
    )
}
pub fn margin_note_id(
    market_id: &str,
    position_id: &str,
    kind: MarginNoteKind,
    amount_commitment: &str,
    spend_nullifier_hash: &str,
    created_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PERPS-RISK-MARGIN-NOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(market_id),
            HashPart::Str(position_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(amount_commitment),
            HashPart::Str(spend_nullifier_hash),
            HashPart::U64(created_at_height),
            HashPart::U64(nonce),
        ],
        32,
    )
}
pub fn funding_snapshot_id(
    market_id: &str,
    funding_epoch: u64,
    funding_rate_bps: i64,
    oracle_price_root: &str,
    previous_snapshot_id: &str,
    captured_at_height: u64,
) -> String {
    domain_hash(
        "PERPS-RISK-FUNDING-SNAPSHOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(market_id),
            HashPart::U64(funding_epoch),
            HashPart::Int(funding_rate_bps as i128),
            HashPart::Str(oracle_price_root),
            HashPart::Str(previous_snapshot_id),
            HashPart::U64(captured_at_height),
        ],
        32,
    )
}
pub fn risk_band_id(
    market_id: &str,
    position_id: &str,
    kind: RiskBandKind,
    margin_ratio_bps: u64,
    risk_proof_root: &str,
    computed_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PERPS-RISK-BAND-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(market_id),
            HashPart::Str(position_id),
            HashPart::Str(kind.as_str()),
            HashPart::U64(margin_ratio_bps),
            HashPart::Str(risk_proof_root),
            HashPart::U64(computed_at_height),
            HashPart::U64(nonce),
        ],
        32,
    )
}
pub fn liquidation_queue_id(
    market_id: &str,
    position_id: &str,
    risk_band_id: &str,
    priority: u64,
    sealed_bid_root: &str,
    queued_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PERPS-RISK-LIQUIDATION-QUEUE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(market_id),
            HashPart::Str(position_id),
            HashPart::Str(risk_band_id),
            HashPart::U64(priority),
            HashPart::Str(sealed_bid_root),
            HashPart::U64(queued_at_height),
            HashPart::U64(nonce),
        ],
        32,
    )
}
pub fn insurance_fund_id(
    market_id: &str,
    asset_id: &str,
    operator_commitment: &str,
    reserve_commitment: &str,
    last_rebalanced_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PERPS-RISK-INSURANCE-FUND-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(market_id),
            HashPart::Str(asset_id),
            HashPart::Str(operator_commitment),
            HashPart::Str(reserve_commitment),
            HashPart::U64(last_rebalanced_height),
            HashPart::U64(nonce),
        ],
        32,
    )
}
pub fn oracle_attestation_id(
    feed_id: &str,
    market_id: &str,
    price_commitment: &str,
    reporter_set_root: &str,
    attested_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PERPS-RISK-ORACLE-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(feed_id),
            HashPart::Str(market_id),
            HashPart::Str(price_commitment),
            HashPart::Str(reporter_set_root),
            HashPart::U64(attested_at_height),
            HashPart::U64(nonce),
        ],
        32,
    )
}
pub fn fee_rebate_id(
    market_id: &str,
    beneficiary_commitment: &str,
    fee_nullifier_hash: &str,
    rebate_commitment: &str,
    created_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PERPS-RISK-FEE-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(market_id),
            HashPart::Str(beneficiary_commitment),
            HashPart::Str(fee_nullifier_hash),
            HashPart::Str(rebate_commitment),
            HashPart::U64(created_at_height),
            HashPart::U64(nonce),
        ],
        32,
    )
}
pub fn privacy_fence_id(
    kind: FenceKind,
    subject_id: &str,
    nullifier_hash: &str,
    privacy_set_root: &str,
    consumed_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PERPS-RISK-PRIVACY-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(nullifier_hash),
            HashPart::Str(privacy_set_root),
            HashPart::U64(consumed_at_height),
            HashPart::U64(nonce),
        ],
        32,
    )
}
pub fn slashing_evidence_id(
    offender_commitment: &str,
    reason: SlashingReason,
    evidence_root: &str,
    disputed_record_id: &str,
    recorded_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PERPS-RISK-SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(offender_commitment),
            HashPart::Str(reason.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Str(disputed_record_id),
            HashPart::U64(recorded_at_height),
            HashPart::U64(nonce),
        ],
        32,
    )
}
pub fn public_event_id(
    event_type: &str,
    subject_id: &str,
    payload_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PERPS-RISK-PUBLIC-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(event_type),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}
pub fn nullifier_hash(
    kind: FenceKind,
    owner_commitment: &str,
    subject_id: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PERPS-RISK-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(owner_commitment),
            HashPart::Str(subject_id),
            HashPart::U64(nonce),
        ],
        32,
    )
}
pub fn root_from_parts(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}
pub fn json_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}
pub fn values_merkle_root(domain: &str, records: &[Value]) -> String {
    let mut leaves = records.to_vec();
    leaves.sort_by_key(|value| json_root(&format!("{domain}-SORT"), value));
    merkle_root(domain, &leaves)
}
pub fn map_merkle_root<T: Serialize>(domain: &str, records: &BTreeMap<String, T>) -> String {
    let leaves = records
        .iter()
        .map(|(key, value)| json!({"id":key,"record":value}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile001 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile001 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-001",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-001",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 1,
            max_leverage_bps: 1_000 + 1,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile002 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile002 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-002",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-002",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 2,
            max_leverage_bps: 1_000 + 2,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile003 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile003 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-003",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-003",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 3,
            max_leverage_bps: 1_000 + 3,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile004 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile004 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-004",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-004",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 4,
            max_leverage_bps: 1_000 + 4,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile005 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile005 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-005",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-005",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 5,
            max_leverage_bps: 1_000 + 5,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile006 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile006 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-006",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-006",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 6,
            max_leverage_bps: 1_000 + 6,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile007 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile007 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-007",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-007",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 7,
            max_leverage_bps: 1_000 + 7,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile008 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile008 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-008",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-008",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 8,
            max_leverage_bps: 1_000 + 8,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile009 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile009 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-009",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-009",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 9,
            max_leverage_bps: 1_000 + 9,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile010 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile010 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-010",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-010",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 10,
            max_leverage_bps: 1_000 + 10,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile011 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile011 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-011",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-011",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 11,
            max_leverage_bps: 1_000 + 11,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile012 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile012 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-012",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-012",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 12,
            max_leverage_bps: 1_000 + 12,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile013 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile013 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-013",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-013",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 13,
            max_leverage_bps: 1_000 + 13,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile014 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile014 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-014",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-014",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 14,
            max_leverage_bps: 1_000 + 14,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile015 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile015 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-015",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-015",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 15,
            max_leverage_bps: 1_000 + 15,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile016 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile016 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-016",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-016",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 16,
            max_leverage_bps: 1_000 + 16,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile017 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile017 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-017",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-017",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 17,
            max_leverage_bps: 1_000 + 17,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile018 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile018 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-018",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-018",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 18,
            max_leverage_bps: 1_000 + 18,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile019 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile019 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-019",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-019",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 19,
            max_leverage_bps: 1_000 + 19,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile020 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile020 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-020",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-020",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 20,
            max_leverage_bps: 1_000 + 20,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile021 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile021 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-021",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-021",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 21,
            max_leverage_bps: 1_000 + 21,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile022 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile022 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-022",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-022",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 22,
            max_leverage_bps: 1_000 + 22,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile023 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile023 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-023",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-023",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 23,
            max_leverage_bps: 1_000 + 0,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile024 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile024 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-024",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-024",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 24,
            max_leverage_bps: 1_000 + 1,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile025 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile025 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-025",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-025",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 25,
            max_leverage_bps: 1_000 + 2,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile026 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile026 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-026",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-026",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 26,
            max_leverage_bps: 1_000 + 3,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile027 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile027 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-027",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-027",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 27,
            max_leverage_bps: 1_000 + 4,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile028 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile028 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-028",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-028",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 28,
            max_leverage_bps: 1_000 + 5,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile029 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile029 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-029",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-029",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 29,
            max_leverage_bps: 1_000 + 6,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile030 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile030 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-030",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-030",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 30,
            max_leverage_bps: 1_000 + 7,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile031 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile031 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-031",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-031",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 31,
            max_leverage_bps: 1_000 + 8,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile032 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile032 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-032",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-032",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 32,
            max_leverage_bps: 1_000 + 9,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile033 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile033 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-033",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-033",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 33,
            max_leverage_bps: 1_000 + 10,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile034 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile034 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-034",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-034",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 34,
            max_leverage_bps: 1_000 + 11,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile035 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile035 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-035",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-035",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 35,
            max_leverage_bps: 1_000 + 12,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile036 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile036 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-036",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-036",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 36,
            max_leverage_bps: 1_000 + 13,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile037 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile037 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-037",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-037",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 37,
            max_leverage_bps: 1_000 + 14,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile038 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile038 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-038",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-038",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 38,
            max_leverage_bps: 1_000 + 15,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile039 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile039 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-039",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-039",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 39,
            max_leverage_bps: 1_000 + 16,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile040 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile040 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-040",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-040",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 40,
            max_leverage_bps: 1_000 + 17,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile041 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile041 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-041",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-041",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 41,
            max_leverage_bps: 1_000 + 18,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile042 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile042 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-042",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-042",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 42,
            max_leverage_bps: 1_000 + 19,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile043 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile043 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-043",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-043",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 43,
            max_leverage_bps: 1_000 + 20,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile044 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile044 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-044",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-044",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 44,
            max_leverage_bps: 1_000 + 21,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile045 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile045 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-045",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-045",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 45,
            max_leverage_bps: 1_000 + 22,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile046 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile046 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-046",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-046",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 46,
            max_leverage_bps: 1_000 + 0,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile047 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile047 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-047",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-047",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 47,
            max_leverage_bps: 1_000 + 1,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile048 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile048 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-048",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-048",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 48,
            max_leverage_bps: 1_000 + 2,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile049 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile049 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-049",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-049",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 49,
            max_leverage_bps: 1_000 + 3,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile050 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile050 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-050",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-050",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 50,
            max_leverage_bps: 1_000 + 4,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile051 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile051 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-051",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-051",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 51,
            max_leverage_bps: 1_000 + 5,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile052 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile052 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-052",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-052",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 52,
            max_leverage_bps: 1_000 + 6,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile053 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile053 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-053",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-053",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 53,
            max_leverage_bps: 1_000 + 7,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile054 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile054 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-054",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-054",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 54,
            max_leverage_bps: 1_000 + 8,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile055 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile055 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-055",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-055",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 55,
            max_leverage_bps: 1_000 + 9,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile056 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile056 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-056",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-056",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 56,
            max_leverage_bps: 1_000 + 10,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile057 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile057 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-057",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-057",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 57,
            max_leverage_bps: 1_000 + 11,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile058 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile058 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-058",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-058",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 58,
            max_leverage_bps: 1_000 + 12,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile059 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile059 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-059",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-059",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 59,
            max_leverage_bps: 1_000 + 13,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile060 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile060 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-060",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-060",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 60,
            max_leverage_bps: 1_000 + 14,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile061 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile061 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-061",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-061",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 61,
            max_leverage_bps: 1_000 + 15,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile062 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile062 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-062",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-062",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 62,
            max_leverage_bps: 1_000 + 16,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile063 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile063 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-063",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-063",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 63,
            max_leverage_bps: 1_000 + 17,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile064 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile064 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-064",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-064",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 64,
            max_leverage_bps: 1_000 + 18,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile065 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile065 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-065",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-065",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 65,
            max_leverage_bps: 1_000 + 19,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile066 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile066 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-066",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-066",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 66,
            max_leverage_bps: 1_000 + 20,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile067 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile067 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-067",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-067",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 67,
            max_leverage_bps: 1_000 + 21,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile068 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile068 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-068",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-068",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 68,
            max_leverage_bps: 1_000 + 22,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile069 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile069 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-069",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-069",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 69,
            max_leverage_bps: 1_000 + 0,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile070 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile070 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-070",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-070",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 70,
            max_leverage_bps: 1_000 + 1,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile071 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile071 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-071",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-071",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 71,
            max_leverage_bps: 1_000 + 2,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile072 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile072 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-072",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-072",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 72,
            max_leverage_bps: 1_000 + 3,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile073 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile073 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-073",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-073",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 73,
            max_leverage_bps: 1_000 + 4,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile074 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile074 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-074",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-074",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 74,
            max_leverage_bps: 1_000 + 5,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile075 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile075 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-075",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-075",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 75,
            max_leverage_bps: 1_000 + 6,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile076 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile076 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-076",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-076",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 76,
            max_leverage_bps: 1_000 + 7,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile077 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile077 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-077",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-077",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 77,
            max_leverage_bps: 1_000 + 8,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile078 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile078 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-078",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-078",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 78,
            max_leverage_bps: 1_000 + 9,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile079 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile079 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-079",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-079",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 79,
            max_leverage_bps: 1_000 + 10,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile080 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile080 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-080",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-080",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 80,
            max_leverage_bps: 1_000 + 11,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile081 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile081 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-081",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-081",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 81,
            max_leverage_bps: 1_000 + 12,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile082 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile082 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-082",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-082",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 82,
            max_leverage_bps: 1_000 + 13,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile083 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile083 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-083",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-083",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 83,
            max_leverage_bps: 1_000 + 14,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile084 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile084 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-084",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-084",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 84,
            max_leverage_bps: 1_000 + 15,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile085 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile085 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-085",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-085",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 85,
            max_leverage_bps: 1_000 + 16,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile086 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile086 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-086",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-086",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 86,
            max_leverage_bps: 1_000 + 17,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile087 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile087 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-087",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-087",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 87,
            max_leverage_bps: 1_000 + 18,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile088 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile088 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-088",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-088",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 88,
            max_leverage_bps: 1_000 + 19,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile089 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile089 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-089",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-089",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 89,
            max_leverage_bps: 1_000 + 20,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile090 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile090 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-090",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-090",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 90,
            max_leverage_bps: 1_000 + 21,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile091 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile091 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-091",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-091",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 91,
            max_leverage_bps: 1_000 + 22,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile092 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile092 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-092",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-092",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 92,
            max_leverage_bps: 1_000 + 0,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile093 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile093 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-093",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-093",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 93,
            max_leverage_bps: 1_000 + 1,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile094 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile094 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-094",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-094",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 94,
            max_leverage_bps: 1_000 + 2,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile095 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile095 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-095",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-095",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 95,
            max_leverage_bps: 1_000 + 3,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile096 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile096 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-096",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-096",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 96,
            max_leverage_bps: 1_000 + 4,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile097 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile097 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-097",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-097",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 0,
            max_leverage_bps: 1_000 + 5,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile098 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile098 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-098",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-098",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 1,
            max_leverage_bps: 1_000 + 6,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile099 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile099 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-099",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-099",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 2,
            max_leverage_bps: 1_000 + 7,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile100 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile100 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-100",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-100",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 3,
            max_leverage_bps: 1_000 + 8,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile101 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile101 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-101",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-101",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 4,
            max_leverage_bps: 1_000 + 9,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile102 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile102 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-102",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-102",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 5,
            max_leverage_bps: 1_000 + 10,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile103 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile103 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-103",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-103",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 6,
            max_leverage_bps: 1_000 + 11,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile104 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile104 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-104",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-104",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 7,
            max_leverage_bps: 1_000 + 12,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile105 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile105 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-105",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-105",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 8,
            max_leverage_bps: 1_000 + 13,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile106 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile106 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-106",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-106",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 9,
            max_leverage_bps: 1_000 + 14,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile107 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile107 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-107",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-107",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 10,
            max_leverage_bps: 1_000 + 15,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile108 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile108 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-108",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-108",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 11,
            max_leverage_bps: 1_000 + 16,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile109 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile109 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-109",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-109",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 12,
            max_leverage_bps: 1_000 + 17,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile110 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile110 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-110",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-110",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 13,
            max_leverage_bps: 1_000 + 18,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile111 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile111 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-111",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-111",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 14,
            max_leverage_bps: 1_000 + 19,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile112 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile112 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-112",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-112",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 15,
            max_leverage_bps: 1_000 + 20,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile113 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile113 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-113",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-113",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 16,
            max_leverage_bps: 1_000 + 21,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile114 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile114 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-114",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-114",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 17,
            max_leverage_bps: 1_000 + 22,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile115 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile115 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-115",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-115",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 18,
            max_leverage_bps: 1_000 + 0,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile116 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile116 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-116",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-116",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 19,
            max_leverage_bps: 1_000 + 1,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile117 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile117 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-117",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-117",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 20,
            max_leverage_bps: 1_000 + 2,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile118 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile118 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-118",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-118",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 21,
            max_leverage_bps: 1_000 + 3,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile119 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile119 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-119",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-119",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 22,
            max_leverage_bps: 1_000 + 4,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile120 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile120 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-120",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-120",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 23,
            max_leverage_bps: 1_000 + 5,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile121 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile121 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-121",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-121",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 24,
            max_leverage_bps: 1_000 + 6,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile122 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile122 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-122",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-122",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 25,
            max_leverage_bps: 1_000 + 7,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile123 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile123 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-123",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-123",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 26,
            max_leverage_bps: 1_000 + 8,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile124 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile124 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-124",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-124",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 27,
            max_leverage_bps: 1_000 + 9,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile125 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile125 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-125",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-125",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 28,
            max_leverage_bps: 1_000 + 10,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile126 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile126 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-126",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-126",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 29,
            max_leverage_bps: 1_000 + 11,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile127 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile127 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-127",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-127",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 30,
            max_leverage_bps: 1_000 + 12,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile128 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile128 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-128",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-128",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 31,
            max_leverage_bps: 1_000 + 13,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile129 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile129 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-129",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-129",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 32,
            max_leverage_bps: 1_000 + 14,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile130 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile130 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-130",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-130",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 33,
            max_leverage_bps: 1_000 + 15,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile131 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile131 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-131",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-131",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 34,
            max_leverage_bps: 1_000 + 16,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile132 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile132 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-132",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-132",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 35,
            max_leverage_bps: 1_000 + 17,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile133 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile133 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-133",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-133",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 36,
            max_leverage_bps: 1_000 + 18,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile134 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile134 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-134",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-134",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 37,
            max_leverage_bps: 1_000 + 19,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile135 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile135 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-135",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-135",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 38,
            max_leverage_bps: 1_000 + 20,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile136 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile136 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-136",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-136",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 39,
            max_leverage_bps: 1_000 + 21,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile137 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile137 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-137",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-137",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 40,
            max_leverage_bps: 1_000 + 22,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile138 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile138 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-138",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-138",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 41,
            max_leverage_bps: 1_000 + 0,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile139 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile139 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-139",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-139",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 42,
            max_leverage_bps: 1_000 + 1,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile140 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile140 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-140",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-140",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 43,
            max_leverage_bps: 1_000 + 2,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile141 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile141 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-141",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-141",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 44,
            max_leverage_bps: 1_000 + 3,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile142 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile142 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-142",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-142",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 45,
            max_leverage_bps: 1_000 + 4,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile143 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile143 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-143",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-143",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 46,
            max_leverage_bps: 1_000 + 5,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile144 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile144 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-144",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-144",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 47,
            max_leverage_bps: 1_000 + 6,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile145 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile145 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-145",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-145",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 48,
            max_leverage_bps: 1_000 + 7,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile146 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile146 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-146",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-146",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 49,
            max_leverage_bps: 1_000 + 8,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile147 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile147 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-147",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-147",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 50,
            max_leverage_bps: 1_000 + 9,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile148 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile148 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-148",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-148",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 51,
            max_leverage_bps: 1_000 + 10,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile149 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile149 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-149",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-149",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 52,
            max_leverage_bps: 1_000 + 11,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile150 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile150 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-150",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-150",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 53,
            max_leverage_bps: 1_000 + 12,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile151 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile151 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-151",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-151",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 54,
            max_leverage_bps: 1_000 + 13,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile152 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile152 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-152",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-152",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 55,
            max_leverage_bps: 1_000 + 14,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile153 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile153 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-153",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-153",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 56,
            max_leverage_bps: 1_000 + 15,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile154 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile154 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-154",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-154",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 57,
            max_leverage_bps: 1_000 + 16,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile155 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile155 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-155",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-155",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 58,
            max_leverage_bps: 1_000 + 17,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile156 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile156 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-156",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-156",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 59,
            max_leverage_bps: 1_000 + 18,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile157 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile157 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-157",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-157",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 60,
            max_leverage_bps: 1_000 + 19,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile158 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile158 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-158",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-158",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 61,
            max_leverage_bps: 1_000 + 20,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile159 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile159 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-159",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-159",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 62,
            max_leverage_bps: 1_000 + 21,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile160 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile160 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-160",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-160",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 63,
            max_leverage_bps: 1_000 + 22,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile161 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile161 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-161",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-161",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 64,
            max_leverage_bps: 1_000 + 0,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile162 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile162 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-162",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-162",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 65,
            max_leverage_bps: 1_000 + 1,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile163 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile163 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-163",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-163",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 66,
            max_leverage_bps: 1_000 + 2,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile164 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile164 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-164",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-164",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 67,
            max_leverage_bps: 1_000 + 3,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile165 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile165 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-165",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-165",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 68,
            max_leverage_bps: 1_000 + 4,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile166 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile166 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-166",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-166",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 69,
            max_leverage_bps: 1_000 + 5,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile167 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile167 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-167",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-167",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 70,
            max_leverage_bps: 1_000 + 6,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile168 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile168 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-168",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-168",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 71,
            max_leverage_bps: 1_000 + 7,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile169 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile169 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-169",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-169",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 72,
            max_leverage_bps: 1_000 + 8,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile170 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile170 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-170",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-170",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 73,
            max_leverage_bps: 1_000 + 9,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile171 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile171 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-171",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-171",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 74,
            max_leverage_bps: 1_000 + 10,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile172 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile172 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-172",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-172",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 75,
            max_leverage_bps: 1_000 + 11,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile173 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile173 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-173",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-173",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 76,
            max_leverage_bps: 1_000 + 12,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile174 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile174 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-174",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-174",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 77,
            max_leverage_bps: 1_000 + 13,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskEngineLimitProfile175 {
    pub profile_id: String,
    pub market_root: String,
    pub margin_floor_bps: u64,
    pub max_leverage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
}
impl RiskEngineLimitProfile175 {
    pub fn devnet(label: &str, sequence: u64) -> Self {
        Self {
            profile_id: domain_hash(
                "PERPS-RISK-LIMIT-PROFILE-175",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(sequence),
                ],
                32,
            ),
            market_root: root_from_parts(
                "PERPS-RISK-LIMIT-MARKET-175",
                &[HashPart::Str(label), HashPart::U64(sequence)],
            ),
            margin_floor_bps: DEFAULT_MAINTENANCE_MARGIN_BPS + 78,
            max_leverage_bps: 1_000 + 14,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn root(&self) -> String {
        json_root("PERPS-RISK-LIMIT-PROFILE-ROOT", &json!(self))
    }
}
