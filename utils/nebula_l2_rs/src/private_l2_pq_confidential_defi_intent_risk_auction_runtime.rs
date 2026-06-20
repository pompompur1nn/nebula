use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialDefiIntentRiskAuctionRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-defi-intent-risk-auction-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const INTENT_ENCRYPTION_SUITE: &str = "ML-KEM-1024-threshold-sealed-defi-intent-v1";
pub const AUCTION_SUITE: &str = "private-risk-aware-uniform-clearing-auction-v1";
pub const REDACTION_SUITE: &str = "roots-only-selective-disclosure-v1";
pub const DEVNET_L2_HEIGHT: u64 = 2_240_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_420_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 16;
pub const DEFAULT_LOW_FEE_CLEARING_BPS: u64 = 4;
pub const DEFAULT_SOLVER_BOND_MICRO_UNITS: u64 = 25_000_000;
pub const DEFAULT_BACKSTOP_COVER_BPS: u64 = 12_500;
pub const DEFAULT_CROSS_MARGIN_HAIRCUT_BPS: u64 = 1_250;
pub const DEFAULT_MAX_ORACLE_VOL_BPS: u64 = 850;
pub const DEFAULT_AUCTION_TTL_BLOCKS: u64 = 8;
pub const DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 28;
pub const DEFAULT_MAX_INTENTS: usize = 1_048_576;
pub const DEFAULT_MAX_AUCTIONS: usize = 262_144;
pub const DEFAULT_MAX_SOLVER_BONDS: usize = 262_144;
pub const DEFAULT_MAX_RISK_BIDS: usize = 1_048_576;
pub const DEFAULT_MAX_SETTLEMENTS: usize = 524_288;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentKind {
    Swap,
    Lend,
    Borrow,
    Repay,
    AddLiquidity,
    RemoveLiquidity,
    PerpHedge,
    LiquidationBackstop,
    ContractCall,
}

impl IntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Swap => "swap",
            Self::Lend => "lend",
            Self::Borrow => "borrow",
            Self::Repay => "repay",
            Self::AddLiquidity => "add_liquidity",
            Self::RemoveLiquidity => "remove_liquidity",
            Self::PerpHedge => "perp_hedge",
            Self::LiquidationBackstop => "liquidation_backstop",
            Self::ContractCall => "contract_call",
        }
    }

    pub fn risk_weight(self) -> u64 {
        match self {
            Self::LiquidationBackstop => 1_450,
            Self::Borrow | Self::PerpHedge => 1_300,
            Self::ContractCall => 1_150,
            Self::RemoveLiquidity => 1_050,
            Self::Swap | Self::AddLiquidity => 1_000,
            Self::Lend | Self::Repay => 820,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionLane {
    LowFeeBatch,
    FastRisk,
    CrossMargin,
    OracleGuarded,
    LiquidationBackstop,
    ContractCovenant,
}

impl AuctionLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFeeBatch => "low_fee_batch",
            Self::FastRisk => "fast_risk",
            Self::CrossMargin => "cross_margin",
            Self::OracleGuarded => "oracle_guarded",
            Self::LiquidationBackstop => "liquidation_backstop",
            Self::ContractCovenant => "contract_covenant",
        }
    }

    pub fn fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::LowFeeBatch => config.low_fee_clearing_bps,
            Self::CrossMargin | Self::ContractCovenant => config.max_user_fee_bps / 2,
            Self::OracleGuarded => config.max_user_fee_bps.saturating_mul(3) / 4,
            Self::FastRisk | Self::LiquidationBackstop => config.max_user_fee_bps,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordStatus {
    Open,
    Sealed,
    Solving,
    Clearing,
    Settled,
    Cancelled,
    Slashed,
}

impl RecordStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Solving => "solving",
            Self::Clearing => "clearing",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_attestation_suite: String,
    pub intent_encryption_suite: String,
    pub auction_suite: String,
    pub redaction_suite: String,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub low_fee_clearing_bps: u64,
    pub solver_bond_micro_units: u64,
    pub liquidation_backstop_cover_bps: u64,
    pub cross_margin_haircut_bps: u64,
    pub max_oracle_volatility_bps: u64,
    pub auction_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
            intent_encryption_suite: INTENT_ENCRYPTION_SUITE.to_string(),
            auction_suite: AUCTION_SUITE.to_string(),
            redaction_suite: REDACTION_SUITE.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            low_fee_clearing_bps: DEFAULT_LOW_FEE_CLEARING_BPS,
            solver_bond_micro_units: DEFAULT_SOLVER_BOND_MICRO_UNITS,
            liquidation_backstop_cover_bps: DEFAULT_BACKSTOP_COVER_BPS,
            cross_margin_haircut_bps: DEFAULT_CROSS_MARGIN_HAIRCUT_BPS,
            max_oracle_volatility_bps: DEFAULT_MAX_ORACLE_VOL_BPS,
            auction_ttl_blocks: DEFAULT_AUCTION_TTL_BLOCKS,
            settlement_ttl_blocks: DEFAULT_SETTLEMENT_TTL_BLOCKS,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub intents_submitted: u64,
    pub auctions_opened: u64,
    pub solver_bonds_locked: u64,
    pub risk_bids_submitted: u64,
    pub batches_cleared: u64,
    pub settlements_recorded: u64,
    pub public_records: u64,
    pub low_fee_micro_units_saved: u64,
    pub backstop_liquidity_micro_units: u64,
    pub slashed_solver_bonds: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub intent_root: String,
    pub auction_root: String,
    pub solver_bond_root: String,
    pub risk_bid_root: String,
    pub oracle_constraint_root: String,
    pub margin_root: String,
    pub covenant_root: String,
    pub backstop_root: String,
    pub attestation_root: String,
    pub redaction_root: String,
    pub settlement_root: String,
    pub summary_root: String,
    pub public_record_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        let empty = empty_root("EMPTY");
        Self {
            config_root: empty.clone(),
            counters_root: empty.clone(),
            intent_root: empty.clone(),
            auction_root: empty.clone(),
            solver_bond_root: empty.clone(),
            risk_bid_root: empty.clone(),
            oracle_constraint_root: empty.clone(),
            margin_root: empty.clone(),
            covenant_root: empty.clone(),
            backstop_root: empty.clone(),
            attestation_root: empty.clone(),
            redaction_root: empty.clone(),
            settlement_root: empty.clone(),
            summary_root: empty.clone(),
            public_record_root: empty,
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedDefiIntentRequest {
    pub owner_commitment: String,
    pub intent_kind: IntentKind,
    pub lane: AuctionLane,
    pub market_id: String,
    pub encrypted_payload_root: String,
    pub amount_commitment: String,
    pub limit_price_commitment: String,
    pub max_fee_bps: u64,
    pub route_covenant_id: String,
    pub cross_margin_account_root: String,
    pub nullifier_commitment: String,
    pub privacy_set_size: u64,
    pub pq_ciphertext_root: String,
    pub proof_root: String,
    pub submitted_height: u64,
    pub expires_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedDefiIntent {
    pub intent_id: String,
    pub status: RecordStatus,
    pub owner_commitment: String,
    pub intent_kind: IntentKind,
    pub lane: AuctionLane,
    pub market_id: String,
    pub encrypted_payload_root: String,
    pub amount_commitment: String,
    pub limit_price_commitment: String,
    pub max_fee_bps: u64,
    pub route_covenant_id: String,
    pub cross_margin_account_root: String,
    pub nullifier_commitment: String,
    pub privacy_set_size: u64,
    pub pq_ciphertext_root: String,
    pub proof_root: String,
    pub submitted_height: u64,
    pub expires_height: u64,
}

impl EncryptedDefiIntent {
    pub fn from_request(request: EncryptedDefiIntentRequest) -> Self {
        let intent_id = record_id(
            "INTENT-ID",
            &[
                HashPart::Str(&request.owner_commitment),
                HashPart::Str(request.intent_kind.as_str()),
                HashPart::Str(&request.nullifier_commitment),
                HashPart::U64(request.submitted_height),
            ],
        );
        Self {
            intent_id,
            status: RecordStatus::Open,
            owner_commitment: request.owner_commitment,
            intent_kind: request.intent_kind,
            lane: request.lane,
            market_id: request.market_id,
            encrypted_payload_root: request.encrypted_payload_root,
            amount_commitment: request.amount_commitment,
            limit_price_commitment: request.limit_price_commitment,
            max_fee_bps: request.max_fee_bps,
            route_covenant_id: request.route_covenant_id,
            cross_margin_account_root: request.cross_margin_account_root,
            nullifier_commitment: request.nullifier_commitment,
            privacy_set_size: request.privacy_set_size,
            pq_ciphertext_root: request.pq_ciphertext_root,
            proof_root: request.proof_root,
            submitted_height: request.submitted_height,
            expires_height: request.expires_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "status": self.status.as_str(),
            "intent_kind": self.intent_kind.as_str(),
            "lane": self.lane.as_str(),
            "market_id": self.market_id,
            "owner_commitment": self.owner_commitment,
            "encrypted_payload_root": self.encrypted_payload_root,
            "amount_commitment": self.amount_commitment,
            "limit_price_commitment": self.limit_price_commitment,
            "max_fee_bps": self.max_fee_bps,
            "route_covenant_id": self.route_covenant_id,
            "cross_margin_account_root": self.cross_margin_account_root,
            "nullifier_commitment": self.nullifier_commitment,
            "privacy_set_size": self.privacy_set_size,
            "pq_ciphertext_root": self.pq_ciphertext_root,
            "proof_root": self.proof_root,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskAuctionBook {
    pub auction_id: String,
    pub lane: AuctionLane,
    pub intent_ids: BTreeSet<String>,
    pub status: RecordStatus,
    pub clearing_asset_id: String,
    pub target_fee_bps: u64,
    pub minimum_solver_bond_micro_units: u64,
    pub opened_height: u64,
    pub expires_height: u64,
}

impl RiskAuctionBook {
    pub fn public_record(&self) -> Value {
        json!({
            "auction_id": self.auction_id,
            "lane": self.lane.as_str(),
            "intent_ids": self.intent_ids.iter().cloned().collect::<Vec<_>>(),
            "status": self.status.as_str(),
            "clearing_asset_id": self.clearing_asset_id,
            "target_fee_bps": self.target_fee_bps,
            "minimum_solver_bond_micro_units": self.minimum_solver_bond_micro_units,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverBond {
    pub solver_id: String,
    pub bond_id: String,
    pub locked_micro_units: u64,
    pub slashed_micro_units: u64,
    pub markets: BTreeSet<String>,
    pub pq_public_key_root: String,
    pub status: RecordStatus,
}

impl SolverBond {
    pub fn public_record(&self) -> Value {
        json!({
            "solver_id": self.solver_id,
            "bond_id": self.bond_id,
            "locked_micro_units": self.locked_micro_units,
            "slashed_micro_units": self.slashed_micro_units,
            "markets": self.markets.iter().cloned().collect::<Vec<_>>(),
            "pq_public_key_root": self.pq_public_key_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskBidRequest {
    pub auction_id: String,
    pub solver_id: String,
    pub encrypted_price_root: String,
    pub risk_score_bps: u64,
    pub fee_bps: u64,
    pub margin_usage_bps: u64,
    pub backstop_cover_bps: u64,
    pub pq_attestation_id: String,
    pub submitted_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskBid {
    pub bid_id: String,
    pub auction_id: String,
    pub solver_id: String,
    pub encrypted_price_root: String,
    pub risk_score_bps: u64,
    pub fee_bps: u64,
    pub margin_usage_bps: u64,
    pub backstop_cover_bps: u64,
    pub pq_attestation_id: String,
    pub submitted_height: u64,
}

impl RiskBid {
    pub fn from_request(request: RiskBidRequest) -> Self {
        let bid_id = record_id(
            "RISK-BID-ID",
            &[
                HashPart::Str(&request.auction_id),
                HashPart::Str(&request.solver_id),
                HashPart::Str(&request.encrypted_price_root),
                HashPart::U64(request.submitted_height),
            ],
        );
        Self {
            bid_id,
            auction_id: request.auction_id,
            solver_id: request.solver_id,
            encrypted_price_root: request.encrypted_price_root,
            risk_score_bps: request.risk_score_bps,
            fee_bps: request.fee_bps,
            margin_usage_bps: request.margin_usage_bps,
            backstop_cover_bps: request.backstop_cover_bps,
            pq_attestation_id: request.pq_attestation_id,
            submitted_height: request.submitted_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleVolatilityConstraint {
    pub market_id: String,
    pub oracle_root: String,
    pub max_volatility_bps: u64,
    pub observed_volatility_bps: u64,
    pub stale_after_height: u64,
}

impl OracleVolatilityConstraint {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossMarginHaircut {
    pub account_root: String,
    pub market_id: String,
    pub haircut_bps: u64,
    pub exposure_commitment: String,
    pub collateral_commitment: String,
}

impl CrossMarginHaircut {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRouteCovenant {
    pub covenant_id: String,
    pub route_root: String,
    pub allowed_token_roots: BTreeSet<String>,
    pub contract_call_root: String,
    pub max_hops: u8,
    pub privacy_redaction_root: String,
}

impl TokenRouteCovenant {
    pub fn public_record(&self) -> Value {
        json!({
            "covenant_id": self.covenant_id,
            "route_root": self.route_root,
            "allowed_token_roots": self.allowed_token_roots.iter().cloned().collect::<Vec<_>>(),
            "contract_call_root": self.contract_call_root,
            "max_hops": self.max_hops,
            "privacy_redaction_root": self.privacy_redaction_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidationBackstopRecord {
    pub pool_id: String,
    pub covered_market_id: String,
    pub liquidity_commitment: String,
    pub cover_bps: u64,
    pub keeper_set_root: String,
    pub emergency_lane_enabled: bool,
}

impl LiquidationBackstopRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSolverAttestation {
    pub attestation_id: String,
    pub solver_id: String,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub security_bits: u16,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
}

impl PqSolverAttestation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyRedactionRoot {
    pub redaction_id: String,
    pub scope: String,
    pub disclosed_fields: BTreeSet<String>,
    pub redacted_payload_root: String,
    pub operator_summary_root: String,
}

impl PrivacyRedactionRoot {
    pub fn public_record(&self) -> Value {
        json!({
            "redaction_id": self.redaction_id,
            "scope": self.scope,
            "disclosed_fields": self.disclosed_fields.iter().cloned().collect::<Vec<_>>(),
            "redacted_payload_root": self.redacted_payload_root,
            "operator_summary_root": self.operator_summary_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchClearingSettlement {
    pub settlement_id: String,
    pub auction_id: String,
    pub winning_solver_id: String,
    pub cleared_intent_ids: BTreeSet<String>,
    pub clearing_root: String,
    pub fee_bps: u64,
    pub low_fee_savings_micro_units: u64,
    pub settlement_height: u64,
    pub public_summary_id: String,
}

impl BatchClearingSettlement {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "auction_id": self.auction_id,
            "winning_solver_id": self.winning_solver_id,
            "cleared_intent_ids": self.cleared_intent_ids.iter().cloned().collect::<Vec<_>>(),
            "clearing_root": self.clearing_root,
            "fee_bps": self.fee_bps,
            "low_fee_savings_micro_units": self.low_fee_savings_micro_units,
            "settlement_height": self.settlement_height,
            "public_summary_id": self.public_summary_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorPublicSummary {
    pub summary_id: String,
    pub height: u64,
    pub lane: AuctionLane,
    pub market_id: String,
    pub cleared_intents: u64,
    pub average_fee_bps: u64,
    pub max_observed_volatility_bps: u64,
    pub privacy_set_size: u64,
    pub state_root: String,
}

impl OperatorPublicSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "height": self.height,
            "lane": self.lane.as_str(),
            "market_id": self.market_id,
            "cleared_intents": self.cleared_intents,
            "average_fee_bps": self.average_fee_bps,
            "max_observed_volatility_bps": self.max_observed_volatility_bps,
            "privacy_set_size": self.privacy_set_size,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub intents: BTreeMap<String, EncryptedDefiIntent>,
    pub auctions: BTreeMap<String, RiskAuctionBook>,
    pub solver_bonds: BTreeMap<String, SolverBond>,
    pub risk_bids: BTreeMap<String, RiskBid>,
    pub oracle_constraints: BTreeMap<String, OracleVolatilityConstraint>,
    pub margin_haircuts: BTreeMap<String, CrossMarginHaircut>,
    pub route_covenants: BTreeMap<String, TokenRouteCovenant>,
    pub liquidation_backstops: BTreeMap<String, LiquidationBackstopRecord>,
    pub pq_attestations: BTreeMap<String, PqSolverAttestation>,
    pub privacy_redactions: BTreeMap<String, PrivacyRedactionRoot>,
    pub settlements: BTreeMap<String, BatchClearingSettlement>,
    pub public_summaries: BTreeMap<String, OperatorPublicSummary>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            intents: BTreeMap::new(),
            auctions: BTreeMap::new(),
            solver_bonds: BTreeMap::new(),
            risk_bids: BTreeMap::new(),
            oracle_constraints: BTreeMap::new(),
            margin_haircuts: BTreeMap::new(),
            route_covenants: BTreeMap::new(),
            liquidation_backstops: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            privacy_redactions: BTreeMap::new(),
            settlements: BTreeMap::new(),
            public_summaries: BTreeMap::new(),
        }
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self::default();
        state.install_devnet_policy();
        let first = state
            .submit_encrypted_intent(deterministic_intent_request(
                "devnet-xmr-swap",
                IntentKind::Swap,
                AuctionLane::LowFeeBatch,
            ))
            .expect("devnet swap intent");
        let second = state
            .submit_encrypted_intent(deterministic_intent_request(
                "devnet-backstop",
                IntentKind::LiquidationBackstop,
                AuctionLane::LiquidationBackstop,
            ))
            .expect("devnet backstop intent");
        let auction = state
            .open_risk_auction(
                AuctionLane::LowFeeBatch,
                "xmr-zusd-confidential".to_string(),
                [first.intent_id.clone(), second.intent_id.clone()]
                    .into_iter()
                    .collect(),
                DEVNET_L2_HEIGHT + 1,
            )
            .expect("devnet auction");
        let bid = state
            .submit_risk_bid(RiskBidRequest {
                auction_id: auction.auction_id.clone(),
                solver_id: "devnet-solver-0".to_string(),
                encrypted_price_root: devnet_hash("bid-price", &auction.auction_id),
                risk_score_bps: 370,
                fee_bps: state.config.low_fee_clearing_bps,
                margin_usage_bps: 2_400,
                backstop_cover_bps: state.config.liquidation_backstop_cover_bps,
                pq_attestation_id: "attest-devnet-solver-0".to_string(),
                submitted_height: DEVNET_L2_HEIGHT + 2,
            })
            .expect("devnet risk bid");
        let _settlement = state
            .clear_low_fee_batch(&auction.auction_id, &bid.bid_id, DEVNET_L2_HEIGHT + 4)
            .expect("devnet clearing");
        state.refresh_roots();
        state
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root());
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn refresh_roots(&mut self) {
        self.roots.config_root = record_root("CONFIG", &self.config.public_record());
        self.roots.counters_root = record_root("COUNTERS", &self.counters.public_record());
        self.roots.intent_root =
            map_root("INTENTS", &self.intents, EncryptedDefiIntent::public_record);
        self.roots.auction_root =
            map_root("AUCTIONS", &self.auctions, RiskAuctionBook::public_record);
        self.roots.solver_bond_root = map_root(
            "SOLVER-BONDS",
            &self.solver_bonds,
            SolverBond::public_record,
        );
        self.roots.risk_bid_root = map_root("RISK-BIDS", &self.risk_bids, RiskBid::public_record);
        self.roots.oracle_constraint_root = map_root(
            "ORACLE-CONSTRAINTS",
            &self.oracle_constraints,
            OracleVolatilityConstraint::public_record,
        );
        self.roots.margin_root = map_root(
            "MARGINS",
            &self.margin_haircuts,
            CrossMarginHaircut::public_record,
        );
        self.roots.covenant_root = map_root(
            "COVENANTS",
            &self.route_covenants,
            TokenRouteCovenant::public_record,
        );
        self.roots.backstop_root = map_root(
            "BACKSTOPS",
            &self.liquidation_backstops,
            LiquidationBackstopRecord::public_record,
        );
        self.roots.attestation_root = map_root(
            "ATTESTATIONS",
            &self.pq_attestations,
            PqSolverAttestation::public_record,
        );
        self.roots.redaction_root = map_root(
            "REDACTIONS",
            &self.privacy_redactions,
            PrivacyRedactionRoot::public_record,
        );
        self.roots.settlement_root = map_root(
            "SETTLEMENTS",
            &self.settlements,
            BatchClearingSettlement::public_record,
        );
        self.roots.summary_root = map_root(
            "SUMMARIES",
            &self.public_summaries,
            OperatorPublicSummary::public_record,
        );
        self.roots.public_record_root =
            public_record_root(&self.public_record_without_state_root());
        self.counters.public_records = self.counters.public_records.saturating_add(1);
    }

    pub fn submit_encrypted_intent(
        &mut self,
        request: EncryptedDefiIntentRequest,
    ) -> Result<EncryptedDefiIntent> {
        ensure_bps("max_fee_bps", request.max_fee_bps)?;
        ensure_capacity("intents", self.intents.len(), DEFAULT_MAX_INTENTS)?;
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy set below configured minimum".to_string());
        }
        let intent = EncryptedDefiIntent::from_request(request);
        ensure_absent("intent", &self.intents, &intent.intent_id)?;
        self.intents
            .insert(intent.intent_id.clone(), intent.clone());
        self.counters.intents_submitted = self.counters.intents_submitted.saturating_add(1);
        self.refresh_roots();
        Ok(intent)
    }

    pub fn open_risk_auction(
        &mut self,
        lane: AuctionLane,
        clearing_asset_id: String,
        intent_ids: BTreeSet<String>,
        opened_height: u64,
    ) -> Result<RiskAuctionBook> {
        ensure_capacity("auctions", self.auctions.len(), DEFAULT_MAX_AUCTIONS)?;
        if intent_ids.is_empty() {
            return Err("auction requires at least one intent".to_string());
        }
        for intent_id in &intent_ids {
            if !self.intents.contains_key(intent_id) {
                return Err(format!("intent {intent_id} missing"));
            }
        }
        let auction_id = record_id(
            "AUCTION-ID",
            &[
                HashPart::Str(lane.as_str()),
                HashPart::Str(&clearing_asset_id),
                HashPart::U64(opened_height),
                HashPart::Str(&record_root("AUCTION-INTENTS", &json!(intent_ids))),
            ],
        );
        let auction = RiskAuctionBook {
            auction_id,
            lane,
            intent_ids,
            status: RecordStatus::Open,
            clearing_asset_id,
            target_fee_bps: lane.fee_bps(&self.config),
            minimum_solver_bond_micro_units: self.config.solver_bond_micro_units,
            opened_height,
            expires_height: opened_height + self.config.auction_ttl_blocks,
        };
        self.auctions
            .insert(auction.auction_id.clone(), auction.clone());
        self.counters.auctions_opened = self.counters.auctions_opened.saturating_add(1);
        self.refresh_roots();
        Ok(auction)
    }

    pub fn lock_solver_bond(&mut self, bond: SolverBond) -> Result<()> {
        ensure_capacity(
            "solver bonds",
            self.solver_bonds.len(),
            DEFAULT_MAX_SOLVER_BONDS,
        )?;
        if bond.locked_micro_units < self.config.solver_bond_micro_units {
            return Err("solver bond below configured minimum".to_string());
        }
        ensure_absent("solver bond", &self.solver_bonds, &bond.bond_id)?;
        self.solver_bonds.insert(bond.bond_id.clone(), bond);
        self.counters.solver_bonds_locked = self.counters.solver_bonds_locked.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn submit_risk_bid(&mut self, request: RiskBidRequest) -> Result<RiskBid> {
        ensure_capacity("risk bids", self.risk_bids.len(), DEFAULT_MAX_RISK_BIDS)?;
        ensure_bps("risk_score_bps", request.risk_score_bps)?;
        ensure_bps("fee_bps", request.fee_bps)?;
        ensure_bps("margin_usage_bps", request.margin_usage_bps)?;
        ensure_bps("backstop_cover_bps", request.backstop_cover_bps)?;
        let auction = self
            .auctions
            .get(&request.auction_id)
            .ok_or_else(|| format!("auction {} missing", request.auction_id))?;
        if request.fee_bps > auction.target_fee_bps {
            return Err("bid fee exceeds auction target".to_string());
        }
        if request.backstop_cover_bps < self.config.liquidation_backstop_cover_bps {
            return Err("bid does not satisfy liquidation backstop cover".to_string());
        }
        let attestation = self
            .pq_attestations
            .get(&request.pq_attestation_id)
            .ok_or_else(|| format!("attestation {} missing", request.pq_attestation_id))?;
        if attestation.security_bits < self.config.min_pq_security_bits {
            return Err("solver attestation below PQ security floor".to_string());
        }
        let bid = RiskBid::from_request(request);
        ensure_absent("risk bid", &self.risk_bids, &bid.bid_id)?;
        self.risk_bids.insert(bid.bid_id.clone(), bid.clone());
        self.counters.risk_bids_submitted = self.counters.risk_bids_submitted.saturating_add(1);
        self.refresh_roots();
        Ok(bid)
    }

    pub fn clear_low_fee_batch(
        &mut self,
        auction_id: &str,
        bid_id: &str,
        settlement_height: u64,
    ) -> Result<BatchClearingSettlement> {
        ensure_capacity(
            "settlements",
            self.settlements.len(),
            DEFAULT_MAX_SETTLEMENTS,
        )?;
        let auction = self
            .auctions
            .get_mut(auction_id)
            .ok_or_else(|| format!("auction {auction_id} missing"))?;
        let bid = self
            .risk_bids
            .get(bid_id)
            .ok_or_else(|| format!("bid {bid_id} missing"))?;
        if bid.auction_id != auction.auction_id {
            return Err("bid belongs to a different auction".to_string());
        }
        auction.status = RecordStatus::Settled;
        let settlement_id = record_id(
            "SETTLEMENT-ID",
            &[
                HashPart::Str(auction_id),
                HashPart::Str(bid_id),
                HashPart::U64(settlement_height),
            ],
        );
        let summary_id = record_id("SUMMARY-ID", &[HashPart::Str(&settlement_id)]);
        let clearing_root = record_root(
            "CLEARING",
            &json!({
                "auction_id": auction_id,
                "bid_id": bid_id,
                "intent_ids": auction.intent_ids.iter().cloned().collect::<Vec<_>>(),
            }),
        );
        let savings = (auction.intent_ids.len() as u64)
            .saturating_mul(self.config.max_user_fee_bps.saturating_sub(bid.fee_bps))
            .saturating_mul(100);
        let settlement = BatchClearingSettlement {
            settlement_id,
            auction_id: auction_id.to_string(),
            winning_solver_id: bid.solver_id.clone(),
            cleared_intent_ids: auction.intent_ids.clone(),
            clearing_root,
            fee_bps: bid.fee_bps,
            low_fee_savings_micro_units: savings,
            settlement_height,
            public_summary_id: summary_id.clone(),
        };
        for intent_id in &settlement.cleared_intent_ids {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = RecordStatus::Settled;
            }
        }
        self.counters.batches_cleared = self.counters.batches_cleared.saturating_add(1);
        self.counters.settlements_recorded = self.counters.settlements_recorded.saturating_add(1);
        self.counters.low_fee_micro_units_saved = self
            .counters
            .low_fee_micro_units_saved
            .saturating_add(savings);
        self.settlements
            .insert(settlement.settlement_id.clone(), settlement.clone());
        let summary_lane = auction.lane;
        let summary_market_id = auction.clearing_asset_id.clone();
        let summary = OperatorPublicSummary {
            summary_id,
            height: settlement_height,
            lane: summary_lane,
            market_id: summary_market_id,
            cleared_intents: settlement.cleared_intent_ids.len() as u64,
            average_fee_bps: bid.fee_bps,
            max_observed_volatility_bps: self
                .oracle_constraints
                .values()
                .map(|oracle| oracle.observed_volatility_bps)
                .max()
                .unwrap_or_default(),
            privacy_set_size: self.config.batch_privacy_set_size,
            state_root: self.state_root(),
        };
        self.public_summaries
            .insert(summary.summary_id.clone(), summary);
        self.refresh_roots();
        Ok(settlement)
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "intents": self.intents.values().map(EncryptedDefiIntent::public_record).collect::<Vec<_>>(),
            "auctions": self.auctions.values().map(RiskAuctionBook::public_record).collect::<Vec<_>>(),
            "solver_bonds": self.solver_bonds.values().map(SolverBond::public_record).collect::<Vec<_>>(),
            "risk_bids": self.risk_bids.values().map(RiskBid::public_record).collect::<Vec<_>>(),
            "oracle_constraints": self.oracle_constraints.values().map(OracleVolatilityConstraint::public_record).collect::<Vec<_>>(),
            "margin_haircuts": self.margin_haircuts.values().map(CrossMarginHaircut::public_record).collect::<Vec<_>>(),
            "route_covenants": self.route_covenants.values().map(TokenRouteCovenant::public_record).collect::<Vec<_>>(),
            "liquidation_backstops": self.liquidation_backstops.values().map(LiquidationBackstopRecord::public_record).collect::<Vec<_>>(),
            "pq_attestations": self.pq_attestations.values().map(PqSolverAttestation::public_record).collect::<Vec<_>>(),
            "privacy_redactions": self.privacy_redactions.values().map(PrivacyRedactionRoot::public_record).collect::<Vec<_>>(),
            "settlements": self.settlements.values().map(BatchClearingSettlement::public_record).collect::<Vec<_>>(),
            "public_summaries": self.public_summaries.values().map(OperatorPublicSummary::public_record).collect::<Vec<_>>(),
        })
    }

    fn install_devnet_policy(&mut self) {
        let covenant = TokenRouteCovenant {
            covenant_id: "covenant-xmr-zusd-low-fee".to_string(),
            route_root: devnet_hash("route", "xmr-zusd"),
            allowed_token_roots: ["xmr-root", "zusd-root", "nebula-fee-root"]
                .into_iter()
                .map(|label| devnet_hash("token", label))
                .collect(),
            contract_call_root: devnet_hash("contract-call", "swap-router-v1"),
            max_hops: 3,
            privacy_redaction_root: devnet_hash("redaction", "route-covenant"),
        };
        self.route_covenants
            .insert(covenant.covenant_id.clone(), covenant);
        self.oracle_constraints.insert(
            "xmr-zusd-confidential".to_string(),
            OracleVolatilityConstraint {
                market_id: "xmr-zusd-confidential".to_string(),
                oracle_root: devnet_hash("oracle", "xmr-zusd"),
                max_volatility_bps: self.config.max_oracle_volatility_bps,
                observed_volatility_bps: 320,
                stale_after_height: DEVNET_L2_HEIGHT + 20,
            },
        );
        self.margin_haircuts.insert(
            "margin-devnet-vault-0".to_string(),
            CrossMarginHaircut {
                account_root: devnet_hash("margin-account", "vault-0"),
                market_id: "xmr-zusd-confidential".to_string(),
                haircut_bps: self.config.cross_margin_haircut_bps,
                exposure_commitment: devnet_hash("exposure", "vault-0"),
                collateral_commitment: devnet_hash("collateral", "vault-0"),
            },
        );
        self.liquidation_backstops.insert(
            "backstop-xmr-zusd".to_string(),
            LiquidationBackstopRecord {
                pool_id: "backstop-xmr-zusd".to_string(),
                covered_market_id: "xmr-zusd-confidential".to_string(),
                liquidity_commitment: devnet_hash("backstop-liquidity", "xmr-zusd"),
                cover_bps: self.config.liquidation_backstop_cover_bps,
                keeper_set_root: devnet_hash("keeper-set", "devnet"),
                emergency_lane_enabled: true,
            },
        );
        self.pq_attestations.insert(
            "attest-devnet-solver-0".to_string(),
            PqSolverAttestation {
                attestation_id: "attest-devnet-solver-0".to_string(),
                solver_id: "devnet-solver-0".to_string(),
                pq_signature_root: devnet_hash("pq-sig", "solver-0"),
                transcript_root: devnet_hash("pq-transcript", "solver-0"),
                security_bits: self.config.min_pq_security_bits,
                valid_from_height: DEVNET_L2_HEIGHT,
                valid_until_height: DEVNET_L2_HEIGHT + 512,
            },
        );
        self.privacy_redactions.insert(
            "redaction-defi-intent-public".to_string(),
            PrivacyRedactionRoot {
                redaction_id: "redaction-defi-intent-public".to_string(),
                scope: "operator_safe_public_summary".to_string(),
                disclosed_fields: ["lane", "market_id", "fee_bps", "privacy_set_size"]
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
                redacted_payload_root: devnet_hash("redacted-payload", "operator-summary"),
                operator_summary_root: devnet_hash("operator-summary", "public"),
            },
        );
        let bond = SolverBond {
            solver_id: "devnet-solver-0".to_string(),
            bond_id: "bond-devnet-solver-0".to_string(),
            locked_micro_units: self.config.solver_bond_micro_units.saturating_mul(2),
            slashed_micro_units: 0,
            markets: ["xmr-zusd-confidential".to_string()].into_iter().collect(),
            pq_public_key_root: devnet_hash("pq-pk", "solver-0"),
            status: RecordStatus::Open,
        };
        self.lock_solver_bond(bond).expect("devnet solver bond");
        self.counters.backstop_liquidity_micro_units = 500_000_000;
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn deterministic_intent_request(
    label: &str,
    intent_kind: IntentKind,
    lane: AuctionLane,
) -> EncryptedDefiIntentRequest {
    let seed = domain_hash(
        "CONFIDENTIAL-DEFI-INTENT-DEVNET-SEED",
        &[HashPart::Str(label), HashPart::U64(DEVNET_L2_HEIGHT)],
        32,
    );
    EncryptedDefiIntentRequest {
        owner_commitment: devnet_hash("owner", &seed),
        intent_kind,
        lane,
        market_id: "xmr-zusd-confidential".to_string(),
        encrypted_payload_root: devnet_hash("encrypted-payload", &seed),
        amount_commitment: devnet_hash("amount", &seed),
        limit_price_commitment: devnet_hash("limit-price", &seed),
        max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
        route_covenant_id: "covenant-xmr-zusd-low-fee".to_string(),
        cross_margin_account_root: devnet_hash("margin-account", "vault-0"),
        nullifier_commitment: devnet_hash("nullifier", &seed),
        privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
        pq_ciphertext_root: devnet_hash("pq-ciphertext", &seed),
        proof_root: devnet_hash("zk-proof", &seed),
        submitted_height: DEVNET_L2_HEIGHT,
        expires_height: DEVNET_L2_HEIGHT + DEFAULT_AUCTION_TTL_BLOCKS,
    }
}

pub fn public_record_root(record: &Value) -> String {
    record_root("PUBLIC-RECORD", record)
}

fn state_root_from_record(record: &Value) -> String {
    record_root("STATE", record)
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-DEFI-INTENT-RISK-AUCTION-RECORD",
        &[HashPart::Str(domain), HashPart::Json(record)],
        32,
    )
}

fn record_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

fn empty_root(domain: &str) -> String {
    let leaf = domain_hash(domain, &[HashPart::Str("empty")], 32);
    let leaves = vec![json!(leaf)];
    merkle_root(
        "PRIVATE-L2-PQ-CONFIDENTIAL-DEFI-INTENT-RISK-AUCTION-EMPTY",
        &leaves,
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    if map.is_empty() {
        return empty_root(domain);
    }
    let leaves = map
        .iter()
        .map(|(key, value)| {
            record_root(
                domain,
                &json!({
                    "key": key,
                    "record": public_record(value),
                }),
            )
        })
        .map(Value::String)
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn devnet_hash(domain: &str, label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-DEFI-INTENT-RISK-AUCTION-DEVNET",
        &[HashPart::Str(domain), HashPart::Str(label)],
        32,
    )
}

fn ensure_bps(field: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{field} must be <= {MAX_BPS}"))
    } else {
        Ok(())
    }
}

fn ensure_capacity(label: &str, len: usize, max: usize) -> Result<()> {
    if len >= max {
        Err(format!("{label} capacity {max} exhausted"))
    } else {
        Ok(())
    }
}

fn ensure_absent<T>(label: &str, map: &BTreeMap<String, T>, id: &str) -> Result<()> {
    if map.contains_key(id) {
        Err(format!("{label} id {id} already exists"))
    } else {
        Ok(())
    }
}
