use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedMinerRevenueForwardRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_MINER_REVENUE_FORWARD_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-tokenized-miner-revenue-forward-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_MINER_REVENUE_FORWARD_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ORACLE_SUITE: &str = "ml-dsa-87+slh-dsa-shake-256f-miner-revenue-oracle-committee-v1";
pub const CONFIDENTIAL_BOOK_SUITE: &str =
    "ml-kem-1024-sealed-tokenized-miner-revenue-forward-book-v1";
pub const FORWARD_TOKEN_SUITE: &str = "confidential-fungible-miner-revenue-forward-token-v1";
pub const SETTLEMENT_SUITE: &str =
    "low-fee-monero-l2-confidential-miner-revenue-forward-settlement-v1";
pub const OPERATOR_SUMMARY_SUITE: &str = "redacted-operator-safe-miner-revenue-forward-summary-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_HEIGHT: u64 = 822_400;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_790_000;
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_COLLATERAL_ASSET_ID: &str = "xmr-revenue-escrow-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_ORACLE_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_SUPERMAJORITY_BPS: u64 = 8_000;
pub const DEFAULT_INITIAL_MARGIN_BPS: u64 = 2_500;
pub const DEFAULT_MAINTENANCE_MARGIN_BPS: u64 = 1_500;
pub const DEFAULT_LIQUIDATION_BUFFER_BPS: u64 = 500;
pub const DEFAULT_MAX_FORWARD_LEVERAGE_BPS: u64 = 4_000;
pub const DEFAULT_MAX_SETTLEMENT_FEE_BPS: u64 = 8;
pub const DEFAULT_REBATE_BPS: u64 = 6;
pub const DEFAULT_REDACTION_BUDGET_UNITS: u64 = 128;
pub const DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_REVENUE_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_BOOKS: usize = 262_144;
pub const DEFAULT_MAX_COHORTS: usize = 262_144;
pub const DEFAULT_MAX_FORWARD_TOKENS: usize = 524_288;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 1_048_576;
pub const DEFAULT_MAX_SETTLEMENT_WINDOWS: usize = 262_144;
pub const DEFAULT_MAX_REBATES: usize = 524_288;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 262_144;
pub const DEFAULT_MAX_OPERATOR_SUMMARIES: usize = 262_144;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevenueBookKind {
    BlockSubsidy,
    TransactionFees,
    MergedMining,
    PoolPayout,
    HashrateLease,
    BlendedForward,
}

impl RevenueBookKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BlockSubsidy => "block_subsidy",
            Self::TransactionFees => "transaction_fees",
            Self::MergedMining => "merged_mining",
            Self::PoolPayout => "pool_payout",
            Self::HashrateLease => "hashrate_lease",
            Self::BlendedForward => "blended_forward",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BookStatus {
    Draft,
    Open,
    Matching,
    Paused,
    Settling,
    Settled,
    Retired,
}

impl BookStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Open => "open",
            Self::Matching => "matching",
            Self::Paused => "paused",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_orders(self) -> bool {
        matches!(self, Self::Open | Self::Matching)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortStatus {
    Forming,
    Active,
    Watchlisted,
    MarginRestricted,
    Settling,
    Retired,
}

impl CohortStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Forming => "forming",
            Self::Active => "active",
            Self::Watchlisted => "watchlisted",
            Self::MarginRestricted => "margin_restricted",
            Self::Settling => "settling",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardSide {
    MinerShortRevenue,
    InvestorLongRevenue,
    LiquidityBackstop,
    SponsorRebate,
}

impl ForwardSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MinerShortRevenue => "miner_short_revenue",
            Self::InvestorLongRevenue => "investor_long_revenue",
            Self::LiquidityBackstop => "liquidity_backstop",
            Self::SponsorRebate => "sponsor_rebate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenStatus {
    Minted,
    Trading,
    MarginCalled,
    Frozen,
    Redeemed,
    Liquidated,
    Cancelled,
}

impl TokenStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Minted => "minted",
            Self::Trading => "trading",
            Self::MarginCalled => "margin_called",
            Self::Frozen => "frozen",
            Self::Redeemed => "redeemed",
            Self::Liquidated => "liquidated",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    Hashrate,
    PoolPayout,
    FeeIndex,
    BlockReward,
    CollateralProof,
    SettlementPrice,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hashrate => "hashrate",
            Self::PoolPayout => "pool_payout",
            Self::FeeIndex => "fee_index",
            Self::BlockReward => "block_reward",
            Self::CollateralProof => "collateral_proof",
            Self::SettlementPrice => "settlement_price",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowStatus {
    Scheduled,
    Open,
    Locked,
    Settling,
    Finalized,
    Disputed,
    Cancelled,
}

impl WindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Open => "open",
            Self::Locked => "locked",
            Self::Settling => "settling",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Cancelled => "cancelled",
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
    pub fee_asset_id: String,
    pub collateral_asset_id: String,
    pub hash_suite: String,
    pub pq_oracle_suite: String,
    pub confidential_book_suite: String,
    pub forward_token_suite: String,
    pub settlement_suite: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub oracle_quorum_bps: u64,
    pub supermajority_bps: u64,
    pub initial_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub liquidation_buffer_bps: u64,
    pub max_forward_leverage_bps: u64,
    pub max_settlement_fee_bps: u64,
    pub default_rebate_bps: u64,
    pub default_redaction_budget_units: u64,
    pub settlement_window_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub revenue_epoch_blocks: u64,
    pub max_books: usize,
    pub max_cohorts: usize,
    pub max_forward_tokens: usize,
    pub max_attestations: usize,
    pub max_settlement_windows: usize,
    pub max_rebates: usize,
    pub max_redaction_budgets: usize,
    pub max_operator_summaries: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            collateral_asset_id: DEVNET_COLLATERAL_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_oracle_suite: PQ_ORACLE_SUITE.to_string(),
            confidential_book_suite: CONFIDENTIAL_BOOK_SUITE.to_string(),
            forward_token_suite: FORWARD_TOKEN_SUITE.to_string(),
            settlement_suite: SETTLEMENT_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            oracle_quorum_bps: DEFAULT_ORACLE_QUORUM_BPS,
            supermajority_bps: DEFAULT_SUPERMAJORITY_BPS,
            initial_margin_bps: DEFAULT_INITIAL_MARGIN_BPS,
            maintenance_margin_bps: DEFAULT_MAINTENANCE_MARGIN_BPS,
            liquidation_buffer_bps: DEFAULT_LIQUIDATION_BUFFER_BPS,
            max_forward_leverage_bps: DEFAULT_MAX_FORWARD_LEVERAGE_BPS,
            max_settlement_fee_bps: DEFAULT_MAX_SETTLEMENT_FEE_BPS,
            default_rebate_bps: DEFAULT_REBATE_BPS,
            default_redaction_budget_units: DEFAULT_REDACTION_BUDGET_UNITS,
            settlement_window_blocks: DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            revenue_epoch_blocks: DEFAULT_REVENUE_EPOCH_BLOCKS,
            max_books: DEFAULT_MAX_BOOKS,
            max_cohorts: DEFAULT_MAX_COHORTS,
            max_forward_tokens: DEFAULT_MAX_FORWARD_TOKENS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_settlement_windows: DEFAULT_MAX_SETTLEMENT_WINDOWS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
            max_operator_summaries: DEFAULT_MAX_OPERATOR_SUMMARIES,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_book_index: u64,
    pub next_cohort_index: u64,
    pub next_token_index: u64,
    pub next_attestation_index: u64,
    pub next_settlement_window_index: u64,
    pub next_rebate_index: u64,
    pub next_redaction_budget_index: u64,
    pub next_operator_summary_index: u64,
    pub total_notional_micro_xmr: u128,
    pub total_collateral_micro_units: u128,
    pub total_settled_micro_xmr: u128,
    pub total_rebated_micro_units: u128,
    pub total_operator_summaries: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub book_root: String,
    pub cohort_root: String,
    pub forward_token_root: String,
    pub pq_attestation_root: String,
    pub settlement_window_root: String,
    pub rebate_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub counters_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RevenueBook {
    pub book_id: String,
    pub kind: RevenueBookKind,
    pub status: BookStatus,
    pub miner_cohort_id: String,
    pub sealed_bid_root: String,
    pub sealed_ask_root: String,
    pub encrypted_orderflow_root: String,
    pub commitment_root: String,
    pub quote_asset_id: String,
    pub revenue_asset_id: String,
    pub maturity_height: u64,
    pub min_notional_micro_xmr: u64,
    pub max_notional_micro_xmr: u64,
    pub matched_notional_micro_xmr: u64,
    pub fee_cap_bps: u64,
    pub privacy_set_size: u64,
}

impl RevenueBook {
    pub fn public_record(&self) -> Value {
        json!({
            "book_id": self.book_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "miner_cohort_id": self.miner_cohort_id,
            "sealed_bid_root": self.sealed_bid_root,
            "sealed_ask_root": self.sealed_ask_root,
            "encrypted_orderflow_root": self.encrypted_orderflow_root,
            "commitment_root": self.commitment_root,
            "quote_asset_id": self.quote_asset_id,
            "revenue_asset_id": self.revenue_asset_id,
            "maturity_height": self.maturity_height,
            "min_notional_micro_xmr": self.min_notional_micro_xmr,
            "max_notional_micro_xmr": self.max_notional_micro_xmr,
            "matched_notional_micro_xmr": self.matched_notional_micro_xmr,
            "fee_cap_bps": self.fee_cap_bps,
            "privacy_set_size": self.privacy_set_size,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MinerCohort {
    pub cohort_id: String,
    pub status: CohortStatus,
    pub operator_commitment: String,
    pub pool_commitment: String,
    pub payout_address_commitment_root: String,
    pub hashrate_commitment_root: String,
    pub hardware_class_commitment_root: String,
    pub jurisdiction_commitment_root: String,
    pub min_observed_hashrate_hps: u64,
    pub committed_hashrate_hps: u64,
    pub revenue_share_bps: u64,
    pub collateral_commitment: String,
    pub collateral_micro_units: u64,
    pub risk_score_bps: u64,
    pub formed_at_height: u64,
}

impl MinerCohort {
    pub fn public_record(&self) -> Value {
        json!({
            "cohort_id": self.cohort_id,
            "status": self.status.as_str(),
            "operator_commitment": self.operator_commitment,
            "pool_commitment": self.pool_commitment,
            "payout_address_commitment_root": self.payout_address_commitment_root,
            "hashrate_commitment_root": self.hashrate_commitment_root,
            "hardware_class_commitment_root": self.hardware_class_commitment_root,
            "jurisdiction_commitment_root": self.jurisdiction_commitment_root,
            "min_observed_hashrate_hps": self.min_observed_hashrate_hps,
            "committed_hashrate_hps": self.committed_hashrate_hps,
            "revenue_share_bps": self.revenue_share_bps,
            "collateral_commitment": self.collateral_commitment,
            "collateral_micro_units": self.collateral_micro_units,
            "risk_score_bps": self.risk_score_bps,
            "formed_at_height": self.formed_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ForwardToken {
    pub token_id: String,
    pub book_id: String,
    pub cohort_id: String,
    pub owner_commitment: String,
    pub side: ForwardSide,
    pub status: TokenStatus,
    pub notional_micro_xmr: u64,
    pub strike_revenue_micro_xmr: u64,
    pub collateral_commitment: String,
    pub collateral_micro_units: u64,
    pub minted_at_height: u64,
    pub maturity_height: u64,
    pub nullifier_root: String,
    pub transfer_commitment_root: String,
}

impl ForwardToken {
    pub fn margin_bps(&self) -> u64 {
        if self.notional_micro_xmr == 0 {
            0
        } else {
            self.collateral_micro_units
                .saturating_mul(MAX_BPS)
                .saturating_div(self.notional_micro_xmr)
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "token_id": self.token_id,
            "book_id": self.book_id,
            "cohort_id": self.cohort_id,
            "owner_commitment": self.owner_commitment,
            "side": self.side.as_str(),
            "status": self.status.as_str(),
            "notional_micro_xmr": self.notional_micro_xmr,
            "strike_revenue_micro_xmr": self.strike_revenue_micro_xmr,
            "collateral_commitment": self.collateral_commitment,
            "collateral_micro_units": self.collateral_micro_units,
            "margin_bps": self.margin_bps(),
            "minted_at_height": self.minted_at_height,
            "maturity_height": self.maturity_height,
            "nullifier_root": self.nullifier_root,
            "transfer_commitment_root": self.transfer_commitment_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestation {
    pub attestation_id: String,
    pub kind: AttestationKind,
    pub committee_id: String,
    pub subject_id: String,
    pub subject_root: String,
    pub oracle_payload_root: String,
    pub signature_root: String,
    pub signer_bitmap_root: String,
    pub quorum_weight_bps: u64,
    pub pq_security_bits: u16,
    pub observed_height: u64,
    pub expires_at_height: u64,
}

impl PqAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "kind": self.kind.as_str(),
            "committee_id": self.committee_id,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "oracle_payload_root": self.oracle_payload_root,
            "signature_root": self.signature_root,
            "signer_bitmap_root": self.signer_bitmap_root,
            "quorum_weight_bps": self.quorum_weight_bps,
            "pq_security_bits": self.pq_security_bits,
            "observed_height": self.observed_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementWindow {
    pub settlement_window_id: String,
    pub book_id: String,
    pub status: WindowStatus,
    pub opens_at_height: u64,
    pub locks_at_height: u64,
    pub settles_at_height: u64,
    pub settlement_price_root: String,
    pub revenue_observation_root: String,
    pub eligible_token_root: String,
    pub payout_commitment_root: String,
    pub fee_micro_units: u64,
    pub fee_bps: u64,
}

impl SettlementWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_window_id": self.settlement_window_id,
            "book_id": self.book_id,
            "status": self.status.as_str(),
            "opens_at_height": self.opens_at_height,
            "locks_at_height": self.locks_at_height,
            "settles_at_height": self.settles_at_height,
            "settlement_price_root": self.settlement_price_root,
            "revenue_observation_root": self.revenue_observation_root,
            "eligible_token_root": self.eligible_token_root,
            "payout_commitment_root": self.payout_commitment_root,
            "fee_micro_units": self.fee_micro_units,
            "fee_bps": self.fee_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Rebate {
    pub rebate_id: String,
    pub settlement_window_id: String,
    pub token_id: String,
    pub beneficiary_commitment: String,
    pub rebate_bps: u64,
    pub rebate_micro_units: u64,
    pub sponsor_commitment: String,
    pub issued_at_height: u64,
    pub claim_nullifier_root: String,
}

impl Rebate {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub redaction_budget_id: String,
    pub operator_commitment: String,
    pub subject_root: String,
    pub remaining_units: u64,
    pub max_units: u64,
    pub public_summary_floor: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl RedactionBudget {
    pub fn consume(&mut self, units: u64) -> Result<()> {
        if self.remaining_units < units {
            return Err("redaction budget exhausted".to_string());
        }
        self.remaining_units -= units;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub operator_summary_id: String,
    pub operator_commitment: String,
    pub summary_epoch: u64,
    pub redaction_budget_id: String,
    pub book_count: u64,
    pub active_cohort_count: u64,
    pub token_count_bucket: String,
    pub notional_bucket_micro_xmr: String,
    pub collateral_bucket_micro_units: String,
    pub avg_margin_bucket_bps: String,
    pub risk_band: String,
    pub open_settlement_windows: u64,
    pub paused_book_count: u64,
    pub summary_root: String,
    pub published_at_height: u64,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub revenue_books: BTreeMap<String, RevenueBook>,
    pub miner_cohorts: BTreeMap<String, MinerCohort>,
    pub forward_tokens: BTreeMap<String, ForwardToken>,
    pub pq_attestations: BTreeMap<String, PqAttestation>,
    pub settlement_windows: BTreeMap<String, SettlementWindow>,
    pub rebates: BTreeMap<String, Rebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            counters: Counters::default(),
            revenue_books: BTreeMap::new(),
            miner_cohorts: BTreeMap::new(),
            forward_tokens: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            settlement_windows: BTreeMap::new(),
            rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::default());
        state.seed_devnet();
        state
    }

    pub fn demo() -> Self {
        Self::devnet()
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: value_root("config", &self.config.public_record()),
            book_root: map_root(
                "revenue-books",
                &self.revenue_books,
                RevenueBook::public_record,
            ),
            cohort_root: map_root(
                "miner-cohorts",
                &self.miner_cohorts,
                MinerCohort::public_record,
            ),
            forward_token_root: map_root(
                "forward-tokens",
                &self.forward_tokens,
                ForwardToken::public_record,
            ),
            pq_attestation_root: map_root(
                "pq-attestations",
                &self.pq_attestations,
                PqAttestation::public_record,
            ),
            settlement_window_root: map_root(
                "settlement-windows",
                &self.settlement_windows,
                SettlementWindow::public_record,
            ),
            rebate_root: map_root("rebates", &self.rebates, Rebate::public_record),
            redaction_budget_root: map_root(
                "redaction-budgets",
                &self.redaction_budgets,
                RedactionBudget::public_record,
            ),
            operator_summary_root: map_root(
                "operator-summaries",
                &self.operator_summaries,
                OperatorSummary::public_record,
            ),
            counters_root: value_root("counters", &self.counters.public_record()),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
            "revenue_books": public_map(&self.revenue_books, RevenueBook::public_record),
            "miner_cohorts": public_map(&self.miner_cohorts, MinerCohort::public_record),
            "forward_tokens": public_map(&self.forward_tokens, ForwardToken::public_record),
            "pq_attestations": public_map(&self.pq_attestations, PqAttestation::public_record),
            "settlement_windows": public_map(&self.settlement_windows, SettlementWindow::public_record),
            "rebates": public_map(&self.rebates, Rebate::public_record),
            "redaction_budgets": public_map(&self.redaction_budgets, RedactionBudget::public_record),
            "operator_summaries": public_map(&self.operator_summaries, OperatorSummary::public_record),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(values) = &mut record {
            values.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        value_root("state", &self.public_record_without_state_root())
    }

    pub fn register_miner_cohort(&mut self, mut cohort: MinerCohort) -> Result<String> {
        ensure_capacity(
            self.miner_cohorts.len(),
            self.config.max_cohorts,
            "miner cohorts",
        )?;
        ensure_non_empty(&cohort.operator_commitment, "operator commitment")?;
        ensure_non_empty(&cohort.collateral_commitment, "collateral commitment")?;
        ensure_bps(cohort.revenue_share_bps, "revenue share")?;
        ensure_bps(cohort.risk_score_bps, "risk score")?;
        ensure_min(
            cohort.collateral_micro_units,
            required_margin(
                cohort.committed_hashrate_hps,
                self.config.initial_margin_bps,
            ),
            "cohort collateral",
        )?;
        if cohort.cohort_id.trim().is_empty() {
            cohort.cohort_id = prefixed(
                "cohort",
                "cohort-id",
                &[
                    HashPart::Str(&cohort.operator_commitment),
                    HashPart::Str(&cohort.pool_commitment),
                    HashPart::U64(self.counters.next_cohort_index),
                ],
            );
        }
        let cohort_id = cohort.cohort_id.clone();
        self.counters.next_cohort_index = self.counters.next_cohort_index.saturating_add(1);
        self.counters.total_collateral_micro_units = self
            .counters
            .total_collateral_micro_units
            .saturating_add(cohort.collateral_micro_units as u128);
        self.miner_cohorts.insert(cohort_id.clone(), cohort);
        Ok(cohort_id)
    }

    pub fn open_revenue_book(&mut self, mut book: RevenueBook) -> Result<String> {
        ensure_capacity(
            self.revenue_books.len(),
            self.config.max_books,
            "revenue books",
        )?;
        ensure_non_empty(&book.miner_cohort_id, "miner cohort id")?;
        ensure_bps(book.fee_cap_bps, "book fee cap")?;
        ensure_min(
            book.privacy_set_size,
            self.config.min_privacy_set_size,
            "privacy set",
        )?;
        if !self.miner_cohorts.contains_key(&book.miner_cohort_id) {
            return Err("miner cohort missing for revenue book".to_string());
        }
        if book.max_notional_micro_xmr < book.min_notional_micro_xmr {
            return Err("book max notional below min notional".to_string());
        }
        if book.book_id.trim().is_empty() {
            book.book_id = prefixed(
                "book",
                "book-id",
                &[
                    HashPart::Str(book.kind.as_str()),
                    HashPart::Str(&book.miner_cohort_id),
                    HashPart::U64(book.maturity_height),
                    HashPart::U64(self.counters.next_book_index),
                ],
            );
        }
        let book_id = book.book_id.clone();
        self.counters.next_book_index = self.counters.next_book_index.saturating_add(1);
        self.revenue_books.insert(book_id.clone(), book);
        Ok(book_id)
    }

    pub fn mint_forward_token(&mut self, mut token: ForwardToken) -> Result<String> {
        ensure_capacity(
            self.forward_tokens.len(),
            self.config.max_forward_tokens,
            "forward tokens",
        )?;
        ensure_non_empty(&token.book_id, "token book id")?;
        ensure_non_empty(&token.owner_commitment, "token owner commitment")?;
        ensure_min(token.notional_micro_xmr, 1, "token notional")?;
        let book = self
            .revenue_books
            .get_mut(&token.book_id)
            .ok_or_else(|| "book missing for forward token".to_string())?;
        if !book.status.accepts_orders() {
            return Err("book is not accepting forward tokens".to_string());
        }
        if token.cohort_id != book.miner_cohort_id {
            return Err("forward token cohort does not match book".to_string());
        }
        ensure_min(
            token.margin_bps(),
            self.config.initial_margin_bps,
            "forward token margin",
        )?;
        let projected = book
            .matched_notional_micro_xmr
            .saturating_add(token.notional_micro_xmr);
        if projected > book.max_notional_micro_xmr {
            return Err("book notional capacity exceeded".to_string());
        }
        if token.token_id.trim().is_empty() {
            token.token_id = prefixed(
                "fwd",
                "forward-token-id",
                &[
                    HashPart::Str(&token.book_id),
                    HashPart::Str(&token.owner_commitment),
                    HashPart::Str(token.side.as_str()),
                    HashPart::U64(self.counters.next_token_index),
                ],
            );
        }
        let token_id = token.token_id.clone();
        book.matched_notional_micro_xmr = projected;
        self.counters.next_token_index = self.counters.next_token_index.saturating_add(1);
        self.counters.total_notional_micro_xmr = self
            .counters
            .total_notional_micro_xmr
            .saturating_add(token.notional_micro_xmr as u128);
        self.counters.total_collateral_micro_units = self
            .counters
            .total_collateral_micro_units
            .saturating_add(token.collateral_micro_units as u128);
        self.forward_tokens.insert(token_id.clone(), token);
        Ok(token_id)
    }

    pub fn record_pq_attestation(&mut self, mut attestation: PqAttestation) -> Result<String> {
        ensure_capacity(
            self.pq_attestations.len(),
            self.config.max_attestations,
            "pq attestations",
        )?;
        ensure_non_empty(&attestation.committee_id, "committee id")?;
        ensure_bps(attestation.quorum_weight_bps, "attestation quorum")?;
        ensure_min(
            attestation.quorum_weight_bps,
            self.config.oracle_quorum_bps,
            "attestation quorum",
        )?;
        if attestation.pq_security_bits < self.config.min_pq_security_bits {
            return Err("attestation below minimum pq security bits".to_string());
        }
        if attestation.attestation_id.trim().is_empty() {
            attestation.attestation_id = prefixed(
                "att",
                "attestation-id",
                &[
                    HashPart::Str(attestation.kind.as_str()),
                    HashPart::Str(&attestation.subject_id),
                    HashPart::Str(&attestation.subject_root),
                    HashPart::U64(self.counters.next_attestation_index),
                ],
            );
        }
        let attestation_id = attestation.attestation_id.clone();
        self.counters.next_attestation_index =
            self.counters.next_attestation_index.saturating_add(1);
        self.pq_attestations
            .insert(attestation_id.clone(), attestation);
        Ok(attestation_id)
    }

    pub fn schedule_settlement_window(&mut self, mut window: SettlementWindow) -> Result<String> {
        ensure_capacity(
            self.settlement_windows.len(),
            self.config.max_settlement_windows,
            "settlement windows",
        )?;
        ensure_bps(window.fee_bps, "settlement fee")?;
        if window.fee_bps > self.config.max_settlement_fee_bps {
            return Err("settlement fee exceeds configured low-fee cap".to_string());
        }
        if !self.revenue_books.contains_key(&window.book_id) {
            return Err("settlement window book missing".to_string());
        }
        if window.opens_at_height > window.locks_at_height
            || window.locks_at_height > window.settles_at_height
        {
            return Err("settlement window heights are not ordered".to_string());
        }
        if window.settlement_window_id.trim().is_empty() {
            window.settlement_window_id = prefixed(
                "settle",
                "settlement-window-id",
                &[
                    HashPart::Str(&window.book_id),
                    HashPart::U64(window.opens_at_height),
                    HashPart::U64(window.settles_at_height),
                    HashPart::U64(self.counters.next_settlement_window_index),
                ],
            );
        }
        let window_id = window.settlement_window_id.clone();
        self.counters.next_settlement_window_index =
            self.counters.next_settlement_window_index.saturating_add(1);
        self.settlement_windows.insert(window_id.clone(), window);
        Ok(window_id)
    }

    pub fn issue_rebate(&mut self, mut rebate: Rebate) -> Result<String> {
        ensure_capacity(self.rebates.len(), self.config.max_rebates, "rebates")?;
        ensure_bps(rebate.rebate_bps, "rebate bps")?;
        if !self
            .settlement_windows
            .contains_key(&rebate.settlement_window_id)
        {
            return Err("rebate settlement window missing".to_string());
        }
        if !self.forward_tokens.contains_key(&rebate.token_id) {
            return Err("rebate forward token missing".to_string());
        }
        if rebate.rebate_id.trim().is_empty() {
            rebate.rebate_id = prefixed(
                "rebate",
                "rebate-id",
                &[
                    HashPart::Str(&rebate.settlement_window_id),
                    HashPart::Str(&rebate.token_id),
                    HashPart::Str(&rebate.beneficiary_commitment),
                    HashPart::U64(self.counters.next_rebate_index),
                ],
            );
        }
        let rebate_id = rebate.rebate_id.clone();
        self.counters.next_rebate_index = self.counters.next_rebate_index.saturating_add(1);
        self.counters.total_rebated_micro_units = self
            .counters
            .total_rebated_micro_units
            .saturating_add(rebate.rebate_micro_units as u128);
        self.rebates.insert(rebate_id.clone(), rebate);
        Ok(rebate_id)
    }

    pub fn open_redaction_budget(&mut self, mut budget: RedactionBudget) -> Result<String> {
        ensure_capacity(
            self.redaction_budgets.len(),
            self.config.max_redaction_budgets,
            "redaction budgets",
        )?;
        ensure_non_empty(&budget.operator_commitment, "redaction operator commitment")?;
        if budget.remaining_units > budget.max_units {
            return Err("redaction budget remaining exceeds max".to_string());
        }
        if budget.redaction_budget_id.trim().is_empty() {
            budget.redaction_budget_id = prefixed(
                "redact",
                "redaction-budget-id",
                &[
                    HashPart::Str(&budget.operator_commitment),
                    HashPart::Str(&budget.subject_root),
                    HashPart::U64(self.counters.next_redaction_budget_index),
                ],
            );
        }
        let budget_id = budget.redaction_budget_id.clone();
        self.counters.next_redaction_budget_index =
            self.counters.next_redaction_budget_index.saturating_add(1);
        self.redaction_budgets.insert(budget_id.clone(), budget);
        Ok(budget_id)
    }

    pub fn publish_operator_summary(&mut self, mut summary: OperatorSummary) -> Result<String> {
        ensure_capacity(
            self.operator_summaries.len(),
            self.config.max_operator_summaries,
            "operator summaries",
        )?;
        let budget = self
            .redaction_budgets
            .get_mut(&summary.redaction_budget_id)
            .ok_or_else(|| "operator summary redaction budget missing".to_string())?;
        budget.consume(1)?;
        if summary.operator_summary_id.trim().is_empty() {
            summary.operator_summary_id = prefixed(
                "ops",
                "operator-summary-id",
                &[
                    HashPart::Str(&summary.operator_commitment),
                    HashPart::U64(summary.summary_epoch),
                    HashPart::Str(&summary.summary_root),
                    HashPart::U64(self.counters.next_operator_summary_index),
                ],
            );
        }
        let summary_id = summary.operator_summary_id.clone();
        self.counters.next_operator_summary_index =
            self.counters.next_operator_summary_index.saturating_add(1);
        self.counters.total_operator_summaries =
            self.counters.total_operator_summaries.saturating_add(1);
        self.operator_summaries.insert(summary_id.clone(), summary);
        Ok(summary_id)
    }

    pub fn mark_margin_call(&mut self, token_id: &str) -> Result<()> {
        let token = self
            .forward_tokens
            .get_mut(token_id)
            .ok_or_else(|| "forward token missing for margin call".to_string())?;
        if token.margin_bps() >= self.config.maintenance_margin_bps {
            return Err("forward token remains above maintenance margin".to_string());
        }
        token.status = TokenStatus::MarginCalled;
        Ok(())
    }

    fn seed_devnet(&mut self) {
        let cohort_id = self
            .register_miner_cohort(MinerCohort {
                cohort_id: String::new(),
                status: CohortStatus::Active,
                operator_commitment: "devnet-miner-operator-commitment-a".to_string(),
                pool_commitment: "devnet-pool-commitment-a".to_string(),
                payout_address_commitment_root: "devnet-payout-address-root-a".to_string(),
                hashrate_commitment_root: "devnet-hashrate-root-a".to_string(),
                hardware_class_commitment_root: "devnet-hardware-class-root-a".to_string(),
                jurisdiction_commitment_root: "devnet-jurisdiction-root-a".to_string(),
                min_observed_hashrate_hps: 4_200_000_000_000,
                committed_hashrate_hps: 5_000_000_000_000,
                revenue_share_bps: 8_500,
                collateral_commitment: "devnet-cohort-collateral-commitment-a".to_string(),
                collateral_micro_units: 2_000_000_000,
                risk_score_bps: 1_250,
                formed_at_height: DEVNET_HEIGHT,
            })
            .expect("devnet cohort");
        let book_id = self
            .open_revenue_book(RevenueBook {
                book_id: String::new(),
                kind: RevenueBookKind::BlendedForward,
                status: BookStatus::Open,
                miner_cohort_id: cohort_id.clone(),
                sealed_bid_root: "devnet-sealed-bid-root-a".to_string(),
                sealed_ask_root: "devnet-sealed-ask-root-a".to_string(),
                encrypted_orderflow_root: "devnet-encrypted-orderflow-root-a".to_string(),
                commitment_root: "devnet-book-commitment-root-a".to_string(),
                quote_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
                revenue_asset_id: "monero-miner-revenue-forward-devnet".to_string(),
                maturity_height: DEVNET_HEIGHT + DEFAULT_REVENUE_EPOCH_BLOCKS,
                min_notional_micro_xmr: 10_000_000,
                max_notional_micro_xmr: 500_000_000,
                matched_notional_micro_xmr: 0,
                fee_cap_bps: DEFAULT_MAX_SETTLEMENT_FEE_BPS,
                privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE * 2,
            })
            .expect("devnet revenue book");
        let token_id = self
            .mint_forward_token(ForwardToken {
                token_id: String::new(),
                book_id: book_id.clone(),
                cohort_id: cohort_id.clone(),
                owner_commitment: "devnet-investor-owner-commitment-a".to_string(),
                side: ForwardSide::InvestorLongRevenue,
                status: TokenStatus::Trading,
                notional_micro_xmr: 100_000_000,
                strike_revenue_micro_xmr: 102_500_000,
                collateral_commitment: "devnet-token-collateral-commitment-a".to_string(),
                collateral_micro_units: 30_000_000,
                minted_at_height: DEVNET_HEIGHT + 2,
                maturity_height: DEVNET_HEIGHT + DEFAULT_REVENUE_EPOCH_BLOCKS,
                nullifier_root: "devnet-token-nullifier-root-a".to_string(),
                transfer_commitment_root: "devnet-token-transfer-root-a".to_string(),
            })
            .expect("devnet forward token");
        let _ = self.record_pq_attestation(PqAttestation {
            attestation_id: String::new(),
            kind: AttestationKind::Hashrate,
            committee_id: "devnet-pq-miner-oracle-committee-a".to_string(),
            subject_id: cohort_id.clone(),
            subject_root: value_root(
                "devnet-cohort-subject",
                &self.miner_cohorts[&cohort_id].public_record(),
            ),
            oracle_payload_root: "devnet-hashrate-oracle-payload-root-a".to_string(),
            signature_root: "devnet-pq-signature-root-a".to_string(),
            signer_bitmap_root: "devnet-signer-bitmap-root-a".to_string(),
            quorum_weight_bps: DEFAULT_SUPERMAJORITY_BPS,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            observed_height: DEVNET_HEIGHT + 4,
            expires_at_height: DEVNET_HEIGHT + DEFAULT_ATTESTATION_TTL_BLOCKS,
        });
        let window_id = self
            .schedule_settlement_window(SettlementWindow {
                settlement_window_id: String::new(),
                book_id: book_id.clone(),
                status: WindowStatus::Open,
                opens_at_height: DEVNET_HEIGHT + DEFAULT_REVENUE_EPOCH_BLOCKS,
                locks_at_height: DEVNET_HEIGHT + DEFAULT_REVENUE_EPOCH_BLOCKS + 36,
                settles_at_height: DEVNET_HEIGHT + DEFAULT_REVENUE_EPOCH_BLOCKS + 72,
                settlement_price_root: "devnet-settlement-price-root-a".to_string(),
                revenue_observation_root: "devnet-revenue-observation-root-a".to_string(),
                eligible_token_root: "devnet-eligible-token-root-a".to_string(),
                payout_commitment_root: "devnet-payout-commitment-root-a".to_string(),
                fee_micro_units: 75_000,
                fee_bps: DEFAULT_MAX_SETTLEMENT_FEE_BPS,
            })
            .expect("devnet settlement window");
        let _ = self.issue_rebate(Rebate {
            rebate_id: String::new(),
            settlement_window_id: window_id.clone(),
            token_id,
            beneficiary_commitment: "devnet-rebate-beneficiary-commitment-a".to_string(),
            rebate_bps: DEFAULT_REBATE_BPS,
            rebate_micro_units: 4_500,
            sponsor_commitment: "devnet-sponsor-commitment-a".to_string(),
            issued_at_height: DEVNET_HEIGHT + DEFAULT_REVENUE_EPOCH_BLOCKS + 80,
            claim_nullifier_root: "devnet-rebate-claim-nullifier-root-a".to_string(),
        });
        let budget_id = self
            .open_redaction_budget(RedactionBudget {
                redaction_budget_id: String::new(),
                operator_commitment: "devnet-miner-operator-commitment-a".to_string(),
                subject_root: "devnet-operator-summary-subject-root-a".to_string(),
                remaining_units: DEFAULT_REDACTION_BUDGET_UNITS,
                max_units: DEFAULT_REDACTION_BUDGET_UNITS,
                public_summary_floor: 16,
                opened_at_height: DEVNET_HEIGHT,
                expires_at_height: DEVNET_HEIGHT + DEFAULT_REVENUE_EPOCH_BLOCKS * 8,
            })
            .expect("devnet redaction budget");
        let _ = self.publish_operator_summary(OperatorSummary {
            operator_summary_id: String::new(),
            operator_commitment: "devnet-miner-operator-commitment-a".to_string(),
            summary_epoch: DEVNET_HEIGHT / DEFAULT_REVENUE_EPOCH_BLOCKS,
            redaction_budget_id: budget_id,
            book_count: 1,
            active_cohort_count: 1,
            token_count_bucket: "1-64".to_string(),
            notional_bucket_micro_xmr: "100000000-250000000".to_string(),
            collateral_bucket_micro_units: "25000000-50000000".to_string(),
            avg_margin_bucket_bps: "2500-3500".to_string(),
            risk_band: "moderate".to_string(),
            open_settlement_windows: 1,
            paused_book_count: 0,
            summary_root: "devnet-redacted-operator-summary-root-a".to_string(),
            published_at_height: DEVNET_HEIGHT + 12,
        });
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    let mut full_parts = Vec::with_capacity(parts.len().saturating_add(1));
    full_parts.push(HashPart::Str(CHAIN_ID));
    for part in parts {
        full_parts.push(hash_part_ref(part));
    }
    domain_hash(
        &format!("private-l2-pq-confidential-tokenized-miner-revenue-forward-runtime:{domain}"),
        &full_parts,
        32,
    )
}

fn prefixed(prefix: &str, domain: &str, parts: &[HashPart<'_>]) -> String {
    format!("{prefix}-{}", deterministic_id(domain, parts))
}

fn hash_part_ref<'a>(part: &HashPart<'a>) -> HashPart<'a> {
    match part {
        HashPart::Bytes(value) => HashPart::Bytes(value),
        HashPart::Str(value) => HashPart::Str(value),
        HashPart::U64(value) => HashPart::U64(*value),
        HashPart::Int(value) => HashPart::Int(*value),
        HashPart::Json(value) => HashPart::Json(value),
    }
}

fn value_root(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!("private-l2-pq-confidential-tokenized-miner-revenue-forward-runtime:{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Json(value)],
        32,
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, record_fn: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| json!({"key": key, "value": record_fn(value)}))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("private-l2-pq-confidential-tokenized-miner-revenue-forward-runtime:{domain}"),
        &leaves,
    )
}

fn public_map<T, F>(map: &BTreeMap<String, T>, record_fn: F) -> BTreeMap<String, Value>
where
    F: Fn(&T) -> Value,
{
    map.iter()
        .map(|(key, value)| (key.clone(), record_fn(value)))
        .collect()
}

fn required_margin(committed_hashrate_hps: u64, margin_bps: u64) -> u64 {
    committed_hashrate_hps
        .saturating_div(10_000_000)
        .saturating_mul(margin_bps)
        .saturating_div(MAX_BPS)
}

fn ensure_non_empty(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("miner revenue forward {label} must be non-empty"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, label: &str) -> Result<()> {
    if value <= MAX_BPS {
        Ok(())
    } else {
        Err(format!("miner revenue forward {label} exceeds BPS range"))
    }
}

fn ensure_capacity(len: usize, cap: usize, label: &str) -> Result<()> {
    if len < cap {
        Ok(())
    } else {
        Err(format!("miner revenue forward {label} capacity reached"))
    }
}

fn ensure_min(value: u64, min: u64, label: &str) -> Result<()> {
    if value >= min {
        Ok(())
    } else {
        Err(format!("miner revenue forward {label} below minimum"))
    }
}

#[allow(dead_code)]
fn ensure_unique_strings(values: &[String], label: &str) -> Result<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(value, label)?;
        if !seen.insert(value.clone()) {
            return Err(format!(
                "miner revenue forward {label} contains duplicate value"
            ));
        }
    }
    Ok(())
}
