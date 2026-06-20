use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedEnergyHashrateOptionsRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_ENERGY_HASHRATE_OPTIONS_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-tokenized-energy-hashrate-options-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_ENERGY_HASHRATE_OPTIONS_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-energy-hashrate-options-v1";
pub const PRIVACY_SCHEME: &str =
    "monero-viewtag-stealth-nullifier-confidential-energy-hashrate-options-v1";
pub const OPTION_BOOK_SUITE: &str = "confidential-tokenized-energy-hashrate-options-book-v1";
pub const COLLATERAL_SUITE: &str = "energy-hashrate-collateral-cohort-root-v1";
pub const ORACLE_SUITE: &str = "pq-threshold-energy-hashrate-oracle-report-root-v1";
pub const SETTLEMENT_SUITE: &str = "low-fee-confidential-option-exercise-settlement-root-v1";
pub const REBATE_SUITE: &str = "low-fee-exercise-rebate-root-v1";
pub const REDACTION_SUITE: &str = "operator-safe-redaction-budget-root-v1";
pub const PUBLIC_RECORD_SUITE: &str =
    "roots-only-private-l2-pq-confidential-tokenized-energy-hashrate-options-public-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_HEIGHT: u64 = 2_912_640;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_812_480;
pub const DEVNET_FEE_ASSET_ID: &str = "asset:piconero";
pub const DEVNET_ENERGY_ASSET_ID: &str = "asset:tokenized-renewable-mwh-devnet";
pub const DEVNET_HASHRATE_ASSET_ID: &str = "asset:tokenized-randomx-th-s-devnet";
pub const DEVNET_QUOTE_ASSET_ID: &str = "asset:confidential-usd-note-devnet";
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_ORACLE_QUORUM: u16 = 7;
pub const DEFAULT_KEEPER_QUORUM: u16 = 3;
pub const DEFAULT_ORDER_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 18;
pub const DEFAULT_EXERCISE_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 12;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const DEFAULT_LOW_FEE_EXERCISE_BPS: u64 = 5;
pub const DEFAULT_REBATE_BPS: u64 = 12;
pub const DEFAULT_MIN_COLLATERAL_RATIO_BPS: u64 = 12_500;
pub const DEFAULT_MIN_ENERGY_COVERAGE_BPS: u64 = 2_000;
pub const DEFAULT_MIN_HASHRATE_COVERAGE_BPS: u64 = 2_500;
pub const DEFAULT_MAX_ORACLE_DEVIATION_BPS: u64 = 250;
pub const DEFAULT_MAX_BOOK_SKEW_BPS: u64 = 4_000;
pub const DEFAULT_MAX_EXERCISE_BATCH_ITEMS: usize = 4_096;
pub const DEFAULT_MAX_REDACTION_UNITS_PER_EPOCH: u64 = 25_000;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnderlyingKind {
    EnergyMwh,
    HashrateTh,
    HybridEnergyHashrate,
}

impl UnderlyingKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EnergyMwh => "energy_mwh",
            Self::HashrateTh => "hashrate_th",
            Self::HybridEnergyHashrate => "hybrid_energy_hashrate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionKind {
    Call,
    Put,
    BinaryCall,
    BinaryPut,
    SpreadCall,
    SpreadPut,
    BarrierCall,
    BarrierPut,
}

impl OptionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Put => "put",
            Self::BinaryCall => "binary_call",
            Self::BinaryPut => "binary_put",
            Self::SpreadCall => "spread_call",
            Self::SpreadPut => "spread_put",
            Self::BarrierCall => "barrier_call",
            Self::BarrierPut => "barrier_put",
        }
    }

    pub fn is_call(self) -> bool {
        matches!(
            self,
            Self::Call | Self::BinaryCall | Self::SpreadCall | Self::BarrierCall
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionStyle {
    European,
    American,
    Bermudan,
}

impl OptionStyle {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::European => "european",
            Self::American => "american",
            Self::Bermudan => "bermudan",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BookStatus {
    Draft,
    Active,
    OracleGated,
    CollateralOnly,
    ExerciseOnly,
    Safeguarded,
    Paused,
    Retired,
}

impl BookStatus {
    pub fn accepts_orders(self) -> bool {
        matches!(self, Self::Active | Self::OracleGated)
    }

    pub fn accepts_exercise(self) -> bool {
        matches!(self, Self::Active | Self::ExerciseOnly | Self::Safeguarded)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderSide {
    Bid,
    Ask,
}

impl OrderSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bid => "bid",
            Self::Ask => "ask",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderStatus {
    Sealed,
    RiskAttested,
    CollateralReserved,
    BatchQueued,
    PartiallyFilled,
    Filled,
    Cancelled,
    Expired,
    Rejected,
}

impl OrderStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::RiskAttested => "risk_attested",
            Self::CollateralReserved => "collateral_reserved",
            Self::BatchQueued => "batch_queued",
            Self::PartiallyFilled => "partially_filled",
            Self::Filled => "filled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn matchable(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::RiskAttested | Self::CollateralReserved | Self::BatchQueued
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionStatus {
    Minted,
    Active,
    Exercised,
    Settled,
    Transferred,
    Expired,
    Quarantined,
}

impl PositionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Minted => "minted",
            Self::Active => "active",
            Self::Exercised => "exercised",
            Self::Settled => "settled",
            Self::Transferred => "transferred",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CollateralStatus {
    Proposed,
    Active,
    UnderCovered,
    Rebalancing,
    LockedForExercise,
    Released,
    Slashed,
    Retired,
}

impl CollateralStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Active => "active",
            Self::UnderCovered => "under_covered",
            Self::Rebalancing => "rebalancing",
            Self::LockedForExercise => "locked_for_exercise",
            Self::Released => "released",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleStatus {
    Proposed,
    QuorumAccepted,
    Challenged,
    Stale,
    Rejected,
}

impl OracleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::QuorumAccepted => "quorum_accepted",
            Self::Challenged => "challenged",
            Self::Stale => "stale",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationRole {
    Oracle,
    Risk,
    Keeper,
    Collateral,
    Settlement,
}

impl AttestationRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Oracle => "oracle",
            Self::Risk => "risk",
            Self::Keeper => "keeper",
            Self::Collateral => "collateral",
            Self::Settlement => "settlement",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Accept,
    Reject,
    NeedsReview,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Reject => "reject",
            Self::NeedsReview => "needs_review",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Open,
    Ready,
    Settling,
    Settled,
    PartiallySettled,
    Quarantined,
    Rejected,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Ready => "ready",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::PartiallySettled => "partially_settled",
            Self::Quarantined => "quarantined",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub energy_asset_id: String,
    pub hashrate_asset_id: String,
    pub quote_asset_id: String,
    pub low_fee_lane_id: String,
    pub pq_auth_suite: String,
    pub privacy_scheme: String,
    pub option_book_suite: String,
    pub collateral_suite: String,
    pub oracle_suite: String,
    pub settlement_suite: String,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub oracle_quorum: u16,
    pub keeper_quorum: u16,
    pub order_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub exercise_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub max_user_fee_bps: u64,
    pub low_fee_exercise_bps: u64,
    pub rebate_bps: u64,
    pub min_collateral_ratio_bps: u64,
    pub min_energy_coverage_bps: u64,
    pub min_hashrate_coverage_bps: u64,
    pub max_oracle_deviation_bps: u64,
    pub max_book_skew_bps: u64,
    pub max_exercise_batch_items: usize,
    pub max_redaction_units_per_epoch: u64,
    pub operator_view_redaction: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            energy_asset_id: DEVNET_ENERGY_ASSET_ID.to_string(),
            hashrate_asset_id: DEVNET_HASHRATE_ASSET_ID.to_string(),
            quote_asset_id: DEVNET_QUOTE_ASSET_ID.to_string(),
            low_fee_lane_id: "lane:low-fee-confidential-exercise-devnet".to_string(),
            pq_auth_suite: PQ_AUTH_SUITE.to_string(),
            privacy_scheme: PRIVACY_SCHEME.to_string(),
            option_book_suite: OPTION_BOOK_SUITE.to_string(),
            collateral_suite: COLLATERAL_SUITE.to_string(),
            oracle_suite: ORACLE_SUITE.to_string(),
            settlement_suite: SETTLEMENT_SUITE.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            oracle_quorum: DEFAULT_ORACLE_QUORUM,
            keeper_quorum: DEFAULT_KEEPER_QUORUM,
            order_ttl_blocks: DEFAULT_ORDER_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            exercise_ttl_blocks: DEFAULT_EXERCISE_TTL_BLOCKS,
            settlement_ttl_blocks: DEFAULT_SETTLEMENT_TTL_BLOCKS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            low_fee_exercise_bps: DEFAULT_LOW_FEE_EXERCISE_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            min_collateral_ratio_bps: DEFAULT_MIN_COLLATERAL_RATIO_BPS,
            min_energy_coverage_bps: DEFAULT_MIN_ENERGY_COVERAGE_BPS,
            min_hashrate_coverage_bps: DEFAULT_MIN_HASHRATE_COVERAGE_BPS,
            max_oracle_deviation_bps: DEFAULT_MAX_ORACLE_DEVIATION_BPS,
            max_book_skew_bps: DEFAULT_MAX_BOOK_SKEW_BPS,
            max_exercise_batch_items: DEFAULT_MAX_EXERCISE_BATCH_ITEMS,
            max_redaction_units_per_epoch: DEFAULT_MAX_REDACTION_UNITS_PER_EPOCH,
            operator_view_redaction:
                "operator-safe-roots-only-no-trader-miner-or-energy-provider-pii".to_string(),
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub option_books: u64,
    pub encrypted_orders: u64,
    pub collateral_cohorts: u64,
    pub oracle_reports: u64,
    pub pq_attestations: u64,
    pub tokenized_positions: u64,
    pub exercise_settlements: u64,
    pub rebates: u64,
    pub redaction_budgets: u64,
    pub operator_summaries: u64,
    pub consumed_nullifiers: u64,
    pub accepted_orders: u64,
    pub rejected_orders: u64,
    pub settled_exercises: u64,
    pub quarantined_exercises: u64,
    pub open_interest_units: u64,
    pub energy_collateral_mwh: u64,
    pub hashrate_collateral_th: u64,
    pub matched_notional_micro_units: u64,
    pub exercise_notional_micro_units: u64,
    pub fee_saved_micro_units: u64,
    pub public_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub option_book_root: String,
    pub encrypted_order_root: String,
    pub collateral_cohort_root: String,
    pub oracle_report_root: String,
    pub pq_attestation_root: String,
    pub tokenized_position_root: String,
    pub exercise_settlement_root: String,
    pub rebate_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OptionBook {
    pub book_id: String,
    pub market_id: String,
    pub operator_commitment: String,
    pub underlying: UnderlyingKind,
    pub option_kind: OptionKind,
    pub option_style: OptionStyle,
    pub status: BookStatus,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub collateral_cohort_id: String,
    pub token_class_id: String,
    pub strike_commitment: String,
    pub barrier_commitment: String,
    pub expiry_height: u64,
    pub oracle_report_id: String,
    pub bid_book_root: String,
    pub ask_book_root: String,
    pub match_commitment_root: String,
    pub open_interest_commitment: String,
    pub privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub created_height: u64,
}

impl OptionBook {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_energy_hashrate_option_book",
            "protocol_version": PROTOCOL_VERSION,
            "book_id": self.book_id,
            "market_id": self.market_id,
            "operator_commitment": self.operator_commitment,
            "underlying": self.underlying.as_str(),
            "option_kind": self.option_kind.as_str(),
            "option_style": self.option_style.as_str(),
            "status": self.status,
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "collateral_cohort_id": self.collateral_cohort_id,
            "token_class_id": self.token_class_id,
            "strike_commitment": self.strike_commitment,
            "barrier_commitment": self.barrier_commitment,
            "expiry_height": self.expiry_height,
            "oracle_report_id": self.oracle_report_id,
            "bid_book_root": self.bid_book_root,
            "ask_book_root": self.ask_book_root,
            "match_commitment_root": self.match_commitment_root,
            "open_interest_commitment": self.open_interest_commitment,
            "privacy_set_size": self.privacy_set_size,
            "max_user_fee_bps": self.max_user_fee_bps,
            "created_height": self.created_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptedOrder {
    pub order_id: String,
    pub book_id: String,
    pub owner_commitment: String,
    pub side: OrderSide,
    pub status: OrderStatus,
    pub encrypted_terms_root: String,
    pub price_commitment: String,
    pub size_commitment: String,
    pub collateral_note_commitment: String,
    pub fee_note_commitment: String,
    pub order_nullifier: String,
    pub replay_fence_id: String,
    pub risk_attestation_id: String,
    pub pq_envelope_id: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub created_height: u64,
    pub expiry_height: u64,
}

impl EncryptedOrder {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sealed_energy_hashrate_option_order",
            "protocol_version": PROTOCOL_VERSION,
            "order_id": self.order_id,
            "book_id": self.book_id,
            "owner_commitment": self.owner_commitment,
            "side": self.side.as_str(),
            "status": self.status.as_str(),
            "encrypted_terms_root": self.encrypted_terms_root,
            "price_commitment": self.price_commitment,
            "size_commitment": self.size_commitment,
            "collateral_note_commitment": self.collateral_note_commitment,
            "fee_note_commitment": self.fee_note_commitment,
            "order_nullifier": self.order_nullifier,
            "replay_fence_id": self.replay_fence_id,
            "risk_attestation_id": self.risk_attestation_id,
            "pq_envelope_id": self.pq_envelope_id,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "created_height": self.created_height,
            "expiry_height": self.expiry_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CollateralCohort {
    pub cohort_id: String,
    pub operator_commitment: String,
    pub status: CollateralStatus,
    pub energy_asset_id: String,
    pub hashrate_asset_id: String,
    pub quote_asset_id: String,
    pub energy_commitment_root: String,
    pub hashrate_commitment_root: String,
    pub reserve_note_root: String,
    pub locked_note_root: String,
    pub insurance_note_root: String,
    pub energy_mwh: u64,
    pub hashrate_th: u64,
    pub quote_micro_units: u64,
    pub coverage_bps: u64,
    pub min_collateral_ratio_bps: u64,
    pub oracle_report_id: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl CollateralCohort {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "energy_hashrate_collateral_cohort",
            "protocol_version": PROTOCOL_VERSION,
            "cohort_id": self.cohort_id,
            "operator_commitment": self.operator_commitment,
            "status": self.status.as_str(),
            "energy_asset_id": self.energy_asset_id,
            "hashrate_asset_id": self.hashrate_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "energy_commitment_root": self.energy_commitment_root,
            "hashrate_commitment_root": self.hashrate_commitment_root,
            "reserve_note_root": self.reserve_note_root,
            "locked_note_root": self.locked_note_root,
            "insurance_note_root": self.insurance_note_root,
            "energy_mwh": self.energy_mwh,
            "hashrate_th": self.hashrate_th,
            "quote_micro_units": self.quote_micro_units,
            "coverage_bps": self.coverage_bps,
            "min_collateral_ratio_bps": self.min_collateral_ratio_bps,
            "oracle_report_id": self.oracle_report_id,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OracleReport {
    pub report_id: String,
    pub committee_root: String,
    pub status: OracleStatus,
    pub energy_price_commitment: String,
    pub hashrate_price_commitment: String,
    pub energy_delivery_root: String,
    pub hashrate_delivery_root: String,
    pub volatility_surface_root: String,
    pub deviation_bps: u64,
    pub quorum: u16,
    pub pq_signature_root: String,
    pub security_bits: u16,
    pub observed_height: u64,
    pub valid_until_height: u64,
}

impl OracleReport {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_energy_hashrate_oracle_report",
            "protocol_version": PROTOCOL_VERSION,
            "report_id": self.report_id,
            "committee_root": self.committee_root,
            "status": self.status.as_str(),
            "energy_price_commitment": self.energy_price_commitment,
            "hashrate_price_commitment": self.hashrate_price_commitment,
            "energy_delivery_root": self.energy_delivery_root,
            "hashrate_delivery_root": self.hashrate_delivery_root,
            "volatility_surface_root": self.volatility_surface_root,
            "deviation_bps": self.deviation_bps,
            "quorum": self.quorum,
            "pq_signature_root": self.pq_signature_root,
            "security_bits": self.security_bits,
            "observed_height": self.observed_height,
            "valid_until_height": self.valid_until_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqAttestation {
    pub attestation_id: String,
    pub subject_id: String,
    pub role: AttestationRole,
    pub verdict: AttestationVerdict,
    pub committee_root: String,
    pub statement_root: String,
    pub evidence_root: String,
    pub pq_signature_root: String,
    pub security_bits: u16,
    pub quorum: u16,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
}

impl PqAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_confidential_energy_hashrate_options_attestation",
            "protocol_version": PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "subject_id": self.subject_id,
            "role": self.role.as_str(),
            "verdict": self.verdict.as_str(),
            "committee_root": self.committee_root,
            "statement_root": self.statement_root,
            "evidence_root": self.evidence_root,
            "pq_signature_root": self.pq_signature_root,
            "security_bits": self.security_bits,
            "quorum": self.quorum,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TokenizedOptionPosition {
    pub position_id: String,
    pub book_id: String,
    pub token_id: String,
    pub owner_commitment: String,
    pub status: PositionStatus,
    pub long_short_commitment: String,
    pub size_commitment: String,
    pub premium_commitment: String,
    pub collateral_cohort_id: String,
    pub transfer_nullifier_root: String,
    pub exercise_nullifier: String,
    pub metadata_ciphertext_root: String,
    pub minted_at_height: u64,
    pub expiry_height: u64,
}

impl TokenizedOptionPosition {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "tokenized_energy_hashrate_option_position",
            "protocol_version": PROTOCOL_VERSION,
            "position_id": self.position_id,
            "book_id": self.book_id,
            "token_id": self.token_id,
            "owner_commitment": self.owner_commitment,
            "status": self.status.as_str(),
            "long_short_commitment": self.long_short_commitment,
            "size_commitment": self.size_commitment,
            "premium_commitment": self.premium_commitment,
            "collateral_cohort_id": self.collateral_cohort_id,
            "transfer_nullifier_root": self.transfer_nullifier_root,
            "exercise_nullifier": self.exercise_nullifier,
            "metadata_ciphertext_root": self.metadata_ciphertext_root,
            "minted_at_height": self.minted_at_height,
            "expiry_height": self.expiry_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExerciseSettlement {
    pub settlement_id: String,
    pub book_id: String,
    pub position_id: String,
    pub collateral_cohort_id: String,
    pub oracle_report_id: String,
    pub keeper_attestation_id: String,
    pub status: SettlementStatus,
    pub exercise_ticket_root: String,
    pub payoff_commitment: String,
    pub consumed_nullifier_root: String,
    pub output_note_root: String,
    pub fee_note_commitment: String,
    pub rebate_id: String,
    pub batch_id: String,
    pub item_count: u64,
    pub user_fee_bps: u64,
    pub exercise_notional_micro_units: u64,
    pub opened_at_height: u64,
    pub settled_at_height: u64,
}

impl ExerciseSettlement {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_energy_hashrate_option_exercise_settlement",
            "protocol_version": PROTOCOL_VERSION,
            "settlement_id": self.settlement_id,
            "book_id": self.book_id,
            "position_id": self.position_id,
            "collateral_cohort_id": self.collateral_cohort_id,
            "oracle_report_id": self.oracle_report_id,
            "keeper_attestation_id": self.keeper_attestation_id,
            "status": self.status.as_str(),
            "exercise_ticket_root": self.exercise_ticket_root,
            "payoff_commitment": self.payoff_commitment,
            "consumed_nullifier_root": self.consumed_nullifier_root,
            "output_note_root": self.output_note_root,
            "fee_note_commitment": self.fee_note_commitment,
            "rebate_id": self.rebate_id,
            "batch_id": self.batch_id,
            "item_count": self.item_count,
            "user_fee_bps": self.user_fee_bps,
            "exercise_notional_micro_units": self.exercise_notional_micro_units,
            "opened_at_height": self.opened_at_height,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub settlement_id: String,
    pub beneficiary_commitment: String,
    pub fee_paid_commitment: String,
    pub rebate_commitment: String,
    pub rebate_bps: u64,
    pub proof_root: String,
    pub issued_height: u64,
}

impl LowFeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_energy_hashrate_option_exercise_rebate",
            "protocol_version": PROTOCOL_VERSION,
            "rebate_id": self.rebate_id,
            "settlement_id": self.settlement_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "fee_paid_commitment": self.fee_paid_commitment,
            "rebate_commitment": self.rebate_commitment,
            "rebate_bps": self.rebate_bps,
            "proof_root": self.proof_root,
            "issued_height": self.issued_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub scope: String,
    pub epoch: u64,
    pub max_units: u64,
    pub used_units: u64,
    pub redacted_field_root: String,
    pub disclosure_policy_root: String,
}

impl RedactionBudget {
    pub fn remaining_units(&self) -> u64 {
        self.max_units.saturating_sub(self.used_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "energy_hashrate_options_redaction_budget",
            "protocol_version": PROTOCOL_VERSION,
            "budget_id": self.budget_id,
            "scope": self.scope,
            "epoch": self.epoch,
            "max_units": self.max_units,
            "used_units": self.used_units,
            "remaining_units": self.remaining_units(),
            "redacted_field_root": self.redacted_field_root,
            "disclosure_policy_root": self.disclosure_policy_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_commitment: String,
    pub summary_height: u64,
    pub book_count: u64,
    pub active_book_count: u64,
    pub collateral_root: String,
    pub oracle_root: String,
    pub settlement_root: String,
    pub redaction_budget_root: String,
    pub open_interest_units: u64,
    pub exercise_count: u64,
    pub settled_count: u64,
    pub quarantined_count: u64,
    pub max_user_fee_bps: u64,
    pub safe_public_note: String,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_safe_energy_hashrate_options_summary",
            "protocol_version": PROTOCOL_VERSION,
            "summary_id": self.summary_id,
            "operator_commitment": self.operator_commitment,
            "summary_height": self.summary_height,
            "book_count": self.book_count,
            "active_book_count": self.active_book_count,
            "collateral_root": self.collateral_root,
            "oracle_root": self.oracle_root,
            "settlement_root": self.settlement_root,
            "redaction_budget_root": self.redaction_budget_root,
            "open_interest_units": self.open_interest_units,
            "exercise_count": self.exercise_count,
            "settled_count": self.settled_count,
            "quarantined_count": self.quarantined_count,
            "max_user_fee_bps": self.max_user_fee_bps,
            "safe_public_note": self.safe_public_note,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub option_books: BTreeMap<String, OptionBook>,
    pub encrypted_orders: BTreeMap<String, EncryptedOrder>,
    pub collateral_cohorts: BTreeMap<String, CollateralCohort>,
    pub oracle_reports: BTreeMap<String, OracleReport>,
    pub pq_attestations: BTreeMap<String, PqAttestation>,
    pub tokenized_positions: BTreeMap<String, TokenizedOptionPosition>,
    pub exercise_settlements: BTreeMap<String, ExerciseSettlement>,
    pub rebates: BTreeMap<String, LowFeeRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, Value>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            config: Config::default(),
            counters: Counters::default(),
            option_books: BTreeMap::new(),
            encrypted_orders: BTreeMap::new(),
            collateral_cohorts: BTreeMap::new(),
            oracle_reports: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            tokenized_positions: BTreeMap::new(),
            exercise_settlements: BTreeMap::new(),
            rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        }
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self::default();
        state.seed_devnet();
        state.refresh_public_records();
        state
    }

    pub fn add_option_book(&mut self, book: OptionBook) -> Result<()> {
        ensure_unique(&self.option_books, &book.book_id, "option book")?;
        ensure!(
            book.privacy_set_size >= self.config.min_privacy_set_size,
            "option book privacy set below runtime minimum"
        )?;
        ensure!(
            book.max_user_fee_bps <= self.config.max_user_fee_bps,
            "option book fee cap exceeds runtime maximum"
        )?;
        ensure!(
            self.collateral_cohorts
                .contains_key(&book.collateral_cohort_id),
            "option book collateral cohort is missing"
        )?;
        self.counters.option_books = self.counters.option_books.saturating_add(1);
        if book.status.accepts_orders() {
            self.counters.accepted_orders = self.counters.accepted_orders.saturating_add(1);
        }
        self.option_books.insert(book.book_id.clone(), book);
        self.refresh_public_records();
        Ok(())
    }

    pub fn add_encrypted_order(&mut self, order: EncryptedOrder) -> Result<()> {
        ensure_unique(&self.encrypted_orders, &order.order_id, "encrypted order")?;
        let book = self
            .option_books
            .get(&order.book_id)
            .ok_or_else(|| "encrypted order book is missing".to_string())?;
        ensure!(
            book.status.accepts_orders(),
            "option book is not accepting orders"
        );
        ensure!(
            order.max_fee_bps <= self.config.max_user_fee_bps,
            "encrypted order fee cap exceeds runtime maximum"
        )?;
        ensure!(
            order.privacy_set_size >= self.config.min_privacy_set_size,
            "encrypted order privacy set below runtime minimum"
        )?;
        ensure!(
            self.consumed_nullifiers
                .insert(order.order_nullifier.clone()),
            "encrypted order nullifier already consumed"
        )?;
        if order.status.matchable() {
            self.counters.accepted_orders = self.counters.accepted_orders.saturating_add(1);
        } else {
            self.counters.rejected_orders = self.counters.rejected_orders.saturating_add(1);
        }
        self.counters.encrypted_orders = self.counters.encrypted_orders.saturating_add(1);
        self.counters.consumed_nullifiers = self.consumed_nullifiers.len() as u64;
        self.encrypted_orders.insert(order.order_id.clone(), order);
        self.refresh_public_records();
        Ok(())
    }

    pub fn add_collateral_cohort(&mut self, cohort: CollateralCohort) -> Result<()> {
        ensure_unique(
            &self.collateral_cohorts,
            &cohort.cohort_id,
            "collateral cohort",
        )?;
        ensure!(
            cohort.coverage_bps >= self.config.min_collateral_ratio_bps,
            "collateral cohort below collateral ratio floor"
        )?;
        self.counters.collateral_cohorts = self.counters.collateral_cohorts.saturating_add(1);
        self.counters.energy_collateral_mwh = self
            .counters
            .energy_collateral_mwh
            .saturating_add(cohort.energy_mwh);
        self.counters.hashrate_collateral_th = self
            .counters
            .hashrate_collateral_th
            .saturating_add(cohort.hashrate_th);
        self.collateral_cohorts
            .insert(cohort.cohort_id.clone(), cohort);
        self.refresh_public_records();
        Ok(())
    }

    pub fn add_oracle_report(&mut self, report: OracleReport) -> Result<()> {
        ensure_unique(&self.oracle_reports, &report.report_id, "oracle report")?;
        ensure!(
            report.quorum >= self.config.oracle_quorum,
            "oracle report quorum below runtime threshold"
        )?;
        ensure!(
            report.security_bits >= self.config.min_pq_security_bits,
            "oracle report PQ security bits below runtime minimum"
        )?;
        ensure!(
            report.deviation_bps <= self.config.max_oracle_deviation_bps,
            "oracle report deviation exceeds runtime maximum"
        )?;
        self.counters.oracle_reports = self.counters.oracle_reports.saturating_add(1);
        self.oracle_reports.insert(report.report_id.clone(), report);
        self.refresh_public_records();
        Ok(())
    }

    pub fn add_pq_attestation(&mut self, attestation: PqAttestation) -> Result<()> {
        ensure_unique(
            &self.pq_attestations,
            &attestation.attestation_id,
            "PQ attestation",
        )?;
        ensure!(
            attestation.security_bits >= self.config.min_pq_security_bits,
            "PQ attestation security bits below runtime minimum"
        )?;
        ensure!(
            attestation.quorum >= self.config.keeper_quorum,
            "PQ attestation quorum below runtime threshold"
        )?;
        self.counters.pq_attestations = self.counters.pq_attestations.saturating_add(1);
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh_public_records();
        Ok(())
    }

    pub fn mint_position(&mut self, position: TokenizedOptionPosition) -> Result<()> {
        ensure_unique(
            &self.tokenized_positions,
            &position.position_id,
            "tokenized option position",
        )?;
        ensure!(
            self.option_books.contains_key(&position.book_id),
            "position option book is missing"
        )?;
        ensure!(
            self.collateral_cohorts
                .contains_key(&position.collateral_cohort_id),
            "position collateral cohort is missing"
        )?;
        self.counters.tokenized_positions = self.counters.tokenized_positions.saturating_add(1);
        self.counters.open_interest_units = self.counters.open_interest_units.saturating_add(1);
        self.tokenized_positions
            .insert(position.position_id.clone(), position);
        self.refresh_public_records();
        Ok(())
    }

    pub fn settle_exercise(&mut self, settlement: ExerciseSettlement) -> Result<()> {
        ensure_unique(
            &self.exercise_settlements,
            &settlement.settlement_id,
            "exercise settlement",
        )?;
        let book = self
            .option_books
            .get(&settlement.book_id)
            .ok_or_else(|| "settlement option book is missing".to_string())?;
        ensure!(
            book.status.accepts_exercise(),
            "option book is not exercisable"
        );
        ensure!(
            self.tokenized_positions
                .contains_key(&settlement.position_id),
            "settlement position is missing"
        )?;
        ensure!(
            self.oracle_reports
                .contains_key(&settlement.oracle_report_id),
            "settlement oracle report is missing"
        )?;
        ensure!(
            settlement.user_fee_bps <= self.config.max_user_fee_bps,
            "settlement fee exceeds runtime maximum"
        )?;
        ensure!(
            settlement.item_count as usize <= self.config.max_exercise_batch_items,
            "settlement batch item count exceeds runtime maximum"
        )?;
        match settlement.status {
            SettlementStatus::Settled | SettlementStatus::PartiallySettled => {
                self.counters.settled_exercises = self.counters.settled_exercises.saturating_add(1);
            }
            SettlementStatus::Quarantined | SettlementStatus::Rejected => {
                self.counters.quarantined_exercises =
                    self.counters.quarantined_exercises.saturating_add(1);
            }
            _ => {}
        }
        self.counters.exercise_settlements = self.counters.exercise_settlements.saturating_add(1);
        self.counters.exercise_notional_micro_units = self
            .counters
            .exercise_notional_micro_units
            .saturating_add(settlement.exercise_notional_micro_units);
        self.exercise_settlements
            .insert(settlement.settlement_id.clone(), settlement);
        self.refresh_public_records();
        Ok(())
    }

    pub fn issue_rebate(&mut self, rebate: LowFeeRebate) -> Result<()> {
        ensure_unique(&self.rebates, &rebate.rebate_id, "rebate")?;
        ensure!(
            self.exercise_settlements
                .contains_key(&rebate.settlement_id),
            "rebate settlement is missing"
        )?;
        ensure!(
            rebate.rebate_bps <= MAX_BPS,
            "rebate basis points exceed MAX_BPS"
        )?;
        self.counters.rebates = self.counters.rebates.saturating_add(1);
        self.counters.fee_saved_micro_units = self
            .counters
            .fee_saved_micro_units
            .saturating_add(rebate.rebate_bps);
        self.rebates.insert(rebate.rebate_id.clone(), rebate);
        self.refresh_public_records();
        Ok(())
    }

    pub fn add_redaction_budget(&mut self, budget: RedactionBudget) -> Result<()> {
        ensure_unique(
            &self.redaction_budgets,
            &budget.budget_id,
            "redaction budget",
        )?;
        ensure!(
            budget.max_units <= self.config.max_redaction_units_per_epoch,
            "redaction budget exceeds runtime epoch maximum"
        )?;
        ensure!(
            budget.used_units <= budget.max_units,
            "redaction budget used units exceed max units"
        )?;
        self.counters.redaction_budgets = self.counters.redaction_budgets.saturating_add(1);
        self.redaction_budgets
            .insert(budget.budget_id.clone(), budget);
        self.refresh_public_records();
        Ok(())
    }

    pub fn add_operator_summary(&mut self, summary: OperatorSummary) -> Result<()> {
        ensure_unique(
            &self.operator_summaries,
            &summary.summary_id,
            "operator summary",
        )?;
        ensure!(
            summary.max_user_fee_bps <= self.config.max_user_fee_bps,
            "operator summary fee exceeds runtime maximum"
        )?;
        self.counters.operator_summaries = self.counters.operator_summaries.saturating_add(1);
        self.operator_summaries
            .insert(summary.summary_id.clone(), summary);
        self.refresh_public_records();
        Ok(())
    }

    pub fn roots(&self) -> Roots {
        let mut roots = Roots {
            config_root: state_root_from_record(&self.config.public_record()),
            counters_root: state_root_from_record(&self.counters.public_record()),
            option_book_root: map_root(
                "ENERGY-HASHRATE-OPTIONS-BOOK-ROOT",
                &self.option_books,
                OptionBook::public_record,
            ),
            encrypted_order_root: map_root(
                "ENERGY-HASHRATE-OPTIONS-ORDER-ROOT",
                &self.encrypted_orders,
                EncryptedOrder::public_record,
            ),
            collateral_cohort_root: map_root(
                "ENERGY-HASHRATE-OPTIONS-COLLATERAL-ROOT",
                &self.collateral_cohorts,
                CollateralCohort::public_record,
            ),
            oracle_report_root: map_root(
                "ENERGY-HASHRATE-OPTIONS-ORACLE-ROOT",
                &self.oracle_reports,
                OracleReport::public_record,
            ),
            pq_attestation_root: map_root(
                "ENERGY-HASHRATE-OPTIONS-PQ-ATTESTATION-ROOT",
                &self.pq_attestations,
                PqAttestation::public_record,
            ),
            tokenized_position_root: map_root(
                "ENERGY-HASHRATE-OPTIONS-POSITION-ROOT",
                &self.tokenized_positions,
                TokenizedOptionPosition::public_record,
            ),
            exercise_settlement_root: map_root(
                "ENERGY-HASHRATE-OPTIONS-EXERCISE-SETTLEMENT-ROOT",
                &self.exercise_settlements,
                ExerciseSettlement::public_record,
            ),
            rebate_root: map_root(
                "ENERGY-HASHRATE-OPTIONS-REBATE-ROOT",
                &self.rebates,
                LowFeeRebate::public_record,
            ),
            redaction_budget_root: map_root(
                "ENERGY-HASHRATE-OPTIONS-REDACTION-BUDGET-ROOT",
                &self.redaction_budgets,
                RedactionBudget::public_record,
            ),
            operator_summary_root: map_root(
                "ENERGY-HASHRATE-OPTIONS-OPERATOR-SUMMARY-ROOT",
                &self.operator_summaries,
                OperatorSummary::public_record,
            ),
            nullifier_root: set_root(
                "ENERGY-HASHRATE-OPTIONS-CONSUMED-NULLIFIER-ROOT",
                &self.consumed_nullifiers,
            ),
            public_record_root: value_map_root(
                "ENERGY-HASHRATE-OPTIONS-PUBLIC-RECORD-ROOT",
                &self.public_records,
            ),
            state_root: String::new(),
        };
        let record = roots.public_record();
        roots.state_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-ENERGY-HASHRATE-OPTIONS-RUNTIME-ROOT",
            &[HashPart::Str(CHAIN_ID), HashPart::Json(&record)],
            32,
        );
        roots
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_l2_pq_confidential_tokenized_energy_hashrate_options_runtime",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_auth_suite": PQ_AUTH_SUITE,
            "privacy_scheme": PRIVACY_SCHEME,
            "public_record_suite": PUBLIC_RECORD_SUITE,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        set_json_field(&mut record, "state_root", json!(self.state_root()));
        record
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn refresh_public_records(&mut self) {
        self.public_records
            .insert("config".to_string(), self.config.public_record());
        self.public_records
            .insert("counters".to_string(), self.counters.public_record());
        self.public_records
            .insert("roots".to_string(), self.roots().public_record());
        self.counters.public_records = self.public_records.len() as u64;
    }

    fn seed_devnet(&mut self) {
        let oracle = OracleReport {
            report_id: id("oracle", "devnet-energy-hashrate-surface", DEVNET_HEIGHT),
            committee_root: commitment("oracle-committee", "energy-hashrate", 0),
            status: OracleStatus::QuorumAccepted,
            energy_price_commitment: commitment("energy-price", "mwh-usd", DEVNET_HEIGHT),
            hashrate_price_commitment: commitment("hashrate-price", "randomx-th", DEVNET_HEIGHT),
            energy_delivery_root: commitment("energy-delivery", "renewable-mwh", DEVNET_HEIGHT),
            hashrate_delivery_root: commitment("hashrate-delivery", "randomx", DEVNET_HEIGHT),
            volatility_surface_root: commitment("vol-surface", "hybrid", DEVNET_HEIGHT),
            deviation_bps: 90,
            quorum: self.config.oracle_quorum,
            pq_signature_root: commitment("pq-signature", "oracle", DEVNET_HEIGHT),
            security_bits: self.config.min_pq_security_bits,
            observed_height: DEVNET_HEIGHT,
            valid_until_height: DEVNET_HEIGHT + self.config.attestation_ttl_blocks,
        };
        let _ = self.add_oracle_report(oracle.clone());

        let cohort = CollateralCohort {
            cohort_id: id("cohort", "renewable-randomx", DEVNET_HEIGHT),
            operator_commitment: commitment("operator", "cohort", 1),
            status: CollateralStatus::Active,
            energy_asset_id: self.config.energy_asset_id.clone(),
            hashrate_asset_id: self.config.hashrate_asset_id.clone(),
            quote_asset_id: self.config.quote_asset_id.clone(),
            energy_commitment_root: commitment("energy-notes", "mwh", 1),
            hashrate_commitment_root: commitment("hashrate-notes", "th", 1),
            reserve_note_root: commitment("reserve-notes", "cohort", 1),
            locked_note_root: commitment("locked-notes", "cohort", 1),
            insurance_note_root: commitment("insurance-notes", "cohort", 1),
            energy_mwh: 42_000,
            hashrate_th: 180_000,
            quote_micro_units: 9_500_000_000,
            coverage_bps: 15_250,
            min_collateral_ratio_bps: self.config.min_collateral_ratio_bps,
            oracle_report_id: oracle.report_id.clone(),
            opened_at_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT + 10_080,
        };
        let _ = self.add_collateral_cohort(cohort.clone());

        let book = OptionBook {
            book_id: id("book", "hybrid-energy-hashrate-call", DEVNET_HEIGHT),
            market_id: "market:private-energy-hashrate-options-devnet".to_string(),
            operator_commitment: commitment("operator", "book", 1),
            underlying: UnderlyingKind::HybridEnergyHashrate,
            option_kind: OptionKind::Call,
            option_style: OptionStyle::European,
            status: BookStatus::Active,
            base_asset_id: self.config.energy_asset_id.clone(),
            quote_asset_id: self.config.quote_asset_id.clone(),
            collateral_cohort_id: cohort.cohort_id.clone(),
            token_class_id: id("token-class", "hybrid-call", DEVNET_HEIGHT),
            strike_commitment: commitment("strike", "hybrid-call", DEVNET_HEIGHT),
            barrier_commitment: commitment("barrier", "none", DEVNET_HEIGHT),
            expiry_height: DEVNET_HEIGHT + 7_200,
            oracle_report_id: oracle.report_id.clone(),
            bid_book_root: commitment("bid-book", "hybrid-call", 1),
            ask_book_root: commitment("ask-book", "hybrid-call", 1),
            match_commitment_root: commitment("matches", "hybrid-call", 1),
            open_interest_commitment: commitment("open-interest", "hybrid-call", 1),
            privacy_set_size: self.config.batch_privacy_set_size,
            max_user_fee_bps: self.config.max_user_fee_bps,
            created_height: DEVNET_HEIGHT,
        };
        let _ = self.add_option_book(book.clone());

        let risk_attestation = PqAttestation {
            attestation_id: id("attestation", "risk-order-1", DEVNET_HEIGHT),
            subject_id: "order:devnet-sealed-1".to_string(),
            role: AttestationRole::Risk,
            verdict: AttestationVerdict::Accept,
            committee_root: commitment("risk-committee", "book", 1),
            statement_root: commitment("risk-statement", "order", 1),
            evidence_root: commitment("risk-evidence", "order", 1),
            pq_signature_root: commitment("pq-signature", "risk", 1),
            security_bits: self.config.min_pq_security_bits,
            quorum: self.config.keeper_quorum,
            valid_from_height: DEVNET_HEIGHT,
            valid_until_height: DEVNET_HEIGHT + self.config.attestation_ttl_blocks,
        };
        let _ = self.add_pq_attestation(risk_attestation.clone());

        let order = EncryptedOrder {
            order_id: "order:devnet-sealed-1".to_string(),
            book_id: book.book_id.clone(),
            owner_commitment: commitment("owner", "order", 1),
            side: OrderSide::Bid,
            status: OrderStatus::RiskAttested,
            encrypted_terms_root: commitment("encrypted-terms", "order", 1),
            price_commitment: commitment("price", "order", 1),
            size_commitment: commitment("size", "order", 1),
            collateral_note_commitment: commitment("collateral-note", "order", 1),
            fee_note_commitment: commitment("fee-note", "order", 1),
            order_nullifier: commitment("nullifier", "order", 1),
            replay_fence_id: id("replay-fence", "order", 1),
            risk_attestation_id: risk_attestation.attestation_id.clone(),
            pq_envelope_id: id("pq-envelope", "order", 1),
            max_fee_bps: self.config.max_user_fee_bps,
            privacy_set_size: self.config.batch_privacy_set_size,
            created_height: DEVNET_HEIGHT,
            expiry_height: DEVNET_HEIGHT + self.config.order_ttl_blocks,
        };
        let _ = self.add_encrypted_order(order);

        let position = TokenizedOptionPosition {
            position_id: id("position", "hybrid-call-long", 1),
            book_id: book.book_id.clone(),
            token_id: id("option-token", "hybrid-call-long", 1),
            owner_commitment: commitment("owner", "position", 1),
            status: PositionStatus::Active,
            long_short_commitment: commitment("long-short", "long", 1),
            size_commitment: commitment("position-size", "hybrid-call", 1),
            premium_commitment: commitment("premium", "hybrid-call", 1),
            collateral_cohort_id: cohort.cohort_id.clone(),
            transfer_nullifier_root: commitment("transfer-nullifiers", "position", 1),
            exercise_nullifier: commitment("exercise-nullifier", "position", 1),
            metadata_ciphertext_root: commitment("metadata", "position", 1),
            minted_at_height: DEVNET_HEIGHT + 2,
            expiry_height: book.expiry_height,
        };
        let _ = self.mint_position(position.clone());

        let keeper_attestation = PqAttestation {
            attestation_id: id("attestation", "keeper-exercise-1", DEVNET_HEIGHT),
            subject_id: position.position_id.clone(),
            role: AttestationRole::Keeper,
            verdict: AttestationVerdict::Accept,
            committee_root: commitment("keeper-committee", "exercise", 1),
            statement_root: commitment("keeper-statement", "exercise", 1),
            evidence_root: commitment("keeper-evidence", "exercise", 1),
            pq_signature_root: commitment("pq-signature", "keeper", 1),
            security_bits: self.config.min_pq_security_bits,
            quorum: self.config.keeper_quorum,
            valid_from_height: DEVNET_HEIGHT + 3,
            valid_until_height: DEVNET_HEIGHT + 3 + self.config.attestation_ttl_blocks,
        };
        let _ = self.add_pq_attestation(keeper_attestation.clone());

        let settlement = ExerciseSettlement {
            settlement_id: id("settlement", "hybrid-call-exercise", 1),
            book_id: book.book_id.clone(),
            position_id: position.position_id.clone(),
            collateral_cohort_id: cohort.cohort_id.clone(),
            oracle_report_id: oracle.report_id.clone(),
            keeper_attestation_id: keeper_attestation.attestation_id.clone(),
            status: SettlementStatus::Settled,
            exercise_ticket_root: commitment("exercise-ticket", "position", 1),
            payoff_commitment: commitment("payoff", "position", 1),
            consumed_nullifier_root: commitment("settlement-nullifiers", "batch", 1),
            output_note_root: commitment("output-notes", "batch", 1),
            fee_note_commitment: commitment("fee-note", "settlement", 1),
            rebate_id: id("rebate", "hybrid-call-exercise", 1),
            batch_id: id("exercise-batch", "hybrid-call", 1),
            item_count: 24,
            user_fee_bps: self.config.low_fee_exercise_bps,
            exercise_notional_micro_units: 820_000_000,
            opened_at_height: DEVNET_HEIGHT + 4,
            settled_at_height: DEVNET_HEIGHT + 5,
        };
        let _ = self.settle_exercise(settlement.clone());

        let rebate = LowFeeRebate {
            rebate_id: settlement.rebate_id.clone(),
            settlement_id: settlement.settlement_id.clone(),
            beneficiary_commitment: commitment("beneficiary", "rebate", 1),
            fee_paid_commitment: commitment("fee-paid", "rebate", 1),
            rebate_commitment: commitment("rebate", "settlement", 1),
            rebate_bps: self.config.rebate_bps,
            proof_root: commitment("rebate-proof", "settlement", 1),
            issued_height: DEVNET_HEIGHT + 6,
        };
        let _ = self.issue_rebate(rebate);

        let budget = RedactionBudget {
            budget_id: id("redaction-budget", "operator", 1),
            scope: "operator-public-summary".to_string(),
            epoch: DEVNET_HEIGHT / 720,
            max_units: self.config.max_redaction_units_per_epoch,
            used_units: 144,
            redacted_field_root: commitment("redacted-fields", "operator", 1),
            disclosure_policy_root: commitment("disclosure-policy", "operator", 1),
        };
        let _ = self.add_redaction_budget(budget);

        let summary = OperatorSummary {
            summary_id: id("operator-summary", "devnet", DEVNET_HEIGHT),
            operator_commitment: commitment("operator", "summary", 1),
            summary_height: DEVNET_HEIGHT + 6,
            book_count: self.option_books.len() as u64,
            active_book_count: self
                .option_books
                .values()
                .filter(|book| book.status.accepts_orders())
                .count() as u64,
            collateral_root: map_root(
                "ENERGY-HASHRATE-OPTIONS-SUMMARY-COLLATERAL-ROOT",
                &self.collateral_cohorts,
                CollateralCohort::public_record,
            ),
            oracle_root: map_root(
                "ENERGY-HASHRATE-OPTIONS-SUMMARY-ORACLE-ROOT",
                &self.oracle_reports,
                OracleReport::public_record,
            ),
            settlement_root: map_root(
                "ENERGY-HASHRATE-OPTIONS-SUMMARY-SETTLEMENT-ROOT",
                &self.exercise_settlements,
                ExerciseSettlement::public_record,
            ),
            redaction_budget_root: map_root(
                "ENERGY-HASHRATE-OPTIONS-SUMMARY-REDACTION-ROOT",
                &self.redaction_budgets,
                RedactionBudget::public_record,
            ),
            open_interest_units: self.counters.open_interest_units,
            exercise_count: self.counters.exercise_settlements,
            settled_count: self.counters.settled_exercises,
            quarantined_count: self.counters.quarantined_exercises,
            max_user_fee_bps: self.config.max_user_fee_bps,
            safe_public_note:
                "roots-only summary; no trader, miner, energy provider, or position plaintext"
                    .to_string(),
        };
        let _ = self.add_operator_summary(summary);
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

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-ENERGY-HASHRATE-OPTIONS-STATE-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let records = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": public_record(value) }))
        .collect::<Vec<_>>();
    public_record_root(domain, &records)
}

fn value_map_root(domain: &str, map: &BTreeMap<String, Value>) -> String {
    let records = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": value }))
        .collect::<Vec<_>>();
    public_record_root(domain, &records)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let records = set
        .iter()
        .map(|value| json!({ "nullifier": value }))
        .collect::<Vec<_>>();
    public_record_root(domain, &records)
}

fn set_json_field(record: &mut Value, key: &str, value: Value) {
    if let Value::Object(map) = record {
        map.insert(key.to_string(), value);
    }
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn ensure_unique<T>(map: &BTreeMap<String, T>, key: &str, label: &str) -> Result<()> {
    ensure(
        !map.contains_key(key),
        &format!("{label} already exists: {key}"),
    )
}

fn id(domain: &str, label: &str, height: u64) -> String {
    domain_hash(
        "ENERGY-HASHRATE-OPTIONS-ID",
        &[
            HashPart::Str(domain),
            HashPart::Str(label),
            HashPart::U64(height),
        ],
        16,
    )
}

fn commitment(domain: &str, label: &str, nonce: u64) -> String {
    domain_hash(
        "ENERGY-HASHRATE-OPTIONS-COMMITMENT",
        &[
            HashPart::Str(domain),
            HashPart::Str(label),
            HashPart::U64(nonce),
        ],
        32,
    )
}
