use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedSequencerDelayInsurancePerpsRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_SEQUENCER_DELAY_INSURANCE_PERPS_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-tokenized-sequencer-delay-insurance-perps-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_SEQUENCER_DELAY_INSURANCE_PERPS_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_CLAIM_COUPON_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-sequencer-delay-insurance-claim-coupon-v1";
pub const CONFIDENTIAL_FUNDING_CURVE_SUITE: &str =
    "confidential-tokenized-sequencer-delay-insurance-perps-funding-curve-root-v1";
pub const SEALED_PERPS_TRANCHE_SUITE: &str =
    "sealed-confidential-sequencer-delay-insurance-perps-tranche-root-v1";
pub const DELAY_OBSERVATION_SUITE: &str = "pq-confidential-sequencer-delay-observation-root-v1";
pub const POSITION_NOTE_SUITE: &str =
    "sealed-confidential-sequencer-delay-insurance-perps-position-note-root-v1";
pub const COLLATERAL_ROOT_SUITE: &str =
    "privacy-preserving-sequencer-delay-insurance-perps-collateral-root-v1";
pub const MARGIN_ROOT_SUITE: &str =
    "privacy-preserving-sequencer-delay-insurance-perps-margin-root-v1";
pub const PREMIUM_ROOT_SUITE: &str =
    "privacy-preserving-sequencer-delay-insurance-perps-premium-root-v1";
pub const CLAIM_COUPON_ROOT_SUITE: &str =
    "pq-signed-sequencer-delay-insurance-perps-claim-coupon-root-v1";
pub const LOW_FEE_NETTED_FUNDING_SUITE: &str =
    "low-fee-confidential-sequencer-delay-insurance-perps-netted-funding-root-v1";
pub const PUBLIC_RECORD_SUITE: &str =
    "privacy-preserving-roots-only-sequencer-delay-insurance-perps-public-record-v1";
pub const STATE_ROOT_SUITE: &str =
    "private-l2-pq-confidential-tokenized-sequencer-delay-insurance-perps-state-root-v1";
pub const PAYLOAD_ROOT_SUITE: &str =
    "private-l2-pq-confidential-tokenized-sequencer-delay-insurance-perps-payload-root-v1";
pub const DEVNET_REPLAY_DOMAIN: &str =
    "nebula-private-l2-pq-confidential-tokenized-sequencer-delay-insurance-perps-devnet";
pub const DEVNET_RUNTIME_ID: &str = "private-l2-pq-sequencer-delay-insurance-perps-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_456_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 5_184_000;
pub const DEVNET_EPOCH: u64 = 23_040;
pub const DEVNET_DELAY_INDEX_ID: &str = "monero-private-l2-sequencer-delay-index-devnet";
pub const DEVNET_INSURANCE_TOKEN_ID: &str = "tsdip-devnet";
pub const DEVNET_COLLATERAL_ASSET_ID: &str = "dusd-private-devnet";
pub const DEVNET_MARGIN_ASSET_ID: &str = "sxmr-margin-devnet";
pub const DEVNET_PREMIUM_ASSET_ID: &str = "nebula-premium-credit-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_LOW_FEE_SETTLEMENT_BPS: u64 = 2;
pub const DEFAULT_PROTOCOL_FEE_BPS: u64 = 1;
pub const DEFAULT_PREMIUM_FEE_BPS: u64 = 8;
pub const DEFAULT_MAKER_REBATE_BPS: u64 = 1_600;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_OBSERVER_QUORUM: u16 = 5;
pub const DEFAULT_COUPON_QUORUM: u16 = 4;
pub const DEFAULT_FUNDING_QUORUM: u16 = 5;
pub const DEFAULT_POSITION_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_CLAIM_TTL_BLOCKS: u64 = 128;
pub const DEFAULT_FUNDING_INTERVAL_BLOCKS: u64 = 20;
pub const DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 24;
pub const DEFAULT_DELAY_OBSERVATION_WINDOW_BLOCKS: u64 = 12;
pub const DEFAULT_MIN_COLLATERAL_COVERAGE_BPS: u64 = 11_500;
pub const DEFAULT_MIN_MARGIN_COVERAGE_BPS: u64 = 1_200;
pub const DEFAULT_MIN_PREMIUM_COVERAGE_BPS: u64 = 1_050;
pub const DEFAULT_MAX_PAYOUT_BPS: u64 = 8_750;
pub const DEFAULT_MAX_POOL_UTILIZATION_BPS: u64 = 8_500;
pub const DEFAULT_MAX_FUNDING_RATE_BPS: i64 = 450;
pub const DEFAULT_SOFT_DELAY_THRESHOLD_MS: u64 = 1_500;
pub const DEFAULT_HARD_DELAY_THRESHOLD_MS: u64 = 6_000;
pub const DEFAULT_CATASTROPHIC_DELAY_THRESHOLD_MS: u64 = 30_000;
pub const DEFAULT_LOW_FEE_BATCH_LIMIT: usize = 4_096;
pub const DEFAULT_MAX_TRANCHES: usize = 262_144;
pub const DEFAULT_MAX_POSITIONS: usize = 1_048_576;
pub const DEFAULT_MAX_FUNDING_CURVES: usize = 262_144;
pub const DEFAULT_MAX_CLAIM_COUPONS: usize = 1_048_576;
pub const DEFAULT_MAX_SETTLEMENTS: usize = 262_144;
pub const DEFAULT_MAX_OBSERVATIONS: usize = 524_288;
pub const DEFAULT_MAX_NULLIFIERS: usize = 2_097_152;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SequencerDelayRiskKind {
    SoftDelay,
    HardDelay,
    CatastrophicDelay,
    CensorshipDelay,
    MicroblockStall,
    PreconfirmationMiss,
    ForcedInclusionLag,
    OracleClockDrift,
}

impl SequencerDelayRiskKind {
    pub fn base_weight_bps(self) -> u64 {
        match self {
            Self::SoftDelay => 700,
            Self::HardDelay => 1_400,
            Self::CatastrophicDelay => 2_200,
            Self::CensorshipDelay => 1_900,
            Self::MicroblockStall => 1_250,
            Self::PreconfirmationMiss => 950,
            Self::ForcedInclusionLag => 1_650,
            Self::OracleClockDrift => 850,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionSide {
    LongDelayProtection,
    ShortDelayProtection,
    TrancheBackstop,
    PremiumMaker,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrancheStatus {
    Draft,
    Sealed,
    Active,
    FundingOnly,
    ClaimsOnly,
    DelayGuarded,
    ReduceOnly,
    Halted,
    Settled,
    Retired,
}

impl TrancheStatus {
    pub fn accepts_positions(self) -> bool {
        matches!(self, Self::Active | Self::DelayGuarded)
    }

    pub fn accepts_funding(self) -> bool {
        matches!(self, Self::Active | Self::FundingOnly | Self::ReduceOnly)
    }

    pub fn accepts_claims(self) -> bool {
        matches!(self, Self::Active | Self::ClaimsOnly | Self::DelayGuarded)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionStatus {
    Pending,
    Open,
    FundingAccruing,
    DelayObserved,
    ClaimPending,
    Couponed,
    Settling,
    Settled,
    Liquidated,
    Expired,
    Quarantined,
}

impl PositionStatus {
    pub fn open(self) -> bool {
        matches!(
            self,
            Self::Open
                | Self::FundingAccruing
                | Self::DelayObserved
                | Self::ClaimPending
                | Self::Couponed
                | Self::Settling
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStatus {
    Submitted,
    Encrypted,
    PrivacyChecked,
    QuorumPending,
    Attested,
    Actionable,
    UsedInClaim,
    Dismissed,
    Expired,
    Quarantined,
}

impl ObservationStatus {
    pub fn actionable(self) -> bool {
        matches!(self, Self::Attested | Self::Actionable | Self::UsedInClaim)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FundingCurveStatus {
    Proposed,
    PqQuorumSigned,
    Active,
    Frozen,
    Superseded,
    Disputed,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Draft,
    PqSigned,
    Admitted,
    Netted,
    Clearing,
    Settled,
    Redeemed,
    Disputed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Draft,
    Collecting,
    Proving,
    Posted,
    Settled,
    Rejected,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub runtime_id: String,
    pub delay_index_id: String,
    pub insurance_token_id: String,
    pub collateral_asset_id: String,
    pub margin_asset_id: String,
    pub premium_asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_claim_coupon_suite: String,
    pub confidential_funding_curve_suite: String,
    pub low_fee_netted_funding_suite: String,
    pub replay_domain: String,
    pub low_fee_settlement_bps: u64,
    pub protocol_fee_bps: u64,
    pub premium_fee_bps: u64,
    pub maker_rebate_bps: u64,
    pub min_collateral_coverage_bps: u64,
    pub min_margin_coverage_bps: u64,
    pub min_premium_coverage_bps: u64,
    pub max_payout_bps: u64,
    pub max_pool_utilization_bps: u64,
    pub max_funding_rate_bps: i64,
    pub soft_delay_threshold_ms: u64,
    pub hard_delay_threshold_ms: u64,
    pub catastrophic_delay_threshold_ms: u64,
    pub funding_interval_blocks: u64,
    pub claim_ttl_blocks: u64,
    pub position_ttl_blocks: u64,
    pub settlement_window_blocks: u64,
    pub delay_observation_window_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub observer_quorum: u16,
    pub coupon_quorum: u16,
    pub funding_quorum: u16,
    pub low_fee_batch_limit: usize,
    pub max_tranches: usize,
    pub max_positions: usize,
    pub max_funding_curves: usize,
    pub max_claim_coupons: usize,
    pub max_settlements: usize,
    pub max_observations: usize,
    pub max_nullifiers: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            runtime_id: DEVNET_RUNTIME_ID.to_string(),
            delay_index_id: DEVNET_DELAY_INDEX_ID.to_string(),
            insurance_token_id: DEVNET_INSURANCE_TOKEN_ID.to_string(),
            collateral_asset_id: DEVNET_COLLATERAL_ASSET_ID.to_string(),
            margin_asset_id: DEVNET_MARGIN_ASSET_ID.to_string(),
            premium_asset_id: DEVNET_PREMIUM_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_claim_coupon_suite: PQ_CLAIM_COUPON_SUITE.to_string(),
            confidential_funding_curve_suite: CONFIDENTIAL_FUNDING_CURVE_SUITE.to_string(),
            low_fee_netted_funding_suite: LOW_FEE_NETTED_FUNDING_SUITE.to_string(),
            replay_domain: DEVNET_REPLAY_DOMAIN.to_string(),
            low_fee_settlement_bps: DEFAULT_LOW_FEE_SETTLEMENT_BPS,
            protocol_fee_bps: DEFAULT_PROTOCOL_FEE_BPS,
            premium_fee_bps: DEFAULT_PREMIUM_FEE_BPS,
            maker_rebate_bps: DEFAULT_MAKER_REBATE_BPS,
            min_collateral_coverage_bps: DEFAULT_MIN_COLLATERAL_COVERAGE_BPS,
            min_margin_coverage_bps: DEFAULT_MIN_MARGIN_COVERAGE_BPS,
            min_premium_coverage_bps: DEFAULT_MIN_PREMIUM_COVERAGE_BPS,
            max_payout_bps: DEFAULT_MAX_PAYOUT_BPS,
            max_pool_utilization_bps: DEFAULT_MAX_POOL_UTILIZATION_BPS,
            max_funding_rate_bps: DEFAULT_MAX_FUNDING_RATE_BPS,
            soft_delay_threshold_ms: DEFAULT_SOFT_DELAY_THRESHOLD_MS,
            hard_delay_threshold_ms: DEFAULT_HARD_DELAY_THRESHOLD_MS,
            catastrophic_delay_threshold_ms: DEFAULT_CATASTROPHIC_DELAY_THRESHOLD_MS,
            funding_interval_blocks: DEFAULT_FUNDING_INTERVAL_BLOCKS,
            claim_ttl_blocks: DEFAULT_CLAIM_TTL_BLOCKS,
            position_ttl_blocks: DEFAULT_POSITION_TTL_BLOCKS,
            settlement_window_blocks: DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            delay_observation_window_blocks: DEFAULT_DELAY_OBSERVATION_WINDOW_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            observer_quorum: DEFAULT_OBSERVER_QUORUM,
            coupon_quorum: DEFAULT_COUPON_QUORUM,
            funding_quorum: DEFAULT_FUNDING_QUORUM,
            low_fee_batch_limit: DEFAULT_LOW_FEE_BATCH_LIMIT,
            max_tranches: DEFAULT_MAX_TRANCHES,
            max_positions: DEFAULT_MAX_POSITIONS,
            max_funding_curves: DEFAULT_MAX_FUNDING_CURVES,
            max_claim_coupons: DEFAULT_MAX_CLAIM_COUPONS,
            max_settlements: DEFAULT_MAX_SETTLEMENTS,
            max_observations: DEFAULT_MAX_OBSERVATIONS,
            max_nullifiers: DEFAULT_MAX_NULLIFIERS,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        require(
            self.protocol_version == PROTOCOL_VERSION,
            "unsupported protocol version",
        )?;
        require(
            self.schema_version == SCHEMA_VERSION,
            "unsupported schema version",
        )?;
        require_nonempty("chain_id", &self.chain_id)?;
        require_nonempty("runtime_id", &self.runtime_id)?;
        require_nonempty("delay_index_id", &self.delay_index_id)?;
        require_bps("low_fee_settlement_bps", self.low_fee_settlement_bps)?;
        require_bps("protocol_fee_bps", self.protocol_fee_bps)?;
        require_bps("premium_fee_bps", self.premium_fee_bps)?;
        require_bps("maker_rebate_bps", self.maker_rebate_bps)?;
        require_bps(
            "min_collateral_coverage_bps",
            self.min_collateral_coverage_bps,
        )?;
        require_bps("min_margin_coverage_bps", self.min_margin_coverage_bps)?;
        require_bps("min_premium_coverage_bps", self.min_premium_coverage_bps)?;
        require_bps("max_payout_bps", self.max_payout_bps)?;
        require_bps("max_pool_utilization_bps", self.max_pool_utilization_bps)?;
        require(
            self.max_funding_rate_bps >= 0,
            "max funding clamp must be positive",
        )?;
        require(
            self.hard_delay_threshold_ms > self.soft_delay_threshold_ms,
            "hard delay threshold must exceed soft threshold",
        )?;
        require(
            self.catastrophic_delay_threshold_ms > self.hard_delay_threshold_ms,
            "catastrophic delay threshold must exceed hard threshold",
        )?;
        require(self.observer_quorum > 0, "observer quorum must be positive")?;
        require(self.coupon_quorum > 0, "coupon quorum must be positive")?;
        require(self.funding_quorum > 0, "funding quorum must be positive")?;
        require(
            self.low_fee_batch_limit > 0,
            "low fee batch limit must be positive",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "runtime_id": self.runtime_id,
            "delay_index_id": self.delay_index_id,
            "insurance_token_id": self.insurance_token_id,
            "collateral_asset_id": self.collateral_asset_id,
            "margin_asset_id": self.margin_asset_id,
            "premium_asset_id": self.premium_asset_id,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "pq_claim_coupon_suite": self.pq_claim_coupon_suite,
            "confidential_funding_curve_suite": self.confidential_funding_curve_suite,
            "low_fee_netted_funding_suite": self.low_fee_netted_funding_suite,
            "replay_domain": self.replay_domain,
            "low_fee_settlement_bps": self.low_fee_settlement_bps,
            "protocol_fee_bps": self.protocol_fee_bps,
            "premium_fee_bps": self.premium_fee_bps,
            "maker_rebate_bps": self.maker_rebate_bps,
            "min_collateral_coverage_bps": self.min_collateral_coverage_bps,
            "min_margin_coverage_bps": self.min_margin_coverage_bps,
            "min_premium_coverage_bps": self.min_premium_coverage_bps,
            "max_payout_bps": self.max_payout_bps,
            "max_pool_utilization_bps": self.max_pool_utilization_bps,
            "max_funding_rate_bps": self.max_funding_rate_bps,
            "soft_delay_threshold_ms": self.soft_delay_threshold_ms,
            "hard_delay_threshold_ms": self.hard_delay_threshold_ms,
            "catastrophic_delay_threshold_ms": self.catastrophic_delay_threshold_ms,
            "funding_interval_blocks": self.funding_interval_blocks,
            "claim_ttl_blocks": self.claim_ttl_blocks,
            "position_ttl_blocks": self.position_ttl_blocks,
            "settlement_window_blocks": self.settlement_window_blocks,
            "delay_observation_window_blocks": self.delay_observation_window_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "observer_quorum": self.observer_quorum,
            "coupon_quorum": self.coupon_quorum,
            "funding_quorum": self.funding_quorum,
            "low_fee_batch_limit": self.low_fee_batch_limit,
            "max_tranches": self.max_tranches,
            "max_positions": self.max_positions,
            "max_funding_curves": self.max_funding_curves,
            "max_claim_coupons": self.max_claim_coupons,
            "max_settlements": self.max_settlements,
            "max_observations": self.max_observations,
            "max_nullifiers": self.max_nullifiers,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub tranches: u64,
    pub active_tranches: u64,
    pub positions: u64,
    pub open_positions: u64,
    pub funding_curves: u64,
    pub active_funding_curves: u64,
    pub delay_observations: u64,
    pub actionable_observations: u64,
    pub claim_coupons: u64,
    pub admitted_claim_coupons: u64,
    pub settlements: u64,
    pub settled_batches: u64,
    pub collateral_roots: u64,
    pub margin_roots: u64,
    pub premium_roots: u64,
    pub consumed_nullifiers: u64,
    pub public_summaries: u64,
    pub total_notional_units: u128,
    pub total_collateral_units: u128,
    pub total_margin_units: u128,
    pub total_premium_units: u128,
    pub total_claim_units: u128,
    pub total_netted_funding_units: i128,
    pub total_low_fee_units: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "tranches": self.tranches,
            "active_tranches": self.active_tranches,
            "positions": self.positions,
            "open_positions": self.open_positions,
            "funding_curves": self.funding_curves,
            "active_funding_curves": self.active_funding_curves,
            "delay_observations": self.delay_observations,
            "actionable_observations": self.actionable_observations,
            "claim_coupons": self.claim_coupons,
            "admitted_claim_coupons": self.admitted_claim_coupons,
            "settlements": self.settlements,
            "settled_batches": self.settled_batches,
            "collateral_roots": self.collateral_roots,
            "margin_roots": self.margin_roots,
            "premium_roots": self.premium_roots,
            "consumed_nullifiers": self.consumed_nullifiers,
            "public_summaries": self.public_summaries,
            "total_notional_units": self.total_notional_units.to_string(),
            "total_collateral_units": self.total_collateral_units.to_string(),
            "total_margin_units": self.total_margin_units.to_string(),
            "total_premium_units": self.total_premium_units.to_string(),
            "total_claim_units": self.total_claim_units.to_string(),
            "total_netted_funding_units": self.total_netted_funding_units.to_string(),
            "total_low_fee_units": self.total_low_fee_units.to_string(),
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub tranches_root: String,
    pub positions_root: String,
    pub funding_curves_root: String,
    pub delay_observations_root: String,
    pub claim_coupons_root: String,
    pub settlements_root: String,
    pub collateral_root: String,
    pub margin_root: String,
    pub premium_root: String,
    pub nullifiers_root: String,
    pub public_summaries_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "tranches_root": self.tranches_root,
            "positions_root": self.positions_root,
            "funding_curves_root": self.funding_curves_root,
            "delay_observations_root": self.delay_observations_root,
            "claim_coupons_root": self.claim_coupons_root,
            "settlements_root": self.settlements_root,
            "collateral_root": self.collateral_root,
            "margin_root": self.margin_root,
            "premium_root": self.premium_root,
            "nullifiers_root": self.nullifiers_root,
            "public_summaries_root": self.public_summaries_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }

    pub fn compute_state_root(&self, l2_height: u64, monero_height: u64, epoch: u64) -> String {
        let mut record = self.public_record();
        set_json_field(&mut record, "state_root", json!(""));
        domain_hash(
            STATE_ROOT_SUITE,
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(l2_height),
                HashPart::U64(monero_height),
                HashPart::U64(epoch),
                HashPart::Json(&record),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SealedPerpsTranche {
    pub tranche_id: String,
    pub risk_kind: SequencerDelayRiskKind,
    pub status: TrancheStatus,
    pub notional_cap_units: u128,
    pub collateral_root: String,
    pub margin_root: String,
    pub premium_root: String,
    pub funding_curve_id: String,
    pub maturity_l2_height: u64,
    pub delay_floor_ms: u64,
    pub delay_cap_ms: u64,
    pub leverage_bps: u64,
    pub attachment_bps: u64,
    pub detachment_bps: u64,
    pub utilization_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub sealed_terms_root: String,
    pub token_commitment_root: String,
    pub created_l2_height: u64,
}

impl SealedPerpsTranche {
    pub fn validate(&self, config: &Config, l2_height: u64) -> Result<()> {
        require_nonempty("tranche_id", &self.tranche_id)?;
        require_nonempty("funding_curve_id", &self.funding_curve_id)?;
        require_nonzero_u128("notional_cap_units", self.notional_cap_units)?;
        require_root("collateral_root", &self.collateral_root)?;
        require_root("margin_root", &self.margin_root)?;
        require_root("premium_root", &self.premium_root)?;
        require_root("sealed_terms_root", &self.sealed_terms_root)?;
        require_root("token_commitment_root", &self.token_commitment_root)?;
        require_bps("leverage_bps", self.leverage_bps)?;
        require_bps("attachment_bps", self.attachment_bps)?;
        require_bps("detachment_bps", self.detachment_bps)?;
        require_bps("utilization_bps", self.utilization_bps)?;
        require(
            self.detachment_bps > self.attachment_bps,
            "detachment must exceed attachment",
        )?;
        require(
            self.delay_cap_ms >= self.delay_floor_ms,
            "delay cap below floor",
        )?;
        require(
            self.maturity_l2_height > l2_height,
            "tranche maturity must be in the future",
        )?;
        require_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "tranche_id": self.tranche_id,
            "risk_kind": self.risk_kind,
            "status": self.status,
            "notional_cap_units": self.notional_cap_units.to_string(),
            "collateral_root": self.collateral_root,
            "margin_root": self.margin_root,
            "premium_root": self.premium_root,
            "funding_curve_id": self.funding_curve_id,
            "maturity_l2_height": self.maturity_l2_height,
            "delay_floor_ms": self.delay_floor_ms,
            "delay_cap_ms": self.delay_cap_ms,
            "leverage_bps": self.leverage_bps,
            "attachment_bps": self.attachment_bps,
            "detachment_bps": self.detachment_bps,
            "utilization_bps": self.utilization_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "sealed_terms_root": self.sealed_terms_root,
            "token_commitment_root": self.token_commitment_root,
            "created_l2_height": self.created_l2_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PositionNote {
    pub position_id: String,
    pub tranche_id: String,
    pub side: PositionSide,
    pub status: PositionStatus,
    pub owner_commitment: String,
    pub note_commitment: String,
    pub collateral_commitment: String,
    pub margin_commitment: String,
    pub entry_funding_curve_id: String,
    pub notional_units: u128,
    pub collateral_units: u128,
    pub margin_units: u128,
    pub premium_units: u128,
    pub max_delay_ms: u64,
    pub entry_l2_height: u64,
    pub expiry_l2_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl PositionNote {
    pub fn validate(&self, config: &Config, tranche: &SealedPerpsTranche) -> Result<()> {
        require_nonempty("position_id", &self.position_id)?;
        require(
            self.tranche_id == tranche.tranche_id,
            "position tranche mismatch",
        )?;
        require(
            tranche.status.accepts_positions(),
            "tranche does not accept positions",
        )?;
        require_root("owner_commitment", &self.owner_commitment)?;
        require_root("note_commitment", &self.note_commitment)?;
        require_root("collateral_commitment", &self.collateral_commitment)?;
        require_root("margin_commitment", &self.margin_commitment)?;
        require_nonempty("entry_funding_curve_id", &self.entry_funding_curve_id)?;
        require_nonzero_u128("notional_units", self.notional_units)?;
        require_nonzero_u128("collateral_units", self.collateral_units)?;
        require_nonzero_u128("margin_units", self.margin_units)?;
        require(
            self.expiry_l2_height > self.entry_l2_height,
            "position expiry must exceed entry",
        )?;
        require(
            self.max_delay_ms >= tranche.delay_floor_ms,
            "position max delay below tranche floor",
        )?;
        require_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        require(
            coverage_bps(self.collateral_units, self.notional_units)?
                >= config.min_collateral_coverage_bps,
            "collateral coverage below configured floor",
        )?;
        require(
            coverage_bps(self.margin_units, self.notional_units)? >= config.min_margin_coverage_bps,
            "margin coverage below configured floor",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "position_id": self.position_id,
            "tranche_id": self.tranche_id,
            "side": self.side,
            "status": self.status,
            "owner_commitment": self.owner_commitment,
            "note_commitment": self.note_commitment,
            "collateral_commitment": self.collateral_commitment,
            "margin_commitment": self.margin_commitment,
            "entry_funding_curve_id": self.entry_funding_curve_id,
            "notional_units": self.notional_units.to_string(),
            "collateral_units": self.collateral_units.to_string(),
            "margin_units": self.margin_units.to_string(),
            "premium_units": self.premium_units.to_string(),
            "max_delay_ms": self.max_delay_ms,
            "entry_l2_height": self.entry_l2_height,
            "expiry_l2_height": self.expiry_l2_height,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FundingCurve {
    pub funding_curve_id: String,
    pub tranche_id: String,
    pub status: FundingCurveStatus,
    pub private_curve_root: String,
    pub utilization_root: String,
    pub volatility_root: String,
    pub delay_surface_root: String,
    pub base_rate_bps: i64,
    pub slope_bps: i64,
    pub clamp_bps: i64,
    pub funding_interval_blocks: u64,
    pub quorum_weight: u16,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub effective_l2_height: u64,
}

impl FundingCurve {
    pub fn validate(&self, config: &Config, tranche: &SealedPerpsTranche) -> Result<()> {
        require_nonempty("funding_curve_id", &self.funding_curve_id)?;
        require(
            self.tranche_id == tranche.tranche_id,
            "funding curve tranche mismatch",
        )?;
        require_root("private_curve_root", &self.private_curve_root)?;
        require_root("utilization_root", &self.utilization_root)?;
        require_root("volatility_root", &self.volatility_root)?;
        require_root("delay_surface_root", &self.delay_surface_root)?;
        require(
            self.clamp_bps.abs() <= config.max_funding_rate_bps,
            "funding clamp exceeds configured maximum",
        )?;
        require(
            self.funding_interval_blocks > 0,
            "funding interval must be positive",
        )?;
        require(
            self.quorum_weight >= config.funding_quorum,
            "funding curve lacks configured PQ quorum",
        )?;
        require_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "funding_curve_id": self.funding_curve_id,
            "tranche_id": self.tranche_id,
            "status": self.status,
            "private_curve_root": self.private_curve_root,
            "utilization_root": self.utilization_root,
            "volatility_root": self.volatility_root,
            "delay_surface_root": self.delay_surface_root,
            "base_rate_bps": self.base_rate_bps,
            "slope_bps": self.slope_bps,
            "clamp_bps": self.clamp_bps,
            "funding_interval_blocks": self.funding_interval_blocks,
            "quorum_weight": self.quorum_weight,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "effective_l2_height": self.effective_l2_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SequencerDelayObservation {
    pub observation_id: String,
    pub tranche_id: String,
    pub risk_kind: SequencerDelayRiskKind,
    pub status: ObservationStatus,
    pub sequencer_commitment: String,
    pub delay_window_root: String,
    pub observed_delay_ms: u64,
    pub missed_slots: u64,
    pub preconfirmation_lag_ms: u64,
    pub forced_inclusion_lag_blocks: u64,
    pub oracle_attestation_root: String,
    pub observer_quorum_weight: u16,
    pub l2_height: u64,
    pub monero_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl SequencerDelayObservation {
    pub fn validate(&self, config: &Config, tranche: &SealedPerpsTranche) -> Result<()> {
        require_nonempty("observation_id", &self.observation_id)?;
        require(
            self.tranche_id == tranche.tranche_id,
            "observation tranche mismatch",
        )?;
        require_root("sequencer_commitment", &self.sequencer_commitment)?;
        require_root("delay_window_root", &self.delay_window_root)?;
        require_root("oracle_attestation_root", &self.oracle_attestation_root)?;
        require(
            self.observer_quorum_weight >= config.observer_quorum,
            "observation lacks configured observer quorum",
        )?;
        require(
            self.observed_delay_ms >= tranche.delay_floor_ms,
            "observed delay below tranche floor",
        )?;
        require_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )
    }

    pub fn severity_bps(&self, config: &Config) -> u64 {
        if self.observed_delay_ms >= config.catastrophic_delay_threshold_ms {
            10_000
        } else if self.observed_delay_ms >= config.hard_delay_threshold_ms {
            6_500
        } else if self.observed_delay_ms >= config.soft_delay_threshold_ms {
            3_000
        } else {
            self.risk_kind.base_weight_bps().min(2_000)
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "observation_id": self.observation_id,
            "tranche_id": self.tranche_id,
            "risk_kind": self.risk_kind,
            "status": self.status,
            "sequencer_commitment": self.sequencer_commitment,
            "delay_window_root": self.delay_window_root,
            "observed_delay_ms": self.observed_delay_ms,
            "missed_slots": self.missed_slots,
            "preconfirmation_lag_ms": self.preconfirmation_lag_ms,
            "forced_inclusion_lag_blocks": self.forced_inclusion_lag_blocks,
            "oracle_attestation_root": self.oracle_attestation_root,
            "observer_quorum_weight": self.observer_quorum_weight,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqClaimCoupon {
    pub coupon_id: String,
    pub tranche_id: String,
    pub position_id: String,
    pub observation_id: String,
    pub status: CouponStatus,
    pub claimant_commitment: String,
    pub coupon_commitment: String,
    pub payout_commitment: String,
    pub claim_amount_units: u128,
    pub premium_offset_units: u128,
    pub coupon_quorum_weight: u16,
    pub expires_l2_height: u64,
    pub nullifier: String,
    pub pq_authorization_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl PqClaimCoupon {
    pub fn validate(
        &self,
        config: &Config,
        tranche: &SealedPerpsTranche,
        position: &PositionNote,
        observation: &SequencerDelayObservation,
    ) -> Result<()> {
        require_nonempty("coupon_id", &self.coupon_id)?;
        require(
            self.tranche_id == tranche.tranche_id,
            "coupon tranche mismatch",
        )?;
        require(
            self.position_id == position.position_id,
            "coupon position mismatch",
        )?;
        require(
            self.observation_id == observation.observation_id,
            "coupon observation mismatch",
        )?;
        require(
            tranche.status.accepts_claims(),
            "tranche does not accept claims",
        )?;
        require(position.status.open(), "position is not claimable")?;
        require(
            observation.status.actionable(),
            "observation is not actionable",
        )?;
        require_root("claimant_commitment", &self.claimant_commitment)?;
        require_root("coupon_commitment", &self.coupon_commitment)?;
        require_root("payout_commitment", &self.payout_commitment)?;
        require_root("pq_authorization_root", &self.pq_authorization_root)?;
        require_nonempty("nullifier", &self.nullifier)?;
        require_nonzero_u128("claim_amount_units", self.claim_amount_units)?;
        require(
            self.coupon_quorum_weight >= config.coupon_quorum,
            "claim coupon lacks configured PQ quorum",
        )?;
        require(
            self.claim_amount_units <= payout_cap(position.notional_units, config.max_payout_bps)?,
            "claim amount exceeds configured payout cap",
        )?;
        require_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "coupon_id": self.coupon_id,
            "tranche_id": self.tranche_id,
            "position_id": self.position_id,
            "observation_id": self.observation_id,
            "status": self.status,
            "claimant_commitment": self.claimant_commitment,
            "coupon_commitment": self.coupon_commitment,
            "payout_commitment": self.payout_commitment,
            "claim_amount_units": self.claim_amount_units.to_string(),
            "premium_offset_units": self.premium_offset_units.to_string(),
            "coupon_quorum_weight": self.coupon_quorum_weight,
            "expires_l2_height": self.expires_l2_height,
            "nullifier": self.nullifier,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeNettedFundingSettlement {
    pub settlement_id: String,
    pub tranche_id: String,
    pub status: SettlementStatus,
    pub funding_curve_id: String,
    pub position_set_root: String,
    pub debit_root: String,
    pub credit_root: String,
    pub fee_root: String,
    pub net_funding_units: i128,
    pub protocol_fee_units: u128,
    pub maker_rebate_units: u128,
    pub low_fee_units: u128,
    pub settled_positions: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub posted_l2_height: u64,
}

impl LowFeeNettedFundingSettlement {
    pub fn validate(
        &self,
        config: &Config,
        tranche: &SealedPerpsTranche,
        curve: &FundingCurve,
    ) -> Result<()> {
        require_nonempty("settlement_id", &self.settlement_id)?;
        require(
            self.tranche_id == tranche.tranche_id,
            "settlement tranche mismatch",
        )?;
        require(
            self.funding_curve_id == curve.funding_curve_id,
            "settlement funding curve mismatch",
        )?;
        require(
            tranche.status.accepts_funding(),
            "tranche does not accept funding",
        )?;
        require_root("position_set_root", &self.position_set_root)?;
        require_root("debit_root", &self.debit_root)?;
        require_root("credit_root", &self.credit_root)?;
        require_root("fee_root", &self.fee_root)?;
        require(
            self.settled_positions > 0,
            "settlement must include positions",
        )?;
        require(
            self.settled_positions as usize <= config.low_fee_batch_limit,
            "settlement exceeds low-fee batch limit",
        )?;
        require_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "tranche_id": self.tranche_id,
            "status": self.status,
            "funding_curve_id": self.funding_curve_id,
            "position_set_root": self.position_set_root,
            "debit_root": self.debit_root,
            "credit_root": self.credit_root,
            "fee_root": self.fee_root,
            "net_funding_units": self.net_funding_units.to_string(),
            "protocol_fee_units": self.protocol_fee_units.to_string(),
            "maker_rebate_units": self.maker_rebate_units.to_string(),
            "low_fee_units": self.low_fee_units.to_string(),
            "settled_positions": self.settled_positions,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "posted_l2_height": self.posted_l2_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicSummary {
    pub summary_id: String,
    pub tranche_id: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub tranche_root: String,
    pub position_root: String,
    pub funding_root: String,
    pub observation_root: String,
    pub claim_coupon_root: String,
    pub settlement_root: String,
    pub collateral_root: String,
    pub margin_root: String,
    pub premium_root: String,
    pub nullifier_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl PublicSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "tranche_id": self.tranche_id,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
            "tranche_root": self.tranche_root,
            "position_root": self.position_root,
            "funding_root": self.funding_root,
            "observation_root": self.observation_root,
            "claim_coupon_root": self.claim_coupon_root,
            "settlement_root": self.settlement_root,
            "collateral_root": self.collateral_root,
            "margin_root": self.margin_root,
            "premium_root": self.premium_root,
            "nullifier_root": self.nullifier_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub tranches: BTreeMap<String, SealedPerpsTranche>,
    pub positions: BTreeMap<String, PositionNote>,
    pub funding_curves: BTreeMap<String, FundingCurve>,
    pub delay_observations: BTreeMap<String, SequencerDelayObservation>,
    pub claim_coupons: BTreeMap<String, PqClaimCoupon>,
    pub settlements: BTreeMap<String, LowFeeNettedFundingSettlement>,
    pub collateral_roots: BTreeMap<String, String>,
    pub margin_roots: BTreeMap<String, String>,
    pub premium_roots: BTreeMap<String, String>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub public_summaries: BTreeMap<String, PublicSummary>,
    pub counters: Counters,
    pub roots: Roots,
}

impl State {
    pub fn new(config: Config, l2_height: u64, monero_height: u64, epoch: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            l2_height,
            monero_height,
            epoch,
            tranches: BTreeMap::new(),
            positions: BTreeMap::new(),
            funding_curves: BTreeMap::new(),
            delay_observations: BTreeMap::new(),
            claim_coupons: BTreeMap::new(),
            settlements: BTreeMap::new(),
            collateral_roots: BTreeMap::new(),
            margin_roots: BTreeMap::new(),
            premium_roots: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            public_summaries: BTreeMap::new(),
            counters: Counters::default(),
            roots: Roots::default(),
        };
        state.refresh();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(
            Config::default(),
            DEVNET_L2_HEIGHT,
            DEVNET_MONERO_HEIGHT,
            DEVNET_EPOCH,
        )
        .expect("valid devnet sequencer delay insurance perps config");
        state.seed_devnet();
        state
    }

    pub fn advance_heights(
        &mut self,
        l2_height: u64,
        monero_height: u64,
        epoch: u64,
    ) -> Result<()> {
        require(l2_height >= self.l2_height, "l2 height cannot rewind")?;
        require(
            monero_height >= self.monero_height,
            "monero height cannot rewind",
        )?;
        require(epoch >= self.epoch, "epoch cannot rewind")?;
        self.l2_height = l2_height;
        self.monero_height = monero_height;
        self.epoch = epoch;
        self.refresh();
        Ok(())
    }

    pub fn add_tranche(&mut self, tranche: SealedPerpsTranche) -> Result<()> {
        ensure_capacity("tranches", self.tranches.len(), self.config.max_tranches)?;
        tranche.validate(&self.config, self.l2_height)?;
        insert_unique(
            &mut self.collateral_roots,
            tranche.tranche_id.clone(),
            tranche.collateral_root.clone(),
        )?;
        insert_unique(
            &mut self.margin_roots,
            tranche.tranche_id.clone(),
            tranche.margin_root.clone(),
        )?;
        insert_unique(
            &mut self.premium_roots,
            tranche.tranche_id.clone(),
            tranche.premium_root.clone(),
        )?;
        insert_unique(&mut self.tranches, tranche.tranche_id.clone(), tranche)?;
        self.refresh();
        Ok(())
    }

    pub fn add_position(&mut self, position: PositionNote) -> Result<()> {
        ensure_capacity("positions", self.positions.len(), self.config.max_positions)?;
        let tranche = self
            .tranches
            .get(&position.tranche_id)
            .ok_or_else(|| format!("missing tranche {}", position.tranche_id))?;
        position.validate(&self.config, tranche)?;
        insert_unique(&mut self.positions, position.position_id.clone(), position)?;
        self.refresh();
        Ok(())
    }

    pub fn add_funding_curve(&mut self, curve: FundingCurve) -> Result<()> {
        ensure_capacity(
            "funding_curves",
            self.funding_curves.len(),
            self.config.max_funding_curves,
        )?;
        let tranche = self
            .tranches
            .get(&curve.tranche_id)
            .ok_or_else(|| format!("missing tranche {}", curve.tranche_id))?;
        curve.validate(&self.config, tranche)?;
        insert_unique(
            &mut self.funding_curves,
            curve.funding_curve_id.clone(),
            curve,
        )?;
        self.refresh();
        Ok(())
    }

    pub fn add_delay_observation(&mut self, observation: SequencerDelayObservation) -> Result<()> {
        ensure_capacity(
            "delay_observations",
            self.delay_observations.len(),
            self.config.max_observations,
        )?;
        let tranche = self
            .tranches
            .get(&observation.tranche_id)
            .ok_or_else(|| format!("missing tranche {}", observation.tranche_id))?;
        observation.validate(&self.config, tranche)?;
        insert_unique(
            &mut self.delay_observations,
            observation.observation_id.clone(),
            observation,
        )?;
        self.refresh();
        Ok(())
    }

    pub fn admit_claim_coupon(&mut self, coupon: PqClaimCoupon) -> Result<()> {
        ensure_capacity(
            "claim_coupons",
            self.claim_coupons.len(),
            self.config.max_claim_coupons,
        )?;
        require(
            !self.consumed_nullifiers.contains(&coupon.nullifier),
            "claim coupon nullifier already consumed",
        )?;
        let tranche = self
            .tranches
            .get(&coupon.tranche_id)
            .ok_or_else(|| format!("missing tranche {}", coupon.tranche_id))?;
        let position = self
            .positions
            .get(&coupon.position_id)
            .ok_or_else(|| format!("missing position {}", coupon.position_id))?;
        let observation = self
            .delay_observations
            .get(&coupon.observation_id)
            .ok_or_else(|| format!("missing observation {}", coupon.observation_id))?;
        coupon.validate(&self.config, tranche, position, observation)?;
        self.consumed_nullifiers.insert(coupon.nullifier.clone());
        insert_unique(&mut self.claim_coupons, coupon.coupon_id.clone(), coupon)?;
        self.refresh();
        Ok(())
    }

    pub fn add_netted_funding_settlement(
        &mut self,
        settlement: LowFeeNettedFundingSettlement,
    ) -> Result<()> {
        ensure_capacity(
            "settlements",
            self.settlements.len(),
            self.config.max_settlements,
        )?;
        let tranche = self
            .tranches
            .get(&settlement.tranche_id)
            .ok_or_else(|| format!("missing tranche {}", settlement.tranche_id))?;
        let curve = self
            .funding_curves
            .get(&settlement.funding_curve_id)
            .ok_or_else(|| format!("missing funding curve {}", settlement.funding_curve_id))?;
        settlement.validate(&self.config, tranche, curve)?;
        insert_unique(
            &mut self.settlements,
            settlement.settlement_id.clone(),
            settlement,
        )?;
        self.refresh();
        Ok(())
    }

    pub fn publish_roots_only_summary(
        &mut self,
        summary_id: String,
        tranche_id: String,
    ) -> Result<()> {
        require_nonempty("summary_id", &summary_id)?;
        require(
            self.tranches.contains_key(&tranche_id),
            "missing tranche for summary",
        )?;
        let roots = self.roots();
        let summary = PublicSummary {
            summary_id: summary_id.clone(),
            tranche_id,
            l2_height: self.l2_height,
            monero_height: self.monero_height,
            epoch: self.epoch,
            tranche_root: roots.tranches_root,
            position_root: roots.positions_root,
            funding_root: roots.funding_curves_root,
            observation_root: roots.delay_observations_root,
            claim_coupon_root: roots.claim_coupons_root,
            settlement_root: roots.settlements_root,
            collateral_root: roots.collateral_root,
            margin_root: roots.margin_root,
            premium_root: roots.premium_root,
            nullifier_root: roots.nullifiers_root,
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        };
        insert_unique(&mut self.public_summaries, summary_id, summary)?;
        self.refresh();
        Ok(())
    }

    pub fn counters(&self) -> Counters {
        Counters {
            tranches: self.tranches.len() as u64,
            active_tranches: self
                .tranches
                .values()
                .filter(|tranche| tranche.status.accepts_positions())
                .count() as u64,
            positions: self.positions.len() as u64,
            open_positions: self
                .positions
                .values()
                .filter(|position| position.status.open())
                .count() as u64,
            funding_curves: self.funding_curves.len() as u64,
            active_funding_curves: self
                .funding_curves
                .values()
                .filter(|curve| curve.status == FundingCurveStatus::Active)
                .count() as u64,
            delay_observations: self.delay_observations.len() as u64,
            actionable_observations: self
                .delay_observations
                .values()
                .filter(|observation| observation.status.actionable())
                .count() as u64,
            claim_coupons: self.claim_coupons.len() as u64,
            admitted_claim_coupons: self
                .claim_coupons
                .values()
                .filter(|coupon| {
                    matches!(
                        coupon.status,
                        CouponStatus::Admitted
                            | CouponStatus::Netted
                            | CouponStatus::Clearing
                            | CouponStatus::Settled
                    )
                })
                .count() as u64,
            settlements: self.settlements.len() as u64,
            settled_batches: self
                .settlements
                .values()
                .filter(|settlement| settlement.status == SettlementStatus::Settled)
                .count() as u64,
            collateral_roots: self.collateral_roots.len() as u64,
            margin_roots: self.margin_roots.len() as u64,
            premium_roots: self.premium_roots.len() as u64,
            consumed_nullifiers: self.consumed_nullifiers.len() as u64,
            public_summaries: self.public_summaries.len() as u64,
            total_notional_units: self
                .positions
                .values()
                .map(|position| position.notional_units)
                .sum(),
            total_collateral_units: self
                .positions
                .values()
                .map(|position| position.collateral_units)
                .sum(),
            total_margin_units: self
                .positions
                .values()
                .map(|position| position.margin_units)
                .sum(),
            total_premium_units: self
                .positions
                .values()
                .map(|position| position.premium_units)
                .sum(),
            total_claim_units: self
                .claim_coupons
                .values()
                .map(|coupon| coupon.claim_amount_units)
                .sum(),
            total_netted_funding_units: self
                .settlements
                .values()
                .map(|settlement| settlement.net_funding_units)
                .sum(),
            total_low_fee_units: self
                .settlements
                .values()
                .map(|settlement| settlement.low_fee_units)
                .sum(),
        }
    }

    pub fn roots(&self) -> Roots {
        let counters = self.counters();
        let mut roots = Roots {
            config_root: self.config.state_root(),
            tranches_root: map_public_root(
                SEALED_PERPS_TRANCHE_SUITE,
                &self.tranches,
                SealedPerpsTranche::public_record,
            ),
            positions_root: map_public_root(
                POSITION_NOTE_SUITE,
                &self.positions,
                PositionNote::public_record,
            ),
            funding_curves_root: map_public_root(
                CONFIDENTIAL_FUNDING_CURVE_SUITE,
                &self.funding_curves,
                FundingCurve::public_record,
            ),
            delay_observations_root: map_public_root(
                DELAY_OBSERVATION_SUITE,
                &self.delay_observations,
                SequencerDelayObservation::public_record,
            ),
            claim_coupons_root: map_public_root(
                CLAIM_COUPON_ROOT_SUITE,
                &self.claim_coupons,
                PqClaimCoupon::public_record,
            ),
            settlements_root: map_public_root(
                LOW_FEE_NETTED_FUNDING_SUITE,
                &self.settlements,
                LowFeeNettedFundingSettlement::public_record,
            ),
            collateral_root: map_root(COLLATERAL_ROOT_SUITE, &self.collateral_roots),
            margin_root: map_root(MARGIN_ROOT_SUITE, &self.margin_roots),
            premium_root: map_root(PREMIUM_ROOT_SUITE, &self.premium_roots),
            nullifiers_root: set_root(
                "sequencer_delay_insurance_nullifiers",
                &self.consumed_nullifiers,
            ),
            public_summaries_root: map_public_root(
                "sequencer_delay_insurance_public_summaries",
                &self.public_summaries,
                PublicSummary::public_record,
            ),
            counters_root: counters.state_root(),
            state_root: String::new(),
        };
        roots.state_root = roots.compute_state_root(self.l2_height, self.monero_height, self.epoch);
        roots
    }

    pub fn refresh(&mut self) {
        self.counters = self.counters();
        self.roots = self.roots();
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "public_record_suite": PUBLIC_RECORD_SUITE,
            "state_root_suite": STATE_ROOT_SUITE,
            "chain_id": self.config.chain_id,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "config_root": self.config.state_root(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "counters_root": counters.state_root(),
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

    fn seed_devnet(&mut self) {
        let tranche = SealedPerpsTranche {
            tranche_id: "tsdip-senior-soft-delay-devnet".to_string(),
            risk_kind: SequencerDelayRiskKind::HardDelay,
            status: TrancheStatus::Active,
            notional_cap_units: 25_000_000_000,
            collateral_root: demo_root("collateral", "senior"),
            margin_root: demo_root("margin", "senior"),
            premium_root: demo_root("premium", "senior"),
            funding_curve_id: "curve-hard-delay-devnet".to_string(),
            maturity_l2_height: self.l2_height + 10_080,
            delay_floor_ms: 1_500,
            delay_cap_ms: 30_000,
            leverage_bps: 2_500,
            attachment_bps: 500,
            detachment_bps: 6_500,
            utilization_bps: 3_800,
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
            sealed_terms_root: demo_root("sealed_terms", "senior"),
            token_commitment_root: demo_root("token_commitments", "senior"),
            created_l2_height: self.l2_height,
        };
        self.add_tranche(tranche).expect("valid devnet tranche");

        let curve = FundingCurve {
            funding_curve_id: "curve-hard-delay-devnet".to_string(),
            tranche_id: "tsdip-senior-soft-delay-devnet".to_string(),
            status: FundingCurveStatus::Active,
            private_curve_root: demo_root("curve", "hard-delay"),
            utilization_root: demo_root("utilization", "hard-delay"),
            volatility_root: demo_root("volatility", "hard-delay"),
            delay_surface_root: demo_root("delay_surface", "hard-delay"),
            base_rate_bps: 18,
            slope_bps: 240,
            clamp_bps: 300,
            funding_interval_blocks: self.config.funding_interval_blocks,
            quorum_weight: self.config.funding_quorum,
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
            effective_l2_height: self.l2_height,
        };
        self.add_funding_curve(curve)
            .expect("valid devnet funding curve");

        let position = PositionNote {
            position_id: "pos-delay-protection-devnet-0".to_string(),
            tranche_id: "tsdip-senior-soft-delay-devnet".to_string(),
            side: PositionSide::LongDelayProtection,
            status: PositionStatus::Open,
            owner_commitment: demo_root("owner", "alice"),
            note_commitment: demo_root("position_note", "alice"),
            collateral_commitment: demo_root("position_collateral", "alice"),
            margin_commitment: demo_root("position_margin", "alice"),
            entry_funding_curve_id: "curve-hard-delay-devnet".to_string(),
            notional_units: 1_000_000_000,
            collateral_units: 1_250_000_000,
            margin_units: 150_000_000,
            premium_units: 14_000_000,
            max_delay_ms: 30_000,
            entry_l2_height: self.l2_height,
            expiry_l2_height: self.l2_height + self.config.position_ttl_blocks,
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        };
        self.add_position(position).expect("valid devnet position");

        let observation = SequencerDelayObservation {
            observation_id: "obs-hard-delay-devnet-0".to_string(),
            tranche_id: "tsdip-senior-soft-delay-devnet".to_string(),
            risk_kind: SequencerDelayRiskKind::HardDelay,
            status: ObservationStatus::Actionable,
            sequencer_commitment: demo_root("sequencer", "committee-a"),
            delay_window_root: demo_root("delay_window", "window-a"),
            observed_delay_ms: 7_200,
            missed_slots: 4,
            preconfirmation_lag_ms: 6_900,
            forced_inclusion_lag_blocks: 2,
            oracle_attestation_root: demo_root("oracle_attestation", "window-a"),
            observer_quorum_weight: self.config.observer_quorum,
            l2_height: self.l2_height + 12,
            monero_height: self.monero_height + 2,
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        };
        self.add_delay_observation(observation)
            .expect("valid devnet observation");

        let coupon = PqClaimCoupon {
            coupon_id: "coupon-hard-delay-devnet-0".to_string(),
            tranche_id: "tsdip-senior-soft-delay-devnet".to_string(),
            position_id: "pos-delay-protection-devnet-0".to_string(),
            observation_id: "obs-hard-delay-devnet-0".to_string(),
            status: CouponStatus::Admitted,
            claimant_commitment: demo_root("claimant", "alice"),
            coupon_commitment: demo_root("coupon", "alice"),
            payout_commitment: demo_root("payout", "alice"),
            claim_amount_units: 175_000_000,
            premium_offset_units: 4_000_000,
            coupon_quorum_weight: self.config.coupon_quorum,
            expires_l2_height: self.l2_height + self.config.claim_ttl_blocks,
            nullifier: demo_root("nullifier", "coupon-0"),
            pq_authorization_root: demo_root("pq_authorization", "coupon-0"),
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        };
        self.admit_claim_coupon(coupon)
            .expect("valid devnet coupon");

        let settlement = LowFeeNettedFundingSettlement {
            settlement_id: "settlement-netted-funding-devnet-0".to_string(),
            tranche_id: "tsdip-senior-soft-delay-devnet".to_string(),
            status: SettlementStatus::Settled,
            funding_curve_id: "curve-hard-delay-devnet".to_string(),
            position_set_root: demo_root("position_set", "batch-0"),
            debit_root: demo_root("debits", "batch-0"),
            credit_root: demo_root("credits", "batch-0"),
            fee_root: demo_root("fees", "batch-0"),
            net_funding_units: -2_500_000,
            protocol_fee_units: 25_000,
            maker_rebate_units: 12_000,
            low_fee_units: 3_000,
            settled_positions: 1,
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
            posted_l2_height: self.l2_height + self.config.funding_interval_blocks,
        };
        self.add_netted_funding_settlement(settlement)
            .expect("valid devnet settlement");
        self.publish_roots_only_summary(
            "summary-roots-only-devnet-0".to_string(),
            "tsdip-senior-soft-delay-devnet".to_string(),
        )
        .expect("valid devnet summary");
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record() -> Value {
    State::devnet().public_record()
}

pub fn state_root() -> String {
    State::devnet().state_root()
}

pub fn private_l2_pq_confidential_tokenized_sequencer_delay_insurance_perps_runtime_public_record(
) -> Value {
    public_record()
}

pub fn private_l2_pq_confidential_tokenized_sequencer_delay_insurance_perps_runtime_state_root(
) -> String {
    state_root()
}

fn map_public_root<T, F>(label: &str, map: &BTreeMap<String, T>, f: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "label": label,
                "key": key,
                "record": f(value),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(label, &leaves)
}

fn map_root(label: &str, map: &BTreeMap<String, String>) -> String {
    let leaves = map
        .iter()
        .map(|(key, root)| {
            json!({
                "label": label,
                "key": key,
                "root": root,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(label, &leaves)
}

fn set_root(label: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| {
            json!({
                "label": label,
                "value": value,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(label, &leaves)
}

fn demo_root(label: &str, salt: &str) -> String {
    domain_hash(
        &format!("{PAYLOAD_ROOT_SUITE}:devnet:{label}"),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(salt)],
        32,
    )
}

fn payload_root(label: &str, value: &Value) -> String {
    domain_hash(
        PAYLOAD_ROOT_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Json(value),
        ],
        32,
    )
}

fn set_json_field(record: &mut Value, key: &str, value: Value) {
    if let Some(object) = record.as_object_mut() {
        object.insert(key.to_string(), value);
    }
}

fn insert_unique<T>(map: &mut BTreeMap<String, T>, key: String, value: T) -> Result<()> {
    if map.contains_key(&key) {
        Err(format!("duplicate key {key}"))
    } else {
        map.insert(key, value);
        Ok(())
    }
}

fn ensure_capacity(label: &str, len: usize, max: usize) -> Result<()> {
    if len >= max {
        Err(format!("{label} capacity exceeded"))
    } else {
        Ok(())
    }
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn require_nonempty(label: &str, value: &str) -> Result<()> {
    require(
        !value.trim().is_empty(),
        &format!("{label} must not be empty"),
    )
}

fn require_root(label: &str, value: &str) -> Result<()> {
    require(
        value.len() >= 32 && value.chars().all(|ch| ch.is_ascii_hexdigit()),
        &format!("{label} must be a hex commitment/root of at least 32 chars"),
    )
}

fn require_bps(label: &str, value: u64) -> Result<()> {
    require(value <= MAX_BPS, &format!("{label} exceeds MAX_BPS"))
}

fn require_nonzero_u128(label: &str, value: u128) -> Result<()> {
    require(value > 0, &format!("{label} must be positive"))
}

fn require_privacy_and_pq(
    privacy_set_size: u64,
    pq_security_bits: u16,
    min_privacy_set_size: u64,
    min_pq_security_bits: u16,
) -> Result<()> {
    require(
        privacy_set_size >= min_privacy_set_size,
        "privacy set is below configured anonymity threshold",
    )?;
    require(
        pq_security_bits >= min_pq_security_bits,
        "PQ authorization security bits below configured minimum",
    )
}

fn coverage_bps(numerator: u128, denominator: u128) -> Result<u64> {
    require(denominator > 0, "coverage denominator must be positive")?;
    Ok(((numerator.saturating_mul(MAX_BPS as u128)) / denominator) as u64)
}

fn payout_cap(notional_units: u128, max_payout_bps: u64) -> Result<u128> {
    require_bps("max_payout_bps", max_payout_bps)?;
    Ok(notional_units.saturating_mul(max_payout_bps as u128) / MAX_BPS as u128)
}
