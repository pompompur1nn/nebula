use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePqConfidentialSponsorRebateDerivativeVaultRuntimeResult<T> = Result<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_SPONSOR_REBATE_DERIVATIVE_VAULT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-sponsor-rebate-derivative-vault-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_SPONSOR_REBATE_DERIVATIVE_VAULT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_SPONSOR_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256f-confidential-sponsor-rebate-attestation-v1";
pub const PQ_POOL_SEALING_SCHEME: &str = "ml-kem-1024+xwing-sealed-sponsor-pool-liability-state-v1";
pub const REBATE_DERIVATIVE_SCHEME: &str =
    "zk-pq-private-low-fee-sponsor-rebate-derivative-note-v1";
pub const HEDGE_LEG_SCHEME: &str = "roots-only-private-sponsor-rebate-hedge-leg-v1";
pub const FEE_FLOOR_TRIGGER_SCHEME: &str = "low-fee-floor-trigger-confidential-rebate-vault-v1";
pub const SETTLEMENT_RECEIPT_SCHEME: &str =
    "zk-pq-confidential-sponsor-rebate-vault-settlement-receipt-v1";
pub const ANTI_ABUSE_THROTTLE_SCHEME: &str =
    "private-l2-low-fee-sponsor-rebate-anti-abuse-throttle-root-v1";
pub const REDACTION_BUDGET_SCHEME: &str =
    "selective-disclosure-redaction-budget-confidential-rebate-vault-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str =
    "operator-summary-private-low-fee-sponsor-rebate-vault-runtime-v1";
pub const DEVNET_HEIGHT: u64 = 2_116_404;
pub const DEVNET_EPOCH: u64 = 2_941;
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEFAULT_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const DEFAULT_REBATE_ASSET_ID: &str = "sponsor-rebate-credit-devnet";
pub const DEFAULT_COLLATERAL_ASSET_ID: &str = "dusd-private-devnet";
pub const DEFAULT_SETTLEMENT_VAULT_ID: &str =
    "private-l2-low-fee-pq-confidential-sponsor-rebate-derivative-vault";
pub const DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_DECOY_SET_SIZE: u64 = 4_096;
pub const DEFAULT_BASE_LOW_FEE_MICRO_UNITS: u64 = 9;
pub const DEFAULT_FEE_FLOOR_MICRO_UNITS: u64 = 5;
pub const DEFAULT_REBATE_RATE_BPS: u64 = 72;
pub const DEFAULT_SPONSOR_RESERVE_BPS: u64 = 1_500;
pub const DEFAULT_SPONSOR_UTILIZATION_WARN_BPS: u64 = 8_250;
pub const DEFAULT_MAX_SPONSOR_UTILIZATION_BPS: u64 = 9_250;
pub const DEFAULT_HEDGE_MARGIN_BPS: u64 = 1_250;
pub const DEFAULT_SETTLEMENT_FINALITY_BLOCKS: u64 = 12;
pub const DEFAULT_THROTTLE_WINDOW_BLOCKS: u64 = 120;
pub const DEFAULT_REDACTION_WINDOW_BLOCKS: u64 = 21_600;
pub const DEFAULT_MAX_USER_REBATE_BPS: u64 = 250;
pub const DEFAULT_MAX_POOL_REBATE_BPS: u64 = 650;
pub const DEFAULT_MAX_DERIVATIVES: usize = 524_288;
pub const DEFAULT_MAX_SPONSOR_POOLS: usize = 131_072;
pub const DEFAULT_MAX_HEDGE_LEGS: usize = 1_048_576;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 1_048_576;
pub const DEFAULT_MAX_FEE_FLOOR_TRIGGERS: usize = 524_288;
pub const DEFAULT_MAX_RECEIPTS: usize = 1_048_576;
pub const DEFAULT_MAX_THROTTLES: usize = 524_288;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 262_144;
pub const DEFAULT_MAX_OPERATOR_SUMMARIES: usize = 262_144;
pub const DEFAULT_MAX_NULLIFIERS: usize = 2_097_152;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateDerivativeKind {
    SponsorFeeFuture,
    SponsorFeeCall,
    SponsorFeePut,
    FeeFloorNote,
    RebateSwap,
    PoolUtilizationForward,
    ProofCostCap,
    DaCostCollar,
    SettlementCreditNote,
    AntiAbuseInsurance,
}

impl RebateDerivativeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SponsorFeeFuture => "sponsor_fee_future",
            Self::SponsorFeeCall => "sponsor_fee_call",
            Self::SponsorFeePut => "sponsor_fee_put",
            Self::FeeFloorNote => "fee_floor_note",
            Self::RebateSwap => "rebate_swap",
            Self::PoolUtilizationForward => "pool_utilization_forward",
            Self::ProofCostCap => "proof_cost_cap",
            Self::DaCostCollar => "da_cost_collar",
            Self::SettlementCreditNote => "settlement_credit_note",
            Self::AntiAbuseInsurance => "anti_abuse_insurance",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivativeStatus {
    Draft,
    Open,
    Hedged,
    FloorTriggered,
    Netting,
    Settling,
    Settled,
    Suspended,
    Slashed,
    Expired,
}

impl DerivativeStatus {
    pub fn accepts_hedges(self) -> bool {
        matches!(self, Self::Open | Self::Hedged | Self::FloorTriggered)
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Slashed | Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorPoolStatus {
    Bootstrapping,
    Active,
    Throttled,
    FloorOnly,
    Draining,
    Paused,
    Slashed,
    Retired,
}

impl SponsorPoolStatus {
    pub fn accepts_derivatives(self) -> bool {
        matches!(self, Self::Active | Self::Throttled | Self::FloorOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HedgeLegKind {
    FixedFeeReceive,
    FixedFeePay,
    FloorProtection,
    CapProtection,
    ProofCostHedge,
    DaCostHedge,
    UtilizationHedge,
    RebateDeltaHedge,
    SettlementCreditHedge,
    AbuseLossHedge,
}

impl HedgeLegKind {
    pub fn signed_notional(self, notional: u64) -> i128 {
        match self {
            Self::FixedFeeReceive
            | Self::FloorProtection
            | Self::ProofCostHedge
            | Self::DaCostHedge
            | Self::SettlementCreditHedge => notional as i128,
            Self::FixedFeePay
            | Self::CapProtection
            | Self::UtilizationHedge
            | Self::RebateDeltaHedge
            | Self::AbuseLossHedge => -(notional as i128),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    PoolSolvency,
    SponsorAuthorization,
    RebateEligibility,
    FeeFloorObservation,
    HedgeCommitment,
    SettlementAuthorization,
    RedactionDisclosure,
    AbuseThrottleDecision,
    OperatorCheckpoint,
    EmergencyPause,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PoolSolvency => "pool_solvency",
            Self::SponsorAuthorization => "sponsor_authorization",
            Self::RebateEligibility => "rebate_eligibility",
            Self::FeeFloorObservation => "fee_floor_observation",
            Self::HedgeCommitment => "hedge_commitment",
            Self::SettlementAuthorization => "settlement_authorization",
            Self::RedactionDisclosure => "redaction_disclosure",
            Self::AbuseThrottleDecision => "abuse_throttle_decision",
            Self::OperatorCheckpoint => "operator_checkpoint",
            Self::EmergencyPause => "emergency_pause",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerStatus {
    Observed,
    PendingAttestation,
    Armed,
    Fired,
    Settled,
    Disputed,
    Rejected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Finalizing,
    Final,
    Redacted,
    Disputed,
    Reversed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThrottleAction {
    Allow,
    ReduceRebate,
    DelaySettlement,
    RequireFreshAttestation,
    PoolOnly,
    Reject,
    SlashSponsor,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub collateral_asset_id: String,
    pub settlement_vault_id: String,
    pub epoch_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub min_decoy_set_size: u64,
    pub base_low_fee_micro_units: u64,
    pub fee_floor_micro_units: u64,
    pub default_rebate_rate_bps: u64,
    pub sponsor_reserve_bps: u64,
    pub sponsor_utilization_warn_bps: u64,
    pub max_sponsor_utilization_bps: u64,
    pub hedge_margin_bps: u64,
    pub settlement_finality_blocks: u64,
    pub throttle_window_blocks: u64,
    pub redaction_window_blocks: u64,
    pub max_user_rebate_bps: u64,
    pub max_pool_rebate_bps: u64,
    pub max_derivatives: usize,
    pub max_sponsor_pools: usize,
    pub max_hedge_legs: usize,
    pub max_attestations: usize,
    pub max_fee_floor_triggers: usize,
    pub max_receipts: usize,
    pub max_throttles: usize,
    pub max_redaction_budgets: usize,
    pub max_operator_summaries: usize,
    pub max_nullifiers: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEFAULT_REBATE_ASSET_ID.to_string(),
            collateral_asset_id: DEFAULT_COLLATERAL_ASSET_ID.to_string(),
            settlement_vault_id: DEFAULT_SETTLEMENT_VAULT_ID.to_string(),
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_decoy_set_size: DEFAULT_MIN_DECOY_SET_SIZE,
            base_low_fee_micro_units: DEFAULT_BASE_LOW_FEE_MICRO_UNITS,
            fee_floor_micro_units: DEFAULT_FEE_FLOOR_MICRO_UNITS,
            default_rebate_rate_bps: DEFAULT_REBATE_RATE_BPS,
            sponsor_reserve_bps: DEFAULT_SPONSOR_RESERVE_BPS,
            sponsor_utilization_warn_bps: DEFAULT_SPONSOR_UTILIZATION_WARN_BPS,
            max_sponsor_utilization_bps: DEFAULT_MAX_SPONSOR_UTILIZATION_BPS,
            hedge_margin_bps: DEFAULT_HEDGE_MARGIN_BPS,
            settlement_finality_blocks: DEFAULT_SETTLEMENT_FINALITY_BLOCKS,
            throttle_window_blocks: DEFAULT_THROTTLE_WINDOW_BLOCKS,
            redaction_window_blocks: DEFAULT_REDACTION_WINDOW_BLOCKS,
            max_user_rebate_bps: DEFAULT_MAX_USER_REBATE_BPS,
            max_pool_rebate_bps: DEFAULT_MAX_POOL_REBATE_BPS,
            max_derivatives: DEFAULT_MAX_DERIVATIVES,
            max_sponsor_pools: DEFAULT_MAX_SPONSOR_POOLS,
            max_hedge_legs: DEFAULT_MAX_HEDGE_LEGS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_fee_floor_triggers: DEFAULT_MAX_FEE_FLOOR_TRIGGERS,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_throttles: DEFAULT_MAX_THROTTLES,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
            max_operator_summaries: DEFAULT_MAX_OPERATOR_SUMMARIES,
            max_nullifiers: DEFAULT_MAX_NULLIFIERS,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_sponsor_attestation_scheme": PQ_SPONSOR_ATTESTATION_SCHEME,
            "pq_pool_sealing_scheme": PQ_POOL_SEALING_SCHEME,
            "rebate_derivative_scheme": REBATE_DERIVATIVE_SCHEME,
            "hedge_leg_scheme": HEDGE_LEG_SCHEME,
            "fee_floor_trigger_scheme": FEE_FLOOR_TRIGGER_SCHEME,
            "settlement_receipt_scheme": SETTLEMENT_RECEIPT_SCHEME,
            "anti_abuse_throttle_scheme": ANTI_ABUSE_THROTTLE_SCHEME,
            "redaction_budget_scheme": REDACTION_BUDGET_SCHEME,
            "operator_summary_scheme": OPERATOR_SUMMARY_SCHEME,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "collateral_asset_id": self.collateral_asset_id,
            "settlement_vault_id": self.settlement_vault_id,
            "epoch_blocks": self.epoch_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_decoy_set_size": self.min_decoy_set_size,
            "base_low_fee_micro_units": self.base_low_fee_micro_units,
            "fee_floor_micro_units": self.fee_floor_micro_units,
            "default_rebate_rate_bps": self.default_rebate_rate_bps,
            "sponsor_reserve_bps": self.sponsor_reserve_bps,
            "sponsor_utilization_warn_bps": self.sponsor_utilization_warn_bps,
            "max_sponsor_utilization_bps": self.max_sponsor_utilization_bps,
            "hedge_margin_bps": self.hedge_margin_bps,
            "settlement_finality_blocks": self.settlement_finality_blocks,
            "throttle_window_blocks": self.throttle_window_blocks,
            "redaction_window_blocks": self.redaction_window_blocks,
            "max_user_rebate_bps": self.max_user_rebate_bps,
            "max_pool_rebate_bps": self.max_pool_rebate_bps,
            "max_derivatives": self.max_derivatives,
            "max_sponsor_pools": self.max_sponsor_pools,
            "max_hedge_legs": self.max_hedge_legs,
            "max_attestations": self.max_attestations,
            "max_fee_floor_triggers": self.max_fee_floor_triggers,
            "max_receipts": self.max_receipts,
            "max_throttles": self.max_throttles,
            "max_redaction_budgets": self.max_redaction_budgets,
            "max_operator_summaries": self.max_operator_summaries,
            "max_nullifiers": self.max_nullifiers,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub sponsor_pool_count: u64,
    pub derivative_count: u64,
    pub hedge_leg_count: u64,
    pub attestation_count: u64,
    pub fee_floor_trigger_count: u64,
    pub settlement_receipt_count: u64,
    pub anti_abuse_throttle_count: u64,
    pub redaction_budget_count: u64,
    pub operator_summary_count: u64,
    pub nullifier_count: u64,
    pub open_derivative_count: u64,
    pub active_pool_count: u64,
    pub throttled_pool_count: u64,
    pub fired_trigger_count: u64,
    pub final_receipt_count: u64,
    pub total_sponsor_liquidity: u64,
    pub total_locked_liquidity: u64,
    pub total_rebate_notional: u64,
    pub total_hedge_notional: u64,
    pub total_settled_rebate: u64,
    pub total_redacted_fields: u64,
    pub total_abuse_score: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_pool_count": self.sponsor_pool_count,
            "derivative_count": self.derivative_count,
            "hedge_leg_count": self.hedge_leg_count,
            "attestation_count": self.attestation_count,
            "fee_floor_trigger_count": self.fee_floor_trigger_count,
            "settlement_receipt_count": self.settlement_receipt_count,
            "anti_abuse_throttle_count": self.anti_abuse_throttle_count,
            "redaction_budget_count": self.redaction_budget_count,
            "operator_summary_count": self.operator_summary_count,
            "nullifier_count": self.nullifier_count,
            "open_derivative_count": self.open_derivative_count,
            "active_pool_count": self.active_pool_count,
            "throttled_pool_count": self.throttled_pool_count,
            "fired_trigger_count": self.fired_trigger_count,
            "final_receipt_count": self.final_receipt_count,
            "total_sponsor_liquidity": self.total_sponsor_liquidity,
            "total_locked_liquidity": self.total_locked_liquidity,
            "total_rebate_notional": self.total_rebate_notional,
            "total_hedge_notional": self.total_hedge_notional,
            "total_settled_rebate": self.total_settled_rebate,
            "total_redacted_fields": self.total_redacted_fields,
            "total_abuse_score": self.total_abuse_score,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub sponsor_pool_root: String,
    pub rebate_derivative_root: String,
    pub hedge_leg_root: String,
    pub pq_attestation_root: String,
    pub fee_floor_trigger_root: String,
    pub settlement_receipt_root: String,
    pub anti_abuse_throttle_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "sponsor_pool_root": self.sponsor_pool_root,
            "rebate_derivative_root": self.rebate_derivative_root,
            "hedge_leg_root": self.hedge_leg_root,
            "pq_attestation_root": self.pq_attestation_root,
            "fee_floor_trigger_root": self.fee_floor_trigger_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "anti_abuse_throttle_root": self.anti_abuse_throttle_root,
            "redaction_budget_root": self.redaction_budget_root,
            "operator_summary_root": self.operator_summary_root,
            "nullifier_root": self.nullifier_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SponsorPool {
    pub pool_id: String,
    pub sponsor_commitment: String,
    pub reserve_commitment: String,
    pub liability_root: String,
    pub eligibility_root: String,
    pub status: SponsorPoolStatus,
    pub liquidity_units: u64,
    pub locked_units: u64,
    pub reserve_units: u64,
    pub rebate_rate_bps: u64,
    pub utilization_bps: u64,
    pub min_privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
    pub updated_at_height: u64,
}

impl SponsorPool {
    pub fn new(
        pool_id: impl Into<String>,
        sponsor_commitment: impl Into<String>,
        liquidity_units: u64,
        rebate_rate_bps: u64,
        opened_at_height: u64,
    ) -> Self {
        let pool_id = pool_id.into();
        let sponsor_commitment = sponsor_commitment.into();
        let reserve_units = liquidity_units.saturating_mul(DEFAULT_SPONSOR_RESERVE_BPS) / MAX_BPS;
        let reserve_commitment = commitment_id(
            "SPONSOR-POOL-RESERVE",
            &[&pool_id, &sponsor_commitment, &reserve_units.to_string()],
        );
        let liability_root = domain_hash(
            "PRIVATE-L2-SPONSOR-REBATE-POOL-LIABILITY-EMPTY",
            &[HashPart::Str(&pool_id)],
            32,
        );
        let eligibility_root = domain_hash(
            "PRIVATE-L2-SPONSOR-REBATE-POOL-ELIGIBILITY-EMPTY",
            &[HashPart::Str(&pool_id)],
            32,
        );
        Self {
            pool_id,
            sponsor_commitment,
            reserve_commitment,
            liability_root,
            eligibility_root,
            status: SponsorPoolStatus::Active,
            liquidity_units,
            locked_units: 0,
            reserve_units,
            rebate_rate_bps,
            utilization_bps: 0,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            opened_at_height,
            updated_at_height: opened_at_height,
        }
    }

    pub fn available_liquidity(&self) -> u64 {
        self.liquidity_units
            .saturating_sub(self.locked_units)
            .saturating_sub(self.reserve_units)
    }

    pub fn refresh_utilization(&mut self) {
        self.utilization_bps = if self.liquidity_units == 0 {
            0
        } else {
            self.locked_units.saturating_mul(MAX_BPS) / self.liquidity_units
        };
    }

    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("sponsor pool public record")
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-SPONSOR-REBATE-POOL",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RebateDerivative {
    pub derivative_id: String,
    pub pool_id: String,
    pub owner_commitment: String,
    pub derivative_kind: RebateDerivativeKind,
    pub status: DerivativeStatus,
    pub notional_units: u64,
    pub floor_micro_units: u64,
    pub cap_micro_units: u64,
    pub rebate_rate_bps: u64,
    pub maturity_height: u64,
    pub encrypted_terms_root: String,
    pub eligibility_attestation_root: String,
    pub hedge_set_root: String,
    pub abuse_throttle_root: String,
    pub redaction_policy_root: String,
    pub opened_at_height: u64,
    pub updated_at_height: u64,
}

impl RebateDerivative {
    pub fn new(
        derivative_id: impl Into<String>,
        pool_id: impl Into<String>,
        owner_commitment: impl Into<String>,
        derivative_kind: RebateDerivativeKind,
        notional_units: u64,
        opened_at_height: u64,
    ) -> Self {
        let derivative_id = derivative_id.into();
        let pool_id = pool_id.into();
        let owner_commitment = owner_commitment.into();
        let encrypted_terms_root = commitment_id(
            "REBATE-DERIVATIVE-TERMS",
            &[&derivative_id, &pool_id, derivative_kind.as_str()],
        );
        Self {
            derivative_id: derivative_id.clone(),
            pool_id,
            owner_commitment,
            derivative_kind,
            status: DerivativeStatus::Open,
            notional_units,
            floor_micro_units: DEFAULT_FEE_FLOOR_MICRO_UNITS,
            cap_micro_units: DEFAULT_BASE_LOW_FEE_MICRO_UNITS.saturating_mul(3),
            rebate_rate_bps: DEFAULT_REBATE_RATE_BPS,
            maturity_height: opened_at_height + DEFAULT_EPOCH_BLOCKS,
            encrypted_terms_root,
            eligibility_attestation_root: empty_root("REBATE-DERIVATIVE-ELIGIBILITY"),
            hedge_set_root: empty_root("REBATE-DERIVATIVE-HEDGE-SET"),
            abuse_throttle_root: empty_root("REBATE-DERIVATIVE-ABUSE-THROTTLE"),
            redaction_policy_root: empty_root("REBATE-DERIVATIVE-REDACTION-POLICY"),
            opened_at_height,
            updated_at_height: opened_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("rebate derivative public record")
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-SPONSOR-REBATE-DERIVATIVE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HedgeLeg {
    pub hedge_id: String,
    pub derivative_id: String,
    pub pool_id: String,
    pub counterparty_commitment: String,
    pub leg_kind: HedgeLegKind,
    pub notional_units: u64,
    pub margin_commitment: String,
    pub mark_root: String,
    pub signed_notional: i128,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub settled: bool,
}

impl HedgeLeg {
    pub fn new(
        hedge_id: impl Into<String>,
        derivative_id: impl Into<String>,
        pool_id: impl Into<String>,
        counterparty_commitment: impl Into<String>,
        leg_kind: HedgeLegKind,
        notional_units: u64,
        opened_at_height: u64,
    ) -> Self {
        let hedge_id = hedge_id.into();
        let derivative_id = derivative_id.into();
        let pool_id = pool_id.into();
        let counterparty_commitment = counterparty_commitment.into();
        Self {
            margin_commitment: commitment_id(
                "REBATE-HEDGE-MARGIN",
                &[&hedge_id, &derivative_id, &notional_units.to_string()],
            ),
            mark_root: empty_root("REBATE-HEDGE-MARK"),
            signed_notional: leg_kind.signed_notional(notional_units),
            hedge_id,
            derivative_id,
            pool_id,
            counterparty_commitment,
            leg_kind,
            notional_units,
            opened_at_height,
            expires_at_height: opened_at_height + DEFAULT_EPOCH_BLOCKS,
            settled: false,
        }
    }

    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("hedge leg public record")
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-SPONSOR-REBATE-HEDGE-LEG",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqSponsorAttestation {
    pub attestation_id: String,
    pub attestation_kind: AttestationKind,
    pub subject_id: String,
    pub sponsor_committee_root: String,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub public_inputs_root: String,
    pub min_security_bits: u16,
    pub privacy_set_size: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub revoked: bool,
}

impl PqSponsorAttestation {
    pub fn new(
        attestation_id: impl Into<String>,
        attestation_kind: AttestationKind,
        subject_id: impl Into<String>,
        issued_at_height: u64,
    ) -> Self {
        let attestation_id = attestation_id.into();
        let subject_id = subject_id.into();
        Self {
            sponsor_committee_root: commitment_id(
                "SPONSOR-ATTESTATION-COMMITTEE",
                &[&attestation_id, &subject_id, attestation_kind.as_str()],
            ),
            pq_signature_root: commitment_id(
                "SPONSOR-ATTESTATION-PQ-SIGNATURE",
                &[&attestation_id],
            ),
            transcript_root: commitment_id("SPONSOR-ATTESTATION-TRANSCRIPT", &[&subject_id]),
            public_inputs_root: commitment_id("SPONSOR-ATTESTATION-PUBLIC-INPUTS", &[&subject_id]),
            attestation_id,
            attestation_kind,
            subject_id,
            min_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            issued_at_height,
            expires_at_height: issued_at_height + DEFAULT_EPOCH_BLOCKS * 4,
            revoked: false,
        }
    }

    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("pq sponsor attestation public record")
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-SPONSOR-REBATE-PQ-ATTESTATION",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeFloorTrigger {
    pub trigger_id: String,
    pub derivative_id: String,
    pub pool_id: String,
    pub observed_fee_micro_units: u64,
    pub floor_micro_units: u64,
    pub trigger_height: u64,
    pub oracle_observation_root: String,
    pub attestation_root: String,
    pub status: TriggerStatus,
}

impl FeeFloorTrigger {
    pub fn new(
        trigger_id: impl Into<String>,
        derivative_id: impl Into<String>,
        pool_id: impl Into<String>,
        observed_fee_micro_units: u64,
        floor_micro_units: u64,
        trigger_height: u64,
    ) -> Self {
        let trigger_id = trigger_id.into();
        let derivative_id = derivative_id.into();
        let pool_id = pool_id.into();
        Self {
            oracle_observation_root: commitment_id(
                "FEE-FLOOR-OBSERVATION",
                &[&trigger_id, &observed_fee_micro_units.to_string()],
            ),
            attestation_root: empty_root("FEE-FLOOR-ATTESTATION"),
            trigger_id,
            derivative_id,
            pool_id,
            observed_fee_micro_units,
            floor_micro_units,
            trigger_height,
            status: TriggerStatus::Observed,
        }
    }

    pub fn is_below_floor(&self) -> bool {
        self.observed_fee_micro_units < self.floor_micro_units
    }

    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("fee floor trigger public record")
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-SPONSOR-REBATE-FEE-FLOOR-TRIGGER",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub derivative_id: String,
    pub pool_id: String,
    pub beneficiary_commitment: String,
    pub settled_rebate_units: u64,
    pub sponsor_debit_units: u64,
    pub hedge_pnl_units: i128,
    pub settlement_batch_root: String,
    pub receipt_proof_root: String,
    pub status: ReceiptStatus,
    pub settled_at_height: u64,
    pub final_at_height: u64,
}

impl SettlementReceipt {
    pub fn new(
        receipt_id: impl Into<String>,
        derivative_id: impl Into<String>,
        pool_id: impl Into<String>,
        beneficiary_commitment: impl Into<String>,
        settled_rebate_units: u64,
        hedge_pnl_units: i128,
        settled_at_height: u64,
    ) -> Self {
        let receipt_id = receipt_id.into();
        let derivative_id = derivative_id.into();
        let pool_id = pool_id.into();
        Self {
            settlement_batch_root: commitment_id(
                "SPONSOR-REBATE-SETTLEMENT-BATCH",
                &[&receipt_id, &derivative_id],
            ),
            receipt_proof_root: commitment_id("SPONSOR-REBATE-RECEIPT-PROOF", &[&receipt_id]),
            receipt_id,
            derivative_id,
            pool_id,
            beneficiary_commitment: beneficiary_commitment.into(),
            settled_rebate_units,
            sponsor_debit_units: settled_rebate_units,
            hedge_pnl_units,
            status: ReceiptStatus::Pending,
            settled_at_height,
            final_at_height: settled_at_height + DEFAULT_SETTLEMENT_FINALITY_BLOCKS,
        }
    }

    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("settlement receipt public record")
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-SPONSOR-REBATE-SETTLEMENT-RECEIPT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AntiAbuseThrottle {
    pub throttle_id: String,
    pub subject_commitment: String,
    pub pool_id: String,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub request_count: u64,
    pub rebate_units_requested: u64,
    pub abuse_score: u64,
    pub action: ThrottleAction,
    pub evidence_root: String,
}

impl AntiAbuseThrottle {
    pub fn new(
        throttle_id: impl Into<String>,
        subject_commitment: impl Into<String>,
        pool_id: impl Into<String>,
        window_start_height: u64,
    ) -> Self {
        let throttle_id = throttle_id.into();
        Self {
            evidence_root: commitment_id("ANTI-ABUSE-THROTTLE-EVIDENCE", &[&throttle_id]),
            throttle_id,
            subject_commitment: subject_commitment.into(),
            pool_id: pool_id.into(),
            window_start_height,
            window_end_height: window_start_height + DEFAULT_THROTTLE_WINDOW_BLOCKS,
            request_count: 0,
            rebate_units_requested: 0,
            abuse_score: 0,
            action: ThrottleAction::Allow,
        }
    }

    pub fn record_request(&mut self, rebate_units: u64) {
        self.request_count = self.request_count.saturating_add(1);
        self.rebate_units_requested = self.rebate_units_requested.saturating_add(rebate_units);
        self.abuse_score = self
            .request_count
            .saturating_mul(7)
            .saturating_add(self.rebate_units_requested / 10_000);
        self.action = if self.abuse_score >= 250 {
            ThrottleAction::Reject
        } else if self.abuse_score >= 120 {
            ThrottleAction::RequireFreshAttestation
        } else if self.abuse_score >= 70 {
            ThrottleAction::ReduceRebate
        } else {
            ThrottleAction::Allow
        };
    }

    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("anti abuse throttle public record")
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-SPONSOR-REBATE-ANTI-ABUSE-THROTTLE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub subject_id: String,
    pub disclosure_root: String,
    pub max_redacted_fields: u64,
    pub used_redacted_fields: u64,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub auditor_committee_root: String,
    pub exhausted: bool,
}

impl RedactionBudget {
    pub fn new(
        budget_id: impl Into<String>,
        subject_id: impl Into<String>,
        max_redacted_fields: u64,
        window_start_height: u64,
    ) -> Self {
        let budget_id = budget_id.into();
        let subject_id = subject_id.into();
        Self {
            disclosure_root: commitment_id(
                "REDACTION-BUDGET-DISCLOSURE",
                &[&budget_id, &subject_id],
            ),
            auditor_committee_root: commitment_id("REDACTION-BUDGET-AUDITOR", &[&budget_id]),
            budget_id,
            subject_id,
            max_redacted_fields,
            used_redacted_fields: 0,
            window_start_height,
            window_end_height: window_start_height + DEFAULT_REDACTION_WINDOW_BLOCKS,
            exhausted: false,
        }
    }

    pub fn consume(&mut self, fields: u64) -> Result<()> {
        ensure!(!self.exhausted, "redaction budget already exhausted");
        ensure!(
            self.used_redacted_fields.saturating_add(fields) <= self.max_redacted_fields,
            "redaction budget exceeded"
        );
        self.used_redacted_fields = self.used_redacted_fields.saturating_add(fields);
        self.exhausted = self.used_redacted_fields == self.max_redacted_fields;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("redaction budget public record")
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-SPONSOR-REBATE-REDACTION-BUDGET",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_commitment: String,
    pub epoch: u64,
    pub height: u64,
    pub pool_root: String,
    pub derivative_root: String,
    pub risk_root: String,
    pub throttle_root: String,
    pub receipts_root: String,
    pub utilization_bps: u64,
    pub fee_floor_events: u64,
    pub settled_rebate_units: u64,
    pub warnings: BTreeSet<String>,
}

impl OperatorSummary {
    pub fn new(
        summary_id: impl Into<String>,
        operator_commitment: impl Into<String>,
        epoch: u64,
        height: u64,
        roots: &Roots,
        counters: &Counters,
    ) -> Self {
        let utilization_bps = if counters.total_sponsor_liquidity == 0 {
            0
        } else {
            counters.total_locked_liquidity.saturating_mul(MAX_BPS)
                / counters.total_sponsor_liquidity
        };
        let mut warnings = BTreeSet::new();
        if utilization_bps >= DEFAULT_SPONSOR_UTILIZATION_WARN_BPS {
            warnings.insert("sponsor_utilization_warn".to_string());
        }
        if counters.fired_trigger_count > 0 {
            warnings.insert("fee_floor_trigger_activity".to_string());
        }
        if counters.total_abuse_score > 500 {
            warnings.insert("anti_abuse_pressure".to_string());
        }
        Self {
            summary_id: summary_id.into(),
            operator_commitment: operator_commitment.into(),
            epoch,
            height,
            pool_root: roots.sponsor_pool_root.clone(),
            derivative_root: roots.rebate_derivative_root.clone(),
            risk_root: roots.hedge_leg_root.clone(),
            throttle_root: roots.anti_abuse_throttle_root.clone(),
            receipts_root: roots.settlement_receipt_root.clone(),
            utilization_bps,
            fee_floor_events: counters.fired_trigger_count,
            settled_rebate_units: counters.total_settled_rebate,
            warnings,
        }
    }

    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("operator summary public record")
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-SPONSOR-REBATE-OPERATOR-SUMMARY",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub sponsor_pools: BTreeMap<String, SponsorPool>,
    pub rebate_derivatives: BTreeMap<String, RebateDerivative>,
    pub hedge_legs: BTreeMap<String, HedgeLeg>,
    pub pq_attestations: BTreeMap<String, PqSponsorAttestation>,
    pub fee_floor_triggers: BTreeMap<String, FeeFloorTrigger>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub anti_abuse_throttles: BTreeMap<String, AntiAbuseThrottle>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub nullifiers: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default(), DEVNET_HEIGHT, DEVNET_EPOCH)
    }
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64) -> Self {
        Self {
            config,
            height,
            epoch,
            sponsor_pools: BTreeMap::new(),
            rebate_derivatives: BTreeMap::new(),
            hedge_legs: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            fee_floor_triggers: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            anti_abuse_throttles: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
        }
    }

    pub fn devnet() -> Self {
        devnet()
    }

    pub fn insert_sponsor_pool(&mut self, mut pool: SponsorPool) -> Result<String> {
        ensure!(
            self.sponsor_pools.len() < self.config.max_sponsor_pools,
            "sponsor pool capacity exceeded"
        );
        ensure!(
            !self.sponsor_pools.contains_key(&pool.pool_id),
            "duplicate sponsor pool {}",
            pool.pool_id
        );
        ensure!(
            pool.rebate_rate_bps <= self.config.max_pool_rebate_bps,
            "pool rebate exceeds configured cap"
        );
        ensure!(
            pool.pq_security_bits >= self.config.min_pq_security_bits,
            "pool pq security below runtime floor"
        );
        pool.refresh_utilization();
        let id = pool.pool_id.clone();
        self.sponsor_pools.insert(id.clone(), pool);
        Ok(id)
    }

    pub fn insert_rebate_derivative(&mut self, derivative: RebateDerivative) -> Result<String> {
        ensure!(
            self.rebate_derivatives.len() < self.config.max_derivatives,
            "rebate derivative capacity exceeded"
        );
        ensure!(
            !self
                .rebate_derivatives
                .contains_key(&derivative.derivative_id),
            "duplicate rebate derivative {}",
            derivative.derivative_id
        );
        let pool = self
            .sponsor_pools
            .get_mut(&derivative.pool_id)
            .ok_or_else(|| format!("missing sponsor pool {}", derivative.pool_id))?;
        ensure!(
            pool.status.accepts_derivatives(),
            "sponsor pool {} does not accept derivatives",
            pool.pool_id
        );
        ensure!(
            derivative.rebate_rate_bps <= self.config.max_user_rebate_bps,
            "derivative rebate exceeds user cap"
        );
        ensure!(
            pool.available_liquidity() >= derivative.notional_units,
            "insufficient sponsor pool available liquidity"
        );
        pool.locked_units = pool.locked_units.saturating_add(derivative.notional_units);
        pool.updated_at_height = self.height;
        pool.refresh_utilization();
        if pool.utilization_bps >= self.config.max_sponsor_utilization_bps {
            pool.status = SponsorPoolStatus::Throttled;
        }
        let id = derivative.derivative_id.clone();
        self.rebate_derivatives.insert(id.clone(), derivative);
        Ok(id)
    }

    pub fn insert_hedge_leg(&mut self, hedge: HedgeLeg) -> Result<String> {
        ensure!(
            self.hedge_legs.len() < self.config.max_hedge_legs,
            "hedge leg capacity exceeded"
        );
        ensure!(
            !self.hedge_legs.contains_key(&hedge.hedge_id),
            "duplicate hedge leg {}",
            hedge.hedge_id
        );
        let derivative = self
            .rebate_derivatives
            .get_mut(&hedge.derivative_id)
            .ok_or_else(|| format!("missing derivative {}", hedge.derivative_id))?;
        ensure!(
            derivative.status.accepts_hedges(),
            "derivative {} is not hedgeable",
            derivative.derivative_id
        );
        ensure!(
            derivative.pool_id == hedge.pool_id,
            "hedge pool does not match derivative pool"
        );
        derivative.status = DerivativeStatus::Hedged;
        derivative.updated_at_height = self.height;
        let id = hedge.hedge_id.clone();
        self.hedge_legs.insert(id.clone(), hedge);
        Ok(id)
    }

    pub fn insert_pq_attestation(&mut self, attestation: PqSponsorAttestation) -> Result<String> {
        ensure!(
            self.pq_attestations.len() < self.config.max_attestations,
            "pq attestation capacity exceeded"
        );
        ensure!(
            !self
                .pq_attestations
                .contains_key(&attestation.attestation_id),
            "duplicate pq attestation {}",
            attestation.attestation_id
        );
        ensure!(
            attestation.min_security_bits >= self.config.min_pq_security_bits,
            "pq attestation security below runtime floor"
        );
        ensure!(
            attestation.privacy_set_size >= self.config.min_privacy_set_size,
            "pq attestation privacy set below runtime floor"
        );
        let id = attestation.attestation_id.clone();
        self.pq_attestations.insert(id.clone(), attestation);
        Ok(id)
    }

    pub fn insert_fee_floor_trigger(&mut self, mut trigger: FeeFloorTrigger) -> Result<String> {
        ensure!(
            self.fee_floor_triggers.len() < self.config.max_fee_floor_triggers,
            "fee floor trigger capacity exceeded"
        );
        ensure!(
            !self.fee_floor_triggers.contains_key(&trigger.trigger_id),
            "duplicate fee floor trigger {}",
            trigger.trigger_id
        );
        let derivative = self
            .rebate_derivatives
            .get_mut(&trigger.derivative_id)
            .ok_or_else(|| format!("missing derivative {}", trigger.derivative_id))?;
        ensure!(
            derivative.pool_id == trigger.pool_id,
            "trigger pool does not match derivative pool"
        );
        if trigger.is_below_floor() {
            trigger.status = TriggerStatus::Fired;
            derivative.status = DerivativeStatus::FloorTriggered;
        } else {
            trigger.status = TriggerStatus::Rejected;
        }
        derivative.updated_at_height = self.height;
        let id = trigger.trigger_id.clone();
        self.fee_floor_triggers.insert(id.clone(), trigger);
        Ok(id)
    }

    pub fn insert_settlement_receipt(&mut self, mut receipt: SettlementReceipt) -> Result<String> {
        ensure!(
            self.settlement_receipts.len() < self.config.max_receipts,
            "settlement receipt capacity exceeded"
        );
        ensure!(
            !self.settlement_receipts.contains_key(&receipt.receipt_id),
            "duplicate settlement receipt {}",
            receipt.receipt_id
        );
        let derivative = self
            .rebate_derivatives
            .get_mut(&receipt.derivative_id)
            .ok_or_else(|| format!("missing derivative {}", receipt.derivative_id))?;
        ensure!(
            derivative.pool_id == receipt.pool_id,
            "receipt pool does not match derivative pool"
        );
        ensure!(
            !derivative.status.is_terminal(),
            "derivative already terminal"
        );
        let pool = self
            .sponsor_pools
            .get_mut(&receipt.pool_id)
            .ok_or_else(|| format!("missing sponsor pool {}", receipt.pool_id))?;
        pool.locked_units = pool.locked_units.saturating_sub(derivative.notional_units);
        pool.liquidity_units = pool
            .liquidity_units
            .saturating_sub(receipt.sponsor_debit_units);
        pool.updated_at_height = self.height;
        pool.refresh_utilization();
        if pool.status == SponsorPoolStatus::Throttled
            && pool.utilization_bps < self.config.sponsor_utilization_warn_bps
        {
            pool.status = SponsorPoolStatus::Active;
        }
        derivative.status = DerivativeStatus::Settled;
        derivative.updated_at_height = self.height;
        if self.height >= receipt.final_at_height {
            receipt.status = ReceiptStatus::Final;
        } else {
            receipt.status = ReceiptStatus::Finalizing;
        }
        let id = receipt.receipt_id.clone();
        self.settlement_receipts.insert(id.clone(), receipt);
        Ok(id)
    }

    pub fn insert_anti_abuse_throttle(&mut self, throttle: AntiAbuseThrottle) -> Result<String> {
        ensure!(
            self.anti_abuse_throttles.len() < self.config.max_throttles,
            "anti abuse throttle capacity exceeded"
        );
        ensure!(
            !self
                .anti_abuse_throttles
                .contains_key(&throttle.throttle_id),
            "duplicate anti abuse throttle {}",
            throttle.throttle_id
        );
        let id = throttle.throttle_id.clone();
        self.anti_abuse_throttles.insert(id.clone(), throttle);
        Ok(id)
    }

    pub fn insert_redaction_budget(&mut self, budget: RedactionBudget) -> Result<String> {
        ensure!(
            self.redaction_budgets.len() < self.config.max_redaction_budgets,
            "redaction budget capacity exceeded"
        );
        ensure!(
            !self.redaction_budgets.contains_key(&budget.budget_id),
            "duplicate redaction budget {}",
            budget.budget_id
        );
        let id = budget.budget_id.clone();
        self.redaction_budgets.insert(id.clone(), budget);
        Ok(id)
    }

    pub fn insert_operator_summary(&mut self, summary: OperatorSummary) -> Result<String> {
        ensure!(
            self.operator_summaries.len() < self.config.max_operator_summaries,
            "operator summary capacity exceeded"
        );
        ensure!(
            !self.operator_summaries.contains_key(&summary.summary_id),
            "duplicate operator summary {}",
            summary.summary_id
        );
        let id = summary.summary_id.clone();
        self.operator_summaries.insert(id.clone(), summary);
        Ok(id)
    }

    pub fn insert_nullifier(&mut self, nullifier: impl Into<String>) -> Result<String> {
        ensure!(
            self.nullifiers.len() < self.config.max_nullifiers,
            "nullifier capacity exceeded"
        );
        let nullifier = nullifier.into();
        ensure!(
            self.nullifiers.insert(nullifier.clone()),
            "duplicate nullifier {}",
            nullifier
        );
        Ok(nullifier)
    }

    pub fn consume_redaction_budget(&mut self, budget_id: &str, fields: u64) -> Result<()> {
        let budget = self
            .redaction_budgets
            .get_mut(budget_id)
            .ok_or_else(|| format!("missing redaction budget {budget_id}"))?;
        budget.consume(fields)
    }

    pub fn record_throttle_request(&mut self, throttle_id: &str, rebate_units: u64) -> Result<()> {
        let throttle = self
            .anti_abuse_throttles
            .get_mut(throttle_id)
            .ok_or_else(|| format!("missing anti abuse throttle {throttle_id}"))?;
        throttle.record_request(rebate_units);
        Ok(())
    }

    pub fn counters(&self) -> Counters {
        let mut counters = Counters {
            sponsor_pool_count: self.sponsor_pools.len() as u64,
            derivative_count: self.rebate_derivatives.len() as u64,
            hedge_leg_count: self.hedge_legs.len() as u64,
            attestation_count: self.pq_attestations.len() as u64,
            fee_floor_trigger_count: self.fee_floor_triggers.len() as u64,
            settlement_receipt_count: self.settlement_receipts.len() as u64,
            anti_abuse_throttle_count: self.anti_abuse_throttles.len() as u64,
            redaction_budget_count: self.redaction_budgets.len() as u64,
            operator_summary_count: self.operator_summaries.len() as u64,
            nullifier_count: self.nullifiers.len() as u64,
            ..Counters::default()
        };
        for pool in self.sponsor_pools.values() {
            if pool.status == SponsorPoolStatus::Active {
                counters.active_pool_count += 1;
            }
            if pool.status == SponsorPoolStatus::Throttled {
                counters.throttled_pool_count += 1;
            }
            counters.total_sponsor_liquidity = counters
                .total_sponsor_liquidity
                .saturating_add(pool.liquidity_units);
            counters.total_locked_liquidity = counters
                .total_locked_liquidity
                .saturating_add(pool.locked_units);
        }
        for derivative in self.rebate_derivatives.values() {
            if !derivative.status.is_terminal() {
                counters.open_derivative_count += 1;
            }
            counters.total_rebate_notional = counters
                .total_rebate_notional
                .saturating_add(derivative.notional_units);
        }
        for hedge in self.hedge_legs.values() {
            counters.total_hedge_notional = counters
                .total_hedge_notional
                .saturating_add(hedge.notional_units);
        }
        for trigger in self.fee_floor_triggers.values() {
            if trigger.status == TriggerStatus::Fired {
                counters.fired_trigger_count += 1;
            }
        }
        for receipt in self.settlement_receipts.values() {
            if receipt.status == ReceiptStatus::Final {
                counters.final_receipt_count += 1;
            }
            counters.total_settled_rebate = counters
                .total_settled_rebate
                .saturating_add(receipt.settled_rebate_units);
        }
        for budget in self.redaction_budgets.values() {
            counters.total_redacted_fields = counters
                .total_redacted_fields
                .saturating_add(budget.used_redacted_fields);
        }
        for throttle in self.anti_abuse_throttles.values() {
            counters.total_abuse_score = counters
                .total_abuse_score
                .saturating_add(throttle.abuse_score);
        }
        counters
    }

    pub fn roots(&self) -> Roots {
        let config_record = self.config.public_record();
        let sponsor_pool_root = map_root(
            "PRIVATE-L2-SPONSOR-REBATE-POOL-ROOT",
            self.sponsor_pools.iter().map(
                |(id, pool)| json!({"id": id, "root": pool.root(), "record": pool.public_record()}),
            ),
        );
        let rebate_derivative_root = map_root(
            "PRIVATE-L2-SPONSOR-REBATE-DERIVATIVE-ROOT",
            self.rebate_derivatives.iter().map(|(id, derivative)| {
                json!({"id": id, "root": derivative.root(), "record": derivative.public_record()})
            }),
        );
        let hedge_leg_root = map_root(
            "PRIVATE-L2-SPONSOR-REBATE-HEDGE-ROOT",
            self.hedge_legs
                .iter()
                .map(|(id, hedge)| json!({"id": id, "root": hedge.root(), "record": hedge.public_record()})),
        );
        let pq_attestation_root = map_root(
            "PRIVATE-L2-SPONSOR-REBATE-PQ-ATTESTATION-ROOT",
            self.pq_attestations.iter().map(|(id, attestation)| {
                json!({"id": id, "root": attestation.root(), "record": attestation.public_record()})
            }),
        );
        let fee_floor_trigger_root = map_root(
            "PRIVATE-L2-SPONSOR-REBATE-FEE-FLOOR-ROOT",
            self.fee_floor_triggers
                .iter()
                .map(|(id, trigger)| json!({"id": id, "root": trigger.root(), "record": trigger.public_record()})),
        );
        let settlement_receipt_root = map_root(
            "PRIVATE-L2-SPONSOR-REBATE-RECEIPT-ROOT",
            self.settlement_receipts
                .iter()
                .map(|(id, receipt)| json!({"id": id, "root": receipt.root(), "record": receipt.public_record()})),
        );
        let anti_abuse_throttle_root = map_root(
            "PRIVATE-L2-SPONSOR-REBATE-THROTTLE-ROOT",
            self.anti_abuse_throttles
                .iter()
                .map(|(id, throttle)| json!({"id": id, "root": throttle.root(), "record": throttle.public_record()})),
        );
        let redaction_budget_root = map_root(
            "PRIVATE-L2-SPONSOR-REBATE-REDACTION-ROOT",
            self.redaction_budgets
                .iter()
                .map(|(id, budget)| json!({"id": id, "root": budget.root(), "record": budget.public_record()})),
        );
        let operator_summary_root = map_root(
            "PRIVATE-L2-SPONSOR-REBATE-OPERATOR-SUMMARY-ROOT",
            self.operator_summaries
                .iter()
                .map(|(id, summary)| json!({"id": id, "root": summary.root(), "record": summary.public_record()})),
        );
        let nullifier_root = merkle_root(
            "PRIVATE-L2-SPONSOR-REBATE-NULLIFIER-ROOT",
            &self
                .nullifiers
                .iter()
                .map(|nullifier| json!(nullifier))
                .collect::<Vec<_>>(),
        );
        let preliminary = json!({
            "protocol_version": PROTOCOL_VERSION,
            "height": self.height,
            "epoch": self.epoch,
            "config_root": domain_hash("PRIVATE-L2-SPONSOR-REBATE-CONFIG", &[HashPart::Json(&config_record)], 32),
            "sponsor_pool_root": sponsor_pool_root,
            "rebate_derivative_root": rebate_derivative_root,
            "hedge_leg_root": hedge_leg_root,
            "pq_attestation_root": pq_attestation_root,
            "fee_floor_trigger_root": fee_floor_trigger_root,
            "settlement_receipt_root": settlement_receipt_root,
            "anti_abuse_throttle_root": anti_abuse_throttle_root,
            "redaction_budget_root": redaction_budget_root,
            "operator_summary_root": operator_summary_root,
            "nullifier_root": nullifier_root,
        });
        let public_record_root = domain_hash(
            "PRIVATE-L2-SPONSOR-REBATE-PUBLIC-RECORD-ROOT",
            &[HashPart::Json(&preliminary)],
            32,
        );
        Roots {
            config_root: preliminary["config_root"]
                .as_str()
                .expect("config root string")
                .to_string(),
            sponsor_pool_root,
            rebate_derivative_root,
            hedge_leg_root,
            pq_attestation_root,
            fee_floor_trigger_root,
            settlement_receipt_root,
            anti_abuse_throttle_root,
            redaction_budget_root,
            operator_summary_root,
            nullifier_root,
            public_record_root,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "sponsor_pools": self.sponsor_pools.iter().map(|(id, pool)| json!({"id": id, "record": pool.public_record()})).collect::<Vec<_>>(),
            "rebate_derivatives": self.rebate_derivatives.iter().map(|(id, derivative)| json!({"id": id, "record": derivative.public_record()})).collect::<Vec<_>>(),
            "hedge_legs": self.hedge_legs.iter().map(|(id, hedge)| json!({"id": id, "record": hedge.public_record()})).collect::<Vec<_>>(),
            "pq_attestations": self.pq_attestations.iter().map(|(id, attestation)| json!({"id": id, "record": attestation.public_record()})).collect::<Vec<_>>(),
            "fee_floor_triggers": self.fee_floor_triggers.iter().map(|(id, trigger)| json!({"id": id, "record": trigger.public_record()})).collect::<Vec<_>>(),
            "settlement_receipts": self.settlement_receipts.iter().map(|(id, receipt)| json!({"id": id, "record": receipt.public_record()})).collect::<Vec<_>>(),
            "anti_abuse_throttles": self.anti_abuse_throttles.iter().map(|(id, throttle)| json!({"id": id, "record": throttle.public_record()})).collect::<Vec<_>>(),
            "redaction_budgets": self.redaction_budgets.iter().map(|(id, budget)| json!({"id": id, "record": budget.public_record()})).collect::<Vec<_>>(),
            "operator_summaries": self.operator_summaries.iter().map(|(id, summary)| json!({"id": id, "record": summary.public_record()})).collect::<Vec<_>>(),
            "nullifier_root": roots.nullifier_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(object) = &mut record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let pool_a = SponsorPool::new(
        "pool:devnet:sponsor-alpha",
        commitment_id("SPONSOR-COMMITMENT", &["alpha", "low-fee-rebate"]),
        2_500_000_000,
        72,
        DEVNET_HEIGHT,
    );
    let pool_b = SponsorPool::new(
        "pool:devnet:sponsor-beta",
        commitment_id("SPONSOR-COMMITMENT", &["beta", "fee-floor-backstop"]),
        1_750_000_000,
        64,
        DEVNET_HEIGHT,
    );
    state.insert_sponsor_pool(pool_a).expect("devnet pool a");
    state.insert_sponsor_pool(pool_b).expect("devnet pool b");

    let derivative_a = RebateDerivative::new(
        "derivative:rebate:alpha:001",
        "pool:devnet:sponsor-alpha",
        commitment_id("OWNER-COMMITMENT", &["wallet-a", "session-17"]),
        RebateDerivativeKind::SponsorFeeFuture,
        125_000_000,
        DEVNET_HEIGHT + 1,
    );
    let derivative_b = RebateDerivative::new(
        "derivative:floor:beta:001",
        "pool:devnet:sponsor-beta",
        commitment_id("OWNER-COMMITMENT", &["wallet-b", "session-22"]),
        RebateDerivativeKind::FeeFloorNote,
        88_000_000,
        DEVNET_HEIGHT + 2,
    );
    state
        .insert_rebate_derivative(derivative_a)
        .expect("devnet derivative a");
    state
        .insert_rebate_derivative(derivative_b)
        .expect("devnet derivative b");

    state
        .insert_hedge_leg(HedgeLeg::new(
            "hedge:alpha:fixed-receive:001",
            "derivative:rebate:alpha:001",
            "pool:devnet:sponsor-alpha",
            commitment_id("HEDGE-COUNTERPARTY", &["maker-a"]),
            HedgeLegKind::FixedFeeReceive,
            75_000_000,
            DEVNET_HEIGHT + 3,
        ))
        .expect("devnet hedge a");
    state
        .insert_hedge_leg(HedgeLeg::new(
            "hedge:beta:floor:001",
            "derivative:floor:beta:001",
            "pool:devnet:sponsor-beta",
            commitment_id("HEDGE-COUNTERPARTY", &["maker-b"]),
            HedgeLegKind::FloorProtection,
            88_000_000,
            DEVNET_HEIGHT + 3,
        ))
        .expect("devnet hedge b");

    for (id, kind, subject) in [
        (
            "attestation:pool-alpha:solvency",
            AttestationKind::PoolSolvency,
            "pool:devnet:sponsor-alpha",
        ),
        (
            "attestation:pool-beta:floor",
            AttestationKind::FeeFloorObservation,
            "pool:devnet:sponsor-beta",
        ),
        (
            "attestation:operator:checkpoint",
            AttestationKind::OperatorCheckpoint,
            "operator:devnet:rebate-vault",
        ),
    ] {
        state
            .insert_pq_attestation(PqSponsorAttestation::new(
                id,
                kind,
                subject,
                DEVNET_HEIGHT + 4,
            ))
            .expect("devnet attestation");
    }

    state
        .insert_fee_floor_trigger(FeeFloorTrigger::new(
            "trigger:floor:beta:001",
            "derivative:floor:beta:001",
            "pool:devnet:sponsor-beta",
            3,
            DEFAULT_FEE_FLOOR_MICRO_UNITS,
            DEVNET_HEIGHT + 5,
        ))
        .expect("devnet trigger");
    state
        .insert_anti_abuse_throttle(AntiAbuseThrottle::new(
            "throttle:wallet-a:devnet",
            commitment_id("OWNER-COMMITMENT", &["wallet-a", "session-17"]),
            "pool:devnet:sponsor-alpha",
            DEVNET_HEIGHT,
        ))
        .expect("devnet throttle");
    state
        .record_throttle_request("throttle:wallet-a:devnet", 14_000)
        .expect("devnet throttle request");
    state
        .insert_redaction_budget(RedactionBudget::new(
            "redaction:derivative-alpha:budget",
            "derivative:rebate:alpha:001",
            12,
            DEVNET_HEIGHT,
        ))
        .expect("devnet redaction budget");
    state
        .consume_redaction_budget("redaction:derivative-alpha:budget", 3)
        .expect("devnet redaction consume");
    state
        .insert_settlement_receipt(SettlementReceipt::new(
            "receipt:alpha:001",
            "derivative:rebate:alpha:001",
            "pool:devnet:sponsor-alpha",
            commitment_id("BENEFICIARY", &["wallet-a"]),
            900_000,
            12_000,
            DEVNET_HEIGHT + 20,
        ))
        .expect("devnet receipt");
    state
        .insert_nullifier(commitment_id("NULLIFIER", &["rebate", "alpha", "001"]))
        .expect("devnet nullifier");
    let roots = state.roots();
    let counters = state.counters();
    state
        .insert_operator_summary(OperatorSummary::new(
            "summary:operator:devnet:001",
            commitment_id("OPERATOR-COMMITMENT", &["rebate-vault-operator"]),
            DEVNET_EPOCH,
            DEVNET_HEIGHT + 24,
            &roots,
            &counters,
        ))
        .expect("devnet summary");
    state
}

pub fn demo() -> State {
    devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-SPONSOR-REBATE-DERIVATIVE-VAULT-RUNTIME-STATE",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn commitment_id(domain: &str, parts: &[&str]) -> String {
    let hash_parts = parts
        .iter()
        .map(|part| HashPart::Str(part))
        .collect::<Vec<_>>();
    domain_hash(domain, &hash_parts, 32)
}

pub fn empty_root(domain: &str) -> String {
    domain_hash(domain, &[], 32)
}

pub fn map_root(domain: &str, records: impl Iterator<Item = Value>) -> String {
    merkle_root(domain, &records.collect::<Vec<_>>())
}
