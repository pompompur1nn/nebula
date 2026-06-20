use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_CONTRACT_STRESS_HARNESS_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-defi-contract-stress-harness-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_CONTRACT_STRESS_HARNESS_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_POLICY_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-defi-contract-stress-v1";
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_MAX_PRIVACY_BUDGET_BPS: u64 = 7_500;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_LOW_FEE_MICRO_UNITS: u64 = 12;
pub const DEFAULT_MAX_ORACLE_DELAY_BLOCKS: u64 = 18;
pub const DEFAULT_MAX_CALLBACK_FANOUT: usize = 64;
pub const DEFAULT_MAX_BATCH_CALLS: usize = 2_048;
pub const DEFAULT_MIN_VAULT_SOLVENCY_BPS: i128 = 10_400;
pub const DEFAULT_MAX_LEVERAGE_BPS: i128 = 300_000;
pub const DEFAULT_LIQUIDATION_MARGIN_BPS: i128 = 6_250;
pub const MAX_BPS: i128 = 10_000;
pub const DEVNET_HEIGHT: u64 = 4_250_000;
pub const DEVNET_FEE_ASSET_ID: &str = "asset:piconero";
pub const DEVNET_BASE_ASSET_ID: &str = "asset:wxmr-devnet";
pub const DEVNET_QUOTE_ASSET_ID: &str = "asset:xusd-devnet";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StressSeverity {
    Info,
    Warning,
    Breach,
    Critical,
}

impl StressSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Breach => "breach",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioKind {
    TokenMintBurst,
    TokenBurnBurst,
    TokenTransferBurst,
    AmmSwapShock,
    LendingBorrowShock,
    PerpsFundingShock,
    LiquidationCascade,
    CallbackFanout,
    OracleDelay,
    GasNetting,
    VaultSolvency,
    CovenantPressure,
    PrivacyBudgetPressure,
    PqPolicyViolation,
    LowFeeSettlementBatch,
}

impl ScenarioKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TokenMintBurst => "token_mint_burst",
            Self::TokenBurnBurst => "token_burn_burst",
            Self::TokenTransferBurst => "token_transfer_burst",
            Self::AmmSwapShock => "amm_swap_shock",
            Self::LendingBorrowShock => "lending_borrow_shock",
            Self::PerpsFundingShock => "perps_funding_shock",
            Self::LiquidationCascade => "liquidation_cascade",
            Self::CallbackFanout => "callback_fanout",
            Self::OracleDelay => "oracle_delay",
            Self::GasNetting => "gas_netting",
            Self::VaultSolvency => "vault_solvency",
            Self::CovenantPressure => "covenant_pressure",
            Self::PrivacyBudgetPressure => "privacy_budget_pressure",
            Self::PqPolicyViolation => "pq_policy_violation",
            Self::LowFeeSettlementBatch => "low_fee_settlement_batch",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentKind {
    Mint,
    Burn,
    Transfer,
    Swap,
    Deposit,
    Borrow,
    Repay,
    OpenPerp,
    ClosePerp,
    Liquidate,
    Callback,
    OracleUpdate,
    GasNet,
    CovenantCheck,
    Settle,
}

impl IntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mint => "mint",
            Self::Burn => "burn",
            Self::Transfer => "transfer",
            Self::Swap => "swap",
            Self::Deposit => "deposit",
            Self::Borrow => "borrow",
            Self::Repay => "repay",
            Self::OpenPerp => "open_perp",
            Self::ClosePerp => "close_perp",
            Self::Liquidate => "liquidate",
            Self::Callback => "callback",
            Self::OracleUpdate => "oracle_update",
            Self::GasNet => "gas_net",
            Self::CovenantCheck => "covenant_check",
            Self::Settle => "settle",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallStatus {
    Planned,
    Applied,
    Rejected,
    Settled,
}

impl CallStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Applied => "applied",
            Self::Rejected => "rejected",
            Self::Settled => "settled",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub operator_commitment: String,
    pub fee_asset_id: String,
    pub min_privacy_set_size: u64,
    pub max_privacy_budget_bps: u64,
    pub min_pq_security_bits: u16,
    pub low_fee_micro_units: u64,
    pub max_oracle_delay_blocks: u64,
    pub max_callback_fanout: usize,
    pub max_batch_calls: usize,
    pub min_vault_solvency_bps: i128,
    pub max_leverage_bps: i128,
    pub liquidation_margin_bps: i128,
    pub enabled_scenarios: BTreeSet<ScenarioKind>,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            operator_commitment: deterministic_id("DEVNET-STRESS-OPERATOR", "operator"),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_privacy_budget_bps: DEFAULT_MAX_PRIVACY_BUDGET_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            low_fee_micro_units: DEFAULT_LOW_FEE_MICRO_UNITS,
            max_oracle_delay_blocks: DEFAULT_MAX_ORACLE_DELAY_BLOCKS,
            max_callback_fanout: DEFAULT_MAX_CALLBACK_FANOUT,
            max_batch_calls: DEFAULT_MAX_BATCH_CALLS,
            min_vault_solvency_bps: DEFAULT_MIN_VAULT_SOLVENCY_BPS,
            max_leverage_bps: DEFAULT_MAX_LEVERAGE_BPS,
            liquidation_margin_bps: DEFAULT_LIQUIDATION_MARGIN_BPS,
            enabled_scenarios: all_scenarios(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        require(self.chain_id == CHAIN_ID, "config chain id mismatch")?;
        require(
            !self.operator_commitment.is_empty(),
            "missing operator commitment",
        )?;
        require(!self.fee_asset_id.is_empty(), "missing fee asset")?;
        require(
            self.min_privacy_set_size > 0,
            "privacy set must be positive",
        )?;
        require(
            self.max_privacy_budget_bps <= MAX_BPS as u64,
            "privacy budget exceeds 100%",
        )?;
        require(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "insufficient pq security bits",
        )?;
        require(self.low_fee_micro_units > 0, "low fee must be positive")?;
        require(
            self.max_callback_fanout > 0,
            "callback fanout must be positive",
        )?;
        require(self.max_batch_calls > 0, "batch calls must be positive")?;
        require(
            self.min_vault_solvency_bps >= MAX_BPS,
            "vault solvency floor below par",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "operator_commitment": self.operator_commitment,
            "fee_asset_id": self.fee_asset_id,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_privacy_budget_bps": self.max_privacy_budget_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "low_fee_micro_units": self.low_fee_micro_units,
            "max_oracle_delay_blocks": self.max_oracle_delay_blocks,
            "max_callback_fanout": self.max_callback_fanout,
            "max_batch_calls": self.max_batch_calls,
            "min_vault_solvency_bps": self.min_vault_solvency_bps,
            "max_leverage_bps": self.max_leverage_bps,
            "liquidation_margin_bps": self.liquidation_margin_bps,
            "enabled_scenarios": self.enabled_scenarios.iter().map(|kind| kind.as_str()).collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub token_mints: u64,
    pub token_burns: u64,
    pub token_transfers: u64,
    pub amm_swaps: u64,
    pub lending_actions: u64,
    pub perp_actions: u64,
    pub liquidations: u64,
    pub callbacks: u64,
    pub oracle_delays: u64,
    pub gas_netting_events: u64,
    pub covenant_checks: u64,
    pub privacy_budget_events: u64,
    pub pq_policy_violations: u64,
    pub low_fee_batches: u64,
    pub assertions: u64,
    pub assertion_breaches: u64,
    pub receipts: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "token_mints": self.token_mints,
            "token_burns": self.token_burns,
            "token_transfers": self.token_transfers,
            "amm_swaps": self.amm_swaps,
            "lending_actions": self.lending_actions,
            "perp_actions": self.perp_actions,
            "liquidations": self.liquidations,
            "callbacks": self.callbacks,
            "oracle_delays": self.oracle_delays,
            "gas_netting_events": self.gas_netting_events,
            "covenant_checks": self.covenant_checks,
            "privacy_budget_events": self.privacy_budget_events,
            "pq_policy_violations": self.pq_policy_violations,
            "low_fee_batches": self.low_fee_batches,
            "assertions": self.assertions,
            "assertion_breaches": self.assertion_breaches,
            "receipts": self.receipts,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub token_root: String,
    pub account_root: String,
    pub amm_root: String,
    pub lending_root: String,
    pub perps_root: String,
    pub vault_root: String,
    pub covenant_root: String,
    pub intent_root: String,
    pub call_root: String,
    pub oracle_root: String,
    pub gas_netting_root: String,
    pub privacy_root: String,
    pub pq_violation_root: String,
    pub assertion_root: String,
    pub receipt_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "token_root": self.token_root,
            "account_root": self.account_root,
            "amm_root": self.amm_root,
            "lending_root": self.lending_root,
            "perps_root": self.perps_root,
            "vault_root": self.vault_root,
            "covenant_root": self.covenant_root,
            "intent_root": self.intent_root,
            "call_root": self.call_root,
            "oracle_root": self.oracle_root,
            "gas_netting_root": self.gas_netting_root,
            "privacy_root": self.privacy_root,
            "pq_violation_root": self.pq_violation_root,
            "assertion_root": self.assertion_root,
            "receipt_root": self.receipt_root,
            "nullifier_root": self.nullifier_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TokenPosition {
    pub account_commitment: String,
    pub asset_id: String,
    pub confidential_balance: i128,
    pub minted_units: u64,
    pub burned_units: u64,
    pub transfer_in_units: u64,
    pub transfer_out_units: u64,
    pub note_root: String,
}

impl TokenPosition {
    pub fn public_record(&self) -> Value {
        json!({
            "account_commitment": self.account_commitment,
            "asset_id": self.asset_id,
            "confidential_balance": self.confidential_balance,
            "minted_units": self.minted_units,
            "burned_units": self.burned_units,
            "transfer_in_units": self.transfer_in_units,
            "transfer_out_units": self.transfer_out_units,
            "note_root": self.note_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AmmPoolState {
    pub pool_id: String,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub base_reserve_units: i128,
    pub quote_reserve_units: i128,
    pub fee_bps: u64,
    pub invariant_root: String,
}

impl AmmPoolState {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "base_reserve_units": self.base_reserve_units,
            "quote_reserve_units": self.quote_reserve_units,
            "fee_bps": self.fee_bps,
            "invariant_root": self.invariant_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LendingMarketState {
    pub market_id: String,
    pub collateral_asset_id: String,
    pub debt_asset_id: String,
    pub collateral_units: i128,
    pub debt_units: i128,
    pub interest_index_bps: i128,
    pub health_factor_bps: i128,
}

impl LendingMarketState {
    pub fn public_record(&self) -> Value {
        json!({
            "market_id": self.market_id,
            "collateral_asset_id": self.collateral_asset_id,
            "debt_asset_id": self.debt_asset_id,
            "collateral_units": self.collateral_units,
            "debt_units": self.debt_units,
            "interest_index_bps": self.interest_index_bps,
            "health_factor_bps": self.health_factor_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PerpsPositionState {
    pub position_id: String,
    pub owner_commitment: String,
    pub market_id: String,
    pub notional_units: i128,
    pub margin_units: i128,
    pub funding_bps: i128,
    pub leverage_bps: i128,
}

impl PerpsPositionState {
    pub fn public_record(&self) -> Value {
        json!({
            "position_id": self.position_id,
            "owner_commitment": self.owner_commitment,
            "market_id": self.market_id,
            "notional_units": self.notional_units,
            "margin_units": self.margin_units,
            "funding_bps": self.funding_bps,
            "leverage_bps": self.leverage_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VaultState {
    pub vault_id: String,
    pub asset_id: String,
    pub assets_units: i128,
    pub liabilities_units: i128,
    pub solvency_bps: i128,
    pub proof_root: String,
}

impl VaultState {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "asset_id": self.asset_id,
            "assets_units": self.assets_units,
            "liabilities_units": self.liabilities_units,
            "solvency_bps": self.solvency_bps,
            "proof_root": self.proof_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CovenantRule {
    pub covenant_id: String,
    pub subject_id: String,
    pub rule_root: String,
    pub max_exposure_units: i128,
    pub min_privacy_set_size: u64,
    pub active: bool,
}

impl CovenantRule {
    pub fn public_record(&self) -> Value {
        json!({
            "covenant_id": self.covenant_id,
            "subject_id": self.subject_id,
            "rule_root": self.rule_root,
            "max_exposure_units": self.max_exposure_units,
            "min_privacy_set_size": self.min_privacy_set_size,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OracleDelayScenario {
    pub scenario_id: String,
    pub feed_id: String,
    pub observed_height: u64,
    pub published_height: u64,
    pub drift_bps: i128,
    pub price_root: String,
}

impl OracleDelayScenario {
    pub fn public_record(&self) -> Value {
        json!({
            "scenario_id": self.scenario_id,
            "feed_id": self.feed_id,
            "observed_height": self.observed_height,
            "published_height": self.published_height,
            "delay_blocks": self.delay_blocks(),
            "drift_bps": self.drift_bps,
            "price_root": self.price_root,
        })
    }

    pub fn delay_blocks(&self) -> u64 {
        self.published_height.saturating_sub(self.observed_height)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyBudgetPressure {
    pub pressure_id: String,
    pub account_commitment: String,
    pub spent_budget_bps: u64,
    pub anonymity_set_size: u64,
    pub nullifier_root: String,
}

impl PrivacyBudgetPressure {
    pub fn public_record(&self) -> Value {
        json!({
            "pressure_id": self.pressure_id,
            "account_commitment": self.account_commitment,
            "spent_budget_bps": self.spent_budget_bps,
            "anonymity_set_size": self.anonymity_set_size,
            "nullifier_root": self.nullifier_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqPolicyViolation {
    pub violation_id: String,
    pub subject_id: String,
    pub policy_root: String,
    pub observed_security_bits: u16,
    pub required_security_bits: u16,
    pub signature_scheme: String,
    pub rejected: bool,
}

impl PqPolicyViolation {
    pub fn public_record(&self) -> Value {
        json!({
            "violation_id": self.violation_id,
            "subject_id": self.subject_id,
            "policy_root": self.policy_root,
            "observed_security_bits": self.observed_security_bits,
            "required_security_bits": self.required_security_bits,
            "signature_scheme": self.signature_scheme,
            "rejected": self.rejected,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IntentRecord {
    pub intent_id: String,
    pub scenario_id: String,
    pub kind: IntentKind,
    pub account_commitment: String,
    pub asset_id: String,
    pub amount_units: i128,
    pub privacy_budget_bps: u64,
    pub pq_policy_root: String,
    pub created_at_height: u64,
}

impl IntentRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "scenario_id": self.scenario_id,
            "kind": self.kind.as_str(),
            "account_commitment": self.account_commitment,
            "asset_id": self.asset_id,
            "amount_units": self.amount_units,
            "privacy_budget_bps": self.privacy_budget_bps,
            "pq_policy_root": self.pq_policy_root,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ContractCallRecord {
    pub call_id: String,
    pub intent_id: String,
    pub from_contract_id: String,
    pub to_contract_id: String,
    pub selector: String,
    pub calldata_root: String,
    pub gas_debit_units: i128,
    pub gas_credit_units: i128,
    pub callback_count: u64,
    pub status: CallStatus,
}

impl ContractCallRecord {
    pub fn net_gas_units(&self) -> i128 {
        self.gas_debit_units - self.gas_credit_units
    }

    pub fn public_record(&self) -> Value {
        json!({
            "call_id": self.call_id,
            "intent_id": self.intent_id,
            "from_contract_id": self.from_contract_id,
            "to_contract_id": self.to_contract_id,
            "selector": self.selector,
            "calldata_root": self.calldata_root,
            "gas_debit_units": self.gas_debit_units,
            "gas_credit_units": self.gas_credit_units,
            "net_gas_units": self.net_gas_units(),
            "callback_count": self.callback_count,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GasNettingRecord {
    pub netting_id: String,
    pub batch_id: String,
    pub contract_id: String,
    pub debits_units: i128,
    pub credits_units: i128,
    pub settled_units: i128,
}

impl GasNettingRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "netting_id": self.netting_id,
            "batch_id": self.batch_id,
            "contract_id": self.contract_id,
            "debits_units": self.debits_units,
            "credits_units": self.credits_units,
            "settled_units": self.settled_units,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RiskAssertion {
    pub assertion_id: String,
    pub scenario_id: String,
    pub severity: StressSeverity,
    pub subject_id: String,
    pub predicate: String,
    pub observed_value: i128,
    pub threshold_value: i128,
    pub passed: bool,
}

impl RiskAssertion {
    pub fn public_record(&self) -> Value {
        json!({
            "assertion_id": self.assertion_id,
            "scenario_id": self.scenario_id,
            "severity": self.severity.as_str(),
            "subject_id": self.subject_id,
            "predicate": self.predicate,
            "observed_value": self.observed_value,
            "threshold_value": self.threshold_value,
            "passed": self.passed,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub scenario_id: String,
    pub call_count: u64,
    pub fee_asset_id: String,
    pub fee_paid_micro_units: u64,
    pub low_fee: bool,
    pub state_root_before: String,
    pub state_root_after: String,
    pub settled_at_height: u64,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "scenario_id": self.scenario_id,
            "call_count": self.call_count,
            "fee_asset_id": self.fee_asset_id,
            "fee_paid_micro_units": self.fee_paid_micro_units,
            "low_fee": self.low_fee,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StressScenario {
    pub scenario_id: String,
    pub kind: ScenarioKind,
    pub label: String,
    pub account_commitment: String,
    pub asset_id: String,
    pub amount_units: i128,
    pub repeat_count: u64,
    pub fanout: u64,
    pub fee_micro_units: u64,
    pub created_at_height: u64,
}

impl StressScenario {
    pub fn devnet(kind: ScenarioKind, index: u64) -> Self {
        let label = format!("devnet-{}-{index}", kind.as_str());
        let scenario_id = deterministic_id("STRESS-SCENARIO", &label);
        Self {
            scenario_id,
            kind,
            label: label.clone(),
            account_commitment: deterministic_id("STRESS-ACCOUNT", &label),
            asset_id: if index % 2 == 0 {
                DEVNET_BASE_ASSET_ID.to_string()
            } else {
                DEVNET_QUOTE_ASSET_ID.to_string()
            },
            amount_units: 10_000 + (index as i128 * 1_337),
            repeat_count: 4 + index,
            fanout: 2 + (index % 8),
            fee_micro_units: DEFAULT_LOW_FEE_MICRO_UNITS,
            created_at_height: DEVNET_HEIGHT + index,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "scenario_id": self.scenario_id,
            "kind": self.kind.as_str(),
            "label": self.label,
            "account_commitment": self.account_commitment,
            "asset_id": self.asset_id,
            "amount_units": self.amount_units,
            "repeat_count": self.repeat_count,
            "fanout": self.fanout,
            "fee_micro_units": self.fee_micro_units,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub scenarios: BTreeMap<String, StressScenario>,
    pub token_positions: BTreeMap<String, TokenPosition>,
    pub amm_pools: BTreeMap<String, AmmPoolState>,
    pub lending_markets: BTreeMap<String, LendingMarketState>,
    pub perps_positions: BTreeMap<String, PerpsPositionState>,
    pub vaults: BTreeMap<String, VaultState>,
    pub covenants: BTreeMap<String, CovenantRule>,
    pub intents: BTreeMap<String, IntentRecord>,
    pub calls: BTreeMap<String, ContractCallRecord>,
    pub oracle_delays: BTreeMap<String, OracleDelayScenario>,
    pub gas_netting: BTreeMap<String, GasNettingRecord>,
    pub privacy_pressure: BTreeMap<String, PrivacyBudgetPressure>,
    pub pq_policy_violations: BTreeMap<String, PqPolicyViolation>,
    pub assertions: BTreeMap<String, RiskAssertion>,
    pub receipts: BTreeMap<String, SettlementReceipt>,
    pub spent_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            scenarios: BTreeMap::new(),
            token_positions: BTreeMap::new(),
            amm_pools: BTreeMap::new(),
            lending_markets: BTreeMap::new(),
            perps_positions: BTreeMap::new(),
            vaults: BTreeMap::new(),
            covenants: BTreeMap::new(),
            intents: BTreeMap::new(),
            calls: BTreeMap::new(),
            oracle_delays: BTreeMap::new(),
            gas_netting: BTreeMap::new(),
            privacy_pressure: BTreeMap::new(),
            pq_policy_violations: BTreeMap::new(),
            assertions: BTreeMap::new(),
            receipts: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        })
    }

    pub fn devnet() -> Self {
        let mut state = match Self::new(Config::devnet()) {
            Ok(state) => state,
            Err(_) => Self::fallback_devnet(),
        };
        state.seed_devnet_markets();
        let mut index = 1_u64;
        for kind in all_scenarios() {
            let scenario = StressScenario::devnet(kind, index);
            let _ = state.apply_scenario(scenario);
            index = index.saturating_add(1);
        }
        state
    }

    pub fn demo() -> Self {
        Self::devnet()
    }

    pub fn add_scenario(&mut self, scenario: StressScenario) -> Result<()> {
        require(
            self.config.enabled_scenarios.contains(&scenario.kind),
            "scenario kind disabled",
        )?;
        require(!scenario.scenario_id.is_empty(), "missing scenario id")?;
        require(scenario.repeat_count > 0, "scenario repeat count is zero")?;
        require(
            scenario.fanout as usize <= self.config.max_callback_fanout,
            "fanout too high",
        )?;
        self.scenarios
            .insert(scenario.scenario_id.clone(), scenario);
        Ok(())
    }

    pub fn apply_scenario(&mut self, scenario: StressScenario) -> Result<SettlementReceipt> {
        let state_root_before = self.roots().state_root;
        self.add_scenario(scenario.clone())?;
        let mut call_count = 0_u64;
        for step in 0..scenario.repeat_count {
            let intent = self.build_intent(&scenario, step);
            self.apply_intent_effect(&scenario, &intent)?;
            call_count = call_count.saturating_add(self.fanout_contract_calls(&scenario, &intent)?);
            self.intents.insert(intent.intent_id.clone(), intent);
        }
        self.evaluate_scenario_risk(&scenario);
        let state_root_after = self.roots().state_root;
        let receipt = SettlementReceipt {
            receipt_id: deterministic_record_id(
                "STRESS-RECEIPT",
                self.receipts.len() as u64,
                &scenario.public_record(),
            ),
            batch_id: deterministic_id("STRESS-BATCH", &scenario.scenario_id),
            scenario_id: scenario.scenario_id.clone(),
            call_count,
            fee_asset_id: self.config.fee_asset_id.clone(),
            fee_paid_micro_units: scenario.fee_micro_units.saturating_mul(call_count.max(1)),
            low_fee: scenario.fee_micro_units <= self.config.low_fee_micro_units,
            state_root_before,
            state_root_after,
            settled_at_height: scenario
                .created_at_height
                .saturating_add(scenario.repeat_count),
        };
        self.counters.receipts = self.counters.receipts.saturating_add(1);
        if receipt.low_fee {
            self.counters.low_fee_batches = self.counters.low_fee_batches.saturating_add(1);
        }
        self.receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        Ok(receipt)
    }

    pub fn roots(&self) -> Roots {
        let token_root = map_root(
            "STRESS-TOKENS",
            &self.token_positions,
            TokenPosition::public_record,
        );
        let account_set = self
            .token_positions
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        let account_root = set_root("STRESS-ACCOUNTS", &account_set);
        let amm_root = map_root("STRESS-AMM", &self.amm_pools, AmmPoolState::public_record);
        let lending_root = map_root(
            "STRESS-LENDING",
            &self.lending_markets,
            LendingMarketState::public_record,
        );
        let perps_root = map_root(
            "STRESS-PERPS",
            &self.perps_positions,
            PerpsPositionState::public_record,
        );
        let vault_root = map_root("STRESS-VAULTS", &self.vaults, VaultState::public_record);
        let covenant_root = map_root(
            "STRESS-COVENANTS",
            &self.covenants,
            CovenantRule::public_record,
        );
        let intent_root = map_root("STRESS-INTENTS", &self.intents, IntentRecord::public_record);
        let call_root = map_root(
            "STRESS-CALLS",
            &self.calls,
            ContractCallRecord::public_record,
        );
        let oracle_root = map_root(
            "STRESS-ORACLE-DELAYS",
            &self.oracle_delays,
            OracleDelayScenario::public_record,
        );
        let gas_netting_root = map_root(
            "STRESS-GAS-NETTING",
            &self.gas_netting,
            GasNettingRecord::public_record,
        );
        let privacy_root = map_root(
            "STRESS-PRIVACY",
            &self.privacy_pressure,
            PrivacyBudgetPressure::public_record,
        );
        let pq_violation_root = map_root(
            "STRESS-PQ-VIOLATIONS",
            &self.pq_policy_violations,
            PqPolicyViolation::public_record,
        );
        let assertion_root = map_root(
            "STRESS-ASSERTIONS",
            &self.assertions,
            RiskAssertion::public_record,
        );
        let receipt_root = map_root(
            "STRESS-RECEIPTS",
            &self.receipts,
            SettlementReceipt::public_record,
        );
        let nullifier_root = set_root("STRESS-NULLIFIERS", &self.spent_nullifiers);
        let state_record = json!({
            "token_root": token_root,
            "amm_root": amm_root,
            "lending_root": lending_root,
            "perps_root": perps_root,
            "vault_root": vault_root,
            "covenant_root": covenant_root,
            "intent_root": intent_root,
            "call_root": call_root,
            "oracle_root": oracle_root,
            "gas_netting_root": gas_netting_root,
            "privacy_root": privacy_root,
            "pq_violation_root": pq_violation_root,
            "assertion_root": assertion_root,
            "receipt_root": receipt_root,
            "nullifier_root": nullifier_root,
            "counters": self.counters.public_record(),
        });
        let state_root = payload_root("STRESS-STATE", &state_record);
        Roots {
            token_root,
            account_root,
            amm_root,
            lending_root,
            perps_root,
            vault_root,
            covenant_root,
            intent_root,
            call_root,
            oracle_root,
            gas_netting_root,
            privacy_root,
            pq_violation_root,
            assertion_root,
            receipt_root,
            nullifier_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "hash_suite": HASH_SUITE,
            "pq_policy_suite": PQ_POLICY_SUITE,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
            "scenarios": map_records(&self.scenarios, StressScenario::public_record),
            "token_positions": map_records(&self.token_positions, TokenPosition::public_record),
            "amm_pools": map_records(&self.amm_pools, AmmPoolState::public_record),
            "lending_markets": map_records(&self.lending_markets, LendingMarketState::public_record),
            "perps_positions": map_records(&self.perps_positions, PerpsPositionState::public_record),
            "vaults": map_records(&self.vaults, VaultState::public_record),
            "covenants": map_records(&self.covenants, CovenantRule::public_record),
            "intents": map_records(&self.intents, IntentRecord::public_record),
            "calls": map_records(&self.calls, ContractCallRecord::public_record),
            "oracle_delays": map_records(&self.oracle_delays, OracleDelayScenario::public_record),
            "gas_netting": map_records(&self.gas_netting, GasNettingRecord::public_record),
            "privacy_pressure": map_records(&self.privacy_pressure, PrivacyBudgetPressure::public_record),
            "pq_policy_violations": map_records(&self.pq_policy_violations, PqPolicyViolation::public_record),
            "assertions": map_records(&self.assertions, RiskAssertion::public_record),
            "receipts": map_records(&self.receipts, SettlementReceipt::public_record),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn fallback_devnet() -> Self {
        Self {
            config: Config::devnet(),
            counters: Counters::default(),
            scenarios: BTreeMap::new(),
            token_positions: BTreeMap::new(),
            amm_pools: BTreeMap::new(),
            lending_markets: BTreeMap::new(),
            perps_positions: BTreeMap::new(),
            vaults: BTreeMap::new(),
            covenants: BTreeMap::new(),
            intents: BTreeMap::new(),
            calls: BTreeMap::new(),
            oracle_delays: BTreeMap::new(),
            gas_netting: BTreeMap::new(),
            privacy_pressure: BTreeMap::new(),
            pq_policy_violations: BTreeMap::new(),
            assertions: BTreeMap::new(),
            receipts: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        }
    }

    fn seed_devnet_markets(&mut self) {
        let pool_id = deterministic_id("STRESS-AMM-POOL", "wxmr-xusd");
        self.amm_pools.insert(
            pool_id.clone(),
            AmmPoolState {
                pool_id: pool_id.clone(),
                base_asset_id: DEVNET_BASE_ASSET_ID.to_string(),
                quote_asset_id: DEVNET_QUOTE_ASSET_ID.to_string(),
                base_reserve_units: 90_000_000,
                quote_reserve_units: 18_000_000_000,
                fee_bps: 18,
                invariant_root: deterministic_id("STRESS-AMM-INVARIANT", &pool_id),
            },
        );
        let market_id = deterministic_id("STRESS-LENDING-MARKET", "wxmr-xusd");
        self.lending_markets.insert(
            market_id.clone(),
            LendingMarketState {
                market_id: market_id.clone(),
                collateral_asset_id: DEVNET_BASE_ASSET_ID.to_string(),
                debt_asset_id: DEVNET_QUOTE_ASSET_ID.to_string(),
                collateral_units: 15_000_000,
                debt_units: 1_900_000_000,
                interest_index_bps: 10_125,
                health_factor_bps: 16_500,
            },
        );
        let vault_id = deterministic_id("STRESS-VAULT", "xusd-solvency");
        self.vaults.insert(
            vault_id.clone(),
            VaultState {
                vault_id: vault_id.clone(),
                asset_id: DEVNET_QUOTE_ASSET_ID.to_string(),
                assets_units: 25_000_000_000,
                liabilities_units: 22_000_000_000,
                solvency_bps: 11_363,
                proof_root: deterministic_id("STRESS-VAULT-PROOF", &vault_id),
            },
        );
        let covenant_id = deterministic_id("STRESS-COVENANT", "devnet-exposure");
        self.covenants.insert(
            covenant_id.clone(),
            CovenantRule {
                covenant_id,
                subject_id: vault_id,
                rule_root: deterministic_id("STRESS-COVENANT-RULE", "devnet-exposure"),
                max_exposure_units: 24_000_000_000,
                min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
                active: true,
            },
        );
    }

    fn build_intent(&self, scenario: &StressScenario, step: u64) -> IntentRecord {
        let intent_kind = match scenario.kind {
            ScenarioKind::TokenMintBurst => IntentKind::Mint,
            ScenarioKind::TokenBurnBurst => IntentKind::Burn,
            ScenarioKind::TokenTransferBurst => IntentKind::Transfer,
            ScenarioKind::AmmSwapShock => IntentKind::Swap,
            ScenarioKind::LendingBorrowShock => IntentKind::Borrow,
            ScenarioKind::PerpsFundingShock => IntentKind::OpenPerp,
            ScenarioKind::LiquidationCascade => IntentKind::Liquidate,
            ScenarioKind::CallbackFanout => IntentKind::Callback,
            ScenarioKind::OracleDelay => IntentKind::OracleUpdate,
            ScenarioKind::GasNetting => IntentKind::GasNet,
            ScenarioKind::VaultSolvency => IntentKind::Deposit,
            ScenarioKind::CovenantPressure => IntentKind::CovenantCheck,
            ScenarioKind::PrivacyBudgetPressure => IntentKind::Transfer,
            ScenarioKind::PqPolicyViolation => IntentKind::CovenantCheck,
            ScenarioKind::LowFeeSettlementBatch => IntentKind::Settle,
        };
        let record = json!({
            "scenario_id": scenario.scenario_id,
            "step": step,
            "kind": intent_kind.as_str(),
            "account": scenario.account_commitment,
        });
        IntentRecord {
            intent_id: deterministic_record_id("STRESS-INTENT", step, &record),
            scenario_id: scenario.scenario_id.clone(),
            kind: intent_kind,
            account_commitment: scenario.account_commitment.clone(),
            asset_id: scenario.asset_id.clone(),
            amount_units: scenario.amount_units,
            privacy_budget_bps: privacy_budget_for_step(step),
            pq_policy_root: deterministic_id("STRESS-PQ-POLICY", &scenario.scenario_id),
            created_at_height: scenario.created_at_height.saturating_add(step),
        }
    }

    fn apply_intent_effect(
        &mut self,
        scenario: &StressScenario,
        intent: &IntentRecord,
    ) -> Result<()> {
        match scenario.kind {
            ScenarioKind::TokenMintBurst => {
                self.apply_token_delta(intent, intent.amount_units, true)
            }
            ScenarioKind::TokenBurnBurst => {
                self.apply_token_delta(intent, -intent.amount_units, true)
            }
            ScenarioKind::TokenTransferBurst => self.apply_token_delta(intent, 0, true),
            ScenarioKind::AmmSwapShock => self.apply_amm_shock(intent),
            ScenarioKind::LendingBorrowShock => self.apply_lending_shock(intent),
            ScenarioKind::PerpsFundingShock => self.apply_perps_shock(intent),
            ScenarioKind::LiquidationCascade => self.apply_liquidation(intent),
            ScenarioKind::CallbackFanout => Ok(()),
            ScenarioKind::OracleDelay => self.apply_oracle_delay(scenario, intent),
            ScenarioKind::GasNetting => Ok(()),
            ScenarioKind::VaultSolvency => self.apply_vault_solvency(intent),
            ScenarioKind::CovenantPressure => self.apply_covenant_pressure(intent),
            ScenarioKind::PrivacyBudgetPressure => self.apply_privacy_pressure(intent),
            ScenarioKind::PqPolicyViolation => self.apply_pq_violation(intent),
            ScenarioKind::LowFeeSettlementBatch => Ok(()),
        }
    }

    fn apply_token_delta(
        &mut self,
        intent: &IntentRecord,
        delta: i128,
        count_transfer: bool,
    ) -> Result<()> {
        let key = position_key(&intent.account_commitment, &intent.asset_id);
        let mut position =
            self.token_positions
                .get(&key)
                .cloned()
                .unwrap_or_else(|| TokenPosition {
                    account_commitment: intent.account_commitment.clone(),
                    asset_id: intent.asset_id.clone(),
                    confidential_balance: 0,
                    minted_units: 0,
                    burned_units: 0,
                    transfer_in_units: 0,
                    transfer_out_units: 0,
                    note_root: deterministic_id("STRESS-NOTE", &key),
                });
        let next_balance = position.confidential_balance.saturating_add(delta);
        require(next_balance >= 0, "token balance would become negative")?;
        position.confidential_balance = next_balance;
        if delta > 0 {
            position.minted_units = position.minted_units.saturating_add(delta as u64);
            self.counters.token_mints = self.counters.token_mints.saturating_add(1);
        } else if delta < 0 {
            position.burned_units = position.burned_units.saturating_add((-delta) as u64);
            self.counters.token_burns = self.counters.token_burns.saturating_add(1);
        } else if count_transfer {
            position.transfer_out_units = position
                .transfer_out_units
                .saturating_add(intent.amount_units.max(0) as u64);
            self.counters.token_transfers = self.counters.token_transfers.saturating_add(1);
        }
        self.spent_nullifiers
            .insert(deterministic_id("STRESS-NULLIFIER", &intent.intent_id));
        self.token_positions.insert(key, position);
        Ok(())
    }

    fn apply_amm_shock(&mut self, intent: &IntentRecord) -> Result<()> {
        let pool_key = first_key(&self.amm_pools, "missing amm pool")?;
        let mut pool = match self.amm_pools.get(&pool_key).cloned() {
            Some(pool) => pool,
            None => return Err("missing amm pool".to_string()),
        };
        let input = intent.amount_units.max(1);
        let fee = input.saturating_mul(pool.fee_bps as i128) / MAX_BPS;
        pool.base_reserve_units = pool.base_reserve_units.saturating_add(input);
        pool.quote_reserve_units = pool
            .quote_reserve_units
            .saturating_sub(input.saturating_sub(fee).saturating_mul(180));
        pool.invariant_root = payload_root("STRESS-AMM-INVARIANT", &pool.public_record());
        self.amm_pools.insert(pool_key, pool);
        self.counters.amm_swaps = self.counters.amm_swaps.saturating_add(1);
        Ok(())
    }

    fn apply_lending_shock(&mut self, intent: &IntentRecord) -> Result<()> {
        let market_key = first_key(&self.lending_markets, "missing lending market")?;
        let mut market = match self.lending_markets.get(&market_key).cloned() {
            Some(market) => market,
            None => return Err("missing lending market".to_string()),
        };
        market.debt_units = market.debt_units.saturating_add(intent.amount_units.max(1));
        market.health_factor_bps =
            compute_health_factor(market.collateral_units, market.debt_units);
        self.lending_markets.insert(market_key, market);
        self.counters.lending_actions = self.counters.lending_actions.saturating_add(1);
        Ok(())
    }

    fn apply_perps_shock(&mut self, intent: &IntentRecord) -> Result<()> {
        let position_id = deterministic_id("STRESS-PERPS-POSITION", &intent.intent_id);
        let margin = (intent.amount_units / 12).max(1);
        let notional = intent.amount_units.saturating_mul(8);
        let leverage_bps = notional.saturating_mul(MAX_BPS) / margin.max(1);
        self.perps_positions.insert(
            position_id.clone(),
            PerpsPositionState {
                position_id,
                owner_commitment: intent.account_commitment.clone(),
                market_id: deterministic_id("STRESS-PERPS-MARKET", &intent.asset_id),
                notional_units: notional,
                margin_units: margin,
                funding_bps: 42,
                leverage_bps,
            },
        );
        self.counters.perp_actions = self.counters.perp_actions.saturating_add(1);
        Ok(())
    }

    fn apply_liquidation(&mut self, intent: &IntentRecord) -> Result<()> {
        self.apply_lending_shock(intent)?;
        self.counters.liquidations = self.counters.liquidations.saturating_add(1);
        Ok(())
    }

    fn apply_oracle_delay(
        &mut self,
        scenario: &StressScenario,
        intent: &IntentRecord,
    ) -> Result<()> {
        let observed_height = intent.created_at_height.saturating_sub(scenario.fanout);
        let delay = OracleDelayScenario {
            scenario_id: scenario.scenario_id.clone(),
            feed_id: deterministic_id("STRESS-ORACLE-FEED", &intent.asset_id),
            observed_height,
            published_height: intent.created_at_height,
            drift_bps: scenario.fanout as i128 * 11,
            price_root: deterministic_id("STRESS-PRICE", &intent.intent_id),
        };
        self.oracle_delays.insert(intent.intent_id.clone(), delay);
        self.counters.oracle_delays = self.counters.oracle_delays.saturating_add(1);
        Ok(())
    }

    fn apply_vault_solvency(&mut self, intent: &IntentRecord) -> Result<()> {
        let vault_key = first_key(&self.vaults, "missing vault")?;
        let mut vault = match self.vaults.get(&vault_key).cloned() {
            Some(vault) => vault,
            None => return Err("missing vault".to_string()),
        };
        vault.liabilities_units = vault
            .liabilities_units
            .saturating_add(intent.amount_units / 3);
        vault.solvency_bps = compute_solvency(vault.assets_units, vault.liabilities_units);
        vault.proof_root = payload_root("STRESS-VAULT-PROOF", &vault.public_record());
        self.vaults.insert(vault_key, vault);
        Ok(())
    }

    fn apply_covenant_pressure(&mut self, intent: &IntentRecord) -> Result<()> {
        let covenant_id = deterministic_id("STRESS-COVENANT-CHECK", &intent.intent_id);
        self.covenants.insert(
            covenant_id.clone(),
            CovenantRule {
                covenant_id,
                subject_id: intent.account_commitment.clone(),
                rule_root: deterministic_id("STRESS-COVENANT-RULE", &intent.intent_id),
                max_exposure_units: intent.amount_units.saturating_mul(4),
                min_privacy_set_size: self.config.min_privacy_set_size,
                active: true,
            },
        );
        self.counters.covenant_checks = self.counters.covenant_checks.saturating_add(1);
        Ok(())
    }

    fn apply_privacy_pressure(&mut self, intent: &IntentRecord) -> Result<()> {
        let pressure = PrivacyBudgetPressure {
            pressure_id: deterministic_id("STRESS-PRIVACY-PRESSURE", &intent.intent_id),
            account_commitment: intent.account_commitment.clone(),
            spent_budget_bps: intent.privacy_budget_bps,
            anonymity_set_size: self
                .config
                .min_privacy_set_size
                .saturating_sub(intent.privacy_budget_bps),
            nullifier_root: deterministic_id("STRESS-PRIVACY-NULLIFIERS", &intent.intent_id),
        };
        self.privacy_pressure
            .insert(pressure.pressure_id.clone(), pressure);
        self.counters.privacy_budget_events = self.counters.privacy_budget_events.saturating_add(1);
        Ok(())
    }

    fn apply_pq_violation(&mut self, intent: &IntentRecord) -> Result<()> {
        let violation = PqPolicyViolation {
            violation_id: deterministic_id("STRESS-PQ-VIOLATION", &intent.intent_id),
            subject_id: intent.account_commitment.clone(),
            policy_root: intent.pq_policy_root.clone(),
            observed_security_bits: self.config.min_pq_security_bits.saturating_sub(64),
            required_security_bits: self.config.min_pq_security_bits,
            signature_scheme: PQ_POLICY_SUITE.to_string(),
            rejected: true,
        };
        self.pq_policy_violations
            .insert(violation.violation_id.clone(), violation);
        self.counters.pq_policy_violations = self.counters.pq_policy_violations.saturating_add(1);
        Ok(())
    }

    fn fanout_contract_calls(
        &mut self,
        scenario: &StressScenario,
        intent: &IntentRecord,
    ) -> Result<u64> {
        require(
            scenario.fanout as usize <= self.config.max_callback_fanout,
            "fanout too high",
        )?;
        let mut calls = 0_u64;
        for index in 0..scenario.fanout {
            let call_record = ContractCallRecord {
                call_id: deterministic_record_id("STRESS-CALL", index, &intent.public_record()),
                intent_id: intent.intent_id.clone(),
                from_contract_id: deterministic_id("STRESS-CONTRACT-FROM", &scenario.scenario_id),
                to_contract_id: deterministic_id(
                    "STRESS-CONTRACT-TO",
                    &format!("{}-{index}", scenario.scenario_id),
                ),
                selector: selector_for_kind(intent.kind).to_string(),
                calldata_root: payload_root("STRESS-CALLDATA", &intent.public_record()),
                gas_debit_units: 1_000 + (index as i128 * 17),
                gas_credit_units: if scenario.kind == ScenarioKind::GasNetting {
                    700
                } else {
                    0
                },
                callback_count: if scenario.kind == ScenarioKind::CallbackFanout {
                    scenario.fanout
                } else {
                    1
                },
                status: if scenario.kind == ScenarioKind::PqPolicyViolation {
                    CallStatus::Rejected
                } else {
                    CallStatus::Applied
                },
            };
            if scenario.kind == ScenarioKind::GasNetting {
                self.insert_gas_netting(&scenario.scenario_id, &call_record);
            }
            if scenario.kind == ScenarioKind::CallbackFanout {
                self.counters.callbacks = self
                    .counters
                    .callbacks
                    .saturating_add(call_record.callback_count);
            }
            self.calls.insert(call_record.call_id.clone(), call_record);
            calls = calls.saturating_add(1);
        }
        Ok(calls)
    }

    fn insert_gas_netting(&mut self, scenario_id: &str, call: &ContractCallRecord) {
        let netting = GasNettingRecord {
            netting_id: deterministic_id("STRESS-GAS-NETTING", &call.call_id),
            batch_id: deterministic_id("STRESS-GAS-BATCH", scenario_id),
            contract_id: call.to_contract_id.clone(),
            debits_units: call.gas_debit_units,
            credits_units: call.gas_credit_units,
            settled_units: call.net_gas_units(),
        };
        self.gas_netting.insert(netting.netting_id.clone(), netting);
        self.counters.gas_netting_events = self.counters.gas_netting_events.saturating_add(1);
    }

    fn evaluate_scenario_risk(&mut self, scenario: &StressScenario) {
        match scenario.kind {
            ScenarioKind::VaultSolvency => {
                let items = self.vaults.values().cloned().collect::<Vec<_>>();
                for vault in items {
                    self.assert_risk(
                        &scenario.scenario_id,
                        &vault.vault_id,
                        "vault_solvency_bps_gte_floor",
                        vault.solvency_bps,
                        self.config.min_vault_solvency_bps,
                        vault.solvency_bps >= self.config.min_vault_solvency_bps,
                    );
                }
            }
            ScenarioKind::LendingBorrowShock | ScenarioKind::LiquidationCascade => {
                let items = self.lending_markets.values().cloned().collect::<Vec<_>>();
                for market in items {
                    self.assert_risk(
                        &scenario.scenario_id,
                        &market.market_id,
                        "health_factor_above_liquidation_margin",
                        market.health_factor_bps,
                        self.config.liquidation_margin_bps,
                        market.health_factor_bps >= self.config.liquidation_margin_bps,
                    );
                }
            }
            ScenarioKind::PerpsFundingShock => {
                let items = self.perps_positions.values().cloned().collect::<Vec<_>>();
                for position in items {
                    self.assert_risk(
                        &scenario.scenario_id,
                        &position.position_id,
                        "leverage_bps_lte_cap",
                        position.leverage_bps,
                        self.config.max_leverage_bps,
                        position.leverage_bps <= self.config.max_leverage_bps,
                    );
                }
            }
            ScenarioKind::OracleDelay => {
                let items = self.oracle_delays.values().cloned().collect::<Vec<_>>();
                for delay in items {
                    self.assert_risk(
                        &scenario.scenario_id,
                        &delay.feed_id,
                        "oracle_delay_lte_cap",
                        delay.delay_blocks() as i128,
                        self.config.max_oracle_delay_blocks as i128,
                        delay.delay_blocks() <= self.config.max_oracle_delay_blocks,
                    );
                }
            }
            ScenarioKind::PrivacyBudgetPressure => {
                let items = self.privacy_pressure.values().cloned().collect::<Vec<_>>();
                for pressure in items {
                    self.assert_risk(
                        &scenario.scenario_id,
                        &pressure.pressure_id,
                        "privacy_budget_lte_cap",
                        pressure.spent_budget_bps as i128,
                        self.config.max_privacy_budget_bps as i128,
                        pressure.spent_budget_bps <= self.config.max_privacy_budget_bps,
                    );
                }
            }
            ScenarioKind::PqPolicyViolation => {
                let items = self
                    .pq_policy_violations
                    .values()
                    .cloned()
                    .collect::<Vec<_>>();
                for violation in items {
                    self.assert_risk(
                        &scenario.scenario_id,
                        &violation.violation_id,
                        "pq_security_bits_gte_required",
                        violation.observed_security_bits as i128,
                        violation.required_security_bits as i128,
                        violation.observed_security_bits >= violation.required_security_bits,
                    );
                }
            }
            _ => {}
        }
    }

    fn assert_risk(
        &mut self,
        scenario_id: &str,
        subject_id: &str,
        predicate: &str,
        observed_value: i128,
        threshold_value: i128,
        passed: bool,
    ) {
        let severity = if passed {
            StressSeverity::Info
        } else if observed_value == 0 {
            StressSeverity::Critical
        } else {
            StressSeverity::Breach
        };
        let record = json!({
            "scenario_id": scenario_id,
            "subject_id": subject_id,
            "predicate": predicate,
            "observed_value": observed_value,
            "threshold_value": threshold_value,
        });
        let assertion = RiskAssertion {
            assertion_id: deterministic_record_id(
                "STRESS-ASSERTION",
                self.assertions.len() as u64,
                &record,
            ),
            scenario_id: scenario_id.to_string(),
            severity,
            subject_id: subject_id.to_string(),
            predicate: predicate.to_string(),
            observed_value,
            threshold_value,
            passed,
        };
        self.counters.assertions = self.counters.assertions.saturating_add(1);
        if !passed {
            self.counters.assertion_breaches = self.counters.assertion_breaches.saturating_add(1);
        }
        self.assertions
            .insert(assertion.assertion_id.clone(), assertion);
    }
}

pub fn deterministic_id(domain: &str, label: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn deterministic_record_id(domain: &str, sequence: u64, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, record: &Value) -> String {
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

pub fn scenario_root(scenarios: &BTreeMap<String, StressScenario>) -> String {
    map_root("STRESS-SCENARIOS", scenarios, StressScenario::public_record)
}

pub fn receipt_root(receipts: &BTreeMap<String, SettlementReceipt>) -> String {
    map_root(
        "STRESS-SETTLEMENT-RECEIPTS",
        receipts,
        SettlementReceipt::public_record,
    )
}

fn map_records<T, F>(items: &BTreeMap<String, T>, record: F) -> Vec<Value>
where
    F: Fn(&T) -> Value,
{
    items.values().map(record).collect::<Vec<_>>()
}

fn map_root<T, F>(domain: &str, items: &BTreeMap<String, T>, record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = items
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": record(value) }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, items: &BTreeSet<String>) -> String {
    let leaves = items.iter().map(|item| json!(item)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn all_scenarios() -> BTreeSet<ScenarioKind> {
    [
        ScenarioKind::TokenMintBurst,
        ScenarioKind::TokenBurnBurst,
        ScenarioKind::TokenTransferBurst,
        ScenarioKind::AmmSwapShock,
        ScenarioKind::LendingBorrowShock,
        ScenarioKind::PerpsFundingShock,
        ScenarioKind::LiquidationCascade,
        ScenarioKind::CallbackFanout,
        ScenarioKind::OracleDelay,
        ScenarioKind::GasNetting,
        ScenarioKind::VaultSolvency,
        ScenarioKind::CovenantPressure,
        ScenarioKind::PrivacyBudgetPressure,
        ScenarioKind::PqPolicyViolation,
        ScenarioKind::LowFeeSettlementBatch,
    ]
    .iter()
    .copied()
    .collect()
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn position_key(account_commitment: &str, asset_id: &str) -> String {
    deterministic_id(
        "STRESS-POSITION-KEY",
        &format!("{account_commitment}:{asset_id}"),
    )
}

fn first_key<T>(items: &BTreeMap<String, T>, message: &str) -> Result<String> {
    match items.keys().next() {
        Some(key) => Ok(key.clone()),
        None => Err(message.to_string()),
    }
}

fn compute_solvency(assets_units: i128, liabilities_units: i128) -> i128 {
    if liabilities_units <= 0 {
        return MAX_BPS * 10;
    }
    assets_units.saturating_mul(MAX_BPS) / liabilities_units
}

fn compute_health_factor(collateral_units: i128, debt_units: i128) -> i128 {
    if debt_units <= 0 {
        return MAX_BPS * 10;
    }
    collateral_units.saturating_mul(150).saturating_mul(MAX_BPS) / debt_units
}

fn privacy_budget_for_step(step: u64) -> u64 {
    1_000 + ((step % 9) * 850)
}

fn selector_for_kind(kind: IntentKind) -> &'static str {
    match kind {
        IntentKind::Mint => "mint_confidential(bytes32,uint128)",
        IntentKind::Burn => "burn_confidential(bytes32,uint128)",
        IntentKind::Transfer => "transfer_private(bytes32,bytes32,uint128)",
        IntentKind::Swap => "swap_private(bytes32,bytes32,uint128)",
        IntentKind::Deposit => "deposit_vault_private(bytes32,uint128)",
        IntentKind::Borrow => "borrow_confidential(bytes32,uint128)",
        IntentKind::Repay => "repay_confidential(bytes32,uint128)",
        IntentKind::OpenPerp => "open_private_perp(bytes32,int128)",
        IntentKind::ClosePerp => "close_private_perp(bytes32)",
        IntentKind::Liquidate => "liquidate_private(bytes32)",
        IntentKind::Callback => "stress_callback(bytes32)",
        IntentKind::OracleUpdate => "delayed_oracle_update(bytes32)",
        IntentKind::GasNet => "net_cross_contract_gas(bytes32)",
        IntentKind::CovenantCheck => "enforce_covenant(bytes32)",
        IntentKind::Settle => "settle_low_fee_batch(bytes32)",
    }
}
