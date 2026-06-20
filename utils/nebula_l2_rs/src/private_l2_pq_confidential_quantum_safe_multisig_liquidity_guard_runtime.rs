use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialQuantumSafeMultisigLiquidityGuardRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_QUANTUM_SAFE_MULTISIG_LIQUIDITY_GUARD_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-quantum-safe-multisig-liquidity-guard-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_QUANTUM_SAFE_MULTISIG_LIQUIDITY_GUARD_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_SIGNER_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-liquidity-guard-signer-v1";
pub const SEALED_GUARD_INTENT_SUITE: &str =
    "ML-KEM-1024+zk-sealed-bridge-amm-liquidity-guard-intent-v1";
pub const THRESHOLD_APPROVAL_SUITE: &str = "pq-threshold-liquidity-approval-confidential-root-v1";
pub const EMERGENCY_FREEZE_SUITE: &str = "pq-multisig-liquidity-emergency-freeze-v1";
pub const SIGNER_SLASHING_SUITE: &str = "pq-liquidity-guard-signer-slashing-evidence-v1";
pub const LOW_FEE_REBATE_SUITE: &str = "low-fee-liquidity-approval-rebate-v1";
pub const REDACTION_BUDGET_SUITE: &str = "roots-only-liquidity-redaction-budget-v1";
pub const PUBLIC_RECORD_SUITE: &str =
    "roots-only-quantum-safe-multisig-liquidity-guard-public-record-v1";
pub const DEVNET_HEIGHT: u64 = 3_120_640;
pub const DEVNET_EPOCH: u64 = 42;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_COHORT_SIZE: u16 = 15;
pub const DEFAULT_APPROVAL_THRESHOLD: u16 = 10;
pub const DEFAULT_EMERGENCY_THRESHOLD: u16 = 7;
pub const DEFAULT_SLASH_THRESHOLD: u16 = 6;
pub const DEFAULT_INTENT_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_FREEZE_REVIEW_BLOCKS: u64 = 192;
pub const DEFAULT_ROOT_FRESHNESS_BLOCKS: u64 = 48;
pub const DEFAULT_MAX_LIQUIDITY_BPS: u64 = 2_500;
pub const DEFAULT_MAX_PRICE_IMPACT_BPS: u64 = 120;
pub const DEFAULT_LOW_FEE_TARGET_BPS: u64 = 9;
pub const DEFAULT_LOW_FEE_REBATE_BPS: u64 = 6_000;
pub const DEFAULT_SLASH_BPS: u64 = 2_500;
pub const DEFAULT_REDACTION_BUDGET_FIELDS: u32 = 16;
pub const DEFAULT_REDACTION_BUDGET_BYTES: u32 = 1_024;
pub const MAX_VAULTS: usize = 262_144;
pub const MAX_SIGNER_COHORTS: usize = 65_536;
pub const MAX_GUARD_INTENTS: usize = 1_048_576;
pub const MAX_APPROVALS: usize = 2_097_152;
pub const MAX_FREEZES: usize = 262_144;
pub const MAX_SLASHES: usize = 524_288;
pub const MAX_REBATES: usize = 1_048_576;
pub const MAX_REDACTION_BUDGETS: usize = 262_144;
pub const MAX_PUBLIC_RECORDS: usize = 2_097_152;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultKind {
    BridgeVault,
    AmmPool,
    StableSwapPool,
    DarkpoolVault,
    CrossRuntimeLiquidity,
    EmergencyBackstop,
}

impl VaultKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BridgeVault => "bridge_vault",
            Self::AmmPool => "amm_pool",
            Self::StableSwapPool => "stable_swap_pool",
            Self::DarkpoolVault => "darkpool_vault",
            Self::CrossRuntimeLiquidity => "cross_runtime_liquidity",
            Self::EmergencyBackstop => "emergency_backstop",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Open,
    Guarded,
    Throttled,
    Frozen,
    Draining,
    Retired,
}

impl VaultStatus {
    pub fn accepts_intents(self) -> bool {
        matches!(self, Self::Open | Self::Guarded | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerStatus {
    Candidate,
    Active,
    Degraded,
    Quarantined,
    Slashed,
    Retired,
}

impl SignerStatus {
    pub fn can_approve(self) -> bool {
        matches!(self, Self::Active | Self::Degraded)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardIntentKind {
    BridgeRelease,
    BridgeRefill,
    AmmRebalance,
    AmmWithdraw,
    BackstopDraw,
    EmergencyDrain,
}

impl GuardIntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BridgeRelease => "bridge_release",
            Self::BridgeRefill => "bridge_refill",
            Self::AmmRebalance => "amm_rebalance",
            Self::AmmWithdraw => "amm_withdraw",
            Self::BackstopDraw => "backstop_draw",
            Self::EmergencyDrain => "emergency_drain",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Sealed,
    Admitted,
    ThresholdPending,
    Approved,
    Executed,
    Rebated,
    Frozen,
    Rejected,
    Expired,
    Slashed,
}

impl IntentStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::Admitted | Self::ThresholdPending | Self::Approved
        )
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Executed | Self::Rebated | Self::Rejected | Self::Expired | Self::Slashed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Signed,
    Counted,
    Superseded,
    Rejected,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FreezeScope {
    Global,
    Vault,
    Cohort,
    BridgeLane,
    AmmPair,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FreezeStatus {
    Requested,
    Active,
    Review,
    Lifted,
    Expired,
}

impl FreezeStatus {
    pub fn blocks_execution(self) -> bool {
        matches!(self, Self::Requested | Self::Active | Self::Review)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_signer_suite: String,
    pub sealed_intent_suite: String,
    pub threshold_approval_suite: String,
    pub emergency_freeze_suite: String,
    pub low_fee_rebate_suite: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub cohort_size: u16,
    pub approval_threshold: u16,
    pub emergency_threshold: u16,
    pub slash_threshold: u16,
    pub intent_ttl_blocks: u64,
    pub freeze_review_blocks: u64,
    pub root_freshness_blocks: u64,
    pub max_liquidity_bps: u64,
    pub max_price_impact_bps: u64,
    pub low_fee_target_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub slash_bps: u64,
    pub redaction_budget_fields: u32,
    pub redaction_budget_bytes: u32,
    pub require_dual_pq_schemes: bool,
    pub require_public_record: bool,
    pub allow_low_fee_rebates: bool,
    pub allow_emergency_freezes: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_signer_suite: PQ_SIGNER_SUITE.to_string(),
            sealed_intent_suite: SEALED_GUARD_INTENT_SUITE.to_string(),
            threshold_approval_suite: THRESHOLD_APPROVAL_SUITE.to_string(),
            emergency_freeze_suite: EMERGENCY_FREEZE_SUITE.to_string(),
            low_fee_rebate_suite: LOW_FEE_REBATE_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            cohort_size: DEFAULT_COHORT_SIZE,
            approval_threshold: DEFAULT_APPROVAL_THRESHOLD,
            emergency_threshold: DEFAULT_EMERGENCY_THRESHOLD,
            slash_threshold: DEFAULT_SLASH_THRESHOLD,
            intent_ttl_blocks: DEFAULT_INTENT_TTL_BLOCKS,
            freeze_review_blocks: DEFAULT_FREEZE_REVIEW_BLOCKS,
            root_freshness_blocks: DEFAULT_ROOT_FRESHNESS_BLOCKS,
            max_liquidity_bps: DEFAULT_MAX_LIQUIDITY_BPS,
            max_price_impact_bps: DEFAULT_MAX_PRICE_IMPACT_BPS,
            low_fee_target_bps: DEFAULT_LOW_FEE_TARGET_BPS,
            low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            slash_bps: DEFAULT_SLASH_BPS,
            redaction_budget_fields: DEFAULT_REDACTION_BUDGET_FIELDS,
            redaction_budget_bytes: DEFAULT_REDACTION_BUDGET_BYTES,
            require_dual_pq_schemes: true,
            require_public_record: true,
            allow_low_fee_rebates: true,
            allow_emergency_freezes: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.approval_threshold <= self.cohort_size,
            "approval threshold exceeds cohort size"
        );
        ensure!(
            self.emergency_threshold <= self.cohort_size,
            "emergency threshold exceeds cohort size"
        );
        ensure!(
            self.slash_threshold <= self.cohort_size,
            "slash threshold exceeds cohort size"
        );
        ensure!(
            self.max_liquidity_bps <= MAX_BPS
                && self.max_price_impact_bps <= MAX_BPS
                && self.low_fee_target_bps <= MAX_BPS
                && self.low_fee_rebate_bps <= MAX_BPS
                && self.slash_bps <= MAX_BPS,
            "basis points out of range"
        );
        Ok(())
    }

    pub fn root(&self) -> String {
        payload_root("LIQUIDITY-GUARD-CONFIG", &to_value(self))
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub vaults_registered: u64,
    pub cohorts_registered: u64,
    pub signers_registered: u64,
    pub sealed_intents: u64,
    pub admitted_intents: u64,
    pub approved_intents: u64,
    pub executed_intents: u64,
    pub frozen_intents: u64,
    pub emergency_freezes: u64,
    pub signer_slashes: u64,
    pub low_fee_rebates: u64,
    pub redaction_budgets: u64,
    pub public_records: u64,
    pub total_guarded_liquidity_atomic: u128,
    pub total_approved_liquidity_atomic: u128,
    pub total_rebate_atomic: u128,
    pub total_slashed_bond_atomic: u128,
}

impl Counters {
    pub fn zero() -> Self {
        Self::default()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub vault_root: String,
    pub cohort_root: String,
    pub signer_root: String,
    pub sealed_intent_root: String,
    pub approval_root: String,
    pub freeze_root: String,
    pub slashing_root: String,
    pub rebate_root: String,
    pub redaction_budget_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "vault_root": self.vault_root,
            "cohort_root": self.cohort_root,
            "signer_root": self.signer_root,
            "sealed_intent_root": self.sealed_intent_root,
            "approval_root": self.approval_root,
            "freeze_root": self.freeze_root,
            "slashing_root": self.slashing_root,
            "rebate_root": self.rebate_root,
            "redaction_budget_root": self.redaction_budget_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityVault {
    pub vault_id: String,
    pub kind: VaultKind,
    pub status: VaultStatus,
    pub asset_pair: String,
    pub bridge_domain: String,
    pub operator_commitment: String,
    pub cohort_id: String,
    pub liquidity_commitment: String,
    pub guarded_liquidity_atomic: u128,
    pub max_release_atomic: u128,
    pub max_price_impact_bps: u64,
    pub last_root: String,
    pub last_height: u64,
}

impl LiquidityVault {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "kind": self.kind,
            "status": self.status,
            "asset_pair": self.asset_pair,
            "bridge_domain": self.bridge_domain,
            "operator_commitment": self.operator_commitment,
            "cohort_id": self.cohort_id,
            "liquidity_commitment": self.liquidity_commitment,
            "guarded_liquidity_atomic": self.guarded_liquidity_atomic,
            "max_release_atomic": self.max_release_atomic,
            "max_price_impact_bps": self.max_price_impact_bps,
            "last_root": self.last_root,
            "last_height": self.last_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignerCohort {
    pub cohort_id: String,
    pub label: String,
    pub signer_ids: BTreeSet<String>,
    pub approval_threshold: u16,
    pub emergency_threshold: u16,
    pub slash_threshold: u16,
    pub aggregate_key_root: String,
    pub stake_root: String,
    pub active: bool,
    pub created_height: u64,
}

impl SignerCohort {
    pub fn public_record(&self) -> Value {
        json!({
            "cohort_id": self.cohort_id,
            "label": self.label,
            "signer_count": self.signer_ids.len(),
            "approval_threshold": self.approval_threshold,
            "emergency_threshold": self.emergency_threshold,
            "slash_threshold": self.slash_threshold,
            "aggregate_key_root": self.aggregate_key_root,
            "stake_root": self.stake_root,
            "active": self.active,
            "created_height": self.created_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSigner {
    pub signer_id: String,
    pub cohort_id: String,
    pub status: SignerStatus,
    pub operator_commitment: String,
    pub ml_dsa_key_commitment: String,
    pub slh_dsa_key_commitment: String,
    pub stake_commitment: String,
    pub weight_bps: u64,
    pub last_approval_height: u64,
    pub slash_count: u64,
}

impl PqSigner {
    pub fn public_record(&self) -> Value {
        json!({
            "signer_id": self.signer_id,
            "cohort_id": self.cohort_id,
            "status": self.status,
            "operator_commitment": self.operator_commitment,
            "ml_dsa_key_commitment": self.ml_dsa_key_commitment,
            "slh_dsa_key_commitment": self.slh_dsa_key_commitment,
            "stake_commitment": self.stake_commitment,
            "weight_bps": self.weight_bps,
            "last_approval_height": self.last_approval_height,
            "slash_count": self.slash_count
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedGuardIntent {
    pub intent_id: String,
    pub vault_id: String,
    pub cohort_id: String,
    pub kind: GuardIntentKind,
    pub status: IntentStatus,
    pub sealed_payload_root: String,
    pub route_commitment: String,
    pub beneficiary_commitment: String,
    pub liquidity_atomic: u128,
    pub max_fee_bps: u64,
    pub price_impact_bps: u64,
    pub privacy_set_size: u64,
    pub redaction_budget_id: String,
    pub created_height: u64,
    pub expires_height: u64,
}

impl SealedGuardIntent {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "vault_id": self.vault_id,
            "cohort_id": self.cohort_id,
            "kind": self.kind,
            "status": self.status,
            "sealed_payload_root": self.sealed_payload_root,
            "route_commitment": self.route_commitment,
            "beneficiary_commitment": self.beneficiary_commitment,
            "liquidity_atomic": self.liquidity_atomic,
            "max_fee_bps": self.max_fee_bps,
            "price_impact_bps": self.price_impact_bps,
            "privacy_set_size": self.privacy_set_size,
            "redaction_budget_id": self.redaction_budget_id,
            "created_height": self.created_height,
            "expires_height": self.expires_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ThresholdApproval {
    pub approval_id: String,
    pub intent_id: String,
    pub signer_id: String,
    pub cohort_id: String,
    pub status: ApprovalStatus,
    pub approval_root: String,
    pub signature_root: String,
    pub observed_vault_root: String,
    pub fee_bps: u64,
    pub height: u64,
}

impl ThresholdApproval {
    pub fn public_record(&self) -> Value {
        json!({
            "approval_id": self.approval_id,
            "intent_id": self.intent_id,
            "signer_id": self.signer_id,
            "cohort_id": self.cohort_id,
            "status": self.status,
            "approval_root": self.approval_root,
            "signature_root": self.signature_root,
            "observed_vault_root": self.observed_vault_root,
            "fee_bps": self.fee_bps,
            "height": self.height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EmergencyFreeze {
    pub freeze_id: String,
    pub scope: FreezeScope,
    pub target_id: String,
    pub status: FreezeStatus,
    pub cohort_id: String,
    pub reason_root: String,
    pub approval_root: String,
    pub requested_height: u64,
    pub review_height: u64,
}

impl EmergencyFreeze {
    pub fn public_record(&self) -> Value {
        json!({
            "freeze_id": self.freeze_id,
            "scope": self.scope,
            "target_id": self.target_id,
            "status": self.status,
            "cohort_id": self.cohort_id,
            "reason_root": self.reason_root,
            "approval_root": self.approval_root,
            "requested_height": self.requested_height,
            "review_height": self.review_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignerSlashing {
    pub slash_id: String,
    pub signer_id: String,
    pub cohort_id: String,
    pub evidence_root: String,
    pub challenged_intent_id: String,
    pub slash_bps: u64,
    pub slashed_bond_atomic: u128,
    pub challenger_commitment: String,
    pub height: u64,
}

impl SignerSlashing {
    pub fn public_record(&self) -> Value {
        json!({
            "slash_id": self.slash_id,
            "signer_id": self.signer_id,
            "cohort_id": self.cohort_id,
            "evidence_root": self.evidence_root,
            "challenged_intent_id": self.challenged_intent_id,
            "slash_bps": self.slash_bps,
            "slashed_bond_atomic": self.slashed_bond_atomic,
            "challenger_commitment": self.challenger_commitment,
            "height": self.height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeApprovalRebate {
    pub rebate_id: String,
    pub intent_id: String,
    pub approval_root: String,
    pub recipient_commitment: String,
    pub rebate_asset: String,
    pub rebate_atomic: u128,
    pub fee_bps: u64,
    pub paid_height: u64,
}

impl LowFeeApprovalRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "intent_id": self.intent_id,
            "approval_root": self.approval_root,
            "recipient_commitment": self.recipient_commitment,
            "rebate_asset": self.rebate_asset,
            "rebate_atomic": self.rebate_atomic,
            "fee_bps": self.fee_bps,
            "paid_height": self.paid_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub owner_commitment: String,
    pub scope_root: String,
    pub max_fields: u32,
    pub max_bytes: u32,
    pub used_fields: u32,
    pub used_bytes: u32,
    pub expires_height: u64,
}

impl RedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "owner_commitment": self.owner_commitment,
            "scope_root": self.scope_root,
            "max_fields": self.max_fields,
            "max_bytes": self.max_bytes,
            "used_fields": self.used_fields,
            "used_bytes": self.used_bytes,
            "expires_height": self.expires_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub current_height: u64,
    pub current_epoch: u64,
    pub vaults: BTreeMap<String, LiquidityVault>,
    pub cohorts: BTreeMap<String, SignerCohort>,
    pub signers: BTreeMap<String, PqSigner>,
    pub sealed_intents: BTreeMap<String, SealedGuardIntent>,
    pub approvals: BTreeMap<String, ThresholdApproval>,
    pub freezes: BTreeMap<String, EmergencyFreeze>,
    pub slashes: BTreeMap<String, SignerSlashing>,
    pub rebates: BTreeMap<String, LowFeeApprovalRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub public_records: BTreeMap<String, Value>,
    pub nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::zero(),
            roots: Roots::default(),
            current_height: DEVNET_HEIGHT,
            current_epoch: DEVNET_EPOCH,
            vaults: BTreeMap::new(),
            cohorts: BTreeMap::new(),
            signers: BTreeMap::new(),
            sealed_intents: BTreeMap::new(),
            approvals: BTreeMap::new(),
            freezes: BTreeMap::new(),
            slashes: BTreeMap::new(),
            rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            public_records: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = match Self::new(Config::devnet()) {
            Ok(state) => state,
            Err(error) => devnet_fallback_state(&error),
        };
        seed_devnet(&mut state);
        state.refresh_roots();
        state
    }

    pub fn register_cohort(&mut self, cohort: SignerCohort) -> Result<()> {
        ensure!(
            self.cohorts.len() < MAX_SIGNER_COHORTS,
            "too many signer cohorts"
        );
        ensure!(
            cohort.approval_threshold <= cohort.signer_ids.len() as u16,
            "cohort approval threshold exceeds signer count"
        );
        ensure!(
            !self.cohorts.contains_key(&cohort.cohort_id),
            "cohort already exists"
        );
        self.counters.cohorts_registered = self.counters.cohorts_registered.saturating_add(1);
        self.cohorts.insert(cohort.cohort_id.clone(), cohort);
        self.refresh_roots();
        Ok(())
    }

    pub fn register_signer(&mut self, signer: PqSigner) -> Result<()> {
        ensure!(self.signers.len() < MAX_SIGNER_COHORTS, "too many signers");
        ensure!(signer.weight_bps <= MAX_BPS, "signer weight out of range");
        ensure!(
            !self.signers.contains_key(&signer.signer_id),
            "signer already exists"
        );
        self.counters.signers_registered = self.counters.signers_registered.saturating_add(1);
        self.signers.insert(signer.signer_id.clone(), signer);
        self.refresh_roots();
        Ok(())
    }

    pub fn register_vault(&mut self, vault: LiquidityVault) -> Result<()> {
        ensure!(self.vaults.len() < MAX_VAULTS, "too many vaults");
        ensure!(
            vault.max_price_impact_bps <= self.config.max_price_impact_bps,
            "vault price impact limit exceeds config"
        );
        ensure!(
            self.cohorts.contains_key(&vault.cohort_id),
            "missing signer cohort"
        );
        ensure!(
            !self.vaults.contains_key(&vault.vault_id),
            "vault already exists"
        );
        self.counters.vaults_registered = self.counters.vaults_registered.saturating_add(1);
        self.counters.total_guarded_liquidity_atomic = self
            .counters
            .total_guarded_liquidity_atomic
            .saturating_add(vault.guarded_liquidity_atomic);
        self.vaults.insert(vault.vault_id.clone(), vault);
        self.refresh_roots();
        Ok(())
    }

    pub fn create_redaction_budget(&mut self, budget: RedactionBudget) -> Result<()> {
        ensure!(
            self.redaction_budgets.len() < MAX_REDACTION_BUDGETS,
            "too many redaction budgets"
        );
        ensure!(
            budget.max_fields <= self.config.redaction_budget_fields
                && budget.max_bytes <= self.config.redaction_budget_bytes,
            "redaction budget exceeds config"
        );
        ensure!(
            !self.redaction_budgets.contains_key(&budget.budget_id),
            "redaction budget already exists"
        );
        self.counters.redaction_budgets = self.counters.redaction_budgets.saturating_add(1);
        self.redaction_budgets
            .insert(budget.budget_id.clone(), budget);
        self.refresh_roots();
        Ok(())
    }

    pub fn admit_intent(&mut self, mut intent: SealedGuardIntent) -> Result<()> {
        ensure!(
            self.sealed_intents.len() < MAX_GUARD_INTENTS,
            "too many guard intents"
        );
        ensure!(
            intent.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set too small"
        );
        ensure!(
            intent.price_impact_bps <= self.config.max_price_impact_bps,
            "price impact too high"
        );
        let vault = self
            .vaults
            .get(&intent.vault_id)
            .ok_or_else(|| "missing vault".to_string())?;
        ensure!(
            vault.status.accepts_intents(),
            "vault does not accept intents"
        );
        ensure!(
            self.redaction_budgets
                .contains_key(&intent.redaction_budget_id),
            "missing redaction budget"
        );
        ensure!(
            !self.sealed_intents.contains_key(&intent.intent_id),
            "intent already exists"
        );
        if intent.status == IntentStatus::Sealed {
            intent.status = IntentStatus::Admitted;
        }
        self.counters.sealed_intents = self.counters.sealed_intents.saturating_add(1);
        self.counters.admitted_intents = self.counters.admitted_intents.saturating_add(1);
        self.sealed_intents.insert(intent.intent_id.clone(), intent);
        self.refresh_roots();
        Ok(())
    }

    pub fn record_approval(&mut self, approval: ThresholdApproval) -> Result<()> {
        ensure!(self.approvals.len() < MAX_APPROVALS, "too many approvals");
        ensure!(
            approval.fee_bps <= self.config.max_liquidity_bps,
            "approval fee out of range"
        );
        let signer = self
            .signers
            .get(&approval.signer_id)
            .ok_or_else(|| "missing signer".to_string())?;
        ensure!(signer.status.can_approve(), "signer cannot approve");
        ensure!(
            self.sealed_intents.contains_key(&approval.intent_id),
            "missing intent"
        );
        ensure!(
            !self.approvals.contains_key(&approval.approval_id),
            "approval already exists"
        );
        self.approvals
            .insert(approval.approval_id.clone(), approval.clone());
        let counted = self.counted_approvals(&approval.intent_id, &approval.cohort_id);
        let threshold = self
            .cohorts
            .get(&approval.cohort_id)
            .map(|cohort| cohort.approval_threshold)
            .unwrap_or(self.config.approval_threshold);
        if counted >= threshold {
            if let Some(intent) = self.sealed_intents.get_mut(&approval.intent_id) {
                if intent.live() {
                    intent.status = IntentStatus::Approved;
                    self.counters.approved_intents =
                        self.counters.approved_intents.saturating_add(1);
                    self.counters.total_approved_liquidity_atomic = self
                        .counters
                        .total_approved_liquidity_atomic
                        .saturating_add(intent.liquidity_atomic);
                }
            }
        }
        self.refresh_roots();
        Ok(())
    }

    pub fn request_freeze(&mut self, freeze: EmergencyFreeze) -> Result<()> {
        ensure!(
            self.config.allow_emergency_freezes,
            "emergency freezes disabled"
        );
        ensure!(self.freezes.len() < MAX_FREEZES, "too many freezes");
        ensure!(
            !self.freezes.contains_key(&freeze.freeze_id),
            "freeze already exists"
        );
        self.counters.emergency_freezes = self.counters.emergency_freezes.saturating_add(1);
        if freeze.scope == FreezeScope::Vault {
            if let Some(vault) = self.vaults.get_mut(&freeze.target_id) {
                vault.status = VaultStatus::Frozen;
            }
        }
        self.freezes.insert(freeze.freeze_id.clone(), freeze);
        self.refresh_roots();
        Ok(())
    }

    pub fn slash_signer(&mut self, slash: SignerSlashing) -> Result<()> {
        ensure!(self.slashes.len() < MAX_SLASHES, "too many slashes");
        ensure!(slash.slash_bps <= self.config.slash_bps, "slash too large");
        ensure!(
            !self.slashes.contains_key(&slash.slash_id),
            "slash already exists"
        );
        if let Some(signer) = self.signers.get_mut(&slash.signer_id) {
            signer.status = SignerStatus::Slashed;
            signer.slash_count = signer.slash_count.saturating_add(1);
        }
        if let Some(intent) = self.sealed_intents.get_mut(&slash.challenged_intent_id) {
            if !intent.status.terminal() {
                intent.status = IntentStatus::Slashed;
            }
        }
        self.counters.signer_slashes = self.counters.signer_slashes.saturating_add(1);
        self.counters.total_slashed_bond_atomic = self
            .counters
            .total_slashed_bond_atomic
            .saturating_add(slash.slashed_bond_atomic);
        self.slashes.insert(slash.slash_id.clone(), slash);
        self.refresh_roots();
        Ok(())
    }

    pub fn pay_low_fee_rebate(&mut self, rebate: LowFeeApprovalRebate) -> Result<()> {
        ensure!(self.config.allow_low_fee_rebates, "rebates disabled");
        ensure!(self.rebates.len() < MAX_REBATES, "too many rebates");
        ensure!(
            rebate.fee_bps <= self.config.low_fee_target_bps,
            "fee is not low-fee eligible"
        );
        ensure!(
            !self.rebates.contains_key(&rebate.rebate_id),
            "rebate already exists"
        );
        if let Some(intent) = self.sealed_intents.get_mut(&rebate.intent_id) {
            if intent.status == IntentStatus::Approved {
                intent.status = IntentStatus::Rebated;
            }
        }
        self.counters.low_fee_rebates = self.counters.low_fee_rebates.saturating_add(1);
        self.counters.total_rebate_atomic = self
            .counters
            .total_rebate_atomic
            .saturating_add(rebate.rebate_atomic);
        self.rebates.insert(rebate.rebate_id.clone(), rebate);
        self.refresh_roots();
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "scheme": PUBLIC_RECORD_SUITE,
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "current_height": self.current_height,
            "current_epoch": self.current_epoch,
            "suites": {
                "hash": self.config.hash_suite,
                "pq_signer": self.config.pq_signer_suite,
                "sealed_intent": self.config.sealed_intent_suite,
                "threshold_approval": self.config.threshold_approval_suite,
                "emergency_freeze": self.config.emergency_freeze_suite,
                "low_fee_rebate": self.config.low_fee_rebate_suite,
                "redaction_budget": REDACTION_BUDGET_SUITE
            },
            "counts": {
                "vaults": self.vaults.len(),
                "cohorts": self.cohorts.len(),
                "signers": self.signers.len(),
                "sealed_intents": self.sealed_intents.len(),
                "approvals": self.approvals.len(),
                "freezes": self.freezes.len(),
                "slashes": self.slashes.len(),
                "rebates": self.rebates.len(),
                "redaction_budgets": self.redaction_budgets.len(),
                "public_records": self.public_records.len(),
                "nullifiers": self.nullifiers.len()
            },
            "counters": self.counters,
            "roots": self.roots.public_record()
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn refresh_roots(&mut self) {
        self.roots.config_root = self.config.root();
        self.roots.vault_root = collection_root(
            "LIQUIDITY-GUARD-VAULTS",
            self.vaults
                .values()
                .map(LiquidityVault::public_record)
                .collect(),
        );
        self.roots.cohort_root = collection_root(
            "LIQUIDITY-GUARD-COHORTS",
            self.cohorts
                .values()
                .map(SignerCohort::public_record)
                .collect(),
        );
        self.roots.signer_root = collection_root(
            "LIQUIDITY-GUARD-SIGNERS",
            self.signers.values().map(PqSigner::public_record).collect(),
        );
        self.roots.sealed_intent_root = collection_root(
            "LIQUIDITY-GUARD-SEALED-INTENTS",
            self.sealed_intents
                .values()
                .map(SealedGuardIntent::public_record)
                .collect(),
        );
        self.roots.approval_root = collection_root(
            "LIQUIDITY-GUARD-APPROVALS",
            self.approvals
                .values()
                .map(ThresholdApproval::public_record)
                .collect(),
        );
        self.roots.freeze_root = collection_root(
            "LIQUIDITY-GUARD-FREEZES",
            self.freezes
                .values()
                .map(EmergencyFreeze::public_record)
                .collect(),
        );
        self.roots.slashing_root = collection_root(
            "LIQUIDITY-GUARD-SLASHES",
            self.slashes
                .values()
                .map(SignerSlashing::public_record)
                .collect(),
        );
        self.roots.rebate_root = collection_root(
            "LIQUIDITY-GUARD-REBATES",
            self.rebates
                .values()
                .map(LowFeeApprovalRebate::public_record)
                .collect(),
        );
        self.roots.redaction_budget_root = collection_root(
            "LIQUIDITY-GUARD-REDACTION-BUDGETS",
            self.redaction_budgets
                .values()
                .map(RedactionBudget::public_record)
                .collect(),
        );
        self.roots.public_record_root = collection_root(
            "LIQUIDITY-GUARD-PUBLIC-RECORDS",
            self.public_records.values().cloned().collect(),
        );
        let composite = json!({
            "config_root": self.roots.config_root,
            "vault_root": self.roots.vault_root,
            "cohort_root": self.roots.cohort_root,
            "signer_root": self.roots.signer_root,
            "sealed_intent_root": self.roots.sealed_intent_root,
            "approval_root": self.roots.approval_root,
            "freeze_root": self.roots.freeze_root,
            "slashing_root": self.roots.slashing_root,
            "rebate_root": self.roots.rebate_root,
            "redaction_budget_root": self.roots.redaction_budget_root,
            "public_record_root": self.roots.public_record_root,
            "counters": self.counters,
            "height": self.current_height,
            "epoch": self.current_epoch
        });
        self.roots.state_root = payload_root("LIQUIDITY-GUARD-STATE", &composite);
    }

    fn counted_approvals(&self, intent_id: &str, cohort_id: &str) -> u16 {
        self.approvals
            .values()
            .filter(|approval| {
                approval.intent_id == intent_id
                    && approval.cohort_id == cohort_id
                    && matches!(
                        approval.status,
                        ApprovalStatus::Signed | ApprovalStatus::Counted
                    )
            })
            .map(|approval| approval.signer_id.clone())
            .collect::<BTreeSet<_>>()
            .len() as u16
    }
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> Value {
    State::devnet().public_record()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

pub fn payload_root(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(value),
        ],
        32,
    )
}

pub fn collection_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

fn to_value<T: Serialize>(value: &T) -> Value {
    match serde_json::to_value(value) {
        Ok(value) => value,
        Err(_) => Value::Null,
    }
}

fn devnet_fallback_state(error: &str) -> State {
    State {
        config: Config::devnet(),
        counters: Counters {
            public_records: 1,
            ..Counters::zero()
        },
        roots: Roots {
            state_root: payload_root("LIQUIDITY-GUARD-FALLBACK", &json!({ "error": error })),
            ..Roots::default()
        },
        current_height: DEVNET_HEIGHT,
        current_epoch: DEVNET_EPOCH,
        vaults: BTreeMap::new(),
        cohorts: BTreeMap::new(),
        signers: BTreeMap::new(),
        sealed_intents: BTreeMap::new(),
        approvals: BTreeMap::new(),
        freezes: BTreeMap::new(),
        slashes: BTreeMap::new(),
        rebates: BTreeMap::new(),
        redaction_budgets: BTreeMap::new(),
        public_records: BTreeMap::new(),
        nullifiers: BTreeSet::new(),
    }
}

fn seed_devnet(state: &mut State) {
    let signer_ids = ["pq-signer-alpha", "pq-signer-beta", "pq-signer-gamma"]
        .into_iter()
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    for signer_id in &signer_ids {
        let _ = state.register_signer(PqSigner {
            signer_id: signer_id.clone(),
            cohort_id: "devnet-liquidity-guard-cohort".to_string(),
            status: SignerStatus::Active,
            operator_commitment: format!("{signer_id}-operator-commitment"),
            ml_dsa_key_commitment: format!("{signer_id}-ml-dsa-87-key"),
            slh_dsa_key_commitment: format!("{signer_id}-slh-dsa-shake-256f-key"),
            stake_commitment: format!("{signer_id}-stake-root"),
            weight_bps: 3_333,
            last_approval_height: DEVNET_HEIGHT,
            slash_count: 0,
        });
    }
    let _ = state.register_cohort(SignerCohort {
        cohort_id: "devnet-liquidity-guard-cohort".to_string(),
        label: "devnet bridge and amm quantum-safe liquidity guard".to_string(),
        signer_ids,
        approval_threshold: 2,
        emergency_threshold: 2,
        slash_threshold: 2,
        aggregate_key_root: "devnet-liquidity-guard-aggregate-pq-key-root".to_string(),
        stake_root: "devnet-liquidity-guard-stake-root".to_string(),
        active: true,
        created_height: DEVNET_HEIGHT,
    });
    let _ = state.register_vault(LiquidityVault {
        vault_id: "devnet-bridge-amm-vault".to_string(),
        kind: VaultKind::BridgeVault,
        status: VaultStatus::Guarded,
        asset_pair: "wxmr/dusd".to_string(),
        bridge_domain: "monero-devnet-to-nebula-private-l2".to_string(),
        operator_commitment: "devnet-vault-operator-commitment".to_string(),
        cohort_id: "devnet-liquidity-guard-cohort".to_string(),
        liquidity_commitment: "devnet-confidential-liquidity-commitment".to_string(),
        guarded_liquidity_atomic: 7_500_000_000_000,
        max_release_atomic: 500_000_000_000,
        max_price_impact_bps: 75,
        last_root: deterministic_id(
            "LIQUIDITY-GUARD-DEVNET-VAULT-ROOT",
            &[HashPart::Str("devnet-bridge-amm-vault")],
        ),
        last_height: DEVNET_HEIGHT,
    });
    let _ = state.create_redaction_budget(RedactionBudget {
        budget_id: "devnet-redaction-budget".to_string(),
        owner_commitment: "devnet-intent-owner-commitment".to_string(),
        scope_root: "devnet-guard-intent-redaction-scope".to_string(),
        max_fields: 8,
        max_bytes: 512,
        used_fields: 2,
        used_bytes: 144,
        expires_height: DEVNET_HEIGHT.saturating_add(DEFAULT_INTENT_TTL_BLOCKS),
    });
    let intent = SealedGuardIntent {
        intent_id: "devnet-sealed-guard-intent".to_string(),
        vault_id: "devnet-bridge-amm-vault".to_string(),
        cohort_id: "devnet-liquidity-guard-cohort".to_string(),
        kind: GuardIntentKind::BridgeRelease,
        status: IntentStatus::Sealed,
        sealed_payload_root: "devnet-sealed-liquidity-release-payload-root".to_string(),
        route_commitment: "devnet-amm-route-commitment".to_string(),
        beneficiary_commitment: "devnet-beneficiary-commitment".to_string(),
        liquidity_atomic: 125_000_000_000,
        max_fee_bps: DEFAULT_LOW_FEE_TARGET_BPS,
        price_impact_bps: 42,
        privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
        redaction_budget_id: "devnet-redaction-budget".to_string(),
        created_height: DEVNET_HEIGHT,
        expires_height: DEVNET_HEIGHT.saturating_add(DEFAULT_INTENT_TTL_BLOCKS),
    };
    let _ = state.admit_intent(intent);
    for signer_id in ["pq-signer-alpha", "pq-signer-beta"] {
        let approval_id = format!("devnet-approval-{signer_id}");
        let _ = state.record_approval(ThresholdApproval {
            approval_id,
            intent_id: "devnet-sealed-guard-intent".to_string(),
            signer_id: signer_id.to_string(),
            cohort_id: "devnet-liquidity-guard-cohort".to_string(),
            status: ApprovalStatus::Counted,
            approval_root: format!("devnet-threshold-approval-root-{signer_id}"),
            signature_root: format!("devnet-pq-signature-root-{signer_id}"),
            observed_vault_root: "devnet-confidential-liquidity-commitment".to_string(),
            fee_bps: DEFAULT_LOW_FEE_TARGET_BPS,
            height: DEVNET_HEIGHT.saturating_add(2),
        });
    }
    let _ = state.pay_low_fee_rebate(LowFeeApprovalRebate {
        rebate_id: "devnet-low-fee-approval-rebate".to_string(),
        intent_id: "devnet-sealed-guard-intent".to_string(),
        approval_root: "devnet-threshold-approval-aggregate-root".to_string(),
        recipient_commitment: "devnet-fee-payer-commitment".to_string(),
        rebate_asset: "piconero-devnet".to_string(),
        rebate_atomic: 18_000,
        fee_bps: DEFAULT_LOW_FEE_TARGET_BPS,
        paid_height: DEVNET_HEIGHT.saturating_add(3),
    });
    let _ = state.request_freeze(EmergencyFreeze {
        freeze_id: "devnet-amm-pair-observation-freeze".to_string(),
        scope: FreezeScope::AmmPair,
        target_id: "wxmr/dusd".to_string(),
        status: FreezeStatus::Review,
        cohort_id: "devnet-liquidity-guard-cohort".to_string(),
        reason_root: "devnet-price-impact-review-root".to_string(),
        approval_root: "devnet-freeze-threshold-approval-root".to_string(),
        requested_height: DEVNET_HEIGHT.saturating_add(4),
        review_height: DEVNET_HEIGHT.saturating_add(DEFAULT_FREEZE_REVIEW_BLOCKS),
    });
    let record = state.public_record();
    state.public_records.insert(
        "devnet-liquidity-guard-public-record".to_string(),
        record.clone(),
    );
    state.counters.public_records = state.counters.public_records.saturating_add(1);
}
