use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedExitLiquidityBackstopNoteRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_EXIT_LIQUIDITY_BACKSTOP_NOTE_RUNTIME_PROTOCOL_VERSION: &str = "nebula-private-l2-pq-confidential-tokenized-exit-liquidity-backstop-note-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_EXIT_LIQUIDITY_BACKSTOP_NOTE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_SOLVENCY_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-exit-liquidity-solvency-v1";
pub const CONFIDENTIAL_NOTE_SUITE: &str = "confidential-tokenized-exit-liquidity-backstop-note-v1";
pub const ENCRYPTED_SUBSCRIPTION_SUITE: &str =
    "ml-kem-1024-sealed-exit-backstop-note-subscription-v1";
pub const BACKSTOP_COMMITMENT_SUITE: &str = "pq-confidential-exit-liquidity-backstop-commitment-v1";
pub const EXIT_CLAIM_SETTLEMENT_SUITE: &str = "low-fee-confidential-exit-claim-settlement-v1";
pub const TRANCHE_COUPON_SUITE: &str = "tokenized-exit-liquidity-backstop-tranche-coupon-v1";
pub const LOW_FEE_REBATE_SUITE: &str = "confidential-exit-backstop-low-fee-rebate-v1";
pub const REDACTION_BUDGET_SUITE: &str = "operator-safe-exit-backstop-note-redaction-budget-v1";
pub const OPERATOR_SUMMARY_SUITE: &str =
    "redacted-operator-exit-liquidity-backstop-note-summary-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_HEIGHT: u64 = 2_947_200;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_896_000;
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_EXIT_ASSET_ID: &str = "xmr-exit-liquidity-devnet";
pub const DEVNET_NOTE_ASSET_ID: &str = "elbn-note-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_SOLVENCY_RATIO_BPS: u64 = 10_500;
pub const DEFAULT_TARGET_SOLVENCY_RATIO_BPS: u64 = 13_000;
pub const DEFAULT_MIN_ATTESTATION_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_ATTESTATION_QUORUM_BPS: u64 = 8_400;
pub const DEFAULT_MAX_EXIT_FEE_BPS: u64 = 18;
pub const DEFAULT_TARGET_LOW_FEE_REBATE_BPS: u64 = 7;
pub const DEFAULT_MAX_LOW_FEE_REBATE_BPS: u64 = 32;
pub const DEFAULT_NOTE_TTL_BLOCKS: u64 = 43_200;
pub const DEFAULT_SUBSCRIPTION_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_CLAIM_WINDOW_BLOCKS: u64 = 1_440;
pub const DEFAULT_SETTLEMENT_FINALITY_BLOCKS: u64 = 12;
pub const DEFAULT_COUPON_EPOCH_BLOCKS: u64 = 7_200;
pub const DEFAULT_REDACTION_BUDGET_UNITS: u64 = 160;
pub const DEFAULT_MAX_PUBLIC_REDACTION_BYTES: u64 = 2_048;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteTranche {
    FirstLoss,
    Mezzanine,
    Senior,
    SuperSenior,
}
impl NoteTranche {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FirstLoss => "first_loss",
            Self::Mezzanine => "mezzanine",
            Self::Senior => "senior",
            Self::SuperSenior => "super_senior",
        }
    }
    pub fn coupon_floor_bps(self) -> u64 {
        match self {
            Self::FirstLoss => 1200,
            Self::Mezzanine => 760,
            Self::Senior => 420,
            Self::SuperSenior => 180,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Draft,
    Open,
    Subscribing,
    Active,
    Backstopping,
    Claiming,
    Paused,
    Retired,
}
impl VaultStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Open => "open",
            Self::Subscribing => "subscribing",
            Self::Active => "active",
            Self::Backstopping => "backstopping",
            Self::Claiming => "claiming",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }
    pub fn accepts_subscriptions(self) -> bool {
        matches!(self, Self::Open | Self::Subscribing | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentStatus {
    Sealed,
    Posted,
    Attested,
    Drawn,
    Released,
    Slashed,
    Expired,
}
impl CommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Posted => "posted",
            Self::Attested => "attested",
            Self::Drawn => "drawn",
            Self::Released => "released",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionStatus {
    Encrypted,
    Accepted,
    Minted,
    Refunded,
    Cancelled,
    Expired,
}
impl SubscriptionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Encrypted => "encrypted",
            Self::Accepted => "accepted",
            Self::Minted => "minted",
            Self::Refunded => "refunded",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Submitted,
    Attested,
    PartiallySettled,
    Settled,
    Rejected,
    Quarantined,
    Expired,
}
impl ClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Attested => "attested",
            Self::PartiallySettled => "partially_settled",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Quarantined => "quarantined",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SolvencySignal {
    ReserveObserved,
    LiabilityBounded,
    CommitmentOpened,
    CouponFunded,
    ClaimQueueCovered,
    StressWindowSafe,
    PrivacyBudgetObserved,
    OperatorBondHealthy,
}
impl SolvencySignal {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReserveObserved => "reserve_observed",
            Self::LiabilityBounded => "liability_bounded",
            Self::CommitmentOpened => "commitment_opened",
            Self::CouponFunded => "coupon_funded",
            Self::ClaimQueueCovered => "claim_queue_covered",
            Self::StressWindowSafe => "stress_window_safe",
            Self::PrivacyBudgetObserved => "privacy_budget_observed",
            Self::OperatorBondHealthy => "operator_bond_healthy",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementDecision {
    Approve,
    ApproveWithRebate,
    PartialFill,
    Retry,
    Reject,
    Quarantine,
    Expire,
}
impl SettlementDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::ApproveWithRebate => "approve_with_rebate",
            Self::PartialFill => "partial_fill",
            Self::Retry => "retry",
            Self::Reject => "reject",
            Self::Quarantine => "quarantine",
            Self::Expire => "expire",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Accruing,
    Payable,
    Paid,
    Deferred,
    ClawedBack,
}
impl CouponStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accruing => "accruing",
            Self::Payable => "payable",
            Self::Paid => "paid",
            Self::Deferred => "deferred",
            Self::ClawedBack => "clawed_back",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub hash_suite: String,
    pub pq_solvency_attestation_suite: String,
    pub confidential_note_suite: String,
    pub encrypted_subscription_suite: String,
    pub backstop_commitment_suite: String,
    pub exit_claim_settlement_suite: String,
    pub tranche_coupon_suite: String,
    pub low_fee_rebate_suite: String,
    pub redaction_budget_suite: String,
    pub operator_summary_suite: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub exit_asset_id: String,
    pub note_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_solvency_ratio_bps: u64,
    pub target_solvency_ratio_bps: u64,
    pub min_attestation_quorum_bps: u64,
    pub strong_attestation_quorum_bps: u64,
    pub max_exit_fee_bps: u64,
    pub target_low_fee_rebate_bps: u64,
    pub max_low_fee_rebate_bps: u64,
    pub note_ttl_blocks: u64,
    pub subscription_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub claim_window_blocks: u64,
    pub settlement_finality_blocks: u64,
    pub coupon_epoch_blocks: u64,
    pub redaction_budget_units: u64,
    pub max_public_redaction_bytes: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub vaults: u64,
    pub commitments: u64,
    pub subscriptions: u64,
    pub attestations: u64,
    pub claims: u64,
    pub coupons: u64,
    pub rebates: u64,
    pub redactions: u64,
    pub summaries: u64,
    pub events: u64,
    pub settled_exit_micro_units: u64,
    pub committed_backstop_micro_units: u64,
    pub outstanding_note_micro_units: u64,
    pub coupon_micro_units: u64,
    pub rebate_micro_units: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub note_vaults_root: String,
    pub backstop_commitments_root: String,
    pub encrypted_subscriptions_root: String,
    pub pq_solvency_attestations_root: String,
    pub exit_claim_settlements_root: String,
    pub tranche_coupons_root: String,
    pub low_fee_rebates_root: String,
    pub redaction_budgets_root: String,
    pub operator_summaries_root: String,
    pub event_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NoteVault {
    pub vault_id: String,
    pub operator_id: String,
    pub tranche: NoteTranche,
    pub status: VaultStatus,
    pub reserve_commitment: String,
    pub liability_commitment: String,
    pub note_supply_commitment: String,
    pub coupon_pool_commitment: String,
    pub exit_asset_id: String,
    pub note_asset_id: String,
    pub opened_height: u64,
    pub maturity_height: u64,
    pub min_subscription_micro_units: u64,
    pub max_subscription_micro_units: u64,
    pub privacy_set_size: u64,
    pub metadata_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackstopCommitment {
    pub commitment_id: String,
    pub vault_id: String,
    pub provider_id: String,
    pub status: CommitmentStatus,
    pub sealed_capacity_commitment: String,
    pub bond_commitment: String,
    pub fee_commitment: String,
    pub unlock_height: u64,
    pub nonce_commitment: String,
    pub pq_public_key_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedSubscription {
    pub subscription_id: String,
    pub vault_id: String,
    pub subscriber_key_hash: String,
    pub status: SubscriptionStatus,
    pub encrypted_payload_hash: String,
    pub sealed_amount_commitment: String,
    pub note_mint_commitment: String,
    pub max_fee_bps: u64,
    pub submitted_height: u64,
    pub expiry_height: u64,
    pub nullifier_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSolvencyAttestation {
    pub attestation_id: String,
    pub vault_id: String,
    pub operator_id: String,
    pub signals: BTreeSet<SolvencySignal>,
    pub solvency_ratio_bps: u64,
    pub reserve_root: String,
    pub liability_root: String,
    pub claim_queue_root: String,
    pub pq_signature_hash: String,
    pub quorum_bps: u64,
    pub observed_height: u64,
    pub expires_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExitClaimSettlement {
    pub claim_id: String,
    pub vault_id: String,
    pub claimant_key_hash: String,
    pub status: ClaimStatus,
    pub decision: SettlementDecision,
    pub claim_commitment: String,
    pub settlement_commitment: String,
    pub fee_commitment: String,
    pub rebate_id: Option<String>,
    pub submitted_height: u64,
    pub settled_height: u64,
    pub settlement_tx_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrancheCoupon {
    pub coupon_id: String,
    pub vault_id: String,
    pub tranche: NoteTranche,
    pub status: CouponStatus,
    pub epoch: u64,
    pub rate_bps: u64,
    pub coupon_commitment: String,
    pub recipient_set_root: String,
    pub paid_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub vault_id: String,
    pub claim_id: String,
    pub recipient_key_hash: String,
    pub rebate_commitment: String,
    pub fee_paid_commitment: String,
    pub rebate_bps: u64,
    pub issued_height: u64,
    pub nullifier_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub operator_id: String,
    pub vault_id: String,
    pub allowance_units: u64,
    pub spent_units: u64,
    pub public_bytes: u64,
    pub sealed_reason_hash: String,
    pub last_updated_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_id: String,
    pub vault_count: u64,
    pub active_claim_count: u64,
    pub solvency_floor_bps: u64,
    pub committed_backstop_micro_units: u64,
    pub outstanding_note_micro_units: u64,
    pub coupon_due_micro_units: u64,
    pub rebate_due_micro_units: u64,
    pub redacted_fields: BTreeSet<String>,
    pub summary_height: u64,
    pub summary_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub height: u64,
    pub kind: String,
    pub object_id: String,
    pub commitment: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_solvency_attestation_suite: PQ_SOLVENCY_ATTESTATION_SUITE.to_string(),
            confidential_note_suite: CONFIDENTIAL_NOTE_SUITE.to_string(),
            encrypted_subscription_suite: ENCRYPTED_SUBSCRIPTION_SUITE.to_string(),
            backstop_commitment_suite: BACKSTOP_COMMITMENT_SUITE.to_string(),
            exit_claim_settlement_suite: EXIT_CLAIM_SETTLEMENT_SUITE.to_string(),
            tranche_coupon_suite: TRANCHE_COUPON_SUITE.to_string(),
            low_fee_rebate_suite: LOW_FEE_REBATE_SUITE.to_string(),
            redaction_budget_suite: REDACTION_BUDGET_SUITE.to_string(),
            operator_summary_suite: OPERATOR_SUMMARY_SUITE.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            exit_asset_id: DEVNET_EXIT_ASSET_ID.to_string(),
            note_asset_id: DEVNET_NOTE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_solvency_ratio_bps: DEFAULT_MIN_SOLVENCY_RATIO_BPS,
            target_solvency_ratio_bps: DEFAULT_TARGET_SOLVENCY_RATIO_BPS,
            min_attestation_quorum_bps: DEFAULT_MIN_ATTESTATION_QUORUM_BPS,
            strong_attestation_quorum_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
            max_exit_fee_bps: DEFAULT_MAX_EXIT_FEE_BPS,
            target_low_fee_rebate_bps: DEFAULT_TARGET_LOW_FEE_REBATE_BPS,
            max_low_fee_rebate_bps: DEFAULT_MAX_LOW_FEE_REBATE_BPS,
            note_ttl_blocks: DEFAULT_NOTE_TTL_BLOCKS,
            subscription_ttl_blocks: DEFAULT_SUBSCRIPTION_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            claim_window_blocks: DEFAULT_CLAIM_WINDOW_BLOCKS,
            settlement_finality_blocks: DEFAULT_SETTLEMENT_FINALITY_BLOCKS,
            coupon_epoch_blocks: DEFAULT_COUPON_EPOCH_BLOCKS,
            redaction_budget_units: DEFAULT_REDACTION_BUDGET_UNITS,
            max_public_redaction_bytes: DEFAULT_MAX_PUBLIC_REDACTION_BYTES,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("protocol version mismatch".to_string());
        }
        if self.min_pq_security_bits < 256 {
            return Err("pq security below runtime floor".to_string());
        }
        if self.target_privacy_set_size < self.min_privacy_set_size {
            return Err("invalid privacy set bounds".to_string());
        }
        if self.min_solvency_ratio_bps < MAX_BPS {
            return Err("solvency ratio must exceed liabilities".to_string());
        }
        if self.target_solvency_ratio_bps < self.min_solvency_ratio_bps {
            return Err("target solvency lower than minimum".to_string());
        }
        Ok(())
    }
}

impl NoteVault {
    pub fn validate(&self, cfg: &Config) -> Result<()> {
        if self.vault_id.is_empty() || self.operator_id.is_empty() {
            return Err("vault ids must be present".to_string());
        }
        if self.maturity_height <= self.opened_height {
            return Err("vault maturity must be after open height".to_string());
        }
        if self.privacy_set_size < cfg.min_privacy_set_size {
            return Err("vault privacy set below minimum".to_string());
        }
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

impl BackstopCommitment {
    pub fn validate(&self) -> Result<()> {
        if self.commitment_id.is_empty() || self.vault_id.is_empty() || self.provider_id.is_empty()
        {
            return Err("backstop commitment ids must be present".to_string());
        }
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

impl EncryptedSubscription {
    pub fn validate(&self, cfg: &Config) -> Result<()> {
        if self.subscription_id.is_empty() || self.vault_id.is_empty() {
            return Err("subscription ids must be present".to_string());
        }
        if self.max_fee_bps > cfg.max_exit_fee_bps {
            return Err("subscription fee exceeds cap".to_string());
        }
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

impl PqSolvencyAttestation {
    pub fn validate(&self, cfg: &Config) -> Result<()> {
        if self.attestation_id.is_empty() || self.vault_id.is_empty() {
            return Err("attestation ids must be present".to_string());
        }
        if self.solvency_ratio_bps < cfg.min_solvency_ratio_bps {
            return Err("solvency ratio below minimum".to_string());
        }
        if self.quorum_bps < cfg.min_attestation_quorum_bps {
            return Err("attestation quorum below minimum".to_string());
        }
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

impl ExitClaimSettlement {
    pub fn validate(&self) -> Result<()> {
        if self.claim_id.is_empty() || self.vault_id.is_empty() {
            return Err("claim ids must be present".to_string());
        }
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

impl TrancheCoupon {
    pub fn validate(&self) -> Result<()> {
        if self.coupon_id.is_empty() || self.rate_bps > MAX_BPS {
            return Err("invalid coupon".to_string());
        }
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

impl LowFeeRebate {
    pub fn validate(&self, cfg: &Config) -> Result<()> {
        if self.rebate_id.is_empty() || self.rebate_bps > cfg.max_low_fee_rebate_bps {
            return Err("invalid rebate".to_string());
        }
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

impl RedactionBudget {
    pub fn remaining_units(&self) -> u64 {
        self.allowance_units.saturating_sub(self.spent_units)
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

impl OperatorSummary {
    pub fn validate(&self, cfg: &Config) -> Result<()> {
        if self.summary_id.is_empty() || self.solvency_floor_bps < cfg.min_solvency_ratio_bps {
            return Err("invalid operator summary".to_string());
        }
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub note_vaults: BTreeMap<String, NoteVault>,
    pub backstop_commitments: BTreeMap<String, BackstopCommitment>,
    pub encrypted_subscriptions: BTreeMap<String, EncryptedSubscription>,
    pub pq_solvency_attestations: BTreeMap<String, PqSolvencyAttestation>,
    pub exit_claim_settlements: BTreeMap<String, ExitClaimSettlement>,
    pub tranche_coupons: BTreeMap<String, TrancheCoupon>,
    pub low_fee_rebates: BTreeMap<String, LowFeeRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub events: Vec<RuntimeEvent>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            height: DEVNET_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            epoch: DEVNET_HEIGHT / DEFAULT_COUPON_EPOCH_BLOCKS,
            counters: Counters::default(),
            roots: Roots::default(),
            note_vaults: BTreeMap::new(),
            backstop_commitments: BTreeMap::new(),
            encrypted_subscriptions: BTreeMap::new(),
            pq_solvency_attestations: BTreeMap::new(),
            exit_claim_settlements: BTreeMap::new(),
            tranche_coupons: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            events: Vec::new(),
        };
        state.recompute_roots();
        Ok(state)
    }
    pub fn devnet() -> State {
        devnet()
    }
    pub fn public_record(&self) -> Value {
        public_record(self)
    }
    pub fn state_root(&self) -> String {
        state_root(self)
    }
    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        for v in self.note_vaults.values() {
            v.validate(&self.config)?;
        }
        for v in self.backstop_commitments.values() {
            v.validate()?;
        }
        for v in self.encrypted_subscriptions.values() {
            v.validate(&self.config)?;
        }
        for v in self.pq_solvency_attestations.values() {
            v.validate(&self.config)?;
        }
        for v in self.exit_claim_settlements.values() {
            v.validate()?;
        }
        for v in self.tranche_coupons.values() {
            v.validate()?;
        }
        for v in self.low_fee_rebates.values() {
            v.validate(&self.config)?;
        }
        for v in self.operator_summaries.values() {
            v.validate(&self.config)?;
        }
        Ok(())
    }
    pub fn recompute_counters(&mut self) {
        self.counters.vaults = self.note_vaults.len() as u64;
        self.counters.commitments = self.backstop_commitments.len() as u64;
        self.counters.subscriptions = self.encrypted_subscriptions.len() as u64;
        self.counters.attestations = self.pq_solvency_attestations.len() as u64;
        self.counters.claims = self.exit_claim_settlements.len() as u64;
        self.counters.coupons = self.tranche_coupons.len() as u64;
        self.counters.rebates = self.low_fee_rebates.len() as u64;
        self.counters.redactions = self.redaction_budgets.len() as u64;
        self.counters.summaries = self.operator_summaries.len() as u64;
        self.counters.events = self.events.len() as u64;
        self.counters.committed_backstop_micro_units = self
            .operator_summaries
            .values()
            .map(|s| s.committed_backstop_micro_units)
            .sum();
        self.counters.outstanding_note_micro_units = self
            .operator_summaries
            .values()
            .map(|s| s.outstanding_note_micro_units)
            .sum();
        self.counters.coupon_micro_units = self
            .operator_summaries
            .values()
            .map(|s| s.coupon_due_micro_units)
            .sum();
        self.counters.rebate_micro_units = self
            .operator_summaries
            .values()
            .map(|s| s.rebate_due_micro_units)
            .sum();
    }
    pub fn recompute_roots(&mut self) {
        self.recompute_counters();
        self.roots.note_vaults_root = map_root(
            "note-vaults",
            self.note_vaults
                .values()
                .map(NoteVault::public_record)
                .collect(),
        );
        self.roots.backstop_commitments_root = map_root(
            "backstop-commitments",
            self.backstop_commitments
                .values()
                .map(BackstopCommitment::public_record)
                .collect(),
        );
        self.roots.encrypted_subscriptions_root = map_root(
            "encrypted-subscriptions",
            self.encrypted_subscriptions
                .values()
                .map(EncryptedSubscription::public_record)
                .collect(),
        );
        self.roots.pq_solvency_attestations_root = map_root(
            "pq-solvency-attestations",
            self.pq_solvency_attestations
                .values()
                .map(PqSolvencyAttestation::public_record)
                .collect(),
        );
        self.roots.exit_claim_settlements_root = map_root(
            "exit-claim-settlements",
            self.exit_claim_settlements
                .values()
                .map(ExitClaimSettlement::public_record)
                .collect(),
        );
        self.roots.tranche_coupons_root = map_root(
            "tranche-coupons",
            self.tranche_coupons
                .values()
                .map(TrancheCoupon::public_record)
                .collect(),
        );
        self.roots.low_fee_rebates_root = map_root(
            "low-fee-rebates",
            self.low_fee_rebates
                .values()
                .map(LowFeeRebate::public_record)
                .collect(),
        );
        self.roots.redaction_budgets_root = map_root(
            "redaction-budgets",
            self.redaction_budgets
                .values()
                .map(RedactionBudget::public_record)
                .collect(),
        );
        self.roots.operator_summaries_root = map_root(
            "operator-summaries",
            self.operator_summaries
                .values()
                .map(OperatorSummary::public_record)
                .collect(),
        );
        self.roots.event_root = map_root(
            "events",
            self.events
                .iter()
                .map(RuntimeEvent::public_record)
                .collect(),
        );
        self.roots.public_record_root = domain_hash(
            "private-l2-pq-confidential-tokenized-exit-liquidity-backstop-note:public-record",
            &[HashPart::Json(&self.public_record_without_state_root())],
            32,
        );
        self.roots.state_root = domain_hash(
            "private-l2-pq-confidential-tokenized-exit-liquidity-backstop-note:state-root",
            &[
                HashPart::Json(&self.public_record_without_state_root()),
                HashPart::Str(&self.roots.public_record_root),
            ],
            32,
        );
    }
    pub fn insert_note_vault(&mut self, item: NoteVault) -> Result<()> {
        item.validate(&self.config)?;
        let id = item.vault_id.clone();
        self.note_vaults.insert(id.clone(), item);
        self.push_event("note_vault", &id);
        self.recompute_roots();
        Ok(())
    }
    pub fn insert_backstop_commitment(&mut self, item: BackstopCommitment) -> Result<()> {
        item.validate()?;
        let id = item.commitment_id.clone();
        self.backstop_commitments.insert(id.clone(), item);
        self.push_event("backstop_commitment", &id);
        self.recompute_roots();
        Ok(())
    }
    pub fn insert_encrypted_subscription(&mut self, item: EncryptedSubscription) -> Result<()> {
        item.validate(&self.config)?;
        let id = item.subscription_id.clone();
        self.encrypted_subscriptions.insert(id.clone(), item);
        self.push_event("encrypted_subscription", &id);
        self.recompute_roots();
        Ok(())
    }
    pub fn insert_pq_solvency_attestation(&mut self, item: PqSolvencyAttestation) -> Result<()> {
        item.validate(&self.config)?;
        let id = item.attestation_id.clone();
        self.pq_solvency_attestations.insert(id.clone(), item);
        self.push_event("pq_solvency_attestation", &id);
        self.recompute_roots();
        Ok(())
    }
    pub fn insert_exit_claim_settlement(&mut self, item: ExitClaimSettlement) -> Result<()> {
        item.validate()?;
        let id = item.claim_id.clone();
        self.exit_claim_settlements.insert(id.clone(), item);
        self.push_event("exit_claim_settlement", &id);
        self.recompute_roots();
        Ok(())
    }
    pub fn insert_tranche_coupon(&mut self, item: TrancheCoupon) -> Result<()> {
        item.validate()?;
        let id = item.coupon_id.clone();
        self.tranche_coupons.insert(id.clone(), item);
        self.push_event("tranche_coupon", &id);
        self.recompute_roots();
        Ok(())
    }
    pub fn insert_low_fee_rebate(&mut self, item: LowFeeRebate) -> Result<()> {
        item.validate(&self.config)?;
        let id = item.rebate_id.clone();
        self.low_fee_rebates.insert(id.clone(), item);
        self.push_event("low_fee_rebate", &id);
        self.recompute_roots();
        Ok(())
    }
    pub fn insert_operator_summary(&mut self, item: OperatorSummary) -> Result<()> {
        item.validate(&self.config)?;
        let id = item.summary_id.clone();
        self.operator_summaries.insert(id.clone(), item);
        self.push_event("operator_summary", &id);
        self.recompute_roots();
        Ok(())
    }
    pub fn insert_redaction_budget(&mut self, item: RedactionBudget) -> Result<()> {
        if item.spent_units > item.allowance_units {
            return Err("invalid redaction budget".to_string());
        }
        let id = item.budget_id.clone();
        self.redaction_budgets.insert(id.clone(), item);
        self.push_event("redaction_budget", &id);
        self.recompute_roots();
        Ok(())
    }
    fn push_event(&mut self, kind: &str, object_id: &str) {
        let event_id = domain_hash(
            "private-l2-pq-confidential-tokenized-exit-liquidity-backstop-note:event-id",
            &[
                HashPart::Str(kind),
                HashPart::Str(object_id),
                HashPart::U64(self.events.len() as u64),
                HashPart::U64(self.height),
            ],
            16,
        );
        let commitment = domain_hash(
            "private-l2-pq-confidential-tokenized-exit-liquidity-backstop-note:event",
            &[
                HashPart::Str(&event_id),
                HashPart::Str(kind),
                HashPart::Str(object_id),
                HashPart::U64(self.height),
            ],
            32,
        );
        self.events.push(RuntimeEvent {
            event_id,
            height: self.height,
            kind: kind.to_string(),
            object_id: object_id.to_string(),
            commitment,
        });
    }
    fn public_record_without_state_root(&self) -> Value {
        json!({"protocol_version":PROTOCOL_VERSION,"schema_version":SCHEMA_VERSION,"height":self.height,"monero_height":self.monero_height,"epoch":self.epoch,"config":self.config,"counters":self.counters,"roots":self.roots,"note_vaults":self.note_vaults.values().map(NoteVault::public_record).collect::<Vec<_>>(),"backstop_commitments":self.backstop_commitments.values().map(BackstopCommitment::public_record).collect::<Vec<_>>(),"encrypted_subscriptions":self.encrypted_subscriptions.values().map(EncryptedSubscription::public_record).collect::<Vec<_>>(),"pq_solvency_attestations":self.pq_solvency_attestations.values().map(PqSolvencyAttestation::public_record).collect::<Vec<_>>(),"exit_claim_settlements":self.exit_claim_settlements.values().map(ExitClaimSettlement::public_record).collect::<Vec<_>>(),"tranche_coupons":self.tranche_coupons.values().map(TrancheCoupon::public_record).collect::<Vec<_>>(),"low_fee_rebates":self.low_fee_rebates.values().map(LowFeeRebate::public_record).collect::<Vec<_>>(),"redaction_budgets":self.redaction_budgets.values().map(RedactionBudget::public_record).collect::<Vec<_>>(),"operator_summaries":self.operator_summaries.values().map(OperatorSummary::public_record).collect::<Vec<_>>(),"events":self.events.iter().map(RuntimeEvent::public_record).collect::<Vec<_>>()})
    }
}

impl State {
    pub fn vaults_len(&self) -> usize {
        self.note_vaults.len()
    }
    pub fn vaults_root(&self) -> &str {
        &self.roots.note_vaults_root
    }
    pub fn vaults_domain_note(&self) -> Value {
        json!({"section":"vaults","root":self.roots.note_vaults_root,"height":self.height})
    }
    pub fn commitments_len(&self) -> usize {
        self.backstop_commitments.len()
    }
    pub fn commitments_root(&self) -> &str {
        &self.roots.backstop_commitments_root
    }
    pub fn commitments_domain_note(&self) -> Value {
        json!({"section":"commitments","root":self.roots.backstop_commitments_root,"height":self.height})
    }
    pub fn subscriptions_len(&self) -> usize {
        self.encrypted_subscriptions.len()
    }
    pub fn subscriptions_root(&self) -> &str {
        &self.roots.encrypted_subscriptions_root
    }
    pub fn subscriptions_domain_note(&self) -> Value {
        json!({"section":"subscriptions","root":self.roots.encrypted_subscriptions_root,"height":self.height})
    }
    pub fn attestations_len(&self) -> usize {
        self.pq_solvency_attestations.len()
    }
    pub fn attestations_root(&self) -> &str {
        &self.roots.pq_solvency_attestations_root
    }
    pub fn attestations_domain_note(&self) -> Value {
        json!({"section":"attestations","root":self.roots.pq_solvency_attestations_root,"height":self.height})
    }
    pub fn claims_len(&self) -> usize {
        self.exit_claim_settlements.len()
    }
    pub fn claims_root(&self) -> &str {
        &self.roots.exit_claim_settlements_root
    }
    pub fn claims_domain_note(&self) -> Value {
        json!({"section":"claims","root":self.roots.exit_claim_settlements_root,"height":self.height})
    }
    pub fn coupons_len(&self) -> usize {
        self.tranche_coupons.len()
    }
    pub fn coupons_root(&self) -> &str {
        &self.roots.tranche_coupons_root
    }
    pub fn coupons_domain_note(&self) -> Value {
        json!({"section":"coupons","root":self.roots.tranche_coupons_root,"height":self.height})
    }
    pub fn rebates_len(&self) -> usize {
        self.low_fee_rebates.len()
    }
    pub fn rebates_root(&self) -> &str {
        &self.roots.low_fee_rebates_root
    }
    pub fn rebates_domain_note(&self) -> Value {
        json!({"section":"rebates","root":self.roots.low_fee_rebates_root,"height":self.height})
    }
    pub fn redactions_len(&self) -> usize {
        self.redaction_budgets.len()
    }
    pub fn redactions_root(&self) -> &str {
        &self.roots.redaction_budgets_root
    }
    pub fn redactions_domain_note(&self) -> Value {
        json!({"section":"redactions","root":self.roots.redaction_budgets_root,"height":self.height})
    }
    pub fn summaries_len(&self) -> usize {
        self.operator_summaries.len()
    }
    pub fn summaries_root(&self) -> &str {
        &self.roots.operator_summaries_root
    }
    pub fn summaries_domain_note(&self) -> Value {
        json!({"section":"summaries","root":self.roots.operator_summaries_root,"height":self.height})
    }
}

fn map_root(domain: &str, mut leaves: Vec<Value>) -> String {
    leaves.sort_by_key(crate::hash::canonical_json_string);
    merkle_root(
        &format!("private-l2-pq-confidential-tokenized-exit-liquidity-backstop-note:{domain}"),
        &leaves,
    )
}
pub fn public_record(state: &State) -> Value {
    let mut record = state.public_record_without_state_root();
    if let Some(obj) = record.as_object_mut() {
        obj.insert(
            "state_root".to_string(),
            Value::String(state.roots.state_root.clone()),
        );
    }
    record
}
pub fn state_root(state: &State) -> String {
    domain_hash(
        "private-l2-pq-confidential-tokenized-exit-liquidity-backstop-note:state-root-view",
        &[HashPart::Json(&public_record(state))],
        32,
    )
}
fn demo_hash(label: &str, index: u64) -> String {
    domain_hash(
        "private-l2-pq-confidential-tokenized-exit-liquidity-backstop-note:demo",
        &[
            HashPart::Str(label),
            HashPart::U64(index),
            HashPart::Str(PROTOCOL_VERSION),
        ],
        32,
    )
}

pub fn devnet() -> State {
    let mut state =
        State::new(Config::default()).expect("valid default exit liquidity backstop note config");
    state
        .insert_note_vault(NoteVault {
            vault_id: "elbn-vault-devnet-001".to_string(),
            operator_id: "operator-exit-backstop-alpha".to_string(),
            tranche: NoteTranche::Senior,
            status: VaultStatus::Active,
            reserve_commitment: demo_hash("reserve", 1),
            liability_commitment: demo_hash("liability", 1),
            note_supply_commitment: demo_hash("note-supply", 1),
            coupon_pool_commitment: demo_hash("coupon-pool", 1),
            exit_asset_id: DEVNET_EXIT_ASSET_ID.to_string(),
            note_asset_id: DEVNET_NOTE_ASSET_ID.to_string(),
            opened_height: DEVNET_HEIGHT - 10_000,
            maturity_height: DEVNET_HEIGHT + DEFAULT_NOTE_TTL_BLOCKS,
            min_subscription_micro_units: 100_000,
            max_subscription_micro_units: 50_000_000,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            metadata_hash: demo_hash("vault-metadata", 1),
        })
        .expect("insert vault");
    state
        .insert_backstop_commitment(BackstopCommitment {
            commitment_id: "commitment-devnet-001".to_string(),
            vault_id: "elbn-vault-devnet-001".to_string(),
            provider_id: "provider-alpha".to_string(),
            status: CommitmentStatus::Attested,
            sealed_capacity_commitment: demo_hash("capacity", 1),
            bond_commitment: demo_hash("bond", 1),
            fee_commitment: demo_hash("fee", 1),
            unlock_height: DEVNET_HEIGHT + DEFAULT_NOTE_TTL_BLOCKS,
            nonce_commitment: demo_hash("nonce", 1),
            pq_public_key_hash: demo_hash("pq-key", 1),
        })
        .expect("insert commitment");
    state
        .insert_encrypted_subscription(EncryptedSubscription {
            subscription_id: "subscription-devnet-001".to_string(),
            vault_id: "elbn-vault-devnet-001".to_string(),
            subscriber_key_hash: demo_hash("subscriber", 1),
            status: SubscriptionStatus::Minted,
            encrypted_payload_hash: demo_hash("payload", 1),
            sealed_amount_commitment: demo_hash("amount", 1),
            note_mint_commitment: demo_hash("mint", 1),
            max_fee_bps: 8,
            submitted_height: DEVNET_HEIGHT - 600,
            expiry_height: DEVNET_HEIGHT + 120,
            nullifier_hash: demo_hash("subscription-nullifier", 1),
        })
        .expect("insert subscription");
    let mut signals = BTreeSet::new();
    signals.insert(SolvencySignal::ReserveObserved);
    signals.insert(SolvencySignal::LiabilityBounded);
    signals.insert(SolvencySignal::CommitmentOpened);
    signals.insert(SolvencySignal::ClaimQueueCovered);
    signals.insert(SolvencySignal::PrivacyBudgetObserved);
    state
        .insert_pq_solvency_attestation(PqSolvencyAttestation {
            attestation_id: "attestation-devnet-001".to_string(),
            vault_id: "elbn-vault-devnet-001".to_string(),
            operator_id: "operator-exit-backstop-alpha".to_string(),
            signals,
            solvency_ratio_bps: 13_200,
            reserve_root: demo_hash("reserve-root", 1),
            liability_root: demo_hash("liability-root", 1),
            claim_queue_root: demo_hash("claim-root", 1),
            pq_signature_hash: demo_hash("pq-signature", 1),
            quorum_bps: 8_600,
            observed_height: DEVNET_HEIGHT - 4,
            expires_height: DEVNET_HEIGHT + DEFAULT_ATTESTATION_TTL_BLOCKS,
        })
        .expect("insert attestation");
    state
        .insert_exit_claim_settlement(ExitClaimSettlement {
            claim_id: "claim-devnet-001".to_string(),
            vault_id: "elbn-vault-devnet-001".to_string(),
            claimant_key_hash: demo_hash("claimant", 1),
            status: ClaimStatus::Settled,
            decision: SettlementDecision::ApproveWithRebate,
            claim_commitment: demo_hash("claim", 1),
            settlement_commitment: demo_hash("settlement", 1),
            fee_commitment: demo_hash("claim-fee", 1),
            rebate_id: Some("rebate-devnet-001".to_string()),
            submitted_height: DEVNET_HEIGHT - 32,
            settled_height: DEVNET_HEIGHT - 12,
            settlement_tx_hash: demo_hash("settlement-tx", 1),
        })
        .expect("insert claim");
    state
        .insert_tranche_coupon(TrancheCoupon {
            coupon_id: "coupon-devnet-001".to_string(),
            vault_id: "elbn-vault-devnet-001".to_string(),
            tranche: NoteTranche::Senior,
            status: CouponStatus::Payable,
            epoch: state.epoch,
            rate_bps: NoteTranche::Senior.coupon_floor_bps(),
            coupon_commitment: demo_hash("coupon", 1),
            recipient_set_root: demo_hash("coupon-recipients", 1),
            paid_height: 0,
        })
        .expect("insert coupon");
    state
        .insert_low_fee_rebate(LowFeeRebate {
            rebate_id: "rebate-devnet-001".to_string(),
            vault_id: "elbn-vault-devnet-001".to_string(),
            claim_id: "claim-devnet-001".to_string(),
            recipient_key_hash: demo_hash("rebate-recipient", 1),
            rebate_commitment: demo_hash("rebate", 1),
            fee_paid_commitment: demo_hash("fee-paid", 1),
            rebate_bps: DEFAULT_TARGET_LOW_FEE_REBATE_BPS,
            issued_height: DEVNET_HEIGHT - 11,
            nullifier_hash: demo_hash("rebate-nullifier", 1),
        })
        .expect("insert rebate");
    state
        .insert_redaction_budget(RedactionBudget {
            budget_id: "redaction-devnet-001".to_string(),
            operator_id: "operator-exit-backstop-alpha".to_string(),
            vault_id: "elbn-vault-devnet-001".to_string(),
            allowance_units: DEFAULT_REDACTION_BUDGET_UNITS,
            spent_units: 24,
            public_bytes: 768,
            sealed_reason_hash: demo_hash("redaction-reason", 1),
            last_updated_height: DEVNET_HEIGHT - 2,
        })
        .expect("insert redaction");
    let mut redacted = BTreeSet::new();
    redacted.insert("subscriber_amounts".to_string());
    redacted.insert("provider_capacity_openings".to_string());
    redacted.insert("claimant_view_keys".to_string());
    state
        .insert_operator_summary(OperatorSummary {
            summary_id: "summary-devnet-001".to_string(),
            operator_id: "operator-exit-backstop-alpha".to_string(),
            vault_count: 1,
            active_claim_count: 0,
            solvency_floor_bps: 13_200,
            committed_backstop_micro_units: 75_000_000,
            outstanding_note_micro_units: 42_000_000,
            coupon_due_micro_units: 176_400,
            rebate_due_micro_units: 4_200,
            redacted_fields: redacted,
            summary_height: DEVNET_HEIGHT,
            summary_hash: demo_hash("summary", 1),
        })
        .expect("insert summary");
    state.recompute_roots();
    state
}

pub fn demo() -> State {
    devnet()
}

pub fn generated_operator_summary_metric_1(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_1","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_2(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_2","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_3(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_3","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_4(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_4","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_5(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_5","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_6(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_6","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_7(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_7","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_8(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_8","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_9(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_9","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_10(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_10","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_11(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_11","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_12(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_12","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_13(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_13","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_14(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_14","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_15(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_15","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_16(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_16","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_17(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_17","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_18(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_18","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_19(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_19","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_20(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_20","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_21(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_21","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_22(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_22","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_23(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_23","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_24(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_24","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_25(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_25","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_26(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_26","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_27(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_27","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_28(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_28","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_29(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_29","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_30(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_30","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_31(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_31","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_32(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_32","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_33(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_33","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_34(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_34","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_35(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_35","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_36(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_36","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_37(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_37","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_38(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_38","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_39(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_39","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_40(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_40","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_41(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_41","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_42(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_42","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_43(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_43","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_44(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_44","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_45(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_45","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_46(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_46","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_47(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_47","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_48(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_48","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_49(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_49","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_50(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_50","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_51(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_51","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_52(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_52","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_53(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_53","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_54(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_54","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_55(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_55","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_56(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_56","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_57(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_57","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_58(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_58","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_59(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_59","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_60(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_60","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_61(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_61","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_62(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_62","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_63(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_63","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_64(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_64","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_65(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_65","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_66(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_66","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_67(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_67","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_68(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_68","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_69(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_69","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_70(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_70","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_71(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_71","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_72(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_72","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_73(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_73","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_74(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_74","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_75(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_75","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_76(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_76","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_77(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_77","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_78(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_78","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_79(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_79","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_80(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_80","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_81(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_81","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_82(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_82","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_83(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_83","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_84(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_84","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_85(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_85","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_86(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_86","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_87(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_87","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_88(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_88","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_89(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_89","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_90(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_90","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_91(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_91","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_92(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_92","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_93(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_93","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_94(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_94","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_95(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_95","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_96(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_96","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_97(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_97","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_98(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_98","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_99(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_99","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_100(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_100","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_101(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_101","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_102(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_102","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_103(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_103","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_104(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_104","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_105(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_105","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_106(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_106","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_107(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_107","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_108(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_108","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_109(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_109","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_110(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_110","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_111(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_111","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_112(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_112","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_113(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_113","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_114(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_114","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_115(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_115","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_116(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_116","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_117(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_117","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_118(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_118","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_119(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_119","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_120(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_120","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_121(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_121","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_122(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_122","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_123(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_123","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_124(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_124","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_125(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_125","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_126(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_126","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_127(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_127","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_128(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_128","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_129(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_129","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_130(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_130","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_131(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_131","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_132(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_132","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_133(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_133","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_134(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_134","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_135(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_135","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_136(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_136","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_137(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_137","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_138(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_138","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_139(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_139","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_140(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_140","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_141(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_141","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_142(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_142","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_143(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_143","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_144(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_144","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_145(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_145","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_146(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_146","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_147(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_147","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_148(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_148","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_149(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_149","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
pub fn generated_operator_summary_metric_150(state: &State) -> Value {
    json!({"metric":"generated_operator_summary_metric_150","height":state.height,"state_root":state.roots.state_root,"summaries":state.counters.summaries,"redaction_budget_units":state.config.redaction_budget_units})
}
