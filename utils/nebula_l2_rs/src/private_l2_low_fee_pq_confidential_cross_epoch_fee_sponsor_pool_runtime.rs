use crate::hash::{domain_hash, merkle_root, HashPart};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePqConfidentialCrossEpochFeeSponsorPoolRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_EPOCH_FEE_SPONSOR_POOL_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-cross-epoch-fee-sponsor-pool-runtime-v1";

const CHAIN_ID: &str = "nebula-l2-devnet";
const HASH_BYTES: usize = 32;
const MAX_BPS: u64 = 10_000;
const MAX_EVENTS: usize = 4096;
const MAX_CARRY_EPOCHS: u64 = 4;
const MIN_PQ_SECURITY_BITS: u16 = 256;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SponsorCohortKind {
    RetailRelief,
    BridgeMigration,
    WalletOnboarding,
    MarketMakerRebate,
    EmergencyExit,
}

impl SponsorCohortKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RetailRelief => "retail_relief",
            Self::BridgeMigration => "bridge_migration",
            Self::WalletOnboarding => "wallet_onboarding",
            Self::MarketMakerRebate => "market_maker_rebate",
            Self::EmergencyExit => "emergency_exit",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum CohortStatus {
    Draft,
    Active,
    CarryForwardOnly,
    Draining,
    Closed,
    Slashed,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EpochStatus {
    Open,
    Sealed,
    Settled,
    RolledForward,
    Reconciled,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum BucketStatus {
    Open,
    Locked,
    Carried,
    Exhausted,
    Expired,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Pending,
    Accepted,
    Rejected,
    Revoked,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum VoucherStatus {
    Reserved,
    Settled,
    Rebated,
    Expired,
    Disputed,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ThrottleScope {
    AccountNullifier,
    DeviceCluster,
    SponsorCohort,
    Epoch,
    Global,
}

impl ThrottleScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AccountNullifier => "account_nullifier",
            Self::DeviceCluster => "device_cluster",
            Self::SponsorCohort => "sponsor_cohort",
            Self::Epoch => "epoch",
            Self::Global => "global",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub fee_asset_id: String,
    pub epoch_span_blocks: u64,
    pub max_user_fee_bps: u64,
    pub max_sponsor_cover_bps: u64,
    pub max_rebate_bps: u64,
    pub max_carry_epochs: u64,
    pub min_pq_security_bits: u16,
    pub redaction_budget_per_epoch: u64,
    pub throttle_window_blocks: u64,
    pub account_nullifier_limit: u64,
    pub device_cluster_limit: u64,
    pub cohort_spend_limit: u64,
    pub global_spend_limit: u64,
    pub settlement_delay_blocks: u64,
    pub voucher_ttl_blocks: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            fee_asset_id: "piconero-devnet".to_string(),
            epoch_span_blocks: 720,
            max_user_fee_bps: 25,
            max_sponsor_cover_bps: MAX_BPS,
            max_rebate_bps: 3_000,
            max_carry_epochs: MAX_CARRY_EPOCHS,
            min_pq_security_bits: MIN_PQ_SECURITY_BITS,
            redaction_budget_per_epoch: 65_536,
            throttle_window_blocks: 60,
            account_nullifier_limit: 6,
            device_cluster_limit: 24,
            cohort_spend_limit: 250_000_000,
            global_spend_limit: 2_000_000_000,
            settlement_delay_blocks: 8,
            voucher_ttl_blocks: 1_440,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        require_nonempty("chain_id", &self.chain_id)?;
        require_nonempty("fee_asset_id", &self.fee_asset_id)?;
        require_range("epoch_span_blocks", self.epoch_span_blocks, 1, 1_000_000)?;
        require_range("max_user_fee_bps", self.max_user_fee_bps, 0, MAX_BPS)?;
        require_range(
            "max_sponsor_cover_bps",
            self.max_sponsor_cover_bps,
            1,
            MAX_BPS,
        )?;
        require_range("max_rebate_bps", self.max_rebate_bps, 0, MAX_BPS)?;
        require_range("max_carry_epochs", self.max_carry_epochs, 1, 32)?;
        if self.min_pq_security_bits < MIN_PQ_SECURITY_BITS {
            return Err("min_pq_security_bits below runtime floor".to_string());
        }
        require_range(
            "redaction_budget_per_epoch",
            self.redaction_budget_per_epoch,
            1,
            1_000_000_000,
        )?;
        require_range(
            "throttle_window_blocks",
            self.throttle_window_blocks,
            1,
            10_000,
        )?;
        require_range(
            "account_nullifier_limit",
            self.account_nullifier_limit,
            1,
            10_000,
        )?;
        require_range(
            "device_cluster_limit",
            self.device_cluster_limit,
            1,
            100_000,
        )?;
        require_range("cohort_spend_limit", self.cohort_spend_limit, 1, u64::MAX)?;
        require_range("global_spend_limit", self.global_spend_limit, 1, u64::MAX)?;
        require_range(
            "settlement_delay_blocks",
            self.settlement_delay_blocks,
            0,
            100_000,
        )?;
        require_range("voucher_ttl_blocks", self.voucher_ttl_blocks, 1, 1_000_000)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub sponsor_cohorts: u64,
    pub fee_credit_epochs: u64,
    pub carry_forward_buckets: u64,
    pub pq_sponsor_attestations: u64,
    pub settlement_vouchers: u64,
    pub throttle_records: u64,
    pub rebate_distributions: u64,
    pub redaction_budgets: u64,
    pub operator_summaries: u64,
    pub runtime_events: u64,
    pub total_sponsored_fees: u64,
    pub total_user_fees: u64,
    pub total_rebates: u64,
    pub total_carried_forward: u64,
    pub total_throttle_hits: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub sponsor_cohorts_root: String,
    pub fee_credit_epochs_root: String,
    pub carry_forward_buckets_root: String,
    pub pq_sponsor_attestations_root: String,
    pub settlement_vouchers_root: String,
    pub anti_abuse_throttles_root: String,
    pub rebate_distributions_root: String,
    pub redaction_budgets_root: String,
    pub operator_summaries_root: String,
    pub spent_nullifiers_root: String,
    pub runtime_events_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            sponsor_cohorts_root: empty_root("SPONSOR-COHORTS"),
            fee_credit_epochs_root: empty_root("FEE-CREDIT-EPOCHS"),
            carry_forward_buckets_root: empty_root("CARRY-FORWARD-BUCKETS"),
            pq_sponsor_attestations_root: empty_root("PQ-SPONSOR-ATTESTATIONS"),
            settlement_vouchers_root: empty_root("SETTLEMENT-VOUCHERS"),
            anti_abuse_throttles_root: empty_root("ANTI-ABUSE-THROTTLES"),
            rebate_distributions_root: empty_root("REBATE-DISTRIBUTIONS"),
            redaction_budgets_root: empty_root("REDACTION-BUDGETS"),
            operator_summaries_root: empty_root("OPERATOR-SUMMARIES"),
            spent_nullifiers_root: empty_root("SPENT-NULLIFIERS"),
            runtime_events_root: empty_root("RUNTIME-EVENTS"),
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SponsorCohort {
    pub cohort_id: String,
    pub label: String,
    pub kind: SponsorCohortKind,
    pub status: CohortStatus,
    pub sponsor_commitment_root: String,
    pub pq_public_key_root: String,
    pub policy_root: String,
    pub funding_commitment_root: String,
    pub start_epoch: u64,
    pub end_epoch: u64,
    pub max_fee_per_voucher: u64,
    pub max_total_fee: u64,
    pub available_fee_credit: u64,
    pub spent_fee_credit: u64,
    pub reserved_fee_credit: u64,
    pub carry_forward_credit: u64,
    pub redaction_budget_units: u64,
    pub created_at_height: u64,
}

impl SponsorCohort {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeCreditEpoch {
    pub epoch_id: String,
    pub epoch_index: u64,
    pub status: EpochStatus,
    pub start_height: u64,
    pub end_height: u64,
    pub cohort_root: String,
    pub opening_credit: u64,
    pub sponsored_credit: u64,
    pub user_fee_credit: u64,
    pub rebate_credit: u64,
    pub carried_in_credit: u64,
    pub carried_out_credit: u64,
    pub redaction_budget_root: String,
    pub sealed_state_root: String,
}

impl FeeCreditEpoch {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CarryForwardBucket {
    pub bucket_id: String,
    pub cohort_id: String,
    pub from_epoch: u64,
    pub to_epoch: u64,
    pub status: BucketStatus,
    pub amount: u64,
    pub spent_amount: u64,
    pub expiry_epoch: u64,
    pub nullifier_set_root: String,
    pub carry_policy_root: String,
}

impl CarryForwardBucket {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqSponsorAttestation {
    pub attestation_id: String,
    pub cohort_id: String,
    pub epoch_index: u64,
    pub status: AttestationStatus,
    pub sponsor_key_root: String,
    pub pq_signature_root: String,
    pub attested_credit_root: String,
    pub policy_transcript_root: String,
    pub security_bits: u16,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub accepted_at_height: u64,
}

impl PqSponsorAttestation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlementVoucher {
    pub voucher_id: String,
    pub cohort_id: String,
    pub epoch_index: u64,
    pub status: VoucherStatus,
    pub account_nullifier_root: String,
    pub device_cluster_root: String,
    pub fee_note_root: String,
    pub settlement_commitment_root: String,
    pub sponsor_amount: u64,
    pub user_fee_amount: u64,
    pub rebate_amount: u64,
    pub reserved_at_height: u64,
    pub settled_at_height: u64,
    pub expires_at_height: u64,
}

impl SettlementVoucher {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AntiAbuseThrottle {
    pub throttle_id: String,
    pub scope: ThrottleScope,
    pub subject_root: String,
    pub epoch_index: u64,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub usage_count: u64,
    pub sponsored_amount: u64,
    pub limit_count: u64,
    pub limit_amount: u64,
    pub blocked: bool,
    pub last_hit_height: u64,
}

impl AntiAbuseThrottle {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RebateDistribution {
    pub rebate_id: String,
    pub cohort_id: String,
    pub epoch_index: u64,
    pub voucher_root: String,
    pub recipient_commitment_root: String,
    pub rebate_amount: u64,
    pub distribution_bps: u64,
    pub proof_root: String,
    pub distributed_at_height: u64,
}

impl RebateDistribution {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub cohort_id: String,
    pub epoch_index: u64,
    pub total_units: u64,
    pub spent_units: u64,
    pub carry_forward_units: u64,
    pub redacted_field_root: String,
    pub disclosure_policy_root: String,
}

impl RedactionBudget {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub epoch_index: u64,
    pub operator_key_root: String,
    pub cohorts_root: String,
    pub vouchers_root: String,
    pub throttles_root: String,
    pub rebates_root: String,
    pub redaction_root: String,
    pub total_sponsored: u64,
    pub total_user_paid: u64,
    pub total_rebated: u64,
    pub total_carried: u64,
    pub abuse_hits: u64,
    pub published_at_height: u64,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeEvent {
    pub fn new(
        event_kind: &str,
        subject_id: &str,
        payload: &Value,
        height: u64,
        sequence: u64,
    ) -> Self {
        let payload_root = value_root("EVENT-PAYLOAD", payload);
        let event_id = domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-FEE-SPONSOR-RUNTIME-EVENT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(event_kind),
                HashPart::Str(subject_id),
                HashPart::Str(&payload_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
            HASH_BYTES,
        );
        Self {
            event_id,
            event_kind: event_kind.to_string(),
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterSponsorCohortRequest {
    pub label: String,
    pub kind: SponsorCohortKind,
    pub sponsor_commitment_root: String,
    pub pq_public_key_root: String,
    pub policy_root: String,
    pub funding_commitment_root: String,
    pub start_epoch: u64,
    pub end_epoch: u64,
    pub max_fee_per_voucher: u64,
    pub max_total_fee: u64,
    pub opening_credit: u64,
    pub redaction_budget_units: u64,
    pub created_at_height: u64,
}

impl RegisterSponsorCohortRequest {
    pub fn validate(&self) -> Result<()> {
        require_nonempty("label", &self.label)?;
        require_root("sponsor_commitment_root", &self.sponsor_commitment_root)?;
        require_root("pq_public_key_root", &self.pq_public_key_root)?;
        require_root("policy_root", &self.policy_root)?;
        require_root("funding_commitment_root", &self.funding_commitment_root)?;
        if self.end_epoch < self.start_epoch {
            return Err("end_epoch before start_epoch".to_string());
        }
        require_range("max_fee_per_voucher", self.max_fee_per_voucher, 1, u64::MAX)?;
        require_range("max_total_fee", self.max_total_fee, 1, u64::MAX)?;
        require_range("opening_credit", self.opening_credit, 1, self.max_total_fee)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenEpochRequest {
    pub epoch_index: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub cohort_root: String,
    pub opening_credit: u64,
    pub carried_in_credit: u64,
}

impl OpenEpochRequest {
    pub fn validate(&self) -> Result<()> {
        if self.end_height <= self.start_height {
            return Err("epoch end_height must exceed start_height".to_string());
        }
        require_root("cohort_root", &self.cohort_root)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitPqAttestationRequest {
    pub cohort_id: String,
    pub epoch_index: u64,
    pub sponsor_key_root: String,
    pub pq_signature_root: String,
    pub attested_credit_root: String,
    pub policy_transcript_root: String,
    pub security_bits: u16,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub accepted_at_height: u64,
}

impl SubmitPqAttestationRequest {
    pub fn validate(&self) -> Result<()> {
        require_nonempty("cohort_id", &self.cohort_id)?;
        require_root("sponsor_key_root", &self.sponsor_key_root)?;
        require_root("pq_signature_root", &self.pq_signature_root)?;
        require_root("attested_credit_root", &self.attested_credit_root)?;
        require_root("policy_transcript_root", &self.policy_transcript_root)?;
        if self.security_bits < MIN_PQ_SECURITY_BITS {
            return Err("pq attestation below minimum security bits".to_string());
        }
        if self.valid_until_height <= self.valid_from_height {
            return Err("attestation validity window is empty".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReserveVoucherRequest {
    pub cohort_id: String,
    pub epoch_index: u64,
    pub account_nullifier_root: String,
    pub device_cluster_root: String,
    pub fee_note_root: String,
    pub settlement_commitment_root: String,
    pub sponsor_amount: u64,
    pub user_fee_amount: u64,
    pub rebate_bps: u64,
    pub reserved_at_height: u64,
}

impl ReserveVoucherRequest {
    pub fn validate(&self) -> Result<()> {
        require_nonempty("cohort_id", &self.cohort_id)?;
        require_root("account_nullifier_root", &self.account_nullifier_root)?;
        require_root("device_cluster_root", &self.device_cluster_root)?;
        require_root("fee_note_root", &self.fee_note_root)?;
        require_root(
            "settlement_commitment_root",
            &self.settlement_commitment_root,
        )?;
        require_range("sponsor_amount", self.sponsor_amount, 1, u64::MAX)?;
        require_range("rebate_bps", self.rebate_bps, 0, MAX_BPS)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettleVoucherRequest {
    pub voucher_id: String,
    pub settlement_height: u64,
    pub settlement_proof_root: String,
}

impl SettleVoucherRequest {
    pub fn validate(&self) -> Result<()> {
        require_nonempty("voucher_id", &self.voucher_id)?;
        require_root("settlement_proof_root", &self.settlement_proof_root)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CarryForwardRequest {
    pub cohort_id: String,
    pub from_epoch: u64,
    pub to_epoch: u64,
    pub amount: u64,
    pub nullifier_set_root: String,
    pub carry_policy_root: String,
}

impl CarryForwardRequest {
    pub fn validate(&self) -> Result<()> {
        require_nonempty("cohort_id", &self.cohort_id)?;
        if self.to_epoch <= self.from_epoch {
            return Err("carry-forward target epoch must be greater".to_string());
        }
        require_range("amount", self.amount, 1, u64::MAX)?;
        require_root("nullifier_set_root", &self.nullifier_set_root)?;
        require_root("carry_policy_root", &self.carry_policy_root)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpendRedactionBudgetRequest {
    pub cohort_id: String,
    pub epoch_index: u64,
    pub units: u64,
    pub redacted_field_root: String,
    pub disclosure_policy_root: String,
}

impl SpendRedactionBudgetRequest {
    pub fn validate(&self) -> Result<()> {
        require_nonempty("cohort_id", &self.cohort_id)?;
        require_range("units", self.units, 1, u64::MAX)?;
        require_root("redacted_field_root", &self.redacted_field_root)?;
        require_root("disclosure_policy_root", &self.disclosure_policy_root)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub sponsor_cohorts: BTreeMap<String, SponsorCohort>,
    pub fee_credit_epochs: BTreeMap<String, FeeCreditEpoch>,
    pub carry_forward_buckets: BTreeMap<String, CarryForwardBucket>,
    pub pq_sponsor_attestations: BTreeMap<String, PqSponsorAttestation>,
    pub settlement_vouchers: BTreeMap<String, SettlementVoucher>,
    pub anti_abuse_throttles: BTreeMap<String, AntiAbuseThrottle>,
    pub rebate_distributions: BTreeMap<String, RebateDistribution>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub spent_nullifiers: BTreeSet<String>,
    pub runtime_events: Vec<RuntimeEvent>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            sponsor_cohorts: BTreeMap::new(),
            fee_credit_epochs: BTreeMap::new(),
            carry_forward_buckets: BTreeMap::new(),
            pq_sponsor_attestations: BTreeMap::new(),
            settlement_vouchers: BTreeMap::new(),
            anti_abuse_throttles: BTreeMap::new(),
            rebate_distributions: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            runtime_events: Vec::new(),
        }
    }
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            ..Self::default()
        };
        state.recompute_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::default()).expect("default config is valid");
        let cohort = state
            .register_sponsor_cohort(RegisterSponsorCohortRequest {
                label: "devnet-wallet-onboarding-low-fee-pool".to_string(),
                kind: SponsorCohortKind::WalletOnboarding,
                sponsor_commitment_root: sample_root("devnet-sponsor-commitment"),
                pq_public_key_root: sample_root("devnet-sponsor-pq-key"),
                policy_root: sample_root("devnet-policy"),
                funding_commitment_root: sample_root("devnet-funding"),
                start_epoch: 1,
                end_epoch: 6,
                max_fee_per_voucher: 25_000,
                max_total_fee: 500_000_000,
                opening_credit: 120_000_000,
                redaction_budget_units: 65_536,
                created_at_height: 336_000,
            })
            .expect("devnet cohort");
        state
            .open_fee_credit_epoch(OpenEpochRequest {
                epoch_index: 1,
                start_height: 336_000,
                end_height: 336_720,
                cohort_root: value_root("DEVNET-COHORT", &cohort.public_record()),
                opening_credit: 120_000_000,
                carried_in_credit: 0,
            })
            .expect("devnet epoch");
        state
            .submit_pq_sponsor_attestation(SubmitPqAttestationRequest {
                cohort_id: cohort.cohort_id.clone(),
                epoch_index: 1,
                sponsor_key_root: sample_root("devnet-sponsor-pq-key"),
                pq_signature_root: sample_root("devnet-pq-signature"),
                attested_credit_root: sample_root("devnet-credit-root"),
                policy_transcript_root: sample_root("devnet-policy-transcript"),
                security_bits: 256,
                valid_from_height: 336_000,
                valid_until_height: 337_440,
                accepted_at_height: 336_001,
            })
            .expect("devnet attestation");
        let voucher = state
            .reserve_settlement_voucher(ReserveVoucherRequest {
                cohort_id: cohort.cohort_id.clone(),
                epoch_index: 1,
                account_nullifier_root: sample_root("devnet-account-nullifier-1"),
                device_cluster_root: sample_root("devnet-device-cluster-1"),
                fee_note_root: sample_root("devnet-fee-note-1"),
                settlement_commitment_root: sample_root("devnet-settlement-1"),
                sponsor_amount: 17_500,
                user_fee_amount: 50,
                rebate_bps: 1_000,
                reserved_at_height: 336_004,
            })
            .expect("devnet voucher");
        state
            .settle_voucher(SettleVoucherRequest {
                voucher_id: voucher.voucher_id,
                settlement_height: 336_016,
                settlement_proof_root: sample_root("devnet-settlement-proof-1"),
            })
            .expect("devnet settle");
        state
            .carry_forward_credit(CarryForwardRequest {
                cohort_id: cohort.cohort_id.clone(),
                from_epoch: 1,
                to_epoch: 2,
                amount: 25_000_000,
                nullifier_set_root: sample_root("devnet-carry-nullifiers"),
                carry_policy_root: sample_root("devnet-carry-policy"),
            })
            .expect("devnet carry");
        state
            .spend_redaction_budget(SpendRedactionBudgetRequest {
                cohort_id: cohort.cohort_id,
                epoch_index: 1,
                units: 128,
                redacted_field_root: sample_root("devnet-redacted-fields"),
                disclosure_policy_root: sample_root("devnet-disclosure-policy"),
            })
            .expect("devnet redaction");
        state.publish_operator_summary(1, sample_root("devnet-operator-key"), 336_030);
        state
    }

    pub fn register_sponsor_cohort(
        &mut self,
        request: RegisterSponsorCohortRequest,
    ) -> Result<SponsorCohort> {
        request.validate()?;
        if request.max_fee_per_voucher > request.opening_credit {
            return Err("max_fee_per_voucher exceeds opening_credit".to_string());
        }
        let sequence = self.counters.sponsor_cohorts.saturating_add(1);
        let cohort_id = sponsor_cohort_id(&request, sequence);
        if self.sponsor_cohorts.contains_key(&cohort_id) {
            return Err("sponsor cohort already exists".to_string());
        }
        let cohort = SponsorCohort {
            cohort_id: cohort_id.clone(),
            label: request.label,
            kind: request.kind,
            status: CohortStatus::Active,
            sponsor_commitment_root: request.sponsor_commitment_root,
            pq_public_key_root: request.pq_public_key_root,
            policy_root: request.policy_root,
            funding_commitment_root: request.funding_commitment_root,
            start_epoch: request.start_epoch,
            end_epoch: request.end_epoch,
            max_fee_per_voucher: request.max_fee_per_voucher,
            max_total_fee: request.max_total_fee,
            available_fee_credit: request.opening_credit,
            spent_fee_credit: 0,
            reserved_fee_credit: 0,
            carry_forward_credit: 0,
            redaction_budget_units: request.redaction_budget_units,
            created_at_height: request.created_at_height,
        };
        self.counters.sponsor_cohorts = sequence;
        self.emit_event(
            "sponsor_cohort_registered",
            &cohort_id,
            &cohort.public_record(),
            request.created_at_height,
        );
        self.sponsor_cohorts.insert(cohort_id, cohort.clone());
        self.ensure_redaction_budget(
            &cohort.cohort_id,
            cohort.start_epoch,
            cohort.redaction_budget_units,
        );
        self.recompute_roots();
        Ok(cohort)
    }

    pub fn open_fee_credit_epoch(&mut self, request: OpenEpochRequest) -> Result<FeeCreditEpoch> {
        request.validate()?;
        let epoch_id = fee_credit_epoch_id(
            request.epoch_index,
            request.start_height,
            &request.cohort_root,
        );
        if self.fee_credit_epochs.contains_key(&epoch_id) {
            return Err("fee credit epoch already exists".to_string());
        }
        let epoch = FeeCreditEpoch {
            epoch_id: epoch_id.clone(),
            epoch_index: request.epoch_index,
            status: EpochStatus::Open,
            start_height: request.start_height,
            end_height: request.end_height,
            cohort_root: request.cohort_root,
            opening_credit: request.opening_credit,
            sponsored_credit: 0,
            user_fee_credit: 0,
            rebate_credit: 0,
            carried_in_credit: request.carried_in_credit,
            carried_out_credit: 0,
            redaction_budget_root: self.roots.redaction_budgets_root.clone(),
            sealed_state_root: empty_root("UNSEALED-EPOCH"),
        };
        self.counters.fee_credit_epochs = self.counters.fee_credit_epochs.saturating_add(1);
        self.emit_event(
            "fee_credit_epoch_opened",
            &epoch_id,
            &epoch.public_record(),
            request.start_height,
        );
        self.fee_credit_epochs.insert(epoch_id, epoch.clone());
        self.recompute_roots();
        Ok(epoch)
    }

    pub fn submit_pq_sponsor_attestation(
        &mut self,
        request: SubmitPqAttestationRequest,
    ) -> Result<PqSponsorAttestation> {
        request.validate()?;
        self.ensure_cohort_active(&request.cohort_id, request.epoch_index)?;
        let sequence = self.counters.pq_sponsor_attestations.saturating_add(1);
        let attestation_id = pq_attestation_id(&request, sequence);
        let attestation = PqSponsorAttestation {
            attestation_id: attestation_id.clone(),
            cohort_id: request.cohort_id,
            epoch_index: request.epoch_index,
            status: AttestationStatus::Accepted,
            sponsor_key_root: request.sponsor_key_root,
            pq_signature_root: request.pq_signature_root,
            attested_credit_root: request.attested_credit_root,
            policy_transcript_root: request.policy_transcript_root,
            security_bits: request.security_bits,
            valid_from_height: request.valid_from_height,
            valid_until_height: request.valid_until_height,
            accepted_at_height: request.accepted_at_height,
        };
        self.counters.pq_sponsor_attestations = sequence;
        self.emit_event(
            "pq_sponsor_attestation_accepted",
            &attestation_id,
            &attestation.public_record(),
            request.accepted_at_height,
        );
        self.pq_sponsor_attestations
            .insert(attestation_id, attestation.clone());
        self.recompute_roots();
        Ok(attestation)
    }

    pub fn reserve_settlement_voucher(
        &mut self,
        request: ReserveVoucherRequest,
    ) -> Result<SettlementVoucher> {
        request.validate()?;
        self.ensure_cohort_active(&request.cohort_id, request.epoch_index)?;
        self.ensure_epoch_open(request.epoch_index)?;
        if request.rebate_bps > self.config.max_rebate_bps {
            return Err("rebate_bps exceeds config".to_string());
        }
        if self
            .spent_nullifiers
            .contains(&request.account_nullifier_root)
        {
            return Err("account nullifier already used".to_string());
        }
        self.apply_throttle(
            ThrottleScope::AccountNullifier,
            &request.account_nullifier_root,
            request.epoch_index,
            request.reserved_at_height,
            request.sponsor_amount,
        )?;
        self.apply_throttle(
            ThrottleScope::DeviceCluster,
            &request.device_cluster_root,
            request.epoch_index,
            request.reserved_at_height,
            request.sponsor_amount,
        )?;
        self.apply_throttle(
            ThrottleScope::SponsorCohort,
            &request.cohort_id,
            request.epoch_index,
            request.reserved_at_height,
            request.sponsor_amount,
        )?;
        self.apply_throttle(
            ThrottleScope::Global,
            CHAIN_ID,
            request.epoch_index,
            request.reserved_at_height,
            request.sponsor_amount,
        )?;
        let cohort = self
            .sponsor_cohorts
            .get_mut(&request.cohort_id)
            .ok_or_else(|| "cohort missing".to_string())?;
        if request.sponsor_amount > cohort.max_fee_per_voucher {
            return Err("sponsor_amount exceeds cohort per-voucher cap".to_string());
        }
        if request.sponsor_amount > cohort.available_fee_credit {
            return Err("cohort credit exhausted".to_string());
        }
        cohort.available_fee_credit = cohort
            .available_fee_credit
            .saturating_sub(request.sponsor_amount);
        cohort.reserved_fee_credit = cohort
            .reserved_fee_credit
            .saturating_add(request.sponsor_amount);
        let sequence = self.counters.settlement_vouchers.saturating_add(1);
        let rebate_amount = mul_bps(request.sponsor_amount, request.rebate_bps);
        let voucher_id = settlement_voucher_id(&request, sequence);
        let voucher = SettlementVoucher {
            voucher_id: voucher_id.clone(),
            cohort_id: request.cohort_id,
            epoch_index: request.epoch_index,
            status: VoucherStatus::Reserved,
            account_nullifier_root: request.account_nullifier_root,
            device_cluster_root: request.device_cluster_root,
            fee_note_root: request.fee_note_root,
            settlement_commitment_root: request.settlement_commitment_root,
            sponsor_amount: request.sponsor_amount,
            user_fee_amount: request.user_fee_amount,
            rebate_amount,
            reserved_at_height: request.reserved_at_height,
            settled_at_height: 0,
            expires_at_height: request
                .reserved_at_height
                .saturating_add(self.config.voucher_ttl_blocks),
        };
        self.counters.settlement_vouchers = sequence;
        self.counters.total_user_fees = self
            .counters
            .total_user_fees
            .saturating_add(voucher.user_fee_amount);
        self.spent_nullifiers
            .insert(voucher.account_nullifier_root.clone());
        self.emit_event(
            "settlement_voucher_reserved",
            &voucher_id,
            &voucher.public_record(),
            request.reserved_at_height,
        );
        self.settlement_vouchers.insert(voucher_id, voucher.clone());
        self.recompute_roots();
        Ok(voucher)
    }

    pub fn settle_voucher(&mut self, request: SettleVoucherRequest) -> Result<SettlementVoucher> {
        request.validate()?;
        let mut voucher = self
            .settlement_vouchers
            .get(&request.voucher_id)
            .cloned()
            .ok_or_else(|| "voucher missing".to_string())?;
        if voucher.status != VoucherStatus::Reserved {
            return Err("voucher is not reserved".to_string());
        }
        if request.settlement_height > voucher.expires_at_height {
            voucher.status = VoucherStatus::Expired;
            self.settlement_vouchers
                .insert(voucher.voucher_id.clone(), voucher.clone());
            self.recompute_roots();
            return Err("voucher expired".to_string());
        }
        voucher.status = VoucherStatus::Settled;
        voucher.settled_at_height = request.settlement_height;
        if let Some(cohort) = self.sponsor_cohorts.get_mut(&voucher.cohort_id) {
            cohort.reserved_fee_credit = cohort
                .reserved_fee_credit
                .saturating_sub(voucher.sponsor_amount);
            cohort.spent_fee_credit = cohort
                .spent_fee_credit
                .saturating_add(voucher.sponsor_amount);
        }
        self.counters.total_sponsored_fees = self
            .counters
            .total_sponsored_fees
            .saturating_add(voucher.sponsor_amount);
        self.credit_epoch_for_voucher(&voucher);
        self.distribute_rebate(
            &voucher,
            &request.settlement_proof_root,
            request.settlement_height,
        )?;
        self.emit_event(
            "settlement_voucher_settled",
            &voucher.voucher_id,
            &voucher.public_record(),
            request.settlement_height,
        );
        self.settlement_vouchers
            .insert(voucher.voucher_id.clone(), voucher.clone());
        self.recompute_roots();
        Ok(voucher)
    }

    pub fn carry_forward_credit(
        &mut self,
        request: CarryForwardRequest,
    ) -> Result<CarryForwardBucket> {
        request.validate()?;
        let max_to_epoch = request
            .from_epoch
            .saturating_add(self.config.max_carry_epochs);
        if request.to_epoch > max_to_epoch {
            return Err("carry-forward exceeds max_carry_epochs".to_string());
        }
        let cohort = self
            .sponsor_cohorts
            .get_mut(&request.cohort_id)
            .ok_or_else(|| "cohort missing".to_string())?;
        if request.amount > cohort.available_fee_credit {
            return Err("carry-forward amount exceeds available credit".to_string());
        }
        cohort.available_fee_credit = cohort.available_fee_credit.saturating_sub(request.amount);
        cohort.carry_forward_credit = cohort.carry_forward_credit.saturating_add(request.amount);
        let sequence = self.counters.carry_forward_buckets.saturating_add(1);
        let bucket_id = carry_forward_bucket_id(&request, sequence);
        let bucket = CarryForwardBucket {
            bucket_id: bucket_id.clone(),
            cohort_id: request.cohort_id,
            from_epoch: request.from_epoch,
            to_epoch: request.to_epoch,
            status: BucketStatus::Carried,
            amount: request.amount,
            spent_amount: 0,
            expiry_epoch: max_to_epoch,
            nullifier_set_root: request.nullifier_set_root,
            carry_policy_root: request.carry_policy_root,
        };
        self.counters.carry_forward_buckets = sequence;
        self.counters.total_carried_forward = self
            .counters
            .total_carried_forward
            .saturating_add(bucket.amount);
        self.emit_event(
            "carry_forward_bucket_created",
            &bucket_id,
            &bucket.public_record(),
            0,
        );
        self.carry_forward_buckets.insert(bucket_id, bucket.clone());
        self.recompute_roots();
        Ok(bucket)
    }

    pub fn spend_redaction_budget(
        &mut self,
        request: SpendRedactionBudgetRequest,
    ) -> Result<RedactionBudget> {
        request.validate()?;
        let key = redaction_budget_id(&request.cohort_id, request.epoch_index);
        let budget = self
            .redaction_budgets
            .entry(key.clone())
            .or_insert_with(|| RedactionBudget {
                budget_id: key.clone(),
                cohort_id: request.cohort_id.clone(),
                epoch_index: request.epoch_index,
                total_units: self.config.redaction_budget_per_epoch,
                spent_units: 0,
                carry_forward_units: 0,
                redacted_field_root: request.redacted_field_root.clone(),
                disclosure_policy_root: request.disclosure_policy_root.clone(),
            });
        if budget.spent_units.saturating_add(request.units) > budget.total_units {
            return Err("redaction budget exceeded".to_string());
        }
        budget.spent_units = budget.spent_units.saturating_add(request.units);
        budget.carry_forward_units = budget.total_units.saturating_sub(budget.spent_units);
        budget.redacted_field_root = request.redacted_field_root;
        budget.disclosure_policy_root = request.disclosure_policy_root;
        let budget = budget.clone();
        self.counters.redaction_budgets = self.redaction_budgets.len() as u64;
        self.emit_event(
            "redaction_budget_spent",
            &budget.budget_id,
            &budget.public_record(),
            0,
        );
        self.recompute_roots();
        Ok(budget)
    }

    pub fn seal_epoch(&mut self, epoch_index: u64) -> Result<FeeCreditEpoch> {
        let epoch_id = self.epoch_id_by_index(epoch_index)?;
        let mut epoch = self
            .fee_credit_epochs
            .get(&epoch_id)
            .cloned()
            .ok_or_else(|| "epoch missing".to_string())?;
        if epoch.status != EpochStatus::Open {
            return Err("epoch is not open".to_string());
        }
        epoch.status = EpochStatus::Sealed;
        epoch.carried_out_credit = self
            .carry_forward_buckets
            .values()
            .filter(|bucket| bucket.from_epoch == epoch_index)
            .map(|bucket| bucket.amount.saturating_sub(bucket.spent_amount))
            .sum();
        epoch.redaction_budget_root = self.roots.redaction_budgets_root.clone();
        epoch.sealed_state_root = self.state_root();
        self.emit_event(
            "fee_credit_epoch_sealed",
            &epoch.epoch_id,
            &epoch.public_record(),
            epoch.end_height,
        );
        self.fee_credit_epochs.insert(epoch_id, epoch.clone());
        self.recompute_roots();
        Ok(epoch)
    }

    pub fn publish_operator_summary(
        &mut self,
        epoch_index: u64,
        operator_key_root: String,
        published_at_height: u64,
    ) -> OperatorSummary {
        let sequence = self.counters.operator_summaries.saturating_add(1);
        let summary_id = operator_summary_id(epoch_index, &operator_key_root, sequence);
        let summary = OperatorSummary {
            summary_id: summary_id.clone(),
            epoch_index,
            operator_key_root,
            cohorts_root: self.roots.sponsor_cohorts_root.clone(),
            vouchers_root: self.roots.settlement_vouchers_root.clone(),
            throttles_root: self.roots.anti_abuse_throttles_root.clone(),
            rebates_root: self.roots.rebate_distributions_root.clone(),
            redaction_root: self.roots.redaction_budgets_root.clone(),
            total_sponsored: self.counters.total_sponsored_fees,
            total_user_paid: self.counters.total_user_fees,
            total_rebated: self.counters.total_rebates,
            total_carried: self.counters.total_carried_forward,
            abuse_hits: self.counters.total_throttle_hits,
            published_at_height,
        };
        self.counters.operator_summaries = sequence;
        self.emit_event(
            "operator_summary_published",
            &summary_id,
            &summary.public_record(),
            published_at_height,
        );
        self.operator_summaries.insert(summary_id, summary.clone());
        self.recompute_roots();
        summary
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), json!(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_EPOCH_FEE_SPONSOR_POOL_RUNTIME_PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    fn ensure_cohort_active(&self, cohort_id: &str, epoch_index: u64) -> Result<()> {
        let cohort = self
            .sponsor_cohorts
            .get(cohort_id)
            .ok_or_else(|| "cohort missing".to_string())?;
        if cohort.status != CohortStatus::Active && cohort.status != CohortStatus::CarryForwardOnly
        {
            return Err("cohort not active".to_string());
        }
        if epoch_index < cohort.start_epoch
            || epoch_index
                > cohort
                    .end_epoch
                    .saturating_add(self.config.max_carry_epochs)
        {
            return Err("epoch outside cohort sponsorship window".to_string());
        }
        Ok(())
    }

    fn ensure_epoch_open(&self, epoch_index: u64) -> Result<()> {
        let open = self
            .fee_credit_epochs
            .values()
            .any(|epoch| epoch.epoch_index == epoch_index && epoch.status == EpochStatus::Open);
        if open {
            Ok(())
        } else {
            Err("fee credit epoch is not open".to_string())
        }
    }

    fn epoch_id_by_index(&self, epoch_index: u64) -> Result<String> {
        self.fee_credit_epochs
            .values()
            .find(|epoch| epoch.epoch_index == epoch_index)
            .map(|epoch| epoch.epoch_id.clone())
            .ok_or_else(|| "epoch missing".to_string())
    }

    fn apply_throttle(
        &mut self,
        scope: ThrottleScope,
        subject: &str,
        epoch_index: u64,
        height: u64,
        amount: u64,
    ) -> Result<()> {
        let subject_root = subject_to_root(scope, subject);
        let throttle_id = throttle_id(
            scope,
            &subject_root,
            epoch_index,
            height / self.config.throttle_window_blocks,
        );
        let (limit_count, limit_amount) = match scope {
            ThrottleScope::AccountNullifier => (
                self.config.account_nullifier_limit,
                amount.saturating_mul(self.config.account_nullifier_limit),
            ),
            ThrottleScope::DeviceCluster => (
                self.config.device_cluster_limit,
                amount.saturating_mul(self.config.device_cluster_limit),
            ),
            ThrottleScope::SponsorCohort => (u64::MAX / 2, self.config.cohort_spend_limit),
            ThrottleScope::Epoch => (u64::MAX / 2, self.config.global_spend_limit),
            ThrottleScope::Global => (u64::MAX / 2, self.config.global_spend_limit),
        };
        let window_start = height.saturating_sub(height % self.config.throttle_window_blocks);
        let window_end = window_start.saturating_add(self.config.throttle_window_blocks);
        let throttle = self
            .anti_abuse_throttles
            .entry(throttle_id.clone())
            .or_insert(AntiAbuseThrottle {
                throttle_id: throttle_id.clone(),
                scope,
                subject_root,
                epoch_index,
                window_start_height: window_start,
                window_end_height: window_end,
                usage_count: 0,
                sponsored_amount: 0,
                limit_count,
                limit_amount,
                blocked: false,
                last_hit_height: height,
            });
        throttle.usage_count = throttle.usage_count.saturating_add(1);
        throttle.sponsored_amount = throttle.sponsored_amount.saturating_add(amount);
        throttle.last_hit_height = height;
        throttle.blocked = throttle.usage_count > throttle.limit_count
            || throttle.sponsored_amount > throttle.limit_amount;
        if throttle.blocked {
            self.counters.total_throttle_hits = self.counters.total_throttle_hits.saturating_add(1);
            return Err("anti-abuse throttle exceeded".to_string());
        }
        self.counters.throttle_records = self.anti_abuse_throttles.len() as u64;
        Ok(())
    }

    fn credit_epoch_for_voucher(&mut self, voucher: &SettlementVoucher) {
        if let Some(epoch_id) = self
            .fee_credit_epochs
            .values()
            .find(|epoch| epoch.epoch_index == voucher.epoch_index)
            .map(|epoch| epoch.epoch_id.clone())
        {
            if let Some(epoch) = self.fee_credit_epochs.get_mut(&epoch_id) {
                epoch.sponsored_credit = epoch
                    .sponsored_credit
                    .saturating_add(voucher.sponsor_amount);
                epoch.user_fee_credit = epoch
                    .user_fee_credit
                    .saturating_add(voucher.user_fee_amount);
                epoch.rebate_credit = epoch.rebate_credit.saturating_add(voucher.rebate_amount);
            }
        }
    }

    fn distribute_rebate(
        &mut self,
        voucher: &SettlementVoucher,
        proof_root: &str,
        height: u64,
    ) -> Result<()> {
        if voucher.rebate_amount == 0 {
            return Ok(());
        }
        let sequence = self.counters.rebate_distributions.saturating_add(1);
        let rebate_id = rebate_distribution_id(voucher, proof_root, sequence);
        let rebate = RebateDistribution {
            rebate_id: rebate_id.clone(),
            cohort_id: voucher.cohort_id.clone(),
            epoch_index: voucher.epoch_index,
            voucher_root: value_root("REBATE-VOUCHER", &voucher.public_record()),
            recipient_commitment_root: voucher.fee_note_root.clone(),
            rebate_amount: voucher.rebate_amount,
            distribution_bps: if voucher.sponsor_amount == 0 {
                0
            } else {
                voucher.rebate_amount.saturating_mul(MAX_BPS) / voucher.sponsor_amount
            },
            proof_root: proof_root.to_string(),
            distributed_at_height: height,
        };
        self.counters.rebate_distributions = sequence;
        self.counters.total_rebates = self
            .counters
            .total_rebates
            .saturating_add(rebate.rebate_amount);
        self.rebate_distributions.insert(rebate_id, rebate);
        Ok(())
    }

    fn ensure_redaction_budget(&mut self, cohort_id: &str, epoch_index: u64, units: u64) {
        let budget_id = redaction_budget_id(cohort_id, epoch_index);
        self.redaction_budgets
            .entry(budget_id.clone())
            .or_insert(RedactionBudget {
                budget_id,
                cohort_id: cohort_id.to_string(),
                epoch_index,
                total_units: units.max(self.config.redaction_budget_per_epoch),
                spent_units: 0,
                carry_forward_units: units.max(self.config.redaction_budget_per_epoch),
                redacted_field_root: empty_root("REDACTED-FIELDS"),
                disclosure_policy_root: empty_root("DISCLOSURE-POLICY"),
            });
        self.counters.redaction_budgets = self.redaction_budgets.len() as u64;
    }

    fn emit_event(&mut self, event_kind: &str, subject_id: &str, payload: &Value, height: u64) {
        let sequence = self.counters.runtime_events.saturating_add(1);
        let event = RuntimeEvent::new(event_kind, subject_id, payload, height, sequence);
        self.runtime_events.push(event);
        self.counters.runtime_events = sequence;
        if self.runtime_events.len() > MAX_EVENTS {
            let drain = self.runtime_events.len().saturating_sub(MAX_EVENTS);
            self.runtime_events.drain(0..drain);
        }
    }

    fn recompute_roots(&mut self) {
        self.roots = Roots {
            sponsor_cohorts_root: map_root(
                "SPONSOR-COHORTS",
                self.sponsor_cohorts
                    .values()
                    .map(SponsorCohort::public_record),
            ),
            fee_credit_epochs_root: map_root(
                "FEE-CREDIT-EPOCHS",
                self.fee_credit_epochs
                    .values()
                    .map(FeeCreditEpoch::public_record),
            ),
            carry_forward_buckets_root: map_root(
                "CARRY-FORWARD-BUCKETS",
                self.carry_forward_buckets
                    .values()
                    .map(CarryForwardBucket::public_record),
            ),
            pq_sponsor_attestations_root: map_root(
                "PQ-SPONSOR-ATTESTATIONS",
                self.pq_sponsor_attestations
                    .values()
                    .map(PqSponsorAttestation::public_record),
            ),
            settlement_vouchers_root: map_root(
                "SETTLEMENT-VOUCHERS",
                self.settlement_vouchers
                    .values()
                    .map(SettlementVoucher::public_record),
            ),
            anti_abuse_throttles_root: map_root(
                "ANTI-ABUSE-THROTTLES",
                self.anti_abuse_throttles
                    .values()
                    .map(AntiAbuseThrottle::public_record),
            ),
            rebate_distributions_root: map_root(
                "REBATE-DISTRIBUTIONS",
                self.rebate_distributions
                    .values()
                    .map(RebateDistribution::public_record),
            ),
            redaction_budgets_root: map_root(
                "REDACTION-BUDGETS",
                self.redaction_budgets
                    .values()
                    .map(RedactionBudget::public_record),
            ),
            operator_summaries_root: map_root(
                "OPERATOR-SUMMARIES",
                self.operator_summaries
                    .values()
                    .map(OperatorSummary::public_record),
            ),
            spent_nullifiers_root: id_list_root(
                "SPENT-NULLIFIERS",
                &self.spent_nullifiers.iter().cloned().collect::<Vec<_>>(),
            ),
            runtime_events_root: map_root(
                "RUNTIME-EVENTS",
                self.runtime_events.iter().map(RuntimeEvent::public_record),
            ),
        };
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

pub fn sponsor_cohort_id(request: &RegisterSponsorCohortRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-SPONSOR-COHORT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.label),
            HashPart::Str(request.kind.as_str()),
            HashPart::Str(&request.sponsor_commitment_root),
            HashPart::Str(&request.pq_public_key_root),
            HashPart::U64(request.start_epoch),
            HashPart::U64(sequence),
        ],
        HASH_BYTES,
    )
}

pub fn fee_credit_epoch_id(epoch_index: u64, start_height: u64, cohort_root: &str) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-FEE-CREDIT-EPOCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(epoch_index),
            HashPart::U64(start_height),
            HashPart::Str(cohort_root),
        ],
        HASH_BYTES,
    )
}

pub fn pq_attestation_id(request: &SubmitPqAttestationRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-SPONSOR-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.cohort_id),
            HashPart::U64(request.epoch_index),
            HashPart::Str(&request.sponsor_key_root),
            HashPart::Str(&request.pq_signature_root),
            HashPart::U64(sequence),
        ],
        HASH_BYTES,
    )
}

pub fn settlement_voucher_id(request: &ReserveVoucherRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-SETTLEMENT-VOUCHER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.cohort_id),
            HashPart::U64(request.epoch_index),
            HashPart::Str(&request.account_nullifier_root),
            HashPart::Str(&request.fee_note_root),
            HashPart::U64(request.sponsor_amount),
            HashPart::U64(sequence),
        ],
        HASH_BYTES,
    )
}

pub fn carry_forward_bucket_id(request: &CarryForwardRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CARRY-FORWARD-BUCKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.cohort_id),
            HashPart::U64(request.from_epoch),
            HashPart::U64(request.to_epoch),
            HashPart::U64(request.amount),
            HashPart::Str(&request.nullifier_set_root),
            HashPart::U64(sequence),
        ],
        HASH_BYTES,
    )
}

pub fn redaction_budget_id(cohort_id: &str, epoch_index: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-REDACTION-BUDGET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(cohort_id),
            HashPart::U64(epoch_index),
        ],
        HASH_BYTES,
    )
}

pub fn throttle_id(
    scope: ThrottleScope,
    subject_root: &str,
    epoch_index: u64,
    window_index: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-ANTI-ABUSE-THROTTLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scope.as_str()),
            HashPart::Str(subject_root),
            HashPart::U64(epoch_index),
            HashPart::U64(window_index),
        ],
        HASH_BYTES,
    )
}

pub fn rebate_distribution_id(
    voucher: &SettlementVoucher,
    proof_root: &str,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-REBATE-DISTRIBUTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&voucher.voucher_id),
            HashPart::Str(proof_root),
            HashPart::U64(voucher.rebate_amount),
            HashPart::U64(sequence),
        ],
        HASH_BYTES,
    )
}

pub fn operator_summary_id(epoch_index: u64, operator_key_root: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-OPERATOR-SUMMARY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(epoch_index),
            HashPart::Str(operator_key_root),
            HashPart::U64(sequence),
        ],
        HASH_BYTES,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    value_root(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-CROSS-EPOCH-FEE-SPONSOR-POOL-STATE",
        record,
    )
}

fn require_nonempty(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{name} is empty"))
    } else {
        Ok(())
    }
}

fn require_root(name: &str, value: &str) -> Result<()> {
    require_nonempty(name, value)?;
    if value.len() < 16 {
        Err(format!("{name} is too short"))
    } else {
        Ok(())
    }
}

fn require_range(name: &str, value: u64, min: u64, max: u64) -> Result<()> {
    if value < min || value > max {
        Err(format!("{name} outside allowed range"))
    } else {
        Ok(())
    }
}

fn mul_bps(amount: u64, bps: u64) -> u64 {
    amount.saturating_mul(bps) / MAX_BPS
}

fn subject_to_root(scope: ThrottleScope, subject: &str) -> String {
    if subject.len() >= 16 && subject.chars().all(|c| c.is_ascii_hexdigit()) {
        subject.to_string()
    } else {
        domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-THROTTLE-SUBJECT-ROOT",
            &[HashPart::Str(scope.as_str()), HashPart::Str(subject)],
            HASH_BYTES,
        )
    }
}

fn sample_root(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-DEVNET-SAMPLE-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        HASH_BYTES,
    )
}

fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

fn value_root(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(&crate::hash::canonical_json_string(value))],
        HASH_BYTES,
    )
}

fn map_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let mut leaves = records
        .into_iter()
        .map(|record| Value::String(value_root(domain, &record)))
        .collect::<Vec<_>>();
    leaves.sort_by_key(crate::hash::canonical_json_string);
    merkle_root(domain, &leaves)
}

fn id_list_root(domain: &str, ids: &[String]) -> String {
    let mut leaves = ids
        .iter()
        .map(|id| Value::String(domain_hash(domain, &[HashPart::Str(id)], HASH_BYTES)))
        .collect::<Vec<_>>();
    leaves.sort_by_key(crate::hash::canonical_json_string);
    merkle_root(domain, &leaves)
}
