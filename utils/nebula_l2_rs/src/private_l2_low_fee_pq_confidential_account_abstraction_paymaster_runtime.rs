use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2LowFeePqConfidentialAccountAbstractionPaymasterRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_PAYMASTER_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-low-fee-pq-confidential-account-abstraction-paymaster-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_PAYMASTER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_SESSION_POLICY_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-aa-paymaster-policy-v1";
pub const ENCRYPTED_SPONSORSHIP_TICKET_SUITE: &str =
    "private-l2-low-fee-encrypted-aa-sponsorship-ticket-v1";
pub const FEE_COUPON_SUITE: &str = "private-l2-low-fee-confidential-aa-fee-coupon-v1";
pub const GAS_SPONSORSHIP_BATCH_SUITE: &str =
    "private-l2-low-fee-batched-confidential-gas-sponsorship-v1";
pub const PRIVACY_REDACTION_BUDGET_SUITE: &str =
    "private-l2-confidential-aa-redaction-budget-root-v1";
pub const ABUSE_QUARANTINE_SUITE: &str =
    "private-l2-confidential-aa-paymaster-abuse-quarantine-root-v1";
pub const PUBLIC_RECORD_SUITE: &str = "roots-only-deterministic-public-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_252_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_944_000;
pub const DEVNET_EPOCH: u64 = 12_018;
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_COUPON_ASSET_ID: &str = "aa-fee-coupon-devnet";
pub const DEFAULT_SPONSOR_CREDIT_ASSET_ID: &str = "confidential-sponsor-credit-devnet";
pub const DEFAULT_MAX_PAYMASTER_FEE_BPS: u64 = 12;
pub const DEFAULT_TARGET_DISCOUNT_BPS: u64 = 35;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_BATCH_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TICKET_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_POLICY_ATTESTATION_TTL_BLOCKS: u64 = 192;
pub const DEFAULT_COUPON_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_BATCH_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_QUARANTINE_TTL_BLOCKS: u64 = 17_280;
pub const DEFAULT_REDACTION_BUDGET_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_REDACTIONS_PER_WINDOW: u64 = 24;
pub const DEFAULT_MAX_TICKETS_PER_BATCH: usize = 4_096;
pub const DEFAULT_MAX_GAS_PER_BATCH: u64 = 80_000_000;
pub const DEFAULT_MAX_SPONSORED_GAS_PER_ACCOUNT: u64 = 4_000_000;
pub const DEFAULT_ABUSE_SCORE_THRESHOLD: u64 = 70;
pub const DEFAULT_QUARANTINE_SCORE_THRESHOLD: u64 = 90;
pub const MAX_PAYMASTERS: usize = 1_048_576;
pub const MAX_SESSION_POLICY_ATTESTATIONS: usize = 8_388_608;
pub const MAX_SPONSORSHIP_TICKETS: usize = 8_388_608;
pub const MAX_FEE_COUPONS: usize = 8_388_608;
pub const MAX_GAS_BATCHES: usize = 4_194_304;
pub const MAX_REDACTION_BUDGETS: usize = 2_097_152;
pub const MAX_QUARANTINE_CASES: usize = 2_097_152;
pub const MAX_PUBLIC_EVENTS: usize = 16_777_216;
pub const MAX_BPS: u64 = 10_000;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymasterLane {
    WalletTransfer,
    ContractCall,
    DefiIntent,
    BridgeExit,
    RecoverySession,
    GovernanceVote,
    BlobData,
    EmergencyEscape,
}

impl PaymasterLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletTransfer => "wallet_transfer",
            Self::ContractCall => "contract_call",
            Self::DefiIntent => "defi_intent",
            Self::BridgeExit => "bridge_exit",
            Self::RecoverySession => "recovery_session",
            Self::GovernanceVote => "governance_vote",
            Self::BlobData => "blob_data",
            Self::EmergencyEscape => "emergency_escape",
        }
    }

    pub fn gas_weight(self) -> u64 {
        match self {
            Self::WalletTransfer => 2,
            Self::ContractCall => 5,
            Self::DefiIntent => 8,
            Self::BridgeExit => 9,
            Self::RecoverySession => 6,
            Self::GovernanceVote => 3,
            Self::BlobData => 7,
            Self::EmergencyEscape => 10,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymasterStatus {
    Registered,
    Active,
    Sponsoring,
    BudgetConstrained,
    RedactionLimited,
    Quarantined,
    Paused,
    Retired,
    Slashed,
}

impl PaymasterStatus {
    pub fn usable(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Sponsoring | Self::BudgetConstrained
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    Sealed,
    PolicyAttested,
    CouponReserved,
    BatchQueued,
    Sponsored,
    Redeemed,
    Expired,
    Rejected,
    Quarantined,
}

impl TicketStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::PolicyAttested | Self::CouponReserved | Self::BatchQueued
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAttestationKind {
    SpendLimit,
    GasLimit,
    ContractAllowlist,
    SelectorAllowlist,
    SessionKeyScope,
    PaymasterBudget,
    RecoveryOnly,
    EmergencyEscape,
}

impl PolicyAttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SpendLimit => "spend_limit",
            Self::GasLimit => "gas_limit",
            Self::ContractAllowlist => "contract_allowlist",
            Self::SelectorAllowlist => "selector_allowlist",
            Self::SessionKeyScope => "session_key_scope",
            Self::PaymasterBudget => "paymaster_budget",
            Self::RecoveryOnly => "recovery_only",
            Self::EmergencyEscape => "emergency_escape",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    Submitted,
    Verified,
    Linked,
    Consumed,
    Expired,
    Rejected,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Minted,
    Reserved,
    Applied,
    Refunded,
    Expired,
    Quarantined,
}

impl CouponStatus {
    pub fn spendable(self) -> bool {
        matches!(self, Self::Minted | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GasBatchStatus {
    Open,
    Sealed,
    Submitted,
    Settled,
    PartiallyRejected,
    Quarantined,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionClass {
    AccountId,
    ContractAddress,
    Selector,
    Amount,
    GasLimit,
    Nullifier,
    SessionScope,
    AbuseSignal,
}

impl RedactionClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AccountId => "account_id",
            Self::ContractAddress => "contract_address",
            Self::Selector => "selector",
            Self::Amount => "amount",
            Self::GasLimit => "gas_limit",
            Self::Nullifier => "nullifier",
            Self::SessionScope => "session_scope",
            Self::AbuseSignal => "abuse_signal",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    PolicyMismatch,
    CouponDoubleSpend,
    TicketReplay,
    GasOutlier,
    RedactionBudgetExceeded,
    PqAttestationFailure,
    SponsorLiquidityFailure,
    OperatorReport,
}

impl QuarantineReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PolicyMismatch => "policy_mismatch",
            Self::CouponDoubleSpend => "coupon_double_spend",
            Self::TicketReplay => "ticket_replay",
            Self::GasOutlier => "gas_outlier",
            Self::RedactionBudgetExceeded => "redaction_budget_exceeded",
            Self::PqAttestationFailure => "pq_attestation_failure",
            Self::SponsorLiquidityFailure => "sponsor_liquidity_failure",
            Self::OperatorReport => "operator_report",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub fee_asset_id: String,
    pub coupon_asset_id: String,
    pub sponsor_credit_asset_id: String,
    pub max_paymaster_fee_bps: u64,
    pub target_discount_bps: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub min_batch_privacy_set_size: u64,
    pub ticket_ttl_blocks: u64,
    pub policy_attestation_ttl_blocks: u64,
    pub coupon_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub quarantine_ttl_blocks: u64,
    pub redaction_budget_window_blocks: u64,
    pub max_redactions_per_window: u64,
    pub max_tickets_per_batch: usize,
    pub max_gas_per_batch: u64,
    pub max_sponsored_gas_per_account: u64,
    pub abuse_score_threshold: u64,
    pub quarantine_score_threshold: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            epoch: DEVNET_EPOCH,
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            coupon_asset_id: DEFAULT_COUPON_ASSET_ID.to_string(),
            sponsor_credit_asset_id: DEFAULT_SPONSOR_CREDIT_ASSET_ID.to_string(),
            max_paymaster_fee_bps: DEFAULT_MAX_PAYMASTER_FEE_BPS,
            target_discount_bps: DEFAULT_TARGET_DISCOUNT_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_batch_privacy_set_size: DEFAULT_MIN_BATCH_PRIVACY_SET_SIZE,
            ticket_ttl_blocks: DEFAULT_TICKET_TTL_BLOCKS,
            policy_attestation_ttl_blocks: DEFAULT_POLICY_ATTESTATION_TTL_BLOCKS,
            coupon_ttl_blocks: DEFAULT_COUPON_TTL_BLOCKS,
            batch_ttl_blocks: DEFAULT_BATCH_TTL_BLOCKS,
            quarantine_ttl_blocks: DEFAULT_QUARANTINE_TTL_BLOCKS,
            redaction_budget_window_blocks: DEFAULT_REDACTION_BUDGET_WINDOW_BLOCKS,
            max_redactions_per_window: DEFAULT_MAX_REDACTIONS_PER_WINDOW,
            max_tickets_per_batch: DEFAULT_MAX_TICKETS_PER_BATCH,
            max_gas_per_batch: DEFAULT_MAX_GAS_PER_BATCH,
            max_sponsored_gas_per_account: DEFAULT_MAX_SPONSORED_GAS_PER_ACCOUNT,
            abuse_score_threshold: DEFAULT_ABUSE_SCORE_THRESHOLD,
            quarantine_score_threshold: DEFAULT_QUARANTINE_SCORE_THRESHOLD,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
            "fee_asset_id": self.fee_asset_id,
            "coupon_asset_id": self.coupon_asset_id,
            "sponsor_credit_asset_id": self.sponsor_credit_asset_id,
            "max_paymaster_fee_bps": self.max_paymaster_fee_bps,
            "target_discount_bps": self.target_discount_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_batch_privacy_set_size": self.min_batch_privacy_set_size,
            "ticket_ttl_blocks": self.ticket_ttl_blocks,
            "policy_attestation_ttl_blocks": self.policy_attestation_ttl_blocks,
            "coupon_ttl_blocks": self.coupon_ttl_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "quarantine_ttl_blocks": self.quarantine_ttl_blocks,
            "redaction_budget_window_blocks": self.redaction_budget_window_blocks,
            "max_redactions_per_window": self.max_redactions_per_window,
            "max_tickets_per_batch": self.max_tickets_per_batch,
            "max_gas_per_batch": self.max_gas_per_batch,
            "max_sponsored_gas_per_account": self.max_sponsored_gas_per_account,
            "abuse_score_threshold": self.abuse_score_threshold,
            "quarantine_score_threshold": self.quarantine_score_threshold,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub paymasters_registered: u64,
    pub policy_attestations_submitted: u64,
    pub policy_attestations_verified: u64,
    pub encrypted_tickets_opened: u64,
    pub tickets_attested: u64,
    pub tickets_queued: u64,
    pub tickets_sponsored: u64,
    pub fee_coupons_minted: u64,
    pub fee_coupons_applied: u64,
    pub gas_batches_opened: u64,
    pub gas_batches_settled: u64,
    pub redaction_budgets_registered: u64,
    pub redactions_spent: u64,
    pub quarantine_cases_opened: u64,
    pub quarantine_cases_released: u64,
    pub sponsored_gas_units: u64,
    pub sponsor_fee_piconero: u64,
    pub public_events_emitted: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "paymasters_registered": self.paymasters_registered,
            "policy_attestations_submitted": self.policy_attestations_submitted,
            "policy_attestations_verified": self.policy_attestations_verified,
            "encrypted_tickets_opened": self.encrypted_tickets_opened,
            "tickets_attested": self.tickets_attested,
            "tickets_queued": self.tickets_queued,
            "tickets_sponsored": self.tickets_sponsored,
            "fee_coupons_minted": self.fee_coupons_minted,
            "fee_coupons_applied": self.fee_coupons_applied,
            "gas_batches_opened": self.gas_batches_opened,
            "gas_batches_settled": self.gas_batches_settled,
            "redaction_budgets_registered": self.redaction_budgets_registered,
            "redactions_spent": self.redactions_spent,
            "quarantine_cases_opened": self.quarantine_cases_opened,
            "quarantine_cases_released": self.quarantine_cases_released,
            "sponsored_gas_units": self.sponsored_gas_units,
            "sponsor_fee_piconero": self.sponsor_fee_piconero,
            "public_events_emitted": self.public_events_emitted,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub paymasters_root: String,
    pub session_policy_attestations_root: String,
    pub encrypted_sponsorship_tickets_root: String,
    pub fee_coupons_root: String,
    pub gas_sponsorship_batches_root: String,
    pub privacy_redaction_budgets_root: String,
    pub abuse_quarantine_root: String,
    pub lane_index_root: String,
    pub account_index_root: String,
    pub nullifier_root: String,
    pub deterministic_public_events_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "paymasters_root": self.paymasters_root,
            "session_policy_attestations_root": self.session_policy_attestations_root,
            "encrypted_sponsorship_tickets_root": self.encrypted_sponsorship_tickets_root,
            "fee_coupons_root": self.fee_coupons_root,
            "gas_sponsorship_batches_root": self.gas_sponsorship_batches_root,
            "privacy_redaction_budgets_root": self.privacy_redaction_budgets_root,
            "abuse_quarantine_root": self.abuse_quarantine_root,
            "lane_index_root": self.lane_index_root,
            "account_index_root": self.account_index_root,
            "nullifier_root": self.nullifier_root,
            "deterministic_public_events_root": self.deterministic_public_events_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Paymaster {
    pub paymaster_id: String,
    pub operator_commitment: String,
    pub spend_authority_root: String,
    pub liquidity_commitment: String,
    pub status: PaymasterStatus,
    pub lanes: BTreeSet<PaymasterLane>,
    pub available_gas_units: u64,
    pub available_fee_piconero: u64,
    pub max_fee_bps: u64,
    pub discount_bps: u64,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub policy_root: String,
    pub redaction_budget_id: String,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
}

impl Paymaster {
    pub fn public_record(&self) -> Value {
        json!({
            "paymaster_id": self.paymaster_id,
            "operator_commitment": self.operator_commitment,
            "spend_authority_root": self.spend_authority_root,
            "liquidity_commitment": self.liquidity_commitment,
            "status": self.status,
            "lanes": self.lanes,
            "available_gas_units": self.available_gas_units,
            "available_fee_piconero": self.available_fee_piconero,
            "max_fee_bps": self.max_fee_bps,
            "discount_bps": self.discount_bps,
            "pq_security_bits": self.pq_security_bits,
            "privacy_set_size": self.privacy_set_size,
            "policy_root": self.policy_root,
            "redaction_budget_id": self.redaction_budget_id,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SessionPolicyAttestation {
    pub attestation_id: String,
    pub account_commitment: String,
    pub session_key_commitment: String,
    pub paymaster_id: String,
    pub kind: PolicyAttestationKind,
    pub status: PolicyStatus,
    pub lane: PaymasterLane,
    pub policy_root: String,
    pub allowed_contracts_root: String,
    pub allowed_selectors_root: String,
    pub max_gas_units: u64,
    pub max_fee_piconero: u64,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub issued_height: u64,
    pub expires_height: u64,
    pub attestation_nullifier: String,
}

impl SessionPolicyAttestation {
    pub fn live(&self, height: u64) -> bool {
        matches!(
            self.status,
            PolicyStatus::Submitted | PolicyStatus::Verified | PolicyStatus::Linked
        ) && height <= self.expires_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "account_commitment": self.account_commitment,
            "session_key_commitment": self.session_key_commitment,
            "paymaster_id": self.paymaster_id,
            "kind": self.kind,
            "status": self.status,
            "lane": self.lane,
            "policy_root": self.policy_root,
            "allowed_contracts_root": self.allowed_contracts_root,
            "allowed_selectors_root": self.allowed_selectors_root,
            "max_gas_units": self.max_gas_units,
            "max_fee_piconero": self.max_fee_piconero,
            "pq_security_bits": self.pq_security_bits,
            "privacy_set_size": self.privacy_set_size,
            "issued_height": self.issued_height,
            "expires_height": self.expires_height,
            "attestation_nullifier": self.attestation_nullifier,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptedSponsorshipTicket {
    pub ticket_id: String,
    pub account_commitment: String,
    pub paymaster_id: String,
    pub attestation_id: String,
    pub coupon_id: String,
    pub lane: PaymasterLane,
    pub status: TicketStatus,
    pub encrypted_call_bundle_root: String,
    pub encrypted_witness_root: String,
    pub gas_limit: u64,
    pub max_fee_piconero: u64,
    pub sponsor_fee_bps: u64,
    pub privacy_set_size: u64,
    pub ticket_nullifier: String,
    pub issued_height: u64,
    pub expires_height: u64,
}

impl EncryptedSponsorshipTicket {
    pub fn public_record(&self) -> Value {
        json!({
            "ticket_id": self.ticket_id,
            "account_commitment": self.account_commitment,
            "paymaster_id": self.paymaster_id,
            "attestation_id": self.attestation_id,
            "coupon_id": self.coupon_id,
            "lane": self.lane,
            "status": self.status,
            "encrypted_call_bundle_root": self.encrypted_call_bundle_root,
            "encrypted_witness_root": self.encrypted_witness_root,
            "gas_limit": self.gas_limit,
            "max_fee_piconero": self.max_fee_piconero,
            "sponsor_fee_bps": self.sponsor_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "ticket_nullifier": self.ticket_nullifier,
            "issued_height": self.issued_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeCoupon {
    pub coupon_id: String,
    pub paymaster_id: String,
    pub account_commitment: String,
    pub status: CouponStatus,
    pub coupon_commitment: String,
    pub coupon_nullifier: String,
    pub face_value_piconero: u64,
    pub discount_bps: u64,
    pub lane: PaymasterLane,
    pub issued_height: u64,
    pub expires_height: u64,
}

impl FeeCoupon {
    pub fn public_record(&self) -> Value {
        json!({
            "coupon_id": self.coupon_id,
            "paymaster_id": self.paymaster_id,
            "account_commitment": self.account_commitment,
            "status": self.status,
            "coupon_commitment": self.coupon_commitment,
            "coupon_nullifier": self.coupon_nullifier,
            "face_value_piconero": self.face_value_piconero,
            "discount_bps": self.discount_bps,
            "lane": self.lane,
            "issued_height": self.issued_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GasSponsorshipBatch {
    pub batch_id: String,
    pub paymaster_id: String,
    pub lane: PaymasterLane,
    pub status: GasBatchStatus,
    pub ticket_ids: Vec<String>,
    pub tickets_root: String,
    pub batched_call_root: String,
    pub aggregate_policy_root: String,
    pub total_gas_limit: u64,
    pub total_fee_piconero: u64,
    pub privacy_set_size: u64,
    pub opened_height: u64,
    pub expires_height: u64,
    pub settlement_receipt_root: String,
}

impl GasSponsorshipBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "paymaster_id": self.paymaster_id,
            "lane": self.lane,
            "status": self.status,
            "ticket_ids": self.ticket_ids,
            "tickets_root": self.tickets_root,
            "batched_call_root": self.batched_call_root,
            "aggregate_policy_root": self.aggregate_policy_root,
            "total_gas_limit": self.total_gas_limit,
            "total_fee_piconero": self.total_fee_piconero,
            "privacy_set_size": self.privacy_set_size,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "settlement_receipt_root": self.settlement_receipt_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub paymaster_id: String,
    pub account_commitment: String,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub max_redactions: u64,
    pub spent_redactions: u64,
    pub classes: BTreeSet<RedactionClass>,
    pub redacted_fields_root: String,
    pub disclosure_guard_root: String,
}

impl PrivacyRedactionBudget {
    pub fn available(&self) -> u64 {
        self.max_redactions.saturating_sub(self.spent_redactions)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "paymaster_id": self.paymaster_id,
            "account_commitment": self.account_commitment,
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "max_redactions": self.max_redactions,
            "spent_redactions": self.spent_redactions,
            "classes": self.classes,
            "redacted_fields_root": self.redacted_fields_root,
            "disclosure_guard_root": self.disclosure_guard_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AbuseQuarantineCase {
    pub case_id: String,
    pub subject_commitment: String,
    pub paymaster_id: String,
    pub ticket_id: String,
    pub reason: QuarantineReason,
    pub abuse_score: u64,
    pub evidence_root: String,
    pub status: String,
    pub opened_height: u64,
    pub release_height: u64,
}

impl AbuseQuarantineCase {
    pub fn public_record(&self) -> Value {
        json!({
            "case_id": self.case_id,
            "subject_commitment": self.subject_commitment,
            "paymaster_id": self.paymaster_id,
            "ticket_id": self.ticket_id,
            "reason": self.reason,
            "abuse_score": self.abuse_score,
            "evidence_root": self.evidence_root,
            "status": self.status,
            "opened_height": self.opened_height,
            "release_height": self.release_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub paymasters: BTreeMap<String, Paymaster>,
    pub session_policy_attestations: BTreeMap<String, SessionPolicyAttestation>,
    pub encrypted_sponsorship_tickets: BTreeMap<String, EncryptedSponsorshipTicket>,
    pub fee_coupons: BTreeMap<String, FeeCoupon>,
    pub gas_sponsorship_batches: BTreeMap<String, GasSponsorshipBatch>,
    pub privacy_redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub abuse_quarantine_cases: BTreeMap<String, AbuseQuarantineCase>,
    pub paymasters_by_lane: BTreeMap<PaymasterLane, BTreeSet<String>>,
    pub tickets_by_account: BTreeMap<String, BTreeSet<String>>,
    pub tickets_by_paymaster: BTreeMap<String, BTreeSet<String>>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub deterministic_public_events: Vec<Value>,
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            paymasters: BTreeMap::new(),
            session_policy_attestations: BTreeMap::new(),
            encrypted_sponsorship_tickets: BTreeMap::new(),
            fee_coupons: BTreeMap::new(),
            gas_sponsorship_batches: BTreeMap::new(),
            privacy_redaction_budgets: BTreeMap::new(),
            abuse_quarantine_cases: BTreeMap::new(),
            paymasters_by_lane: BTreeMap::new(),
            tickets_by_account: BTreeMap::new(),
            tickets_by_paymaster: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            deterministic_public_events: Vec::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        seed_devnet(&mut state);
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let ticket_id = sponsorship_ticket_id(
            "acct:demo:second-session",
            "pm:demo:recovery",
            PaymasterLane::RecoverySession,
            3,
        );
        let attestation_id = session_policy_attestation_id(
            "acct:demo:second-session",
            "session-key:demo:recovery",
            PolicyAttestationKind::RecoveryOnly,
            3,
        );
        let coupon_id = fee_coupon_id("pm:demo:recovery", "acct:demo:second-session", 3);
        let _ = state.submit_policy_attestation(SessionPolicyAttestation {
            attestation_id: attestation_id.clone(),
            account_commitment: "acct:demo:second-session".to_string(),
            session_key_commitment: "session-key:demo:recovery".to_string(),
            paymaster_id: "pm:demo:recovery".to_string(),
            kind: PolicyAttestationKind::RecoveryOnly,
            status: PolicyStatus::Submitted,
            lane: PaymasterLane::RecoverySession,
            policy_root: record_root("DEMO-RECOVERY-POLICY", &json!({"scope": "recovery"})),
            allowed_contracts_root: record_root("DEMO-RECOVERY-CONTRACTS", &json!(["recovery"])),
            allowed_selectors_root: record_root("DEMO-RECOVERY-SELECTORS", &json!(["rotate"])),
            max_gas_units: 1_400_000,
            max_fee_piconero: 42_000,
            pq_security_bits: 256,
            privacy_set_size: 262_144,
            issued_height: DEVNET_L2_HEIGHT,
            expires_height: DEVNET_L2_HEIGHT + DEFAULT_POLICY_ATTESTATION_TTL_BLOCKS,
            attestation_nullifier: nullifier("policy", &attestation_id),
        });
        let _ = state.verify_policy_attestation(&attestation_id);
        let _ = state.mint_fee_coupon(FeeCoupon {
            coupon_id: coupon_id.clone(),
            paymaster_id: "pm:demo:recovery".to_string(),
            account_commitment: "acct:demo:second-session".to_string(),
            status: CouponStatus::Minted,
            coupon_commitment: record_root("DEMO-RECOVERY-COUPON", &json!({"face": 42_000})),
            coupon_nullifier: nullifier("coupon", &coupon_id),
            face_value_piconero: 42_000,
            discount_bps: 40,
            lane: PaymasterLane::RecoverySession,
            issued_height: DEVNET_L2_HEIGHT,
            expires_height: DEVNET_L2_HEIGHT + DEFAULT_COUPON_TTL_BLOCKS,
        });
        let _ = state.open_sponsorship_ticket(EncryptedSponsorshipTicket {
            ticket_id: ticket_id.clone(),
            account_commitment: "acct:demo:second-session".to_string(),
            paymaster_id: "pm:demo:recovery".to_string(),
            attestation_id,
            coupon_id,
            lane: PaymasterLane::RecoverySession,
            status: TicketStatus::Sealed,
            encrypted_call_bundle_root: record_root(
                "DEMO-RECOVERY-CALL",
                &json!({"redacted": true}),
            ),
            encrypted_witness_root: record_root("DEMO-RECOVERY-WITNESS", &json!({"pq": true})),
            gas_limit: 1_200_000,
            max_fee_piconero: 36_000,
            sponsor_fee_bps: 8,
            privacy_set_size: 262_144,
            ticket_nullifier: nullifier("ticket", &ticket_id),
            issued_height: DEVNET_L2_HEIGHT,
            expires_height: DEVNET_L2_HEIGHT + DEFAULT_TICKET_TTL_BLOCKS,
        });
        let _ = state.attest_ticket_policy(&ticket_id);
        let _ = state.reserve_coupon_for_ticket(&ticket_id);
        let batch_id =
            gas_sponsorship_batch_id("pm:demo:recovery", PaymasterLane::RecoverySession, 2);
        let _ = state.open_gas_sponsorship_batch(
            batch_id.clone(),
            "pm:demo:recovery",
            PaymasterLane::RecoverySession,
            vec![ticket_id],
        );
        let _ = state.settle_gas_sponsorship_batch(&batch_id);
        state
    }

    pub fn register_paymaster(
        &mut self,
        paymaster: Paymaster,
    ) -> PrivateL2LowFeePqConfidentialAccountAbstractionPaymasterRuntimeResult<String> {
        ensure!(
            self.paymasters.len() < MAX_PAYMASTERS,
            "paymaster capacity exhausted"
        );
        ensure!(
            paymaster.max_fee_bps <= MAX_BPS,
            "paymaster fee exceeds bps ceiling"
        );
        ensure!(
            paymaster.max_fee_bps <= self.config.max_paymaster_fee_bps,
            "paymaster fee exceeds runtime maximum"
        );
        ensure!(
            paymaster.discount_bps <= MAX_BPS,
            "paymaster discount exceeds bps ceiling"
        );
        ensure!(
            paymaster.pq_security_bits >= self.config.min_pq_security_bits,
            "paymaster pq security below runtime minimum"
        );
        ensure!(
            paymaster.privacy_set_size >= self.config.min_privacy_set_size,
            "paymaster privacy set below runtime minimum"
        );
        ensure!(
            !paymaster.lanes.is_empty(),
            "paymaster must sponsor at least one lane"
        );
        let paymaster_id = paymaster.paymaster_id.clone();
        for lane in &paymaster.lanes {
            self.paymasters_by_lane
                .entry(*lane)
                .or_default()
                .insert(paymaster_id.clone());
        }
        self.paymasters.insert(paymaster_id.clone(), paymaster);
        self.counters.paymasters_registered = self.counters.paymasters_registered.saturating_add(1);
        self.emit_event("paymaster_registered", &paymaster_id);
        self.refresh_roots();
        Ok(paymaster_id)
    }

    pub fn register_redaction_budget(
        &mut self,
        budget: PrivacyRedactionBudget,
    ) -> PrivateL2LowFeePqConfidentialAccountAbstractionPaymasterRuntimeResult<String> {
        ensure!(
            self.privacy_redaction_budgets.len() < MAX_REDACTION_BUDGETS,
            "privacy redaction budget capacity exhausted"
        );
        ensure!(
            self.paymasters.contains_key(&budget.paymaster_id),
            "redaction budget references unknown paymaster"
        );
        ensure!(
            budget.max_redactions <= self.config.max_redactions_per_window,
            "redaction budget exceeds runtime window maximum"
        );
        let budget_id = budget.budget_id.clone();
        self.privacy_redaction_budgets
            .insert(budget_id.clone(), budget);
        self.counters.redaction_budgets_registered =
            self.counters.redaction_budgets_registered.saturating_add(1);
        self.emit_event("redaction_budget_registered", &budget_id);
        self.refresh_roots();
        Ok(budget_id)
    }

    pub fn submit_policy_attestation(
        &mut self,
        attestation: SessionPolicyAttestation,
    ) -> PrivateL2LowFeePqConfidentialAccountAbstractionPaymasterRuntimeResult<String> {
        ensure!(
            self.session_policy_attestations.len() < MAX_SESSION_POLICY_ATTESTATIONS,
            "policy attestation capacity exhausted"
        );
        let paymaster = self
            .paymasters
            .get(&attestation.paymaster_id)
            .ok_or_else(|| "policy attestation references unknown paymaster".to_string())?;
        ensure!(paymaster.status.usable(), "paymaster is not usable");
        ensure!(
            paymaster.lanes.contains(&attestation.lane),
            "paymaster does not serve lane"
        );
        ensure!(
            attestation.pq_security_bits >= self.config.min_pq_security_bits,
            "policy attestation pq security below runtime minimum"
        );
        ensure!(
            attestation.privacy_set_size >= self.config.min_privacy_set_size,
            "policy attestation privacy set below runtime minimum"
        );
        ensure!(
            attestation.max_gas_units <= self.config.max_sponsored_gas_per_account,
            "policy attestation gas exceeds account ceiling"
        );
        let attestation_id = attestation.attestation_id.clone();
        self.consumed_nullifiers
            .insert(attestation.attestation_nullifier.clone());
        self.session_policy_attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.policy_attestations_submitted = self
            .counters
            .policy_attestations_submitted
            .saturating_add(1);
        self.emit_event("policy_attestation_submitted", &attestation_id);
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn verify_policy_attestation(
        &mut self,
        attestation_id: &str,
    ) -> PrivateL2LowFeePqConfidentialAccountAbstractionPaymasterRuntimeResult<String> {
        let attestation = self
            .session_policy_attestations
            .get_mut(attestation_id)
            .ok_or_else(|| "unknown policy attestation".to_string())?;
        ensure!(
            attestation.live(self.config.l2_height),
            "policy attestation is not live"
        );
        attestation.status = PolicyStatus::Verified;
        self.counters.policy_attestations_verified =
            self.counters.policy_attestations_verified.saturating_add(1);
        let receipt_id = domain_hash(
            domain("POLICY-ATTESTATION-VERIFIED").as_str(),
            &[
                HashPart::Str(attestation_id),
                HashPart::U64(self.counters.policy_attestations_verified),
            ],
            32,
        );
        self.emit_event("policy_attestation_verified", attestation_id);
        self.refresh_roots();
        Ok(receipt_id)
    }

    pub fn mint_fee_coupon(
        &mut self,
        coupon: FeeCoupon,
    ) -> PrivateL2LowFeePqConfidentialAccountAbstractionPaymasterRuntimeResult<String> {
        ensure!(
            self.fee_coupons.len() < MAX_FEE_COUPONS,
            "fee coupon capacity exhausted"
        );
        let paymaster = self
            .paymasters
            .get(&coupon.paymaster_id)
            .ok_or_else(|| "coupon references unknown paymaster".to_string())?;
        ensure!(
            paymaster.lanes.contains(&coupon.lane),
            "coupon lane not served by paymaster"
        );
        ensure!(
            coupon.discount_bps >= self.config.target_discount_bps,
            "coupon discount below runtime target"
        );
        let coupon_id = coupon.coupon_id.clone();
        self.consumed_nullifiers
            .insert(coupon.coupon_nullifier.clone());
        self.fee_coupons.insert(coupon_id.clone(), coupon);
        self.counters.fee_coupons_minted = self.counters.fee_coupons_minted.saturating_add(1);
        self.emit_event("fee_coupon_minted", &coupon_id);
        self.refresh_roots();
        Ok(coupon_id)
    }

    pub fn open_sponsorship_ticket(
        &mut self,
        ticket: EncryptedSponsorshipTicket,
    ) -> PrivateL2LowFeePqConfidentialAccountAbstractionPaymasterRuntimeResult<String> {
        ensure!(
            self.encrypted_sponsorship_tickets.len() < MAX_SPONSORSHIP_TICKETS,
            "encrypted sponsorship ticket capacity exhausted"
        );
        let paymaster = self
            .paymasters
            .get(&ticket.paymaster_id)
            .ok_or_else(|| "ticket references unknown paymaster".to_string())?;
        ensure!(paymaster.status.usable(), "paymaster is not usable");
        ensure!(
            paymaster.lanes.contains(&ticket.lane),
            "ticket lane not served by paymaster"
        );
        ensure!(
            ticket.sponsor_fee_bps <= paymaster.max_fee_bps,
            "ticket sponsor fee exceeds paymaster maximum"
        );
        ensure!(
            ticket.privacy_set_size >= self.config.min_privacy_set_size,
            "ticket privacy set below runtime minimum"
        );
        ensure!(
            ticket.gas_limit <= self.config.max_sponsored_gas_per_account,
            "ticket gas exceeds account ceiling"
        );
        ensure!(
            self.session_policy_attestations
                .contains_key(&ticket.attestation_id),
            "ticket references unknown policy attestation"
        );
        ensure!(
            self.fee_coupons.contains_key(&ticket.coupon_id),
            "ticket references unknown fee coupon"
        );
        let ticket_id = ticket.ticket_id.clone();
        let account_commitment = ticket.account_commitment.clone();
        let paymaster_id = ticket.paymaster_id.clone();
        self.consumed_nullifiers
            .insert(ticket.ticket_nullifier.clone());
        self.encrypted_sponsorship_tickets
            .insert(ticket_id.clone(), ticket);
        self.tickets_by_account
            .entry(account_commitment)
            .or_default()
            .insert(ticket_id.clone());
        self.tickets_by_paymaster
            .entry(paymaster_id)
            .or_default()
            .insert(ticket_id.clone());
        self.counters.encrypted_tickets_opened =
            self.counters.encrypted_tickets_opened.saturating_add(1);
        self.emit_event("encrypted_sponsorship_ticket_opened", &ticket_id);
        self.refresh_roots();
        Ok(ticket_id)
    }

    pub fn attest_ticket_policy(
        &mut self,
        ticket_id: &str,
    ) -> PrivateL2LowFeePqConfidentialAccountAbstractionPaymasterRuntimeResult<String> {
        let (attestation_id, lane, gas_limit, max_fee_piconero) = {
            let ticket = self
                .encrypted_sponsorship_tickets
                .get(ticket_id)
                .ok_or_else(|| "unknown sponsorship ticket".to_string())?;
            (
                ticket.attestation_id.clone(),
                ticket.lane,
                ticket.gas_limit,
                ticket.max_fee_piconero,
            )
        };
        let attestation = self
            .session_policy_attestations
            .get_mut(&attestation_id)
            .ok_or_else(|| "ticket policy attestation missing".to_string())?;
        ensure!(
            attestation.status == PolicyStatus::Verified,
            "policy is not verified"
        );
        ensure!(attestation.lane == lane, "policy lane mismatch");
        ensure!(
            gas_limit <= attestation.max_gas_units,
            "ticket exceeds attested gas"
        );
        ensure!(
            max_fee_piconero <= attestation.max_fee_piconero,
            "ticket exceeds attested fee"
        );
        attestation.status = PolicyStatus::Linked;
        let ticket = self
            .encrypted_sponsorship_tickets
            .get_mut(ticket_id)
            .ok_or_else(|| "unknown sponsorship ticket".to_string())?;
        ticket.status = TicketStatus::PolicyAttested;
        self.counters.tickets_attested = self.counters.tickets_attested.saturating_add(1);
        let proof_id = domain_hash(
            domain("TICKET-POLICY-ATTESTED").as_str(),
            &[
                HashPart::Str(ticket_id),
                HashPart::Str(&attestation_id),
                HashPart::U64(self.counters.tickets_attested),
            ],
            32,
        );
        self.emit_event("ticket_policy_attested", ticket_id);
        self.refresh_roots();
        Ok(proof_id)
    }

    pub fn reserve_coupon_for_ticket(
        &mut self,
        ticket_id: &str,
    ) -> PrivateL2LowFeePqConfidentialAccountAbstractionPaymasterRuntimeResult<String> {
        let (coupon_id, ticket_fee, lane) = {
            let ticket = self
                .encrypted_sponsorship_tickets
                .get(ticket_id)
                .ok_or_else(|| "unknown sponsorship ticket".to_string())?;
            ensure!(
                ticket.status == TicketStatus::PolicyAttested,
                "ticket policy has not been attested"
            );
            (
                ticket.coupon_id.clone(),
                ticket.max_fee_piconero,
                ticket.lane,
            )
        };
        let coupon = self
            .fee_coupons
            .get_mut(&coupon_id)
            .ok_or_else(|| "ticket coupon missing".to_string())?;
        ensure!(coupon.status.spendable(), "coupon is not spendable");
        ensure!(coupon.lane == lane, "coupon lane mismatch");
        ensure!(
            coupon.face_value_piconero >= ticket_fee,
            "coupon face value below ticket fee"
        );
        coupon.status = CouponStatus::Reserved;
        let ticket = self
            .encrypted_sponsorship_tickets
            .get_mut(ticket_id)
            .ok_or_else(|| "unknown sponsorship ticket".to_string())?;
        ticket.status = TicketStatus::CouponReserved;
        let reservation_id = domain_hash(
            domain("COUPON-RESERVED").as_str(),
            &[HashPart::Str(ticket_id), HashPart::Str(&coupon_id)],
            32,
        );
        self.emit_event("fee_coupon_reserved", ticket_id);
        self.refresh_roots();
        Ok(reservation_id)
    }

    pub fn open_gas_sponsorship_batch(
        &mut self,
        batch_id: String,
        paymaster_id: &str,
        lane: PaymasterLane,
        ticket_ids: Vec<String>,
    ) -> PrivateL2LowFeePqConfidentialAccountAbstractionPaymasterRuntimeResult<String> {
        ensure!(
            self.gas_sponsorship_batches.len() < MAX_GAS_BATCHES,
            "gas sponsorship batch capacity exhausted"
        );
        ensure!(
            !ticket_ids.is_empty(),
            "gas sponsorship batch must include tickets"
        );
        ensure!(
            ticket_ids.len() <= self.config.max_tickets_per_batch,
            "gas sponsorship batch exceeds ticket limit"
        );
        let paymaster = self
            .paymasters
            .get(paymaster_id)
            .ok_or_else(|| "batch references unknown paymaster".to_string())?;
        ensure!(paymaster.status.usable(), "paymaster is not usable");
        ensure!(
            paymaster.lanes.contains(&lane),
            "paymaster does not serve batch lane"
        );
        let mut total_gas_limit = 0_u64;
        let mut total_fee_piconero = 0_u64;
        let mut ticket_records = Vec::new();
        for ticket_id in &ticket_ids {
            let ticket = self
                .encrypted_sponsorship_tickets
                .get(ticket_id)
                .ok_or_else(|| format!("unknown ticket {ticket_id}"))?;
            ensure!(
                ticket.paymaster_id == paymaster_id,
                "ticket paymaster mismatch"
            );
            ensure!(ticket.lane == lane, "ticket lane mismatch");
            ensure!(
                ticket.status == TicketStatus::CouponReserved,
                "ticket is not ready for batching"
            );
            total_gas_limit = total_gas_limit.saturating_add(ticket.gas_limit);
            total_fee_piconero = total_fee_piconero.saturating_add(ticket.max_fee_piconero);
            ticket_records.push(ticket.public_record());
        }
        ensure!(
            total_gas_limit <= self.config.max_gas_per_batch,
            "gas sponsorship batch exceeds gas limit"
        );
        ensure!(
            total_gas_limit <= paymaster.available_gas_units,
            "paymaster gas budget exhausted"
        );
        ensure!(
            total_fee_piconero <= paymaster.available_fee_piconero,
            "paymaster fee budget exhausted"
        );
        for ticket_id in &ticket_ids {
            if let Some(ticket) = self.encrypted_sponsorship_tickets.get_mut(ticket_id) {
                ticket.status = TicketStatus::BatchQueued;
            }
        }
        let tickets_root = collection_root(domain("BATCH-TICKETS").as_str(), ticket_records);
        let batch = GasSponsorshipBatch {
            batch_id: batch_id.clone(),
            paymaster_id: paymaster_id.to_string(),
            lane,
            status: GasBatchStatus::Open,
            ticket_ids,
            tickets_root,
            batched_call_root: record_root("BATCHED-CALL-ROOT", &json!({"batch_id": batch_id})),
            aggregate_policy_root: record_root("AGGREGATE-POLICY-ROOT", &json!({"lane": lane})),
            total_gas_limit,
            total_fee_piconero,
            privacy_set_size: self.config.min_batch_privacy_set_size,
            opened_height: self.config.l2_height,
            expires_height: self.config.l2_height + self.config.batch_ttl_blocks,
            settlement_receipt_root: String::new(),
        };
        self.gas_sponsorship_batches.insert(batch_id.clone(), batch);
        self.counters.gas_batches_opened = self.counters.gas_batches_opened.saturating_add(1);
        self.counters.tickets_queued = self
            .counters
            .tickets_queued
            .saturating_add(self.gas_sponsorship_batches[&batch_id].ticket_ids.len() as u64);
        self.emit_event("gas_sponsorship_batch_opened", &batch_id);
        self.refresh_roots();
        Ok(batch_id)
    }

    pub fn settle_gas_sponsorship_batch(
        &mut self,
        batch_id: &str,
    ) -> PrivateL2LowFeePqConfidentialAccountAbstractionPaymasterRuntimeResult<String> {
        let (paymaster_id, ticket_ids, total_gas_limit, total_fee_piconero) = {
            let batch = self
                .gas_sponsorship_batches
                .get(batch_id)
                .ok_or_else(|| "unknown gas sponsorship batch".to_string())?;
            ensure!(batch.status == GasBatchStatus::Open, "batch is not open");
            (
                batch.paymaster_id.clone(),
                batch.ticket_ids.clone(),
                batch.total_gas_limit,
                batch.total_fee_piconero,
            )
        };
        let paymaster = self
            .paymasters
            .get_mut(&paymaster_id)
            .ok_or_else(|| "batch paymaster missing".to_string())?;
        ensure!(
            paymaster.available_gas_units >= total_gas_limit,
            "paymaster gas budget exhausted"
        );
        ensure!(
            paymaster.available_fee_piconero >= total_fee_piconero,
            "paymaster fee budget exhausted"
        );
        paymaster.available_gas_units = paymaster
            .available_gas_units
            .saturating_sub(total_gas_limit);
        paymaster.available_fee_piconero = paymaster
            .available_fee_piconero
            .saturating_sub(total_fee_piconero);
        paymaster.status = PaymasterStatus::Sponsoring;
        for ticket_id in &ticket_ids {
            if let Some(ticket) = self.encrypted_sponsorship_tickets.get_mut(ticket_id) {
                ticket.status = TicketStatus::Sponsored;
                if let Some(coupon) = self.fee_coupons.get_mut(&ticket.coupon_id) {
                    coupon.status = CouponStatus::Applied;
                    self.counters.fee_coupons_applied =
                        self.counters.fee_coupons_applied.saturating_add(1);
                }
            }
        }
        let settlement_receipt_root = record_root(
            "BATCH-SETTLEMENT-RECEIPT",
            &json!({
                "batch_id": batch_id,
                "paymaster_id": paymaster_id,
                "ticket_count": ticket_ids.len(),
                "total_gas_limit": total_gas_limit,
                "total_fee_piconero": total_fee_piconero,
            }),
        );
        let batch = self
            .gas_sponsorship_batches
            .get_mut(batch_id)
            .ok_or_else(|| "unknown gas sponsorship batch".to_string())?;
        batch.status = GasBatchStatus::Settled;
        batch.settlement_receipt_root = settlement_receipt_root.clone();
        self.counters.gas_batches_settled = self.counters.gas_batches_settled.saturating_add(1);
        self.counters.tickets_sponsored = self
            .counters
            .tickets_sponsored
            .saturating_add(ticket_ids.len() as u64);
        self.counters.sponsored_gas_units = self
            .counters
            .sponsored_gas_units
            .saturating_add(total_gas_limit);
        self.counters.sponsor_fee_piconero = self
            .counters
            .sponsor_fee_piconero
            .saturating_add(total_fee_piconero);
        self.emit_event("gas_sponsorship_batch_settled", batch_id);
        self.refresh_roots();
        Ok(settlement_receipt_root)
    }

    pub fn spend_redaction_budget(
        &mut self,
        budget_id: &str,
        class: RedactionClass,
        count: u64,
    ) -> PrivateL2LowFeePqConfidentialAccountAbstractionPaymasterRuntimeResult<String> {
        let budget = self
            .privacy_redaction_budgets
            .get_mut(budget_id)
            .ok_or_else(|| "unknown redaction budget".to_string())?;
        ensure!(
            budget.classes.contains(&class),
            "redaction class not allowed"
        );
        ensure!(budget.available() >= count, "redaction budget exhausted");
        budget.spent_redactions = budget.spent_redactions.saturating_add(count);
        self.counters.redactions_spent = self.counters.redactions_spent.saturating_add(count);
        let receipt_id = domain_hash(
            domain("REDACTION-BUDGET-SPENT").as_str(),
            &[
                HashPart::Str(budget_id),
                HashPart::Str(class.as_str()),
                HashPart::U64(count),
            ],
            32,
        );
        self.emit_event("privacy_redaction_budget_spent", budget_id);
        self.refresh_roots();
        Ok(receipt_id)
    }

    pub fn open_quarantine_case(
        &mut self,
        case: AbuseQuarantineCase,
    ) -> PrivateL2LowFeePqConfidentialAccountAbstractionPaymasterRuntimeResult<String> {
        ensure!(
            self.abuse_quarantine_cases.len() < MAX_QUARANTINE_CASES,
            "abuse quarantine capacity exhausted"
        );
        ensure!(
            case.abuse_score >= self.config.abuse_score_threshold,
            "abuse score below quarantine intake threshold"
        );
        let case_id = case.case_id.clone();
        if let Some(ticket) = self.encrypted_sponsorship_tickets.get_mut(&case.ticket_id) {
            ticket.status = TicketStatus::Quarantined;
        }
        if let Some(paymaster) = self.paymasters.get_mut(&case.paymaster_id) {
            if case.abuse_score >= self.config.quarantine_score_threshold {
                paymaster.status = PaymasterStatus::Quarantined;
            }
        }
        self.abuse_quarantine_cases.insert(case_id.clone(), case);
        self.counters.quarantine_cases_opened =
            self.counters.quarantine_cases_opened.saturating_add(1);
        self.emit_event("abuse_quarantine_case_opened", &case_id);
        self.refresh_roots();
        Ok(case_id)
    }

    pub fn release_quarantine_case(
        &mut self,
        case_id: &str,
    ) -> PrivateL2LowFeePqConfidentialAccountAbstractionPaymasterRuntimeResult<String> {
        let case = self
            .abuse_quarantine_cases
            .get_mut(case_id)
            .ok_or_else(|| "unknown quarantine case".to_string())?;
        case.status = "released".to_string();
        if let Some(ticket) = self.encrypted_sponsorship_tickets.get_mut(&case.ticket_id) {
            if ticket.status == TicketStatus::Quarantined {
                ticket.status = TicketStatus::Rejected;
            }
        }
        if let Some(paymaster) = self.paymasters.get_mut(&case.paymaster_id) {
            if paymaster.status == PaymasterStatus::Quarantined {
                paymaster.status = PaymasterStatus::Paused;
            }
        }
        self.counters.quarantine_cases_released =
            self.counters.quarantine_cases_released.saturating_add(1);
        let release_id = domain_hash(
            domain("QUARANTINE-RELEASED").as_str(),
            &[
                HashPart::Str(case_id),
                HashPart::U64(self.counters.quarantine_cases_released),
            ],
            32,
        );
        self.emit_event("abuse_quarantine_case_released", case_id);
        self.refresh_roots();
        Ok(release_id)
    }

    pub fn quote_sponsored_fee(&self, lane: PaymasterLane, gas_units: u64) -> u64 {
        gas_units
            .saturating_mul(lane.gas_weight())
            .saturating_mul(self.config.max_paymaster_fee_bps)
            .saturating_div(MAX_BPS)
    }

    pub fn refresh_roots(&mut self) {
        self.roots = Roots {
            paymasters_root: collection_root(
                domain("PAYMASTERS").as_str(),
                self.paymasters.values().map(Paymaster::public_record),
            ),
            session_policy_attestations_root: collection_root(
                domain("SESSION-POLICY-ATTESTATIONS").as_str(),
                self.session_policy_attestations
                    .values()
                    .map(SessionPolicyAttestation::public_record),
            ),
            encrypted_sponsorship_tickets_root: collection_root(
                domain("ENCRYPTED-SPONSORSHIP-TICKETS").as_str(),
                self.encrypted_sponsorship_tickets
                    .values()
                    .map(EncryptedSponsorshipTicket::public_record),
            ),
            fee_coupons_root: collection_root(
                domain("FEE-COUPONS").as_str(),
                self.fee_coupons.values().map(FeeCoupon::public_record),
            ),
            gas_sponsorship_batches_root: collection_root(
                domain("GAS-SPONSORSHIP-BATCHES").as_str(),
                self.gas_sponsorship_batches
                    .values()
                    .map(GasSponsorshipBatch::public_record),
            ),
            privacy_redaction_budgets_root: collection_root(
                domain("PRIVACY-REDACTION-BUDGETS").as_str(),
                self.privacy_redaction_budgets
                    .values()
                    .map(PrivacyRedactionBudget::public_record),
            ),
            abuse_quarantine_root: collection_root(
                domain("ABUSE-QUARANTINE").as_str(),
                self.abuse_quarantine_cases
                    .values()
                    .map(AbuseQuarantineCase::public_record),
            ),
            lane_index_root: collection_root(
                domain("LANE-INDEX").as_str(),
                self.paymasters_by_lane
                    .iter()
                    .map(|(lane, ids)| json!({"lane": lane, "paymasters": ids})),
            ),
            account_index_root: collection_root(
                domain("ACCOUNT-INDEX").as_str(),
                self.tickets_by_account
                    .iter()
                    .map(|(account, ids)| json!({"account_commitment": account, "tickets": ids})),
            ),
            nullifier_root: collection_root(
                domain("NULLIFIERS").as_str(),
                self.consumed_nullifiers
                    .iter()
                    .map(|nullifier| json!({"nullifier": nullifier})),
            ),
            deterministic_public_events_root: collection_root(
                domain("DETERMINISTIC-PUBLIC-EVENTS").as_str(),
                self.deterministic_public_events.iter().cloned(),
            ),
        };
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_session_policy_attestation_suite": PQ_SESSION_POLICY_ATTESTATION_SUITE,
            "encrypted_sponsorship_ticket_suite": ENCRYPTED_SPONSORSHIP_TICKET_SUITE,
            "fee_coupon_suite": FEE_COUPON_SUITE,
            "gas_sponsorship_batch_suite": GAS_SPONSORSHIP_BATCH_SUITE,
            "privacy_redaction_budget_suite": PRIVACY_REDACTION_BUDGET_SUITE,
            "abuse_quarantine_suite": ABUSE_QUARANTINE_SUITE,
            "public_record_suite": PUBLIC_RECORD_SUITE,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "paymasters": self.paymasters.values().map(Paymaster::public_record).collect::<Vec<_>>(),
            "session_policy_attestations": self.session_policy_attestations.values().map(SessionPolicyAttestation::public_record).collect::<Vec<_>>(),
            "encrypted_sponsorship_tickets": self.encrypted_sponsorship_tickets.values().map(EncryptedSponsorshipTicket::public_record).collect::<Vec<_>>(),
            "fee_coupons": self.fee_coupons.values().map(FeeCoupon::public_record).collect::<Vec<_>>(),
            "gas_sponsorship_batches": self.gas_sponsorship_batches.values().map(GasSponsorshipBatch::public_record).collect::<Vec<_>>(),
            "privacy_redaction_budgets": self.privacy_redaction_budgets.values().map(PrivacyRedactionBudget::public_record).collect::<Vec<_>>(),
            "abuse_quarantine_cases": self.abuse_quarantine_cases.values().map(AbuseQuarantineCase::public_record).collect::<Vec<_>>(),
            "paymasters_by_lane": self.paymasters_by_lane,
            "tickets_by_account": self.tickets_by_account,
            "tickets_by_paymaster": self.tickets_by_paymaster,
            "consumed_nullifiers": self.consumed_nullifiers,
            "deterministic_public_events": self.deterministic_public_events,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("STATE", &self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut object) = record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    fn emit_event(&mut self, kind: &str, subject_id: &str) {
        if self.deterministic_public_events.len() >= MAX_PUBLIC_EVENTS {
            return;
        }
        let event_id = domain_hash(
            domain("EVENT").as_str(),
            &[
                HashPart::Str(kind),
                HashPart::Str(subject_id),
                HashPart::U64(self.counters.public_events_emitted),
            ],
            32,
        );
        self.deterministic_public_events.push(json!({
            "event_id": event_id,
            "kind": kind,
            "subject_id": subject_id,
            "event_index": self.counters.public_events_emitted,
        }));
        self.counters.public_events_emitted = self.counters.public_events_emitted.saturating_add(1);
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

pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}

pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}

pub fn state_root_from_public_record(record: &Value) -> String {
    record
        .get("state_root")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| record_root("STATE-FROM-PUBLIC-RECORD", record))
}

pub fn paymaster_id(operator_commitment: &str, policy_root: &str, nonce: u64) -> String {
    domain_hash(
        domain("PAYMASTER-ID").as_str(),
        &[
            HashPart::Str(operator_commitment),
            HashPart::Str(policy_root),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn session_policy_attestation_id(
    account_commitment: &str,
    session_key_commitment: &str,
    kind: PolicyAttestationKind,
    nonce: u64,
) -> String {
    domain_hash(
        domain("SESSION-POLICY-ATTESTATION-ID").as_str(),
        &[
            HashPart::Str(account_commitment),
            HashPart::Str(session_key_commitment),
            HashPart::Str(kind.as_str()),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn sponsorship_ticket_id(
    account_commitment: &str,
    paymaster_id: &str,
    lane: PaymasterLane,
    nonce: u64,
) -> String {
    domain_hash(
        domain("SPONSORSHIP-TICKET-ID").as_str(),
        &[
            HashPart::Str(account_commitment),
            HashPart::Str(paymaster_id),
            HashPart::Str(lane.as_str()),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn fee_coupon_id(paymaster_id: &str, account_commitment: &str, nonce: u64) -> String {
    domain_hash(
        domain("FEE-COUPON-ID").as_str(),
        &[
            HashPart::Str(paymaster_id),
            HashPart::Str(account_commitment),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn gas_sponsorship_batch_id(
    paymaster_id: &str,
    lane: PaymasterLane,
    batch_nonce: u64,
) -> String {
    domain_hash(
        domain("GAS-SPONSORSHIP-BATCH-ID").as_str(),
        &[
            HashPart::Str(paymaster_id),
            HashPart::Str(lane.as_str()),
            HashPart::U64(batch_nonce),
        ],
        32,
    )
}

pub fn redaction_budget_id(paymaster_id: &str, account_commitment: &str, nonce: u64) -> String {
    domain_hash(
        domain("REDACTION-BUDGET-ID").as_str(),
        &[
            HashPart::Str(paymaster_id),
            HashPart::Str(account_commitment),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn quarantine_case_id(ticket_id: &str, reason: QuarantineReason, nonce: u64) -> String {
    domain_hash(
        domain("QUARANTINE-CASE-ID").as_str(),
        &[
            HashPart::Str(ticket_id),
            HashPart::Str(reason.as_str()),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn nullifier(scope: &str, subject_id: &str) -> String {
    domain_hash(
        domain("NULLIFIER").as_str(),
        &[HashPart::Str(scope), HashPart::Str(subject_id)],
        32,
    )
}

fn seed_devnet(state: &mut State) {
    let mut transfer_lanes = BTreeSet::new();
    transfer_lanes.insert(PaymasterLane::WalletTransfer);
    transfer_lanes.insert(PaymasterLane::ContractCall);
    transfer_lanes.insert(PaymasterLane::DefiIntent);
    let mut recovery_lanes = BTreeSet::new();
    recovery_lanes.insert(PaymasterLane::RecoverySession);
    recovery_lanes.insert(PaymasterLane::EmergencyEscape);

    let transfer_pm_id = "pm:demo:low-fee-aa".to_string();
    let recovery_pm_id = "pm:demo:recovery".to_string();
    let transfer_budget_id = redaction_budget_id(&transfer_pm_id, "acct:demo:primary", 1);
    let recovery_budget_id = redaction_budget_id(&recovery_pm_id, "acct:demo:recovery", 2);

    let _ = state.register_paymaster(Paymaster {
        paymaster_id: transfer_pm_id.clone(),
        operator_commitment: "operator:commitment:low-fee-aa".to_string(),
        spend_authority_root: record_root("DEVNET-SPEND-AUTHORITY", &json!(["aa", "defi"])),
        liquidity_commitment: "liquidity:commitment:low-fee-aa".to_string(),
        status: PaymasterStatus::Active,
        lanes: transfer_lanes,
        available_gas_units: 180_000_000,
        available_fee_piconero: 5_400_000,
        max_fee_bps: 10,
        discount_bps: 40,
        pq_security_bits: 256,
        privacy_set_size: 262_144,
        policy_root: record_root("DEVNET-PM-POLICY", &json!({"low_fee": true})),
        redaction_budget_id: transfer_budget_id.clone(),
        valid_from_height: DEVNET_L2_HEIGHT,
        valid_until_height: DEVNET_L2_HEIGHT + 43_200,
    });

    let _ = state.register_paymaster(Paymaster {
        paymaster_id: recovery_pm_id.clone(),
        operator_commitment: "operator:commitment:recovery-aa".to_string(),
        spend_authority_root: record_root("DEVNET-RECOVERY-AUTHORITY", &json!(["recovery"])),
        liquidity_commitment: "liquidity:commitment:recovery-aa".to_string(),
        status: PaymasterStatus::Active,
        lanes: recovery_lanes,
        available_gas_units: 90_000_000,
        available_fee_piconero: 2_100_000,
        max_fee_bps: 8,
        discount_bps: 45,
        pq_security_bits: 256,
        privacy_set_size: 262_144,
        policy_root: record_root("DEVNET-RECOVERY-PM-POLICY", &json!({"recovery": true})),
        redaction_budget_id: recovery_budget_id.clone(),
        valid_from_height: DEVNET_L2_HEIGHT,
        valid_until_height: DEVNET_L2_HEIGHT + 43_200,
    });

    let mut redaction_classes = BTreeSet::new();
    redaction_classes.insert(RedactionClass::AccountId);
    redaction_classes.insert(RedactionClass::ContractAddress);
    redaction_classes.insert(RedactionClass::Selector);
    redaction_classes.insert(RedactionClass::Amount);
    redaction_classes.insert(RedactionClass::Nullifier);

    let _ = state.register_redaction_budget(PrivacyRedactionBudget {
        budget_id: transfer_budget_id,
        paymaster_id: transfer_pm_id.clone(),
        account_commitment: "acct:demo:primary".to_string(),
        window_start_height: DEVNET_L2_HEIGHT,
        window_end_height: DEVNET_L2_HEIGHT + DEFAULT_REDACTION_BUDGET_WINDOW_BLOCKS,
        max_redactions: 20,
        spent_redactions: 2,
        classes: redaction_classes.clone(),
        redacted_fields_root: record_root("DEVNET-REDACTED-FIELDS", &json!(["amount", "selector"])),
        disclosure_guard_root: record_root(
            "DEVNET-DISCLOSURE-GUARD",
            &json!({"guard": "view-key"}),
        ),
    });

    redaction_classes.insert(RedactionClass::SessionScope);
    let _ = state.register_redaction_budget(PrivacyRedactionBudget {
        budget_id: recovery_budget_id,
        paymaster_id: recovery_pm_id.clone(),
        account_commitment: "acct:demo:recovery".to_string(),
        window_start_height: DEVNET_L2_HEIGHT,
        window_end_height: DEVNET_L2_HEIGHT + DEFAULT_REDACTION_BUDGET_WINDOW_BLOCKS,
        max_redactions: 16,
        spent_redactions: 1,
        classes: redaction_classes,
        redacted_fields_root: record_root("DEVNET-RECOVERY-REDACTED-FIELDS", &json!(["account"])),
        disclosure_guard_root: record_root(
            "DEVNET-RECOVERY-DISCLOSURE-GUARD",
            &json!({"guard": "guardian-quorum"}),
        ),
    });

    let attestation_id = session_policy_attestation_id(
        "acct:demo:primary",
        "session-key:demo:defi",
        PolicyAttestationKind::PaymasterBudget,
        1,
    );
    let coupon_id = fee_coupon_id(&transfer_pm_id, "acct:demo:primary", 1);
    let ticket_id = sponsorship_ticket_id(
        "acct:demo:primary",
        &transfer_pm_id,
        PaymasterLane::DefiIntent,
        1,
    );

    let _ = state.submit_policy_attestation(SessionPolicyAttestation {
        attestation_id: attestation_id.clone(),
        account_commitment: "acct:demo:primary".to_string(),
        session_key_commitment: "session-key:demo:defi".to_string(),
        paymaster_id: transfer_pm_id.clone(),
        kind: PolicyAttestationKind::PaymasterBudget,
        status: PolicyStatus::Submitted,
        lane: PaymasterLane::DefiIntent,
        policy_root: record_root("DEVNET-SESSION-POLICY", &json!({"gas": 2_400_000})),
        allowed_contracts_root: record_root("DEVNET-ALLOWED-CONTRACTS", &json!(["swap", "vault"])),
        allowed_selectors_root: record_root("DEVNET-ALLOWED-SELECTORS", &json!(["swap_exact_in"])),
        max_gas_units: 2_400_000,
        max_fee_piconero: 72_000,
        pq_security_bits: 256,
        privacy_set_size: 262_144,
        issued_height: DEVNET_L2_HEIGHT,
        expires_height: DEVNET_L2_HEIGHT + DEFAULT_POLICY_ATTESTATION_TTL_BLOCKS,
        attestation_nullifier: nullifier("policy", &attestation_id),
    });
    let _ = state.verify_policy_attestation(&attestation_id);

    let _ = state.mint_fee_coupon(FeeCoupon {
        coupon_id: coupon_id.clone(),
        paymaster_id: transfer_pm_id.clone(),
        account_commitment: "acct:demo:primary".to_string(),
        status: CouponStatus::Minted,
        coupon_commitment: record_root("DEVNET-FEE-COUPON", &json!({"face": 72_000})),
        coupon_nullifier: nullifier("coupon", &coupon_id),
        face_value_piconero: 72_000,
        discount_bps: 45,
        lane: PaymasterLane::DefiIntent,
        issued_height: DEVNET_L2_HEIGHT,
        expires_height: DEVNET_L2_HEIGHT + DEFAULT_COUPON_TTL_BLOCKS,
    });

    let _ = state.open_sponsorship_ticket(EncryptedSponsorshipTicket {
        ticket_id: ticket_id.clone(),
        account_commitment: "acct:demo:primary".to_string(),
        paymaster_id: transfer_pm_id.clone(),
        attestation_id,
        coupon_id,
        lane: PaymasterLane::DefiIntent,
        status: TicketStatus::Sealed,
        encrypted_call_bundle_root: record_root("DEVNET-ENCRYPTED-CALL", &json!({"bundle": 1})),
        encrypted_witness_root: record_root("DEVNET-ENCRYPTED-WITNESS", &json!({"witness": 1})),
        gas_limit: 2_100_000,
        max_fee_piconero: 63_000,
        sponsor_fee_bps: 9,
        privacy_set_size: 262_144,
        ticket_nullifier: nullifier("ticket", &ticket_id),
        issued_height: DEVNET_L2_HEIGHT,
        expires_height: DEVNET_L2_HEIGHT + DEFAULT_TICKET_TTL_BLOCKS,
    });
    let _ = state.attest_ticket_policy(&ticket_id);
    let _ = state.reserve_coupon_for_ticket(&ticket_id);

    let batch_id = gas_sponsorship_batch_id(&transfer_pm_id, PaymasterLane::DefiIntent, 1);
    let _ = state.open_gas_sponsorship_batch(
        batch_id.clone(),
        &transfer_pm_id,
        PaymasterLane::DefiIntent,
        vec![ticket_id],
    );
    let _ = state.settle_gas_sponsorship_batch(&batch_id);

    let quarantine_id = quarantine_case_id(
        "ticket:devnet:shadow-replay",
        QuarantineReason::TicketReplay,
        1,
    );
    let _ = state.open_quarantine_case(AbuseQuarantineCase {
        case_id: quarantine_id,
        subject_commitment: "acct:demo:shadow".to_string(),
        paymaster_id: transfer_pm_id,
        ticket_id: "ticket:devnet:shadow-replay".to_string(),
        reason: QuarantineReason::TicketReplay,
        abuse_score: 72,
        evidence_root: record_root("DEVNET-QUARANTINE-EVIDENCE", &json!({"replay": true})),
        status: "open".to_string(),
        opened_height: DEVNET_L2_HEIGHT,
        release_height: DEVNET_L2_HEIGHT + DEFAULT_QUARANTINE_TTL_BLOCKS,
    });
}

fn domain(label: &str) -> String {
    format!("PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-ACCOUNT-ABSTRACTION-PAYMASTER-RUNTIME:{label}")
}

fn record_root(label: &str, value: &Value) -> String {
    domain_hash(domain(label).as_str(), &[HashPart::Json(value)], 32)
}

fn collection_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let leaves = records.into_iter().collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}
