use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = PrivateL2PqConfidentialSlhDsaWithdrawalAuthorizationMarketRuntimeResult<T>;
pub type PrivateL2PqConfidentialSlhDsaWithdrawalAuthorizationMarketRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_WITHDRAWAL_AUTHORIZATION_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-slh-dsa-withdrawal-authorization-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_SLH_DSA_WITHDRAWAL_AUTHORIZATION_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_SLOT: u64 = 840_000;
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-stagenet-private-exit-devnet";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero";
pub const DEFAULT_AUTHORIZATION_ASSET_ID: &str = "xmr-withdrawal-note";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_SIGNATURE_SUITE: &str = "SLH-DSA-SHAKE-256f-withdrawal-authorization-v1";
pub const PQ_ATTESTATION_SUITE: &str = "SLH-DSA+ML-DSA-hybrid-authorizer-attestation-v1";
pub const SEALED_BID_SCHEME: &str = "ML-KEM-1024-sealed-authorization-bid-v1";
pub const POLICY_SCHEME: &str = "private-l2-withdrawal-authorization-policy-root-v1";
pub const COHORT_SCHEME: &str = "slh-dsa-authorizer-cohort-root-v1";
pub const WINDOW_SCHEME: &str = "confidential-withdrawal-approval-window-root-v1";
pub const RECEIPT_SCHEME: &str = "monero-private-l2-withdrawal-settlement-receipt-root-v1";
pub const REBATE_SCHEME: &str = "low-fee-withdrawal-authorization-rebate-root-v1";
pub const REDACTION_SCHEME: &str = "operator-safe-withdrawal-redaction-budget-root-v1";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_AUTHORIZATION_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_ATTESTATION_QUORUM_BPS: u64 = 7_500;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 16;
pub const DEFAULT_LOW_FEE_REBATE_BPS: u64 = 8;
pub const DEFAULT_OPERATOR_FEE_SHARE_BPS: u64 = 2_000;
pub const DEFAULT_BID_TTL_SLOTS: u64 = 48;
pub const DEFAULT_APPROVAL_WINDOW_SLOTS: u64 = 72;
pub const DEFAULT_SETTLEMENT_FINALITY_SLOTS: u64 = 12;
pub const DEFAULT_REDACTION_PUBLIC_BYTE_LIMIT: u64 = 1_536;
pub const DEFAULT_MAX_POLICIES: usize = 1_048_576;
pub const DEFAULT_MAX_COHORTS: usize = 262_144;
pub const DEFAULT_MAX_BIDS: usize = 4_194_304;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 8_388_608;
pub const DEFAULT_MAX_WINDOWS: usize = 2_097_152;
pub const DEFAULT_MAX_RECEIPTS: usize = 2_097_152;
pub const DEFAULT_MAX_REBATES: usize = 2_097_152;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 2_097_152;
pub const DEFAULT_MAX_OPERATOR_SUMMARIES: usize = 262_144;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalPolicyKind {
    StandardExit,
    FastExit,
    EmergencyExit,
    LiquidityProviderExit,
    VaultWithdrawal,
    ContractEscrowRelease,
    DisputeResolutionExit,
}

impl WithdrawalPolicyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StandardExit => "standard_exit",
            Self::FastExit => "fast_exit",
            Self::EmergencyExit => "emergency_exit",
            Self::LiquidityProviderExit => "liquidity_provider_exit",
            Self::VaultWithdrawal => "vault_withdrawal",
            Self::ContractEscrowRelease => "contract_escrow_release",
            Self::DisputeResolutionExit => "dispute_resolution_exit",
        }
    }

    pub fn risk_weight(self) -> u64 {
        match self {
            Self::EmergencyExit => 1_000,
            Self::DisputeResolutionExit => 940,
            Self::ContractEscrowRelease => 880,
            Self::VaultWithdrawal => 820,
            Self::FastExit => 760,
            Self::LiquidityProviderExit => 680,
            Self::StandardExit => 520,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    Draft,
    Active,
    CoolingDown,
    Suspended,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortStatus {
    Candidate,
    Active,
    Rotating,
    Quarantined,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Sealed,
    Eligible,
    Selected,
    Replaced,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    PolicySatisfied,
    WithdrawalNoteValid,
    FeeBoundObserved,
    RedactionBudgetObserved,
    MoneroSettlementObserved,
    FraudWarning,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowStatus {
    Open,
    QuorumReached,
    Settling,
    Settled,
    Expired,
    Cancelled,
    Challenged,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Pending,
    Finalized,
    ReorgProtected,
    Rejected,
    Challenged,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Reserved,
    Earned,
    Paid,
    Expired,
    ClawedBack,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub authorization_asset_id: String,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub authorization_quorum_bps: u64,
    pub attestation_quorum_bps: u64,
    pub max_user_fee_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub operator_fee_share_bps: u64,
    pub bid_ttl_slots: u64,
    pub approval_window_slots: u64,
    pub settlement_finality_slots: u64,
    pub redaction_public_byte_limit: u64,
    pub max_policies: usize,
    pub max_cohorts: usize,
    pub max_bids: usize,
    pub max_attestations: usize,
    pub max_windows: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub max_redaction_budgets: usize,
    pub max_operator_summaries: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            authorization_asset_id: DEFAULT_AUTHORIZATION_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            authorization_quorum_bps: DEFAULT_AUTHORIZATION_QUORUM_BPS,
            attestation_quorum_bps: DEFAULT_ATTESTATION_QUORUM_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            operator_fee_share_bps: DEFAULT_OPERATOR_FEE_SHARE_BPS,
            bid_ttl_slots: DEFAULT_BID_TTL_SLOTS,
            approval_window_slots: DEFAULT_APPROVAL_WINDOW_SLOTS,
            settlement_finality_slots: DEFAULT_SETTLEMENT_FINALITY_SLOTS,
            redaction_public_byte_limit: DEFAULT_REDACTION_PUBLIC_BYTE_LIMIT,
            max_policies: DEFAULT_MAX_POLICIES,
            max_cohorts: DEFAULT_MAX_COHORTS,
            max_bids: DEFAULT_MAX_BIDS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_windows: DEFAULT_MAX_WINDOWS,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
            max_operator_summaries: DEFAULT_MAX_OPERATOR_SUMMARIES,
        }
    }

    pub fn root(&self) -> String {
        object_root("config", self)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub policies: u64,
    pub signer_cohorts: u64,
    pub sealed_bids: u64,
    pub pq_attestations: u64,
    pub approval_windows: u64,
    pub settlement_receipts: u64,
    pub low_fee_rebates: u64,
    pub redaction_budgets: u64,
    pub operator_summaries: u64,
    pub selected_bids: u64,
    pub settled_windows: u64,
    pub challenged_items: u64,
}

impl Counters {
    pub fn root(&self) -> String {
        object_root("counters", self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counter_root: String,
    pub policy_root: String,
    pub signer_cohort_root: String,
    pub sealed_bid_root: String,
    pub pq_attestation_root: String,
    pub approval_window_root: String,
    pub settlement_receipt_root: String,
    pub low_fee_rebate_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            config_root: empty_root("config"),
            counter_root: empty_root("counters"),
            policy_root: empty_root("policies"),
            signer_cohort_root: empty_root("signer-cohorts"),
            sealed_bid_root: empty_root("sealed-bids"),
            pq_attestation_root: empty_root("pq-attestations"),
            approval_window_root: empty_root("approval-windows"),
            settlement_receipt_root: empty_root("settlement-receipts"),
            low_fee_rebate_root: empty_root("low-fee-rebates"),
            redaction_budget_root: empty_root("redaction-budgets"),
            operator_summary_root: empty_root("operator-summaries"),
            public_record_root: empty_root("public-record"),
            state_root: empty_root("state"),
        }
    }

    pub fn root(&self) -> String {
        object_root("roots", self)
    }
}

impl Default for Roots {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WithdrawalAuthorizationPolicy {
    pub policy_id: String,
    pub kind: WithdrawalPolicyKind,
    pub status: PolicyStatus,
    pub cohort_id: String,
    pub policy_commitment_root: String,
    pub withdrawal_predicate_root: String,
    pub fee_bound_root: String,
    pub redaction_policy_root: String,
    pub authorization_quorum_bps: u64,
    pub max_user_fee_bps: u64,
    pub min_privacy_set_size: u64,
    pub max_withdrawal_amount_piconero: u64,
    pub activation_slot: u64,
    pub expiry_slot: u64,
    pub bid_count: u64,
    pub window_count: u64,
}

impl WithdrawalAuthorizationPolicy {
    pub fn root(&self) -> String {
        object_root("policy", self)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "kind": self.kind,
            "status": self.status,
            "cohort_id": self.cohort_id,
            "policy_commitment_root": self.policy_commitment_root,
            "withdrawal_predicate_root": self.withdrawal_predicate_root,
            "fee_bound_root": self.fee_bound_root,
            "redaction_policy_root": self.redaction_policy_root,
            "authorization_quorum_bps": self.authorization_quorum_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_withdrawal_amount_piconero": self.max_withdrawal_amount_piconero,
            "activation_slot": self.activation_slot,
            "expiry_slot": self.expiry_slot,
            "bid_count": self.bid_count,
            "window_count": self.window_count,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignerCohort {
    pub cohort_id: String,
    pub status: CohortStatus,
    pub cohort_commitment_root: String,
    pub slh_dsa_public_key_set_root: String,
    pub membership_nullifier_root: String,
    pub stake_commitment_root: String,
    pub operator_hint_root: String,
    pub signer_count: u64,
    pub active_weight_bps: u64,
    pub pq_security_bits: u16,
    pub rotation_epoch: u64,
    pub activation_slot: u64,
    pub expiry_slot: u64,
}

impl SignerCohort {
    pub fn root(&self) -> String {
        object_root("signer-cohort", self)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "cohort_id": self.cohort_id,
            "status": self.status,
            "cohort_commitment_root": self.cohort_commitment_root,
            "slh_dsa_public_key_set_root": self.slh_dsa_public_key_set_root,
            "membership_nullifier_root": self.membership_nullifier_root,
            "stake_commitment_root": self.stake_commitment_root,
            "operator_hint_root": self.operator_hint_root,
            "signer_count": self.signer_count,
            "active_weight_bps": self.active_weight_bps,
            "pq_security_bits": self.pq_security_bits,
            "rotation_epoch": self.rotation_epoch,
            "activation_slot": self.activation_slot,
            "expiry_slot": self.expiry_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SealedAuthorizationBid {
    pub bid_id: String,
    pub policy_id: String,
    pub cohort_id: String,
    pub status: BidStatus,
    pub sealed_bid_root: String,
    pub bidder_commitment_root: String,
    pub fee_commitment_root: String,
    pub withdrawal_note_commitment_root: String,
    pub monero_subaddress_hint_root: String,
    pub privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub requested_rebate_bps: u64,
    pub submitted_slot: u64,
    pub expires_slot: u64,
    pub selected_slot: Option<u64>,
}

impl SealedAuthorizationBid {
    pub fn root(&self) -> String {
        object_root("sealed-authorization-bid", self)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "policy_id": self.policy_id,
            "cohort_id": self.cohort_id,
            "status": self.status,
            "sealed_bid_root": self.sealed_bid_root,
            "bidder_commitment_root": self.bidder_commitment_root,
            "fee_commitment_root": self.fee_commitment_root,
            "withdrawal_note_commitment_root": self.withdrawal_note_commitment_root,
            "monero_subaddress_hint_root": self.monero_subaddress_hint_root,
            "privacy_set_size": self.privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "requested_rebate_bps": self.requested_rebate_bps,
            "submitted_slot": self.submitted_slot,
            "expires_slot": self.expires_slot,
            "selected_slot": self.selected_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqAuthorizationAttestation {
    pub attestation_id: String,
    pub window_id: String,
    pub bid_id: String,
    pub cohort_id: String,
    pub kind: AttestationKind,
    pub statement_root: String,
    pub slh_dsa_signature_root: String,
    pub transcript_root: String,
    pub signer_bitmap_root: String,
    pub observed_slot: u64,
    pub signer_weight_bps: u64,
    pub pq_security_bits: u16,
    pub accepted: bool,
}

impl PqAuthorizationAttestation {
    pub fn root(&self) -> String {
        object_root("pq-authorization-attestation", self)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "window_id": self.window_id,
            "bid_id": self.bid_id,
            "cohort_id": self.cohort_id,
            "kind": self.kind,
            "statement_root": self.statement_root,
            "slh_dsa_signature_root": self.slh_dsa_signature_root,
            "transcript_root": self.transcript_root,
            "signer_bitmap_root": self.signer_bitmap_root,
            "observed_slot": self.observed_slot,
            "signer_weight_bps": self.signer_weight_bps,
            "pq_security_bits": self.pq_security_bits,
            "accepted": self.accepted,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ApprovalWindow {
    pub window_id: String,
    pub policy_id: String,
    pub bid_id: String,
    pub cohort_id: String,
    pub status: WindowStatus,
    pub authorization_request_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_set_root: String,
    pub fee_bound_root: String,
    pub opened_slot: u64,
    pub closes_slot: u64,
    pub quorum_weight_bps: u64,
    pub attestation_count: u64,
    pub selected_rebate_bps: u64,
}

impl ApprovalWindow {
    pub fn root(&self) -> String {
        object_root("approval-window", self)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "policy_id": self.policy_id,
            "bid_id": self.bid_id,
            "cohort_id": self.cohort_id,
            "status": self.status,
            "authorization_request_root": self.authorization_request_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_set_root": self.nullifier_set_root,
            "fee_bound_root": self.fee_bound_root,
            "opened_slot": self.opened_slot,
            "closes_slot": self.closes_slot,
            "quorum_weight_bps": self.quorum_weight_bps,
            "attestation_count": self.attestation_count,
            "selected_rebate_bps": self.selected_rebate_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub window_id: String,
    pub bid_id: String,
    pub policy_id: String,
    pub status: SettlementStatus,
    pub monero_tx_set_root: String,
    pub withdrawal_nullifier_root: String,
    pub authorization_transcript_root: String,
    pub settlement_proof_root: String,
    pub operator_receipt_root: String,
    pub settled_amount_piconero: u64,
    pub charged_fee_piconero: u64,
    pub settled_slot: u64,
    pub finality_slot: u64,
}

impl SettlementReceipt {
    pub fn root(&self) -> String {
        object_root("settlement-receipt", self)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "window_id": self.window_id,
            "bid_id": self.bid_id,
            "policy_id": self.policy_id,
            "status": self.status,
            "monero_tx_set_root": self.monero_tx_set_root,
            "withdrawal_nullifier_root": self.withdrawal_nullifier_root,
            "authorization_transcript_root": self.authorization_transcript_root,
            "settlement_proof_root": self.settlement_proof_root,
            "operator_receipt_root": self.operator_receipt_root,
            "settled_amount_piconero": self.settled_amount_piconero,
            "charged_fee_piconero": self.charged_fee_piconero,
            "settled_slot": self.settled_slot,
            "finality_slot": self.finality_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub receipt_id: String,
    pub bid_id: String,
    pub policy_id: String,
    pub status: RebateStatus,
    pub sponsor_pool_root: String,
    pub beneficiary_commitment_root: String,
    pub rebate_asset_id: String,
    pub rebate_bps: u64,
    pub rebate_amount_piconero: u64,
    pub issued_slot: u64,
    pub expires_slot: u64,
}

impl LowFeeRebate {
    pub fn root(&self) -> String {
        object_root("low-fee-rebate", self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub target_id: String,
    pub budget_root: String,
    pub public_fields: BTreeSet<String>,
    pub redacted_fields: BTreeSet<String>,
    pub max_public_bytes: u64,
    pub actual_public_bytes: u64,
    pub privacy_set_size: u64,
    pub published_slot: u64,
    pub operator_safe: bool,
}

impl RedactionBudget {
    pub fn root(&self) -> String {
        object_root("redaction-budget", self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorSafeSummary {
    pub summary_id: String,
    pub slot: u64,
    pub policy_count: u64,
    pub active_cohort_count: u64,
    pub sealed_bid_count: u64,
    pub open_window_count: u64,
    pub settled_receipt_count: u64,
    pub median_fee_bps: u64,
    pub median_rebate_bps: u64,
    pub aggregate_quorum_bps: u64,
    pub redaction_budget_root: String,
    pub risk_summary_root: String,
}

impl OperatorSafeSummary {
    pub fn root(&self) -> String {
        object_root("operator-safe-summary", self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RegisterPolicyRequest {
    pub kind: WithdrawalPolicyKind,
    pub cohort_id: String,
    pub policy_commitment_root: String,
    pub withdrawal_predicate_root: String,
    pub fee_bound_root: String,
    pub redaction_policy_root: String,
    pub authorization_quorum_bps: u64,
    pub max_user_fee_bps: u64,
    pub min_privacy_set_size: u64,
    pub max_withdrawal_amount_piconero: u64,
    pub activation_slot: u64,
    pub expiry_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RegisterCohortRequest {
    pub cohort_commitment_root: String,
    pub slh_dsa_public_key_set_root: String,
    pub membership_nullifier_root: String,
    pub stake_commitment_root: String,
    pub operator_hint_root: String,
    pub signer_count: u64,
    pub active_weight_bps: u64,
    pub pq_security_bits: u16,
    pub rotation_epoch: u64,
    pub activation_slot: u64,
    pub expiry_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SubmitBidRequest {
    pub policy_id: String,
    pub sealed_bid_root: String,
    pub bidder_commitment_root: String,
    pub fee_commitment_root: String,
    pub withdrawal_note_commitment_root: String,
    pub monero_subaddress_hint_root: String,
    pub privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub requested_rebate_bps: u64,
    pub submitted_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpenApprovalWindowRequest {
    pub bid_id: String,
    pub authorization_request_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_set_root: String,
    pub fee_bound_root: String,
    pub opened_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecordAttestationRequest {
    pub window_id: String,
    pub kind: AttestationKind,
    pub statement_root: String,
    pub slh_dsa_signature_root: String,
    pub transcript_root: String,
    pub signer_bitmap_root: String,
    pub observed_slot: u64,
    pub signer_weight_bps: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettleWindowRequest {
    pub window_id: String,
    pub monero_tx_set_root: String,
    pub withdrawal_nullifier_root: String,
    pub authorization_transcript_root: String,
    pub settlement_proof_root: String,
    pub operator_receipt_root: String,
    pub settled_amount_piconero: u64,
    pub charged_fee_piconero: u64,
    pub settled_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IssueRebateRequest {
    pub receipt_id: String,
    pub sponsor_pool_root: String,
    pub beneficiary_commitment_root: String,
    pub rebate_bps: u64,
    pub rebate_amount_piconero: u64,
    pub issued_slot: u64,
    pub expires_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublishRedactionBudgetRequest {
    pub target_id: String,
    pub public_fields: BTreeSet<String>,
    pub redacted_fields: BTreeSet<String>,
    pub max_public_bytes: u64,
    pub actual_public_bytes: u64,
    pub privacy_set_size: u64,
    pub published_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublishOperatorSummaryRequest {
    pub slot: u64,
    pub median_fee_bps: u64,
    pub median_rebate_bps: u64,
    pub aggregate_quorum_bps: u64,
    pub risk_summary_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub protocol_version: String,
    pub schema_version: u64,
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub policies: BTreeMap<String, WithdrawalAuthorizationPolicy>,
    pub signer_cohorts: BTreeMap<String, SignerCohort>,
    pub sealed_bids: BTreeMap<String, SealedAuthorizationBid>,
    pub pq_attestations: BTreeMap<String, PqAuthorizationAttestation>,
    pub approval_windows: BTreeMap<String, ApprovalWindow>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub low_fee_rebates: BTreeMap<String, LowFeeRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSafeSummary>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            policies: BTreeMap::new(),
            signer_cohorts: BTreeMap::new(),
            sealed_bids: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            approval_windows: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }
}

impl State {
    pub fn devnet() -> Self {
        devnet()
    }

    pub fn register_signer_cohort(
        &mut self,
        request: RegisterCohortRequest,
    ) -> Result<SignerCohort> {
        ensure_capacity(
            self.signer_cohorts.len(),
            self.config.max_cohorts,
            "signer cohorts",
        )?;
        ensure_non_empty(&request.cohort_commitment_root, "cohort commitment root")?;
        ensure_non_empty(
            &request.slh_dsa_public_key_set_root,
            "slh-dsa public key set root",
        )?;
        ensure_non_empty(
            &request.membership_nullifier_root,
            "membership nullifier root",
        )?;
        ensure_bps(request.active_weight_bps, "active weight bps")?;
        if request.pq_security_bits < self.config.min_pq_security_bits {
            return Err("cohort pq security below runtime minimum".to_string());
        }
        if request.activation_slot >= request.expiry_slot {
            return Err("cohort activation slot must be before expiry slot".to_string());
        }

        let cohort_id = stable_id(
            "cohort",
            &[
                HashPart::Str(&request.cohort_commitment_root),
                HashPart::Str(&request.slh_dsa_public_key_set_root),
                HashPart::U64(request.rotation_epoch),
            ],
        );
        let cohort = SignerCohort {
            cohort_id: cohort_id.clone(),
            status: CohortStatus::Active,
            cohort_commitment_root: request.cohort_commitment_root,
            slh_dsa_public_key_set_root: request.slh_dsa_public_key_set_root,
            membership_nullifier_root: request.membership_nullifier_root,
            stake_commitment_root: request.stake_commitment_root,
            operator_hint_root: request.operator_hint_root,
            signer_count: request.signer_count,
            active_weight_bps: request.active_weight_bps,
            pq_security_bits: request.pq_security_bits,
            rotation_epoch: request.rotation_epoch,
            activation_slot: request.activation_slot,
            expiry_slot: request.expiry_slot,
        };
        self.signer_cohorts.insert(cohort_id, cohort.clone());
        self.counters.signer_cohorts = self.signer_cohorts.len() as u64;
        self.refresh_roots();
        Ok(cohort)
    }

    pub fn register_policy(
        &mut self,
        request: RegisterPolicyRequest,
    ) -> Result<WithdrawalAuthorizationPolicy> {
        ensure_capacity(self.policies.len(), self.config.max_policies, "policies")?;
        ensure_bps(request.authorization_quorum_bps, "authorization quorum bps")?;
        ensure_bps(request.max_user_fee_bps, "max user fee bps")?;
        if request.authorization_quorum_bps < self.config.authorization_quorum_bps {
            return Err("authorization quorum below runtime minimum".to_string());
        }
        if request.max_user_fee_bps > self.config.max_user_fee_bps {
            return Err("policy fee bound exceeds runtime maximum".to_string());
        }
        if request.min_privacy_set_size < self.config.min_privacy_set_size {
            return Err("policy privacy set below runtime minimum".to_string());
        }
        if request.activation_slot >= request.expiry_slot {
            return Err("policy activation slot must be before expiry slot".to_string());
        }
        let cohort = self
            .signer_cohorts
            .get(&request.cohort_id)
            .ok_or_else(|| "policy cohort not found".to_string())?;
        if cohort.status != CohortStatus::Active {
            return Err("policy cohort must be active".to_string());
        }
        ensure_non_empty(&request.policy_commitment_root, "policy commitment root")?;
        ensure_non_empty(
            &request.withdrawal_predicate_root,
            "withdrawal predicate root",
        )?;
        ensure_non_empty(&request.fee_bound_root, "fee bound root")?;
        ensure_non_empty(&request.redaction_policy_root, "redaction policy root")?;

        let policy_id = stable_id(
            "policy",
            &[
                HashPart::Str(request.kind.as_str()),
                HashPart::Str(&request.cohort_id),
                HashPart::Str(&request.policy_commitment_root),
                HashPart::U64(request.activation_slot),
            ],
        );
        let policy = WithdrawalAuthorizationPolicy {
            policy_id: policy_id.clone(),
            kind: request.kind,
            status: PolicyStatus::Active,
            cohort_id: request.cohort_id,
            policy_commitment_root: request.policy_commitment_root,
            withdrawal_predicate_root: request.withdrawal_predicate_root,
            fee_bound_root: request.fee_bound_root,
            redaction_policy_root: request.redaction_policy_root,
            authorization_quorum_bps: request.authorization_quorum_bps,
            max_user_fee_bps: request.max_user_fee_bps,
            min_privacy_set_size: request.min_privacy_set_size,
            max_withdrawal_amount_piconero: request.max_withdrawal_amount_piconero,
            activation_slot: request.activation_slot,
            expiry_slot: request.expiry_slot,
            bid_count: 0,
            window_count: 0,
        };
        self.policies.insert(policy_id, policy.clone());
        self.counters.policies = self.policies.len() as u64;
        self.refresh_roots();
        Ok(policy)
    }

    pub fn submit_sealed_bid(
        &mut self,
        request: SubmitBidRequest,
    ) -> Result<SealedAuthorizationBid> {
        ensure_capacity(self.sealed_bids.len(), self.config.max_bids, "sealed bids")?;
        ensure_bps(request.max_fee_bps, "max fee bps")?;
        ensure_bps(request.requested_rebate_bps, "requested rebate bps")?;
        ensure_non_empty(&request.sealed_bid_root, "sealed bid root")?;
        ensure_non_empty(&request.bidder_commitment_root, "bidder commitment root")?;
        ensure_non_empty(&request.fee_commitment_root, "fee commitment root")?;
        ensure_non_empty(
            &request.withdrawal_note_commitment_root,
            "withdrawal note commitment root",
        )?;
        let policy = self
            .policies
            .get_mut(&request.policy_id)
            .ok_or_else(|| "bid policy not found".to_string())?;
        if policy.status != PolicyStatus::Active {
            return Err("bid policy must be active".to_string());
        }
        if request.submitted_slot < policy.activation_slot
            || request.submitted_slot > policy.expiry_slot
        {
            return Err("bid submitted outside policy lifetime".to_string());
        }
        if request.max_fee_bps > policy.max_user_fee_bps {
            return Err("bid fee exceeds policy bound".to_string());
        }
        if request.privacy_set_size < policy.min_privacy_set_size {
            return Err("bid privacy set below policy minimum".to_string());
        }

        let bid_id = stable_id(
            "sealed-bid",
            &[
                HashPart::Str(&request.policy_id),
                HashPart::Str(&request.sealed_bid_root),
                HashPart::Str(&request.withdrawal_note_commitment_root),
                HashPart::U64(request.submitted_slot),
            ],
        );
        let bid = SealedAuthorizationBid {
            bid_id: bid_id.clone(),
            policy_id: request.policy_id,
            cohort_id: policy.cohort_id.clone(),
            status: BidStatus::Eligible,
            sealed_bid_root: request.sealed_bid_root,
            bidder_commitment_root: request.bidder_commitment_root,
            fee_commitment_root: request.fee_commitment_root,
            withdrawal_note_commitment_root: request.withdrawal_note_commitment_root,
            monero_subaddress_hint_root: request.monero_subaddress_hint_root,
            privacy_set_size: request.privacy_set_size,
            max_fee_bps: request.max_fee_bps,
            requested_rebate_bps: request.requested_rebate_bps,
            submitted_slot: request.submitted_slot,
            expires_slot: request.submitted_slot + self.config.bid_ttl_slots,
            selected_slot: None,
        };
        policy.bid_count += 1;
        self.sealed_bids.insert(bid_id, bid.clone());
        self.counters.sealed_bids = self.sealed_bids.len() as u64;
        self.refresh_roots();
        Ok(bid)
    }

    pub fn open_approval_window(
        &mut self,
        request: OpenApprovalWindowRequest,
    ) -> Result<ApprovalWindow> {
        ensure_capacity(
            self.approval_windows.len(),
            self.config.max_windows,
            "approval windows",
        )?;
        ensure_non_empty(
            &request.authorization_request_root,
            "authorization request root",
        )?;
        ensure_non_empty(&request.withdrawal_batch_root, "withdrawal batch root")?;
        ensure_non_empty(&request.nullifier_set_root, "nullifier set root")?;
        let bid = self
            .sealed_bids
            .get_mut(&request.bid_id)
            .ok_or_else(|| "approval bid not found".to_string())?;
        if bid.status != BidStatus::Eligible {
            return Err("approval bid must be eligible".to_string());
        }
        if request.opened_slot > bid.expires_slot {
            return Err("approval window opened after bid expiry".to_string());
        }
        let policy = self
            .policies
            .get_mut(&bid.policy_id)
            .ok_or_else(|| "approval policy not found".to_string())?;
        let window_id = stable_id(
            "approval-window",
            &[
                HashPart::Str(&request.bid_id),
                HashPart::Str(&request.authorization_request_root),
                HashPart::U64(request.opened_slot),
            ],
        );
        let window = ApprovalWindow {
            window_id: window_id.clone(),
            policy_id: bid.policy_id.clone(),
            bid_id: bid.bid_id.clone(),
            cohort_id: bid.cohort_id.clone(),
            status: WindowStatus::Open,
            authorization_request_root: request.authorization_request_root,
            withdrawal_batch_root: request.withdrawal_batch_root,
            nullifier_set_root: request.nullifier_set_root,
            fee_bound_root: request.fee_bound_root,
            opened_slot: request.opened_slot,
            closes_slot: request.opened_slot + self.config.approval_window_slots,
            quorum_weight_bps: 0,
            attestation_count: 0,
            selected_rebate_bps: bid.requested_rebate_bps,
        };
        bid.status = BidStatus::Selected;
        bid.selected_slot = Some(request.opened_slot);
        policy.window_count += 1;
        self.approval_windows.insert(window_id, window.clone());
        self.counters.selected_bids += 1;
        self.counters.approval_windows = self.approval_windows.len() as u64;
        self.refresh_roots();
        Ok(window)
    }

    pub fn record_pq_attestation(
        &mut self,
        request: RecordAttestationRequest,
    ) -> Result<PqAuthorizationAttestation> {
        ensure_capacity(
            self.pq_attestations.len(),
            self.config.max_attestations,
            "pq attestations",
        )?;
        ensure_bps(request.signer_weight_bps, "signer weight bps")?;
        ensure_non_empty(&request.statement_root, "statement root")?;
        ensure_non_empty(&request.slh_dsa_signature_root, "slh-dsa signature root")?;
        ensure_non_empty(&request.transcript_root, "transcript root")?;
        ensure_non_empty(&request.signer_bitmap_root, "signer bitmap root")?;
        if request.pq_security_bits < self.config.min_pq_security_bits {
            return Err("attestation pq security below runtime minimum".to_string());
        }
        let window = self
            .approval_windows
            .get_mut(&request.window_id)
            .ok_or_else(|| "attestation approval window not found".to_string())?;
        if !matches!(
            window.status,
            WindowStatus::Open | WindowStatus::QuorumReached
        ) {
            return Err("attestation window is not open".to_string());
        }
        if request.observed_slot > window.closes_slot {
            return Err("attestation observed after approval window close".to_string());
        }
        let accepted = request.kind != AttestationKind::FraudWarning
            && request.signer_weight_bps >= self.config.authorization_quorum_bps;
        let attestation_id = stable_id(
            "pq-attestation",
            &[
                HashPart::Str(&request.window_id),
                HashPart::Str(request.kind.as_ref()),
                HashPart::Str(&request.statement_root),
                HashPart::U64(request.observed_slot),
            ],
        );
        let attestation = PqAuthorizationAttestation {
            attestation_id: attestation_id.clone(),
            window_id: window.window_id.clone(),
            bid_id: window.bid_id.clone(),
            cohort_id: window.cohort_id.clone(),
            kind: request.kind,
            statement_root: request.statement_root,
            slh_dsa_signature_root: request.slh_dsa_signature_root,
            transcript_root: request.transcript_root,
            signer_bitmap_root: request.signer_bitmap_root,
            observed_slot: request.observed_slot,
            signer_weight_bps: request.signer_weight_bps,
            pq_security_bits: request.pq_security_bits,
            accepted,
        };
        window.attestation_count += 1;
        if accepted {
            window.quorum_weight_bps = window
                .quorum_weight_bps
                .saturating_add(request.signer_weight_bps)
                .min(MAX_BPS);
            if window.quorum_weight_bps >= self.config.attestation_quorum_bps {
                window.status = WindowStatus::QuorumReached;
            }
        } else if request.kind == AttestationKind::FraudWarning {
            window.status = WindowStatus::Challenged;
            self.counters.challenged_items += 1;
        }
        self.pq_attestations
            .insert(attestation_id, attestation.clone());
        self.counters.pq_attestations = self.pq_attestations.len() as u64;
        self.refresh_roots();
        Ok(attestation)
    }

    pub fn settle_window(&mut self, request: SettleWindowRequest) -> Result<SettlementReceipt> {
        ensure_capacity(
            self.settlement_receipts.len(),
            self.config.max_receipts,
            "settlement receipts",
        )?;
        ensure_non_empty(&request.monero_tx_set_root, "monero tx set root")?;
        ensure_non_empty(
            &request.withdrawal_nullifier_root,
            "withdrawal nullifier root",
        )?;
        ensure_non_empty(
            &request.authorization_transcript_root,
            "authorization transcript root",
        )?;
        ensure_non_empty(&request.settlement_proof_root, "settlement proof root")?;
        let window = self
            .approval_windows
            .get_mut(&request.window_id)
            .ok_or_else(|| "settlement approval window not found".to_string())?;
        if window.status != WindowStatus::QuorumReached {
            return Err("window quorum must be reached before settlement".to_string());
        }
        if request.settled_slot < window.opened_slot {
            return Err("settlement slot before window opened".to_string());
        }
        let bid = self
            .sealed_bids
            .get(&window.bid_id)
            .ok_or_else(|| "settlement bid not found".to_string())?;
        let receipt_id = stable_id(
            "settlement-receipt",
            &[
                HashPart::Str(&request.window_id),
                HashPart::Str(&request.monero_tx_set_root),
                HashPart::Str(&request.withdrawal_nullifier_root),
                HashPart::U64(request.settled_slot),
            ],
        );
        let receipt = SettlementReceipt {
            receipt_id: receipt_id.clone(),
            window_id: window.window_id.clone(),
            bid_id: bid.bid_id.clone(),
            policy_id: bid.policy_id.clone(),
            status: SettlementStatus::Finalized,
            monero_tx_set_root: request.monero_tx_set_root,
            withdrawal_nullifier_root: request.withdrawal_nullifier_root,
            authorization_transcript_root: request.authorization_transcript_root,
            settlement_proof_root: request.settlement_proof_root,
            operator_receipt_root: request.operator_receipt_root,
            settled_amount_piconero: request.settled_amount_piconero,
            charged_fee_piconero: request.charged_fee_piconero,
            settled_slot: request.settled_slot,
            finality_slot: request.settled_slot + self.config.settlement_finality_slots,
        };
        window.status = WindowStatus::Settled;
        self.settlement_receipts.insert(receipt_id, receipt.clone());
        self.counters.settled_windows += 1;
        self.counters.settlement_receipts = self.settlement_receipts.len() as u64;
        self.refresh_roots();
        Ok(receipt)
    }

    pub fn issue_low_fee_rebate(&mut self, request: IssueRebateRequest) -> Result<LowFeeRebate> {
        ensure_capacity(
            self.low_fee_rebates.len(),
            self.config.max_rebates,
            "low fee rebates",
        )?;
        ensure_bps(request.rebate_bps, "rebate bps")?;
        ensure_non_empty(&request.sponsor_pool_root, "sponsor pool root")?;
        ensure_non_empty(
            &request.beneficiary_commitment_root,
            "beneficiary commitment root",
        )?;
        if request.rebate_bps > self.config.low_fee_rebate_bps {
            return Err("rebate bps exceeds runtime maximum".to_string());
        }
        let receipt = self
            .settlement_receipts
            .get(&request.receipt_id)
            .ok_or_else(|| "rebate receipt not found".to_string())?;
        let rebate_id = stable_id(
            "low-fee-rebate",
            &[
                HashPart::Str(&request.receipt_id),
                HashPart::Str(&request.sponsor_pool_root),
                HashPart::U64(request.issued_slot),
            ],
        );
        let rebate = LowFeeRebate {
            rebate_id: rebate_id.clone(),
            receipt_id: request.receipt_id,
            bid_id: receipt.bid_id.clone(),
            policy_id: receipt.policy_id.clone(),
            status: RebateStatus::Earned,
            sponsor_pool_root: request.sponsor_pool_root,
            beneficiary_commitment_root: request.beneficiary_commitment_root,
            rebate_asset_id: self.config.fee_asset_id.clone(),
            rebate_bps: request.rebate_bps,
            rebate_amount_piconero: request.rebate_amount_piconero,
            issued_slot: request.issued_slot,
            expires_slot: request.expires_slot,
        };
        self.low_fee_rebates.insert(rebate_id, rebate.clone());
        self.counters.low_fee_rebates = self.low_fee_rebates.len() as u64;
        self.refresh_roots();
        Ok(rebate)
    }

    pub fn publish_redaction_budget(
        &mut self,
        request: PublishRedactionBudgetRequest,
    ) -> Result<RedactionBudget> {
        ensure_capacity(
            self.redaction_budgets.len(),
            self.config.max_redaction_budgets,
            "redaction budgets",
        )?;
        ensure_non_empty(&request.target_id, "redaction target id")?;
        if request.actual_public_bytes > request.max_public_bytes {
            return Err("actual public bytes exceed redaction budget".to_string());
        }
        if request.max_public_bytes > self.config.redaction_public_byte_limit {
            return Err("redaction budget exceeds runtime public byte limit".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("redaction privacy set below runtime minimum".to_string());
        }
        let budget_root = object_root(
            "redaction-budget-policy",
            &json!({
                "target_id": &request.target_id,
                "public_fields": &request.public_fields,
                "redacted_fields": &request.redacted_fields,
                "max_public_bytes": request.max_public_bytes,
                "privacy_set_size": request.privacy_set_size,
            }),
        );
        let budget_id = stable_id(
            "redaction-budget",
            &[
                HashPart::Str(&request.target_id),
                HashPart::Str(&budget_root),
                HashPart::U64(request.published_slot),
            ],
        );
        let budget = RedactionBudget {
            budget_id: budget_id.clone(),
            target_id: request.target_id,
            budget_root,
            public_fields: request.public_fields,
            redacted_fields: request.redacted_fields,
            max_public_bytes: request.max_public_bytes,
            actual_public_bytes: request.actual_public_bytes,
            privacy_set_size: request.privacy_set_size,
            published_slot: request.published_slot,
            operator_safe: true,
        };
        self.redaction_budgets.insert(budget_id, budget.clone());
        self.counters.redaction_budgets = self.redaction_budgets.len() as u64;
        self.refresh_roots();
        Ok(budget)
    }

    pub fn publish_operator_summary(
        &mut self,
        request: PublishOperatorSummaryRequest,
    ) -> Result<OperatorSafeSummary> {
        ensure_capacity(
            self.operator_summaries.len(),
            self.config.max_operator_summaries,
            "operator summaries",
        )?;
        ensure_bps(request.median_fee_bps, "median fee bps")?;
        ensure_bps(request.median_rebate_bps, "median rebate bps")?;
        ensure_bps(request.aggregate_quorum_bps, "aggregate quorum bps")?;
        ensure_non_empty(&request.risk_summary_root, "risk summary root")?;
        let open_window_count = self
            .approval_windows
            .values()
            .filter(|window| {
                matches!(
                    window.status,
                    WindowStatus::Open | WindowStatus::QuorumReached
                )
            })
            .count() as u64;
        let active_cohort_count = self
            .signer_cohorts
            .values()
            .filter(|cohort| cohort.status == CohortStatus::Active)
            .count() as u64;
        let redaction_budget_root = map_root("summary-redaction-budgets", &self.redaction_budgets);
        let summary_id = stable_id(
            "operator-summary",
            &[
                HashPart::U64(request.slot),
                HashPart::Str(&redaction_budget_root),
                HashPart::Str(&request.risk_summary_root),
            ],
        );
        let summary = OperatorSafeSummary {
            summary_id: summary_id.clone(),
            slot: request.slot,
            policy_count: self.policies.len() as u64,
            active_cohort_count,
            sealed_bid_count: self.sealed_bids.len() as u64,
            open_window_count,
            settled_receipt_count: self.settlement_receipts.len() as u64,
            median_fee_bps: request.median_fee_bps,
            median_rebate_bps: request.median_rebate_bps,
            aggregate_quorum_bps: request.aggregate_quorum_bps,
            redaction_budget_root,
            risk_summary_root: request.risk_summary_root,
        };
        self.operator_summaries.insert(summary_id, summary.clone());
        self.counters.operator_summaries = self.operator_summaries.len() as u64;
        self.refresh_roots();
        Ok(summary)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.root(),
            counter_root: self.counters.root(),
            policy_root: map_root("policies", &self.policies),
            signer_cohort_root: map_root("signer-cohorts", &self.signer_cohorts),
            sealed_bid_root: map_root("sealed-bids", &self.sealed_bids),
            pq_attestation_root: map_root("pq-attestations", &self.pq_attestations),
            approval_window_root: map_root("approval-windows", &self.approval_windows),
            settlement_receipt_root: map_root("settlement-receipts", &self.settlement_receipts),
            low_fee_rebate_root: map_root("low-fee-rebates", &self.low_fee_rebates),
            redaction_budget_root: map_root("redaction-budgets", &self.redaction_budgets),
            operator_summary_root: map_root("operator-summaries", &self.operator_summaries),
            public_record_root: empty_root("public-record"),
            state_root: empty_root("state"),
        }
    }

    pub fn refresh_roots(&mut self) {
        let mut roots = self.roots();
        let record = self.public_record_without_state_root_with_roots(&roots);
        roots.public_record_root = public_record_root(&record);
        roots.state_root = state_root_from_record(&record);
        self.roots = roots;
    }

    pub fn public_record_without_state_root(&self) -> Value {
        self.public_record_without_state_root_with_roots(&self.roots)
    }

    pub fn public_record_without_state_root_with_roots(&self, roots: &Roots) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "schemes": {
                "hash": HASH_SUITE,
                "pq_signature": PQ_SIGNATURE_SUITE,
                "pq_attestation": PQ_ATTESTATION_SUITE,
                "sealed_bid": SEALED_BID_SCHEME,
                "policy": POLICY_SCHEME,
                "cohort": COHORT_SCHEME,
                "window": WINDOW_SCHEME,
                "receipt": RECEIPT_SCHEME,
                "rebate": REBATE_SCHEME,
                "redaction": REDACTION_SCHEME,
            },
            "config": self.config,
            "counters": self.counters,
            "roots": {
                "config_root": roots.config_root,
                "counter_root": roots.counter_root,
                "policy_root": roots.policy_root,
                "signer_cohort_root": roots.signer_cohort_root,
                "sealed_bid_root": roots.sealed_bid_root,
                "pq_attestation_root": roots.pq_attestation_root,
                "approval_window_root": roots.approval_window_root,
                "settlement_receipt_root": roots.settlement_receipt_root,
                "low_fee_rebate_root": roots.low_fee_rebate_root,
                "redaction_budget_root": roots.redaction_budget_root,
                "operator_summary_root": roots.operator_summary_root,
            },
            "policies": self.policies.values().map(WithdrawalAuthorizationPolicy::public_record).collect::<Vec<_>>(),
            "signer_cohorts": self.signer_cohorts.values().map(SignerCohort::public_record).collect::<Vec<_>>(),
            "sealed_bids": self.sealed_bids.values().map(SealedAuthorizationBid::public_record).collect::<Vec<_>>(),
            "pq_attestations": self.pq_attestations.values().map(PqAuthorizationAttestation::public_record).collect::<Vec<_>>(),
            "approval_windows": self.approval_windows.values().map(ApprovalWindow::public_record).collect::<Vec<_>>(),
            "settlement_receipts": self.settlement_receipts.values().map(SettlementReceipt::public_record).collect::<Vec<_>>(),
            "low_fee_rebates": self.low_fee_rebates.values().collect::<Vec<_>>(),
            "redaction_budgets": self.redaction_budgets.values().collect::<Vec<_>>(),
            "operator_summaries": self.operator_summaries.values().collect::<Vec<_>>(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(map) = &mut record {
            map.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }
}

impl AsRef<str> for AttestationKind {
    fn as_ref(&self) -> &str {
        match self {
            Self::PolicySatisfied => "policy_satisfied",
            Self::WithdrawalNoteValid => "withdrawal_note_valid",
            Self::FeeBoundObserved => "fee_bound_observed",
            Self::RedactionBudgetObserved => "redaction_budget_observed",
            Self::MoneroSettlementObserved => "monero_settlement_observed",
            Self::FraudWarning => "fraud_warning",
        }
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let cohort = state
        .register_signer_cohort(RegisterCohortRequest {
            cohort_commitment_root: sample_hash("cohort-commitment", 1),
            slh_dsa_public_key_set_root: sample_hash("slh-dsa-key-set", 1),
            membership_nullifier_root: sample_hash("membership-nullifier", 1),
            stake_commitment_root: sample_hash("stake-commitment", 1),
            operator_hint_root: sample_hash("operator-hint", 1),
            signer_count: 128,
            active_weight_bps: MAX_BPS,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            rotation_epoch: 7,
            activation_slot: DEVNET_SLOT,
            expiry_slot: DEVNET_SLOT + 8_640,
        })
        .expect("devnet slh-dsa signer cohort registered");
    let policy = state
        .register_policy(RegisterPolicyRequest {
            kind: WithdrawalPolicyKind::FastExit,
            cohort_id: cohort.cohort_id.clone(),
            policy_commitment_root: sample_hash("policy-commitment", 1),
            withdrawal_predicate_root: sample_hash("withdrawal-predicate", 1),
            fee_bound_root: sample_hash("fee-bound", 1),
            redaction_policy_root: sample_hash("redaction-policy", 1),
            authorization_quorum_bps: DEFAULT_AUTHORIZATION_QUORUM_BPS,
            max_user_fee_bps: 10,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_withdrawal_amount_piconero: 250_000_000_000,
            activation_slot: DEVNET_SLOT + 1,
            expiry_slot: DEVNET_SLOT + 4_320,
        })
        .expect("devnet withdrawal authorization policy registered");
    let bid = state
        .submit_sealed_bid(SubmitBidRequest {
            policy_id: policy.policy_id.clone(),
            sealed_bid_root: sample_hash("sealed-bid", 1),
            bidder_commitment_root: sample_hash("bidder", 1),
            fee_commitment_root: sample_hash("fee", 1),
            withdrawal_note_commitment_root: sample_hash("withdrawal-note", 1),
            monero_subaddress_hint_root: sample_hash("subaddress-hint", 1),
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE * 2,
            max_fee_bps: 9,
            requested_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            submitted_slot: DEVNET_SLOT + 4,
        })
        .expect("devnet sealed authorization bid submitted");
    let window = state
        .open_approval_window(OpenApprovalWindowRequest {
            bid_id: bid.bid_id.clone(),
            authorization_request_root: sample_hash("authorization-request", 1),
            withdrawal_batch_root: sample_hash("withdrawal-batch", 1),
            nullifier_set_root: sample_hash("nullifier-set", 1),
            fee_bound_root: sample_hash("window-fee-bound", 1),
            opened_slot: DEVNET_SLOT + 8,
        })
        .expect("devnet approval window opened");
    state
        .record_pq_attestation(RecordAttestationRequest {
            window_id: window.window_id.clone(),
            kind: AttestationKind::PolicySatisfied,
            statement_root: sample_hash("statement-policy", 1),
            slh_dsa_signature_root: sample_hash("slh-dsa-signature", 1),
            transcript_root: sample_hash("transcript", 1),
            signer_bitmap_root: sample_hash("signer-bitmap", 1),
            observed_slot: DEVNET_SLOT + 12,
            signer_weight_bps: DEFAULT_ATTESTATION_QUORUM_BPS,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        })
        .expect("devnet pq attestation recorded");
    let receipt = state
        .settle_window(SettleWindowRequest {
            window_id: window.window_id.clone(),
            monero_tx_set_root: sample_hash("monero-tx-set", 1),
            withdrawal_nullifier_root: sample_hash("withdrawal-nullifier", 1),
            authorization_transcript_root: sample_hash("authorization-transcript", 1),
            settlement_proof_root: sample_hash("settlement-proof", 1),
            operator_receipt_root: sample_hash("operator-receipt", 1),
            settled_amount_piconero: 125_000_000_000,
            charged_fee_piconero: 112_500_000,
            settled_slot: DEVNET_SLOT + 20,
        })
        .expect("devnet approval window settled");
    state
        .issue_low_fee_rebate(IssueRebateRequest {
            receipt_id: receipt.receipt_id.clone(),
            sponsor_pool_root: sample_hash("sponsor-pool", 1),
            beneficiary_commitment_root: sample_hash("beneficiary", 1),
            rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            rebate_amount_piconero: 10_000_000,
            issued_slot: DEVNET_SLOT + 21,
            expires_slot: DEVNET_SLOT + 1_000,
        })
        .expect("devnet low fee rebate issued");
    state
        .publish_redaction_budget(PublishRedactionBudgetRequest {
            target_id: receipt.receipt_id,
            public_fields: [
                "receipt_id",
                "window_id",
                "policy_id",
                "status",
                "settled_amount_piconero",
                "charged_fee_piconero",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            redacted_fields: [
                "bidder_commitment_root",
                "monero_subaddress_hint_root",
                "slh_dsa_signature_root",
                "signer_bitmap_root",
                "withdrawal_note_commitment_root",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            max_public_bytes: DEFAULT_REDACTION_PUBLIC_BYTE_LIMIT,
            actual_public_bytes: 1_112,
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE * 2,
            published_slot: DEVNET_SLOT + 22,
        })
        .expect("devnet redaction budget published");
    state
        .publish_operator_summary(PublishOperatorSummaryRequest {
            slot: DEVNET_SLOT + 24,
            median_fee_bps: 9,
            median_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            aggregate_quorum_bps: DEFAULT_ATTESTATION_QUORUM_BPS,
            risk_summary_root: sample_hash("risk-summary", 1),
        })
        .expect("devnet operator summary published");
    state.refresh_roots();
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    let cohort = state
        .register_signer_cohort(RegisterCohortRequest {
            cohort_commitment_root: sample_hash("cohort-commitment", 2),
            slh_dsa_public_key_set_root: sample_hash("slh-dsa-key-set", 2),
            membership_nullifier_root: sample_hash("membership-nullifier", 2),
            stake_commitment_root: sample_hash("stake-commitment", 2),
            operator_hint_root: sample_hash("operator-hint", 2),
            signer_count: 96,
            active_weight_bps: 9_400,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            rotation_epoch: 8,
            activation_slot: DEVNET_SLOT + 120,
            expiry_slot: DEVNET_SLOT + 9_000,
        })
        .expect("demo emergency signer cohort registered");
    state
        .register_policy(RegisterPolicyRequest {
            kind: WithdrawalPolicyKind::EmergencyExit,
            cohort_id: cohort.cohort_id,
            policy_commitment_root: sample_hash("policy-commitment", 2),
            withdrawal_predicate_root: sample_hash("withdrawal-predicate", 2),
            fee_bound_root: sample_hash("fee-bound", 2),
            redaction_policy_root: sample_hash("redaction-policy", 2),
            authorization_quorum_bps: 8_200,
            max_user_fee_bps: 12,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE * 4,
            max_withdrawal_amount_piconero: 500_000_000_000,
            activation_slot: DEVNET_SLOT + 128,
            expiry_slot: DEVNET_SLOT + 5_000,
        })
        .expect("demo emergency authorization policy registered");
    state.refresh_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn public_record_root(record: &Value) -> String {
    object_root("public-record", record)
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "private-l2-pq-confidential-slh-dsa-withdrawal-authorization-market:state-root",
        &[HashPart::Json(record)],
        32,
    )
}

fn stable_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("private-l2-pq-confidential-slh-dsa-withdrawal-authorization-market:{domain}:id"),
        parts,
        24,
    )
}

fn empty_root(domain: &str) -> String {
    merkle_root(
        &format!("private-l2-pq-confidential-slh-dsa-withdrawal-authorization-market:{domain}"),
        &[],
    )
}

fn object_root<T: Serialize>(domain: &str, value: &T) -> String {
    merkle_root(
        &format!("private-l2-pq-confidential-slh-dsa-withdrawal-authorization-market:{domain}"),
        &[json!(value)],
    )
}

fn map_root<T: Serialize>(domain: &str, records: &BTreeMap<String, T>) -> String {
    let leaves = records
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("private-l2-pq-confidential-slh-dsa-withdrawal-authorization-market:{domain}"),
        &leaves,
    )
}

fn sample_hash(label: &str, index: u64) -> String {
    domain_hash(
        "private-l2-pq-confidential-slh-dsa-withdrawal-authorization-market:devnet-sample",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}

fn ensure_non_empty(value: &str, name: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    Ok(())
}

fn ensure_bps(value: u64, name: &str) -> Result<()> {
    if value > MAX_BPS {
        return Err(format!("{name} must be <= 10000"));
    }
    Ok(())
}

fn ensure_capacity(current: usize, max: usize, name: &str) -> Result<()> {
    if current >= max {
        return Err(format!("{name} capacity exceeded"));
    }
    Ok(())
}
