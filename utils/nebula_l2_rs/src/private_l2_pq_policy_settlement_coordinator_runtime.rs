use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqPolicySettlementCoordinatorRuntimeResult<T> = std::result::Result<T, String>;
pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_POLICY_SETTLEMENT_COORDINATOR_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-policy-settlement-coordinator-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_POLICY_SETTLEMENT_COORDINATOR_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-policy-settlement-coordinator-v1";
pub const LANE_POLICY_SCHEME: &str = "private-l2-pq-coordinator-lane-policy-root-v1";
pub const ADMISSION_SCHEME: &str = "private-l2-pq-coordinator-admission-ticket-root-v1";
pub const FEE_QUOTE_SCHEME: &str = "private-l2-pq-coordinator-low-fee-quote-root-v1";
pub const PRIVACY_BUDGET_SCHEME: &str = "private-l2-pq-coordinator-privacy-budget-root-v1";
pub const SETTLEMENT_BUNDLE_SCHEME: &str = "private-l2-pq-coordinator-settlement-bundle-root-v1";
pub const PRECONFIRMATION_SCHEME: &str = "private-l2-pq-coordinator-preconfirmation-root-v1";
pub const REBATE_SCHEME: &str = "private-l2-pq-coordinator-rebate-root-v1";
pub const CHALLENGE_SCHEME: &str = "private-l2-pq-coordinator-challenge-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 2_040_000;
pub const DEFAULT_MAX_LANES: usize = 16_384;
pub const DEFAULT_MAX_AUTHORIZATIONS: usize = 8_388_608;
pub const DEFAULT_MAX_ADMISSIONS: usize = 8_388_608;
pub const DEFAULT_MAX_FEE_QUOTES: usize = 8_388_608;
pub const DEFAULT_MAX_PRIVACY_RECORDS: usize = 4_194_304;
pub const DEFAULT_MAX_BUNDLES: usize = 2_097_152;
pub const DEFAULT_MAX_PRECONFIRMATIONS: usize = 8_388_608;
pub const DEFAULT_MAX_REBATES: usize = 8_388_608;
pub const DEFAULT_MAX_CHALLENGES: usize = 1_048_576;
pub const DEFAULT_MAX_INTENTS_PER_BUNDLE: usize = 65_536;
pub const DEFAULT_MAX_BUNDLE_WEIGHT: u64 = 100_000_000;
pub const DEFAULT_ADMISSION_TTL_BLOCKS: u64 = 20;
pub const DEFAULT_PQ_AUTH_TTL_BLOCKS: u64 = 40;
pub const DEFAULT_BUNDLE_TTL_BLOCKS: u64 = 8;
pub const DEFAULT_PRECONFIRMATION_TTL_BLOCKS: u64 = 6;
pub const DEFAULT_SETTLEMENT_FINALITY_BLOCKS: u64 = 8;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 6;
pub const DEFAULT_FAST_LANE_SURCHARGE_BPS: u64 = 4;
pub const DEFAULT_BATCH_DISCOUNT_BPS: u64 = 5;
pub const DEFAULT_PRIVACY_SHORTFALL_PENALTY_BPS: u64 = 20;
pub const DEFAULT_STALE_BUNDLE_SLASH_BPS: u64 = 1_500;
pub const DEFAULT_INVALID_PQ_SLASH_BPS: u64 = 4_000;
pub const DEFAULT_PRIVACY_LEAK_SLASH_BPS: u64 = 6_000;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoordinatorLane {
    MoneroBridge,
    ConfidentialTransfer,
    TokenRuntime,
    SmartContractVm,
    DefiSwap,
    Lending,
    Perpetuals,
    Options,
    Vault,
    Oracle,
    AccountAbstraction,
    Paymaster,
    ProofAggregation,
    DataAvailability,
    Governance,
    Emergency,
}

impl CoordinatorLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroBridge => "monero_bridge",
            Self::ConfidentialTransfer => "confidential_transfer",
            Self::TokenRuntime => "token_runtime",
            Self::SmartContractVm => "smart_contract_vm",
            Self::DefiSwap => "defi_swap",
            Self::Lending => "lending",
            Self::Perpetuals => "perpetuals",
            Self::Options => "options",
            Self::Vault => "vault",
            Self::Oracle => "oracle",
            Self::AccountAbstraction => "account_abstraction",
            Self::Paymaster => "paymaster",
            Self::ProofAggregation => "proof_aggregation",
            Self::DataAvailability => "data_availability",
            Self::Governance => "governance",
            Self::Emergency => "emergency",
        }
    }

    pub fn latency_weight(self) -> u64 {
        match self {
            Self::Emergency => 10_000,
            Self::MoneroBridge => 9_800,
            Self::Perpetuals => 9_500,
            Self::DefiSwap => 9_200,
            Self::Lending => 9_000,
            Self::Vault => 8_800,
            Self::SmartContractVm => 8_600,
            Self::TokenRuntime => 8_400,
            Self::ConfidentialTransfer => 8_200,
            Self::AccountAbstraction => 8_000,
            Self::Paymaster => 7_800,
            Self::Oracle => 7_600,
            Self::Options => 7_400,
            Self::ProofAggregation => 7_200,
            Self::DataAvailability => 7_000,
            Self::Governance => 6_500,
        }
    }

    pub fn defi_relevant(self) -> bool {
        matches!(
            self,
            Self::DefiSwap
                | Self::Lending
                | Self::Perpetuals
                | Self::Options
                | Self::Vault
                | Self::Oracle
                | Self::TokenRuntime
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionMode {
    Normal,
    Fast,
    BatchCheap,
    PrivacyFirst,
    Emergency,
}

impl AdmissionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Fast => "fast",
            Self::BatchCheap => "batch_cheap",
            Self::PrivacyFirst => "privacy_first",
            Self::Emergency => "emergency",
        }
    }

    pub fn latency_multiplier(self) -> u64 {
        match self {
            Self::Emergency => 5,
            Self::Fast => 4,
            Self::Normal => 3,
            Self::PrivacyFirst => 2,
            Self::BatchCheap => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeePolicy {
    UserPays,
    Sponsored,
    RebateEligible,
    BatchDiscount,
    EmergencyWaived,
}

impl FeePolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserPays => "user_pays",
            Self::Sponsored => "sponsored",
            Self::RebateEligible => "rebate_eligible",
            Self::BatchDiscount => "batch_discount",
            Self::EmergencyWaived => "emergency_waived",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyClass {
    Standard,
    DeFi,
    ContractState,
    BridgeWithdrawal,
    Governance,
    Emergency,
}

impl PrivacyClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::DeFi => "defi",
            Self::ContractState => "contract_state",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::Governance => "governance",
            Self::Emergency => "emergency",
        }
    }

    pub fn min_set_multiplier(self) -> u64 {
        match self {
            Self::Emergency => 8,
            Self::BridgeWithdrawal => 6,
            Self::ContractState => 5,
            Self::DeFi => 4,
            Self::Governance => 3,
            Self::Standard => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    Admitted,
    Bundled,
    Preconfirmed,
    Settled,
    Expired,
    Rejected,
    Challenged,
}

impl TicketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::Bundled => "bundled",
            Self::Preconfirmed => "preconfirmed",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Challenged => "challenged",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Admitted | Self::Bundled | Self::Preconfirmed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleStatus {
    Open,
    Sealed,
    Preconfirmed,
    Settled,
    Expired,
    Challenged,
    Rejected,
}

impl BundleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Preconfirmed => "preconfirmed",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
            Self::Rejected => "rejected",
        }
    }

    pub fn accepts_tickets(self) -> bool {
        matches!(self, Self::Open)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    InvalidPqAuthorization,
    PrivacySetShortfall,
    FeeOvercharge,
    InvalidStateRoot,
    StaleBundle,
    MissingDa,
    SequencerCensorship,
    BridgeReserveMismatch,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidPqAuthorization => "invalid_pq_authorization",
            Self::PrivacySetShortfall => "privacy_set_shortfall",
            Self::FeeOvercharge => "fee_overcharge",
            Self::InvalidStateRoot => "invalid_state_root",
            Self::StaleBundle => "stale_bundle",
            Self::MissingDa => "missing_da",
            Self::SequencerCensorship => "sequencer_censorship",
            Self::BridgeReserveMismatch => "bridge_reserve_mismatch",
        }
    }

    pub fn default_slash_bps(self, config: &Config) -> u64 {
        match self {
            Self::InvalidPqAuthorization => config.invalid_pq_slash_bps,
            Self::PrivacySetShortfall => config.privacy_leak_slash_bps,
            Self::StaleBundle => config.stale_bundle_slash_bps,
            Self::BridgeReserveMismatch => config.privacy_leak_slash_bps,
            Self::MissingDa => config.stale_bundle_slash_bps,
            Self::InvalidStateRoot => config.invalid_pq_slash_bps,
            Self::FeeOvercharge => config.stale_bundle_slash_bps / 2,
            Self::SequencerCensorship => config.stale_bundle_slash_bps,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub devnet_height: u64,
    pub max_lanes: usize,
    pub max_authorizations: usize,
    pub max_admissions: usize,
    pub max_fee_quotes: usize,
    pub max_privacy_records: usize,
    pub max_bundles: usize,
    pub max_preconfirmations: usize,
    pub max_rebates: usize,
    pub max_challenges: usize,
    pub max_intents_per_bundle: usize,
    pub max_bundle_weight: u64,
    pub admission_ttl_blocks: u64,
    pub pq_auth_ttl_blocks: u64,
    pub bundle_ttl_blocks: u64,
    pub preconfirmation_ttl_blocks: u64,
    pub settlement_finality_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub fast_lane_surcharge_bps: u64,
    pub batch_discount_bps: u64,
    pub privacy_shortfall_penalty_bps: u64,
    pub stale_bundle_slash_bps: u64,
    pub invalid_pq_slash_bps: u64,
    pub privacy_leak_slash_bps: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            devnet_height: DEVNET_HEIGHT,
            max_lanes: DEFAULT_MAX_LANES,
            max_authorizations: DEFAULT_MAX_AUTHORIZATIONS,
            max_admissions: DEFAULT_MAX_ADMISSIONS,
            max_fee_quotes: DEFAULT_MAX_FEE_QUOTES,
            max_privacy_records: DEFAULT_MAX_PRIVACY_RECORDS,
            max_bundles: DEFAULT_MAX_BUNDLES,
            max_preconfirmations: DEFAULT_MAX_PRECONFIRMATIONS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_challenges: DEFAULT_MAX_CHALLENGES,
            max_intents_per_bundle: DEFAULT_MAX_INTENTS_PER_BUNDLE,
            max_bundle_weight: DEFAULT_MAX_BUNDLE_WEIGHT,
            admission_ttl_blocks: DEFAULT_ADMISSION_TTL_BLOCKS,
            pq_auth_ttl_blocks: DEFAULT_PQ_AUTH_TTL_BLOCKS,
            bundle_ttl_blocks: DEFAULT_BUNDLE_TTL_BLOCKS,
            preconfirmation_ttl_blocks: DEFAULT_PRECONFIRMATION_TTL_BLOCKS,
            settlement_finality_blocks: DEFAULT_SETTLEMENT_FINALITY_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            fast_lane_surcharge_bps: DEFAULT_FAST_LANE_SURCHARGE_BPS,
            batch_discount_bps: DEFAULT_BATCH_DISCOUNT_BPS,
            privacy_shortfall_penalty_bps: DEFAULT_PRIVACY_SHORTFALL_PENALTY_BPS,
            stale_bundle_slash_bps: DEFAULT_STALE_BUNDLE_SLASH_BPS,
            invalid_pq_slash_bps: DEFAULT_INVALID_PQ_SLASH_BPS,
            privacy_leak_slash_bps: DEFAULT_PRIVACY_LEAK_SLASH_BPS,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub lanes_registered: u64,
    pub authorizations_attached: u64,
    pub admission_tickets: u64,
    pub fee_quotes: u64,
    pub privacy_records: u64,
    pub settlement_bundles: u64,
    pub bundled_tickets: u64,
    pub preconfirmations: u64,
    pub settled_bundles: u64,
    pub rebates: u64,
    pub challenges: u64,
    pub resolved_challenges: u64,
    pub expired_tickets: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub lane_policy_root: String,
    pub pq_authorization_root: String,
    pub admission_ticket_root: String,
    pub fee_quote_root: String,
    pub privacy_budget_root: String,
    pub settlement_bundle_root: String,
    pub preconfirmation_root: String,
    pub rebate_root: String,
    pub challenge_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LanePolicy {
    pub lane_id: String,
    pub lane: CoordinatorLane,
    pub operator_commitment: String,
    pub policy_root: String,
    pub pq_verifier_root: String,
    pub max_fee_bps: u64,
    pub target_latency_ms: u64,
    pub max_bundle_weight: u64,
    pub min_privacy_set_size: u64,
    pub supports_defi: bool,
    pub supports_contracts: bool,
    pub supports_bridge: bool,
    pub paused: bool,
    pub registered_height: u64,
}

impl LanePolicy {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_policy_lane",
            "lane_id": self.lane_id,
            "lane": self.lane.as_str(),
            "operator_commitment": self.operator_commitment,
            "policy_root": self.policy_root,
            "pq_verifier_root": self.pq_verifier_root,
            "max_fee_bps": self.max_fee_bps,
            "target_latency_ms": self.target_latency_ms,
            "max_bundle_weight": self.max_bundle_weight,
            "min_privacy_set_size": self.min_privacy_set_size,
            "supports_defi": self.supports_defi,
            "supports_contracts": self.supports_contracts,
            "supports_bridge": self.supports_bridge,
            "paused": self.paused,
            "registered_height": self.registered_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterLaneRequest {
    pub lane: CoordinatorLane,
    pub operator_commitment: String,
    pub policy_payload: Value,
    pub pq_verifier_payload: Value,
    pub max_fee_bps: u64,
    pub target_latency_ms: u64,
    pub max_bundle_weight: u64,
    pub min_privacy_set_size: u64,
    pub supports_defi: bool,
    pub supports_contracts: bool,
    pub supports_bridge: bool,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAuthorization {
    pub authorization_id: String,
    pub subject_root: String,
    pub signer_commitment: String,
    pub lane_id: String,
    pub pq_signature_root: String,
    pub pq_key_root: String,
    pub security_bits: u16,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
    pub revoked: bool,
}

impl PqAuthorization {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_policy_authorization",
            "authorization_id": self.authorization_id,
            "subject_root": self.subject_root,
            "signer_commitment": self.signer_commitment,
            "lane_id": self.lane_id,
            "pq_signature_root": self.pq_signature_root,
            "pq_key_root": self.pq_key_root,
            "security_bits": self.security_bits,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
            "revoked": self.revoked,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttachPqAuthorizationRequest {
    pub subject_root: String,
    pub signer_commitment: String,
    pub lane_id: String,
    pub pq_signature_payload: Value,
    pub pq_key_payload: Value,
    pub security_bits: u16,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AdmissionRequest {
    pub lane_id: String,
    pub intent_kind: String,
    pub sealed_intent_root: String,
    pub account_commitment: String,
    pub authorization_id: String,
    pub privacy_class: PrivacyClass,
    pub admission_mode: AdmissionMode,
    pub fee_policy: FeePolicy,
    pub max_fee_bps: u64,
    pub execution_weight: u64,
    pub dependency_root: String,
    pub calldata_root: String,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AdmissionTicket {
    pub ticket_id: String,
    pub lane_id: String,
    pub intent_kind: String,
    pub sealed_intent_root: String,
    pub account_commitment: String,
    pub authorization_id: String,
    pub privacy_class: PrivacyClass,
    pub admission_mode: AdmissionMode,
    pub fee_policy: FeePolicy,
    pub quoted_fee_bps: u64,
    pub execution_weight: u64,
    pub priority_score: u64,
    pub dependency_root: String,
    pub calldata_root: String,
    pub admitted_height: u64,
    pub expires_at_height: u64,
    pub status: TicketStatus,
}

impl AdmissionTicket {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_policy_admission_ticket",
            "ticket_id": self.ticket_id,
            "lane_id": self.lane_id,
            "intent_kind": self.intent_kind,
            "sealed_intent_root": self.sealed_intent_root,
            "account_commitment": self.account_commitment,
            "authorization_id": self.authorization_id,
            "privacy_class": self.privacy_class.as_str(),
            "admission_mode": self.admission_mode.as_str(),
            "fee_policy": self.fee_policy.as_str(),
            "quoted_fee_bps": self.quoted_fee_bps,
            "execution_weight": self.execution_weight,
            "priority_score": self.priority_score,
            "dependency_root": self.dependency_root,
            "calldata_root": self.calldata_root,
            "admitted_height": self.admitted_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeQuote {
    pub quote_id: String,
    pub ticket_id: String,
    pub lane_id: String,
    pub base_fee_bps: u64,
    pub surcharge_bps: u64,
    pub discount_bps: u64,
    pub privacy_penalty_bps: u64,
    pub final_fee_bps: u64,
    pub fee_asset_id: String,
    pub rebate_eligible: bool,
    pub quoted_height: u64,
}

impl FeeQuote {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_policy_fee_quote",
            "quote_id": self.quote_id,
            "ticket_id": self.ticket_id,
            "lane_id": self.lane_id,
            "base_fee_bps": self.base_fee_bps,
            "surcharge_bps": self.surcharge_bps,
            "discount_bps": self.discount_bps,
            "privacy_penalty_bps": self.privacy_penalty_bps,
            "final_fee_bps": self.final_fee_bps,
            "fee_asset_id": self.fee_asset_id,
            "rebate_eligible": self.rebate_eligible,
            "quoted_height": self.quoted_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyBudgetRecord {
    pub privacy_record_id: String,
    pub ticket_id: String,
    pub lane_id: String,
    pub privacy_class: PrivacyClass,
    pub requested_set_size: u64,
    pub admitted_set_size: u64,
    pub nullifier_root: String,
    pub disclosure_root: String,
    pub privacy_score: u64,
    pub height: u64,
}

impl PrivacyBudgetRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_policy_privacy_budget",
            "privacy_record_id": self.privacy_record_id,
            "ticket_id": self.ticket_id,
            "lane_id": self.lane_id,
            "privacy_class": self.privacy_class.as_str(),
            "requested_set_size": self.requested_set_size,
            "admitted_set_size": self.admitted_set_size,
            "nullifier_root": self.nullifier_root,
            "disclosure_root": self.disclosure_root,
            "privacy_score": self.privacy_score,
            "height": self.height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReservePrivacyBudgetRequest {
    pub ticket_id: String,
    pub requested_set_size: u64,
    pub nullifier_payload: Value,
    pub disclosure_payload: Value,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementBundle {
    pub bundle_id: String,
    pub lane_id: String,
    pub sequencer_commitment: String,
    pub ticket_ids: Vec<String>,
    pub intent_root: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub da_root: String,
    pub recursive_proof_root: String,
    pub total_weight: u64,
    pub total_fee_bps: u64,
    pub opened_height: u64,
    pub sealed_height: Option<u64>,
    pub settled_height: Option<u64>,
    pub status: BundleStatus,
}

impl SettlementBundle {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_policy_settlement_bundle",
            "bundle_id": self.bundle_id,
            "lane_id": self.lane_id,
            "sequencer_commitment": self.sequencer_commitment,
            "ticket_ids": self.ticket_ids,
            "intent_root": self.intent_root,
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "da_root": self.da_root,
            "recursive_proof_root": self.recursive_proof_root,
            "total_weight": self.total_weight,
            "total_fee_bps": self.total_fee_bps,
            "opened_height": self.opened_height,
            "sealed_height": self.sealed_height,
            "settled_height": self.settled_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenSettlementBundleRequest {
    pub lane_id: String,
    pub sequencer_commitment: String,
    pub pre_state_root: String,
    pub da_payload: Value,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealSettlementBundleRequest {
    pub bundle_id: String,
    pub post_state_root: String,
    pub recursive_proof_payload: Value,
    pub da_payload: Value,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreconfirmationReceipt {
    pub preconfirmation_id: String,
    pub bundle_id: String,
    pub lane_id: String,
    pub sequencer_commitment: String,
    pub ticket_root: String,
    pub pq_attestation_root: String,
    pub expires_at_height: u64,
    pub issued_height: u64,
}

impl PreconfirmationReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_policy_preconfirmation",
            "preconfirmation_id": self.preconfirmation_id,
            "bundle_id": self.bundle_id,
            "lane_id": self.lane_id,
            "sequencer_commitment": self.sequencer_commitment,
            "ticket_root": self.ticket_root,
            "pq_attestation_root": self.pq_attestation_root,
            "expires_at_height": self.expires_at_height,
            "issued_height": self.issued_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateRecord {
    pub rebate_id: String,
    pub ticket_id: String,
    pub bundle_id: String,
    pub lane_id: String,
    pub account_commitment: String,
    pub quoted_fee_bps: u64,
    pub settled_fee_bps: u64,
    pub rebate_bps: u64,
    pub issued_height: u64,
}

impl RebateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_policy_rebate",
            "rebate_id": self.rebate_id,
            "ticket_id": self.ticket_id,
            "bundle_id": self.bundle_id,
            "lane_id": self.lane_id,
            "account_commitment": self.account_commitment,
            "quoted_fee_bps": self.quoted_fee_bps,
            "settled_fee_bps": self.settled_fee_bps,
            "rebate_bps": self.rebate_bps,
            "issued_height": self.issued_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChallengeRecord {
    pub challenge_id: String,
    pub bundle_id: String,
    pub ticket_id: Option<String>,
    pub challenger_commitment: String,
    pub kind: ChallengeKind,
    pub evidence_root: String,
    pub slash_bps: u64,
    pub opened_height: u64,
    pub resolved_height: Option<u64>,
    pub upheld: Option<bool>,
}

impl ChallengeRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_policy_challenge",
            "challenge_id": self.challenge_id,
            "bundle_id": self.bundle_id,
            "ticket_id": self.ticket_id,
            "challenger_commitment": self.challenger_commitment,
            "challenge_kind": self.kind.as_str(),
            "evidence_root": self.evidence_root,
            "slash_bps": self.slash_bps,
            "opened_height": self.opened_height,
            "resolved_height": self.resolved_height,
            "upheld": self.upheld,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessStatus {
    Ready,
    Warm,
    Congested,
    PrivacyLimited,
    FeeCapped,
    Paused,
    Unsafe,
}

impl ReadinessStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Warm => "warm",
            Self::Congested => "congested",
            Self::PrivacyLimited => "privacy_limited",
            Self::FeeCapped => "fee_capped",
            Self::Paused => "paused",
            Self::Unsafe => "unsafe",
        }
    }

    pub fn score(self) -> u64 {
        match self {
            Self::Ready => 10_000,
            Self::Warm => 8_500,
            Self::PrivacyLimited => 6_500,
            Self::FeeCapped => 6_000,
            Self::Congested => 4_500,
            Self::Paused => 1_000,
            Self::Unsafe => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoordinatorRiskKind {
    LanePaused,
    PrivacyBudgetMissing,
    PqAuthorizationExpiring,
    FeePressureHigh,
    BundleWeightHigh,
    ChallengeOpen,
    SettlementLagging,
    RebateBacklog,
}

impl CoordinatorRiskKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LanePaused => "lane_paused",
            Self::PrivacyBudgetMissing => "privacy_budget_missing",
            Self::PqAuthorizationExpiring => "pq_authorization_expiring",
            Self::FeePressureHigh => "fee_pressure_high",
            Self::BundleWeightHigh => "bundle_weight_high",
            Self::ChallengeOpen => "challenge_open",
            Self::SettlementLagging => "settlement_lagging",
            Self::RebateBacklog => "rebate_backlog",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LaneReadinessSnapshot {
    pub lane_id: String,
    pub lane: CoordinatorLane,
    pub status: ReadinessStatus,
    pub live_tickets: u64,
    pub total_live_weight: u64,
    pub bundle_pressure_bps: u64,
    pub fee_ceiling_bps: u64,
    pub min_privacy_set_size: u64,
    pub open_bundles: u64,
    pub challenged_bundles: u64,
    pub priority_score: u64,
}

impl LaneReadinessSnapshot {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_policy_lane_readiness_snapshot",
            "lane_id": self.lane_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "status_score": self.status.score(),
            "live_tickets": self.live_tickets,
            "total_live_weight": self.total_live_weight,
            "bundle_pressure_bps": self.bundle_pressure_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "open_bundles": self.open_bundles,
            "challenged_bundles": self.challenged_bundles,
            "priority_score": self.priority_score,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeePressureSnapshot {
    pub lane_id: String,
    pub live_tickets: u64,
    pub quoted_fee_bps_sum: u64,
    pub average_fee_bps: u64,
    pub max_fee_bps: u64,
    pub rebate_eligible_tickets: u64,
    pub pressure_bps: u64,
    pub capped: bool,
}

impl FeePressureSnapshot {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_policy_fee_pressure_snapshot",
            "lane_id": self.lane_id,
            "live_tickets": self.live_tickets,
            "quoted_fee_bps_sum": self.quoted_fee_bps_sum,
            "average_fee_bps": self.average_fee_bps,
            "max_fee_bps": self.max_fee_bps,
            "rebate_eligible_tickets": self.rebate_eligible_tickets,
            "pressure_bps": self.pressure_bps,
            "capped": self.capped,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyReadinessSnapshot {
    pub lane_id: String,
    pub live_tickets: u64,
    pub privacy_records: u64,
    pub missing_budget: u64,
    pub average_privacy_score: u64,
    pub minimum_admitted_set_size: u64,
    pub target_privacy_set_size: u64,
    pub status: ReadinessStatus,
}

impl PrivacyReadinessSnapshot {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_policy_privacy_readiness_snapshot",
            "lane_id": self.lane_id,
            "live_tickets": self.live_tickets,
            "privacy_records": self.privacy_records,
            "missing_budget": self.missing_budget,
            "average_privacy_score": self.average_privacy_score,
            "minimum_admitted_set_size": self.minimum_admitted_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BundleCandidatePlan {
    pub lane_id: String,
    pub candidate_ticket_ids: Vec<String>,
    pub candidate_weight: u64,
    pub candidate_fee_bps: u64,
    pub candidate_priority_score: u64,
    pub privacy_ready: bool,
    pub expected_bundle_pressure_bps: u64,
}

impl BundleCandidatePlan {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_policy_bundle_candidate_plan",
            "lane_id": self.lane_id,
            "candidate_ticket_ids": self.candidate_ticket_ids,
            "candidate_weight": self.candidate_weight,
            "candidate_fee_bps": self.candidate_fee_bps,
            "candidate_priority_score": self.candidate_priority_score,
            "privacy_ready": self.privacy_ready,
            "expected_bundle_pressure_bps": self.expected_bundle_pressure_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CoordinatorRiskEvent {
    pub risk_id: String,
    pub kind: CoordinatorRiskKind,
    pub lane_id: Option<String>,
    pub subject_id: String,
    pub severity_bps: u64,
    pub evidence_root: String,
}

impl CoordinatorRiskEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_policy_risk_event",
            "risk_id": self.risk_id,
            "risk_kind": self.kind.as_str(),
            "lane_id": self.lane_id,
            "subject_id": self.subject_id,
            "severity_bps": self.severity_bps,
            "evidence_root": self.evidence_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CoordinatorReadinessReport {
    pub report_id: String,
    pub state_root: String,
    pub lane_root: String,
    pub fee_pressure_root: String,
    pub privacy_readiness_root: String,
    pub bundle_plan_root: String,
    pub risk_root: String,
    pub ready_lanes: u64,
    pub congested_lanes: u64,
    pub privacy_limited_lanes: u64,
    pub paused_lanes: u64,
    pub live_tickets: u64,
    pub open_bundles: u64,
    pub open_challenges: u64,
}

impl CoordinatorReadinessReport {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_policy_readiness_report",
            "report_id": self.report_id,
            "state_root": self.state_root,
            "lane_root": self.lane_root,
            "fee_pressure_root": self.fee_pressure_root,
            "privacy_readiness_root": self.privacy_readiness_root,
            "bundle_plan_root": self.bundle_plan_root,
            "risk_root": self.risk_root,
            "ready_lanes": self.ready_lanes,
            "congested_lanes": self.congested_lanes,
            "privacy_limited_lanes": self.privacy_limited_lanes,
            "paused_lanes": self.paused_lanes,
            "live_tickets": self.live_tickets,
            "open_bundles": self.open_bundles,
            "open_challenges": self.open_challenges,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub lane_policies: BTreeMap<String, LanePolicy>,
    pub pq_authorizations: BTreeMap<String, PqAuthorization>,
    pub admission_tickets: BTreeMap<String, AdmissionTicket>,
    pub fee_quotes: BTreeMap<String, FeeQuote>,
    pub privacy_records: BTreeMap<String, PrivacyBudgetRecord>,
    pub settlement_bundles: BTreeMap<String, SettlementBundle>,
    pub preconfirmations: BTreeMap<String, PreconfirmationReceipt>,
    pub rebates: BTreeMap<String, RebateRecord>,
    pub challenges: BTreeMap<String, ChallengeRecord>,
}

impl State {
    pub fn lane_readiness_snapshots(&self) -> Vec<LaneReadinessSnapshot> {
        self.lane_policies
            .values()
            .map(|lane| {
                let tickets = self
                    .admission_tickets
                    .values()
                    .filter(|ticket| ticket.lane_id == lane.lane_id && ticket.status.live())
                    .collect::<Vec<_>>();
                let live_tickets = tickets.len() as u64;
                let total_live_weight = tickets
                    .iter()
                    .map(|ticket| ticket.execution_weight)
                    .fold(0_u64, u64::saturating_add);
                let open_bundles = self
                    .settlement_bundles
                    .values()
                    .filter(|bundle| {
                        bundle.lane_id == lane.lane_id
                            && matches!(bundle.status, BundleStatus::Open | BundleStatus::Sealed)
                    })
                    .count() as u64;
                let challenged_bundles = self
                    .settlement_bundles
                    .values()
                    .filter(|bundle| {
                        bundle.lane_id == lane.lane_id
                            && matches!(bundle.status, BundleStatus::Challenged)
                    })
                    .count() as u64;
                let bundle_pressure_bps = total_live_weight
                    .saturating_mul(MAX_BPS)
                    .checked_div(lane.max_bundle_weight.max(1))
                    .unwrap_or(0)
                    .min(MAX_BPS);
                let missing_privacy = tickets
                    .iter()
                    .filter(|ticket| {
                        !self
                            .privacy_records
                            .values()
                            .any(|record| record.ticket_id == ticket.ticket_id)
                    })
                    .count() as u64;
                let status = if lane.paused {
                    ReadinessStatus::Paused
                } else if challenged_bundles > 0 {
                    ReadinessStatus::Unsafe
                } else if missing_privacy > 0 {
                    ReadinessStatus::PrivacyLimited
                } else if lane.max_fee_bps >= self.config.max_user_fee_bps {
                    ReadinessStatus::FeeCapped
                } else if bundle_pressure_bps > 8_500 {
                    ReadinessStatus::Congested
                } else if live_tickets > 0 || open_bundles > 0 {
                    ReadinessStatus::Warm
                } else {
                    ReadinessStatus::Ready
                };
                LaneReadinessSnapshot {
                    lane_id: lane.lane_id.clone(),
                    lane: lane.lane,
                    status,
                    live_tickets,
                    total_live_weight,
                    bundle_pressure_bps,
                    fee_ceiling_bps: lane.max_fee_bps,
                    min_privacy_set_size: lane.min_privacy_set_size,
                    open_bundles,
                    challenged_bundles,
                    priority_score: lane.lane.latency_weight().saturating_add(status.score()),
                }
            })
            .collect()
    }

    pub fn fee_pressure_snapshot(&self, lane_id: &str) -> FeePressureSnapshot {
        let tickets = self
            .admission_tickets
            .values()
            .filter(|ticket| ticket.lane_id == lane_id && ticket.status.live())
            .collect::<Vec<_>>();
        let live_tickets = tickets.len() as u64;
        let quoted_fee_bps_sum = tickets
            .iter()
            .map(|ticket| ticket.quoted_fee_bps)
            .fold(0_u64, u64::saturating_add);
        let average_fee_bps = quoted_fee_bps_sum
            .checked_div(live_tickets.max(1))
            .unwrap_or(0);
        let max_fee_bps = tickets
            .iter()
            .map(|ticket| ticket.quoted_fee_bps)
            .max()
            .unwrap_or(0);
        let rebate_eligible_tickets = tickets
            .iter()
            .filter(|ticket| {
                matches!(
                    ticket.fee_policy,
                    FeePolicy::RebateEligible | FeePolicy::BatchDiscount | FeePolicy::Sponsored
                )
            })
            .count() as u64;
        let pressure_bps = average_fee_bps
            .saturating_mul(MAX_BPS)
            .checked_div(self.config.max_user_fee_bps.max(1))
            .unwrap_or(0)
            .min(MAX_BPS);
        FeePressureSnapshot {
            lane_id: lane_id.to_string(),
            live_tickets,
            quoted_fee_bps_sum,
            average_fee_bps,
            max_fee_bps,
            rebate_eligible_tickets,
            pressure_bps,
            capped: max_fee_bps >= self.config.max_user_fee_bps,
        }
    }

    pub fn privacy_readiness_snapshot(&self, lane_id: &str) -> PrivacyReadinessSnapshot {
        let tickets = self
            .admission_tickets
            .values()
            .filter(|ticket| ticket.lane_id == lane_id && ticket.status.live())
            .collect::<Vec<_>>();
        let ticket_ids = tickets
            .iter()
            .map(|ticket| ticket.ticket_id.clone())
            .collect::<BTreeSet<_>>();
        let records = self
            .privacy_records
            .values()
            .filter(|record| ticket_ids.contains(&record.ticket_id))
            .collect::<Vec<_>>();
        let live_tickets = tickets.len() as u64;
        let privacy_records = records.len() as u64;
        let missing_budget = live_tickets.saturating_sub(privacy_records);
        let total_score = records
            .iter()
            .map(|record| record.privacy_score)
            .fold(0_u64, u64::saturating_add);
        let average_privacy_score = total_score.checked_div(privacy_records.max(1)).unwrap_or(0);
        let minimum_admitted_set_size = records
            .iter()
            .map(|record| record.admitted_set_size)
            .min()
            .unwrap_or(0);
        let status = if missing_budget > 0 {
            ReadinessStatus::PrivacyLimited
        } else if average_privacy_score >= 10_000 {
            ReadinessStatus::Ready
        } else if average_privacy_score >= 6_500 {
            ReadinessStatus::Warm
        } else {
            ReadinessStatus::PrivacyLimited
        };
        PrivacyReadinessSnapshot {
            lane_id: lane_id.to_string(),
            live_tickets,
            privacy_records,
            missing_budget,
            average_privacy_score,
            minimum_admitted_set_size,
            target_privacy_set_size: self.config.target_privacy_set_size,
            status,
        }
    }

    pub fn bundle_candidate_plan(&self, lane_id: &str, max_tickets: usize) -> BundleCandidatePlan {
        let privacy_ready_ids = self
            .privacy_records
            .values()
            .map(|record| record.ticket_id.clone())
            .collect::<BTreeSet<_>>();
        let mut tickets = self
            .admission_tickets
            .values()
            .filter(|ticket| ticket.lane_id == lane_id && ticket.status == TicketStatus::Admitted)
            .cloned()
            .collect::<Vec<_>>();
        tickets.sort_by(|left, right| {
            right
                .priority_score
                .cmp(&left.priority_score)
                .then_with(|| left.quoted_fee_bps.cmp(&right.quoted_fee_bps))
                .then_with(|| left.admitted_height.cmp(&right.admitted_height))
        });

        let mut candidate_ticket_ids = Vec::new();
        let mut candidate_weight = 0_u64;
        let mut candidate_fee_bps = 0_u64;
        let mut candidate_priority_score = 0_u64;
        let mut privacy_ready = true;
        for ticket in tickets.into_iter().take(max_tickets) {
            if candidate_weight.saturating_add(ticket.execution_weight)
                > self.config.max_bundle_weight
            {
                continue;
            }
            privacy_ready &= privacy_ready_ids.contains(&ticket.ticket_id);
            candidate_weight = candidate_weight.saturating_add(ticket.execution_weight);
            candidate_fee_bps = candidate_fee_bps.saturating_add(ticket.quoted_fee_bps);
            candidate_priority_score =
                candidate_priority_score.saturating_add(ticket.priority_score);
            candidate_ticket_ids.push(ticket.ticket_id);
        }
        let expected_bundle_pressure_bps = candidate_weight
            .saturating_mul(MAX_BPS)
            .checked_div(self.config.max_bundle_weight.max(1))
            .unwrap_or(0)
            .min(MAX_BPS);
        BundleCandidatePlan {
            lane_id: lane_id.to_string(),
            candidate_ticket_ids,
            candidate_weight,
            candidate_fee_bps,
            candidate_priority_score,
            privacy_ready,
            expected_bundle_pressure_bps,
        }
    }

    pub fn coordinator_risk_events(&self, height: u64) -> Vec<CoordinatorRiskEvent> {
        let mut events = Vec::new();
        for lane in self.lane_policies.values() {
            if lane.paused {
                events.push(self.risk_event(
                    CoordinatorRiskKind::LanePaused,
                    Some(lane.lane_id.clone()),
                    &lane.lane_id,
                    9_000,
                    &lane.public_record(),
                ));
            }
            let fee = self.fee_pressure_snapshot(&lane.lane_id);
            if fee.pressure_bps > 8_500 {
                events.push(self.risk_event(
                    CoordinatorRiskKind::FeePressureHigh,
                    Some(lane.lane_id.clone()),
                    &lane.lane_id,
                    fee.pressure_bps,
                    &fee.public_record(),
                ));
            }
            let privacy = self.privacy_readiness_snapshot(&lane.lane_id);
            if privacy.missing_budget > 0 {
                events.push(self.risk_event(
                    CoordinatorRiskKind::PrivacyBudgetMissing,
                    Some(lane.lane_id.clone()),
                    &lane.lane_id,
                    privacy.missing_budget.saturating_mul(1_000).min(MAX_BPS),
                    &privacy.public_record(),
                ));
            }
        }
        for authorization in self.pq_authorizations.values() {
            if !authorization.revoked && authorization.expires_at_height <= height.saturating_add(4)
            {
                events.push(self.risk_event(
                    CoordinatorRiskKind::PqAuthorizationExpiring,
                    Some(authorization.lane_id.clone()),
                    &authorization.authorization_id,
                    7_500,
                    &authorization.public_record(),
                ));
            }
        }
        for bundle in self.settlement_bundles.values() {
            if bundle.total_weight > self.config.max_bundle_weight.saturating_mul(9) / 10 {
                events.push(self.risk_event(
                    CoordinatorRiskKind::BundleWeightHigh,
                    Some(bundle.lane_id.clone()),
                    &bundle.bundle_id,
                    8_500,
                    &bundle.public_record(),
                ));
            }
            if bundle.status == BundleStatus::Challenged {
                events.push(self.risk_event(
                    CoordinatorRiskKind::ChallengeOpen,
                    Some(bundle.lane_id.clone()),
                    &bundle.bundle_id,
                    9_000,
                    &bundle.public_record(),
                ));
            }
            if bundle.status == BundleStatus::Sealed
                && height
                    > bundle
                        .opened_height
                        .saturating_add(self.config.bundle_ttl_blocks)
            {
                events.push(self.risk_event(
                    CoordinatorRiskKind::SettlementLagging,
                    Some(bundle.lane_id.clone()),
                    &bundle.bundle_id,
                    7_000,
                    &bundle.public_record(),
                ));
            }
        }
        let settled_ticket_ids = self
            .admission_tickets
            .values()
            .filter(|ticket| ticket.status == TicketStatus::Settled)
            .map(|ticket| ticket.ticket_id.clone())
            .collect::<BTreeSet<_>>();
        let rebated_ticket_ids = self
            .rebates
            .values()
            .map(|rebate| rebate.ticket_id.clone())
            .collect::<BTreeSet<_>>();
        let rebate_backlog = settled_ticket_ids
            .difference(&rebated_ticket_ids)
            .take(1)
            .next()
            .cloned();
        if let Some(ticket_id) = rebate_backlog {
            events.push(self.risk_event(
                CoordinatorRiskKind::RebateBacklog,
                None,
                &ticket_id,
                5_000,
                &json!({"ticket_id": ticket_id.clone(), "state_root": self.state_root()}),
            ));
        }
        events
    }

    pub fn readiness_report(&self, height: u64) -> CoordinatorReadinessReport {
        let lanes = self.lane_readiness_snapshots();
        let fee = self
            .lane_policies
            .keys()
            .map(|lane_id| self.fee_pressure_snapshot(lane_id))
            .collect::<Vec<_>>();
        let privacy = self
            .lane_policies
            .keys()
            .map(|lane_id| self.privacy_readiness_snapshot(lane_id))
            .collect::<Vec<_>>();
        let bundle_plans = self
            .lane_policies
            .keys()
            .map(|lane_id| {
                self.bundle_candidate_plan(lane_id, self.config.max_intents_per_bundle.min(256))
            })
            .collect::<Vec<_>>();
        let risks = self.coordinator_risk_events(height);
        let ready_lanes = lanes
            .iter()
            .filter(|lane| lane.status == ReadinessStatus::Ready)
            .count() as u64;
        let congested_lanes = lanes
            .iter()
            .filter(|lane| lane.status == ReadinessStatus::Congested)
            .count() as u64;
        let privacy_limited_lanes = lanes
            .iter()
            .filter(|lane| lane.status == ReadinessStatus::PrivacyLimited)
            .count() as u64;
        let paused_lanes = lanes
            .iter()
            .filter(|lane| lane.status == ReadinessStatus::Paused)
            .count() as u64;
        let live_tickets = self
            .admission_tickets
            .values()
            .filter(|ticket| ticket.status.live())
            .count() as u64;
        let open_bundles = self
            .settlement_bundles
            .values()
            .filter(|bundle| matches!(bundle.status, BundleStatus::Open | BundleStatus::Sealed))
            .count() as u64;
        let open_challenges = self
            .challenges
            .values()
            .filter(|challenge| challenge.upheld.is_none())
            .count() as u64;
        let lane_root = public_record_root(
            "PRIVATE-L2-PQ-COORDINATOR-LANE-READINESS-ROOT",
            &lanes
                .iter()
                .map(LaneReadinessSnapshot::public_record)
                .collect::<Vec<_>>(),
        );
        let fee_pressure_root = public_record_root(
            "PRIVATE-L2-PQ-COORDINATOR-FEE-PRESSURE-ROOT",
            &fee.iter()
                .map(FeePressureSnapshot::public_record)
                .collect::<Vec<_>>(),
        );
        let privacy_readiness_root = public_record_root(
            "PRIVATE-L2-PQ-COORDINATOR-PRIVACY-READINESS-ROOT",
            &privacy
                .iter()
                .map(PrivacyReadinessSnapshot::public_record)
                .collect::<Vec<_>>(),
        );
        let bundle_plan_root = public_record_root(
            "PRIVATE-L2-PQ-COORDINATOR-BUNDLE-PLAN-ROOT",
            &bundle_plans
                .iter()
                .map(BundleCandidatePlan::public_record)
                .collect::<Vec<_>>(),
        );
        let risk_root = public_record_root(
            "PRIVATE-L2-PQ-COORDINATOR-RISK-ROOT",
            &risks
                .iter()
                .map(CoordinatorRiskEvent::public_record)
                .collect::<Vec<_>>(),
        );
        CoordinatorReadinessReport {
            report_id: domain_hash(
                "PRIVATE-L2-PQ-COORDINATOR-READINESS-REPORT-ID",
                &[
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(&self.state_root()),
                    HashPart::Str(&lane_root),
                    HashPart::Str(&risk_root),
                    HashPart::U64(height),
                ],
                32,
            ),
            state_root: self.state_root(),
            lane_root,
            fee_pressure_root,
            privacy_readiness_root,
            bundle_plan_root,
            risk_root,
            ready_lanes,
            congested_lanes,
            privacy_limited_lanes,
            paused_lanes,
            live_tickets,
            open_bundles,
            open_challenges,
        }
    }

    pub fn operator_digest(&self, height: u64) -> Value {
        let report = self.readiness_report(height);
        json!({
            "kind": "private_l2_pq_policy_operator_digest",
            "protocol_version": PROTOCOL_VERSION,
            "state_root": self.state_root(),
            "report": report.public_record(),
            "lane_count": self.lane_policies.len(),
            "live_ticket_count": report.live_tickets,
            "open_bundle_count": report.open_bundles,
            "open_challenge_count": report.open_challenges,
        })
    }

    fn risk_event(
        &self,
        kind: CoordinatorRiskKind,
        lane_id: Option<String>,
        subject_id: &str,
        severity_bps: u64,
        evidence: &Value,
    ) -> CoordinatorRiskEvent {
        let evidence_root = payload_root("PRIVATE-L2-PQ-COORDINATOR-RISK-EVIDENCE", evidence);
        CoordinatorRiskEvent {
            risk_id: domain_hash(
                "PRIVATE-L2-PQ-COORDINATOR-RISK-ID",
                &[
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(kind.as_str()),
                    HashPart::Str(subject_id),
                    HashPart::Str(&evidence_root),
                ],
                32,
            ),
            kind,
            lane_id,
            subject_id: subject_id.to_string(),
            severity_bps: severity_bps.min(MAX_BPS),
            evidence_root,
        }
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            lane_policies: BTreeMap::new(),
            pq_authorizations: BTreeMap::new(),
            admission_tickets: BTreeMap::new(),
            fee_quotes: BTreeMap::new(),
            privacy_records: BTreeMap::new(),
            settlement_bundles: BTreeMap::new(),
            preconfirmations: BTreeMap::new(),
            rebates: BTreeMap::new(),
            challenges: BTreeMap::new(),
        };
        state.recompute_roots();
        state
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::default());
        let base_height = state.config.devnet_height;
        let lanes = [
            (
                CoordinatorLane::MoneroBridge,
                "devnet-monero-bridge-operator",
                true,
                false,
                true,
            ),
            (
                CoordinatorLane::SmartContractVm,
                "devnet-contract-vm-operator",
                true,
                true,
                false,
            ),
            (
                CoordinatorLane::TokenRuntime,
                "devnet-token-runtime-operator",
                true,
                true,
                false,
            ),
            (
                CoordinatorLane::DefiSwap,
                "devnet-defi-swap-operator",
                true,
                true,
                false,
            ),
            (
                CoordinatorLane::ProofAggregation,
                "devnet-proof-aggregation-operator",
                false,
                true,
                true,
            ),
        ];

        for (offset, (lane, operator, supports_defi, supports_contracts, supports_bridge)) in
            lanes.into_iter().enumerate()
        {
            let _ = state.register_lane(RegisterLaneRequest {
                lane,
                operator_commitment: deterministic_root("DEVNET-OPERATOR", operator, offset as u64),
                policy_payload: json!({
                    "profile": "devnet",
                    "lane": lane.as_str(),
                    "priority": lane.latency_weight(),
                }),
                pq_verifier_payload: json!({
                    "suite": PQ_AUTH_SUITE,
                    "minimum_security_bits": state.config.min_pq_security_bits,
                }),
                max_fee_bps: state.config.max_user_fee_bps,
                target_latency_ms: 350 + (offset as u64 * 40),
                max_bundle_weight: state.config.max_bundle_weight / 8,
                min_privacy_set_size: state.config.min_privacy_set_size
                    * if lane.defi_relevant() { 4 } else { 1 },
                supports_defi,
                supports_contracts,
                supports_bridge,
                height: base_height,
            });
        }

        state
    }

    pub fn register_lane(&mut self, request: RegisterLaneRequest) -> Result<LanePolicy> {
        if self.lane_policies.len() >= self.config.max_lanes {
            return Err("coordinator lane limit exceeded".to_string());
        }
        if request.operator_commitment.is_empty() {
            return Err("coordinator lane operator commitment cannot be empty".to_string());
        }
        if request.max_fee_bps > self.config.max_user_fee_bps {
            return Err("coordinator lane fee exceeds protocol cap".to_string());
        }
        if request.target_latency_ms == 0 {
            return Err("coordinator lane target latency must be positive".to_string());
        }
        if request.max_bundle_weight == 0
            || request.max_bundle_weight > self.config.max_bundle_weight
        {
            return Err("coordinator lane bundle weight is out of range".to_string());
        }
        let policy_root = payload_root(LANE_POLICY_SCHEME, &request.policy_payload);
        let pq_verifier_root = payload_root(PQ_AUTH_SUITE, &request.pq_verifier_payload);
        let lane_id = lane_policy_id(
            request.lane,
            &request.operator_commitment,
            &policy_root,
            request.height,
        );
        if self.lane_policies.contains_key(&lane_id) {
            return Err("coordinator lane already registered".to_string());
        }
        let record = LanePolicy {
            lane_id: lane_id.clone(),
            lane: request.lane,
            operator_commitment: request.operator_commitment,
            policy_root,
            pq_verifier_root,
            max_fee_bps: request.max_fee_bps,
            target_latency_ms: request.target_latency_ms,
            max_bundle_weight: request.max_bundle_weight,
            min_privacy_set_size: request
                .min_privacy_set_size
                .max(self.config.min_privacy_set_size),
            supports_defi: request.supports_defi,
            supports_contracts: request.supports_contracts,
            supports_bridge: request.supports_bridge,
            paused: false,
            registered_height: request.height,
        };
        self.lane_policies.insert(lane_id, record.clone());
        self.counters.lanes_registered = self.counters.lanes_registered.saturating_add(1);
        self.recompute_roots();
        Ok(record)
    }

    pub fn set_lane_paused(&mut self, lane_id: &str, paused: bool) -> Result<LanePolicy> {
        let lane = self
            .lane_policies
            .get_mut(lane_id)
            .ok_or_else(|| "coordinator lane not found".to_string())?;
        lane.paused = paused;
        let updated = lane.clone();
        self.recompute_roots();
        Ok(updated)
    }

    pub fn attach_pq_authorization(
        &mut self,
        request: AttachPqAuthorizationRequest,
    ) -> Result<PqAuthorization> {
        if self.pq_authorizations.len() >= self.config.max_authorizations {
            return Err("coordinator pq authorization limit exceeded".to_string());
        }
        if request.subject_root.is_empty()
            || request.signer_commitment.is_empty()
            || request.lane_id.is_empty()
        {
            return Err("coordinator pq authorization identifiers cannot be empty".to_string());
        }
        if request.security_bits < self.config.min_pq_security_bits {
            return Err("coordinator pq authorization below security floor".to_string());
        }
        let lane = self
            .lane_policies
            .get(&request.lane_id)
            .ok_or_else(|| "coordinator lane missing for pq authorization".to_string())?;
        if lane.paused {
            return Err("coordinator lane paused".to_string());
        }
        let pq_signature_root = payload_root(PQ_AUTH_SUITE, &request.pq_signature_payload);
        let pq_key_root = payload_root(PQ_AUTH_SUITE, &request.pq_key_payload);
        let authorization_id = pq_authorization_id(
            &request.subject_root,
            &request.signer_commitment,
            &request.lane_id,
            &pq_signature_root,
            request.height,
        );
        if self.pq_authorizations.contains_key(&authorization_id) {
            return Err("coordinator pq authorization already exists".to_string());
        }
        let authorization = PqAuthorization {
            authorization_id: authorization_id.clone(),
            subject_root: request.subject_root,
            signer_commitment: request.signer_commitment,
            lane_id: request.lane_id,
            pq_signature_root,
            pq_key_root,
            security_bits: request.security_bits,
            valid_from_height: request.height,
            expires_at_height: request
                .height
                .saturating_add(self.config.pq_auth_ttl_blocks),
            revoked: false,
        };
        self.pq_authorizations
            .insert(authorization_id, authorization.clone());
        self.counters.authorizations_attached =
            self.counters.authorizations_attached.saturating_add(1);
        self.recompute_roots();
        Ok(authorization)
    }

    pub fn revoke_pq_authorization(&mut self, authorization_id: &str) -> Result<PqAuthorization> {
        let authorization = self
            .pq_authorizations
            .get_mut(authorization_id)
            .ok_or_else(|| "coordinator pq authorization not found".to_string())?;
        authorization.revoked = true;
        let updated = authorization.clone();
        self.recompute_roots();
        Ok(updated)
    }

    pub fn admit_execution_intent(&mut self, request: AdmissionRequest) -> Result<AdmissionTicket> {
        if self.admission_tickets.len() >= self.config.max_admissions {
            return Err("coordinator admission limit exceeded".to_string());
        }
        if request.sealed_intent_root.is_empty()
            || request.account_commitment.is_empty()
            || request.authorization_id.is_empty()
        {
            return Err("coordinator admission identifiers cannot be empty".to_string());
        }
        if request.execution_weight == 0 {
            return Err("coordinator admission execution weight must be positive".to_string());
        }
        let lane = self
            .lane_policies
            .get(&request.lane_id)
            .ok_or_else(|| "coordinator lane missing for admission".to_string())?;
        if lane.paused {
            return Err("coordinator lane paused".to_string());
        }
        if request.max_fee_bps > lane.max_fee_bps {
            return Err("coordinator admission max fee exceeds lane cap".to_string());
        }
        let authorization = self
            .pq_authorizations
            .get(&request.authorization_id)
            .ok_or_else(|| "coordinator pq authorization missing".to_string())?;
        if authorization.revoked {
            return Err("coordinator pq authorization revoked".to_string());
        }
        if authorization.lane_id != request.lane_id {
            return Err("coordinator pq authorization lane mismatch".to_string());
        }
        if request.height < authorization.valid_from_height
            || request.height > authorization.expires_at_height
        {
            return Err("coordinator pq authorization expired or not yet valid".to_string());
        }
        let quoted_fee_bps = self.estimate_fee_bps(
            lane,
            request.admission_mode,
            request.fee_policy,
            request.privacy_class,
            request.max_fee_bps,
        );
        let ticket_id = admission_ticket_id(
            &request.lane_id,
            &request.sealed_intent_root,
            &request.authorization_id,
            request.height,
        );
        if self.admission_tickets.contains_key(&ticket_id) {
            return Err("coordinator admission ticket already exists".to_string());
        }
        let priority_score = lane
            .lane
            .latency_weight()
            .saturating_mul(request.admission_mode.latency_multiplier())
            .saturating_add(request.execution_weight.min(10_000));
        let ticket = AdmissionTicket {
            ticket_id: ticket_id.clone(),
            lane_id: request.lane_id,
            intent_kind: request.intent_kind,
            sealed_intent_root: request.sealed_intent_root,
            account_commitment: request.account_commitment,
            authorization_id: request.authorization_id,
            privacy_class: request.privacy_class,
            admission_mode: request.admission_mode,
            fee_policy: request.fee_policy,
            quoted_fee_bps,
            execution_weight: request.execution_weight,
            priority_score,
            dependency_root: request.dependency_root,
            calldata_root: request.calldata_root,
            admitted_height: request.height,
            expires_at_height: request
                .height
                .saturating_add(self.config.admission_ttl_blocks),
            status: TicketStatus::Admitted,
        };
        let quote = self.make_fee_quote(&ticket, lane, request.height);
        self.admission_tickets
            .insert(ticket_id.clone(), ticket.clone());
        self.fee_quotes.insert(quote.quote_id.clone(), quote);
        self.counters.admission_tickets = self.counters.admission_tickets.saturating_add(1);
        self.counters.fee_quotes = self.counters.fee_quotes.saturating_add(1);
        self.recompute_roots();
        Ok(ticket)
    }

    pub fn reserve_privacy_budget(
        &mut self,
        request: ReservePrivacyBudgetRequest,
    ) -> Result<PrivacyBudgetRecord> {
        if self.privacy_records.len() >= self.config.max_privacy_records {
            return Err("coordinator privacy record limit exceeded".to_string());
        }
        let ticket = self
            .admission_tickets
            .get(&request.ticket_id)
            .ok_or_else(|| "coordinator ticket missing for privacy budget".to_string())?;
        if !ticket.status.live() {
            return Err("coordinator ticket cannot reserve privacy budget".to_string());
        }
        let lane = self
            .lane_policies
            .get(&ticket.lane_id)
            .ok_or_else(|| "coordinator lane missing for privacy budget".to_string())?;
        let requested_floor = self
            .config
            .min_privacy_set_size
            .saturating_mul(ticket.privacy_class.min_set_multiplier());
        let admitted_set_size = request
            .requested_set_size
            .max(lane.min_privacy_set_size)
            .max(requested_floor);
        let nullifier_root = payload_root(PRIVACY_BUDGET_SCHEME, &request.nullifier_payload);
        let disclosure_root = payload_root(PRIVACY_BUDGET_SCHEME, &request.disclosure_payload);
        let privacy_score = admitted_set_size
            .saturating_mul(100)
            .checked_div(self.config.target_privacy_set_size.max(1))
            .unwrap_or(0)
            .min(10_000);
        let privacy_record_id = privacy_budget_id(
            &request.ticket_id,
            &ticket.lane_id,
            &nullifier_root,
            request.height,
        );
        if self.privacy_records.contains_key(&privacy_record_id) {
            return Err("coordinator privacy budget already reserved".to_string());
        }
        let record = PrivacyBudgetRecord {
            privacy_record_id: privacy_record_id.clone(),
            ticket_id: request.ticket_id,
            lane_id: ticket.lane_id.clone(),
            privacy_class: ticket.privacy_class,
            requested_set_size: request.requested_set_size,
            admitted_set_size,
            nullifier_root,
            disclosure_root,
            privacy_score,
            height: request.height,
        };
        self.privacy_records
            .insert(privacy_record_id, record.clone());
        self.counters.privacy_records = self.counters.privacy_records.saturating_add(1);
        self.recompute_roots();
        Ok(record)
    }

    pub fn open_settlement_bundle(
        &mut self,
        request: OpenSettlementBundleRequest,
    ) -> Result<SettlementBundle> {
        if self.settlement_bundles.len() >= self.config.max_bundles {
            return Err("coordinator settlement bundle limit exceeded".to_string());
        }
        if request.sequencer_commitment.is_empty() || request.pre_state_root.is_empty() {
            return Err("coordinator bundle identifiers cannot be empty".to_string());
        }
        let lane = self
            .lane_policies
            .get(&request.lane_id)
            .ok_or_else(|| "coordinator lane missing for settlement bundle".to_string())?;
        if lane.paused {
            return Err("coordinator lane paused".to_string());
        }
        let da_root = payload_root(SETTLEMENT_BUNDLE_SCHEME, &request.da_payload);
        let bundle_id = settlement_bundle_id(
            &request.lane_id,
            &request.sequencer_commitment,
            &request.pre_state_root,
            request.height,
        );
        if self.settlement_bundles.contains_key(&bundle_id) {
            return Err("coordinator settlement bundle already exists".to_string());
        }
        let bundle = SettlementBundle {
            bundle_id: bundle_id.clone(),
            lane_id: request.lane_id,
            sequencer_commitment: request.sequencer_commitment,
            ticket_ids: Vec::new(),
            intent_root: public_record_root(SETTLEMENT_BUNDLE_SCHEME, &[]),
            pre_state_root: request.pre_state_root,
            post_state_root: String::new(),
            da_root,
            recursive_proof_root: String::new(),
            total_weight: 0,
            total_fee_bps: 0,
            opened_height: request.height,
            sealed_height: None,
            settled_height: None,
            status: BundleStatus::Open,
        };
        self.settlement_bundles.insert(bundle_id, bundle.clone());
        self.counters.settlement_bundles = self.counters.settlement_bundles.saturating_add(1);
        self.recompute_roots();
        Ok(bundle)
    }

    pub fn attach_ticket_to_bundle(
        &mut self,
        bundle_id: &str,
        ticket_id: &str,
    ) -> Result<SettlementBundle> {
        let ticket_snapshot = self
            .admission_tickets
            .get(ticket_id)
            .ok_or_else(|| "coordinator ticket missing for bundle attach".to_string())?
            .clone();
        if !ticket_snapshot.status.live() || ticket_snapshot.status != TicketStatus::Admitted {
            return Err("coordinator ticket is not attachable".to_string());
        }
        let bundle = self
            .settlement_bundles
            .get_mut(bundle_id)
            .ok_or_else(|| "coordinator bundle missing".to_string())?;
        if !bundle.status.accepts_tickets() {
            return Err("coordinator bundle is not open".to_string());
        }
        if bundle.lane_id != ticket_snapshot.lane_id {
            return Err("coordinator bundle lane mismatch".to_string());
        }
        if bundle.ticket_ids.len() >= self.config.max_intents_per_bundle {
            return Err("coordinator bundle ticket limit exceeded".to_string());
        }
        if bundle
            .total_weight
            .saturating_add(ticket_snapshot.execution_weight)
            > self.config.max_bundle_weight
        {
            return Err("coordinator bundle weight limit exceeded".to_string());
        }
        if bundle.ticket_ids.iter().any(|id| id == ticket_id) {
            return Err("coordinator ticket already bundled".to_string());
        }
        bundle.ticket_ids.push(ticket_id.to_string());
        bundle.total_weight = bundle
            .total_weight
            .saturating_add(ticket_snapshot.execution_weight);
        bundle.total_fee_bps = bundle
            .total_fee_bps
            .saturating_add(ticket_snapshot.quoted_fee_bps);
        bundle.intent_root = string_set_root(SETTLEMENT_BUNDLE_SCHEME, &bundle.ticket_ids);
        let updated_bundle = bundle.clone();
        if let Some(ticket) = self.admission_tickets.get_mut(ticket_id) {
            ticket.status = TicketStatus::Bundled;
        }
        self.counters.bundled_tickets = self.counters.bundled_tickets.saturating_add(1);
        self.recompute_roots();
        Ok(updated_bundle)
    }

    pub fn seal_settlement_bundle(
        &mut self,
        request: SealSettlementBundleRequest,
    ) -> Result<SettlementBundle> {
        let bundle = self
            .settlement_bundles
            .get_mut(&request.bundle_id)
            .ok_or_else(|| "coordinator bundle missing for seal".to_string())?;
        if bundle.status != BundleStatus::Open {
            return Err("coordinator bundle is not open".to_string());
        }
        if bundle.ticket_ids.is_empty() {
            return Err("coordinator cannot seal empty bundle".to_string());
        }
        if request.post_state_root.is_empty() {
            return Err("coordinator post state root cannot be empty".to_string());
        }
        bundle.post_state_root = request.post_state_root;
        bundle.recursive_proof_root =
            payload_root(SETTLEMENT_BUNDLE_SCHEME, &request.recursive_proof_payload);
        bundle.da_root = payload_root(SETTLEMENT_BUNDLE_SCHEME, &request.da_payload);
        bundle.sealed_height = Some(request.height);
        bundle.status = BundleStatus::Sealed;
        let updated = bundle.clone();
        self.recompute_roots();
        Ok(updated)
    }

    pub fn issue_preconfirmation(
        &mut self,
        bundle_id: &str,
        pq_attestation_payload: &Value,
        height: u64,
    ) -> Result<PreconfirmationReceipt> {
        if self.preconfirmations.len() >= self.config.max_preconfirmations {
            return Err("coordinator preconfirmation limit exceeded".to_string());
        }
        let bundle = self
            .settlement_bundles
            .get_mut(bundle_id)
            .ok_or_else(|| "coordinator bundle missing for preconfirmation".to_string())?;
        if bundle.status != BundleStatus::Sealed {
            return Err("coordinator bundle must be sealed before preconfirmation".to_string());
        }
        let pq_attestation_root = payload_root(PRECONFIRMATION_SCHEME, pq_attestation_payload);
        let ticket_root = string_set_root(PRECONFIRMATION_SCHEME, &bundle.ticket_ids);
        let preconfirmation_id = preconfirmation_id(
            bundle_id,
            &bundle.lane_id,
            &ticket_root,
            &pq_attestation_root,
            height,
        );
        if self.preconfirmations.contains_key(&preconfirmation_id) {
            return Err("coordinator preconfirmation already exists".to_string());
        }
        bundle.status = BundleStatus::Preconfirmed;
        for ticket_id in &bundle.ticket_ids {
            if let Some(ticket) = self.admission_tickets.get_mut(ticket_id) {
                ticket.status = TicketStatus::Preconfirmed;
            }
        }
        let receipt = PreconfirmationReceipt {
            preconfirmation_id: preconfirmation_id.clone(),
            bundle_id: bundle_id.to_string(),
            lane_id: bundle.lane_id.clone(),
            sequencer_commitment: bundle.sequencer_commitment.clone(),
            ticket_root,
            pq_attestation_root,
            expires_at_height: height.saturating_add(self.config.preconfirmation_ttl_blocks),
            issued_height: height,
        };
        self.preconfirmations
            .insert(preconfirmation_id, receipt.clone());
        self.counters.preconfirmations = self.counters.preconfirmations.saturating_add(1);
        self.recompute_roots();
        Ok(receipt)
    }

    pub fn settle_bundle(&mut self, bundle_id: &str, height: u64) -> Result<SettlementBundle> {
        let bundle = self
            .settlement_bundles
            .get_mut(bundle_id)
            .ok_or_else(|| "coordinator bundle missing for settlement".to_string())?;
        if bundle.status != BundleStatus::Preconfirmed && bundle.status != BundleStatus::Sealed {
            return Err("coordinator bundle cannot settle from current status".to_string());
        }
        if bundle.post_state_root.is_empty() || bundle.recursive_proof_root.is_empty() {
            return Err("coordinator sealed bundle roots missing".to_string());
        }
        bundle.status = BundleStatus::Settled;
        bundle.settled_height = Some(height.saturating_add(self.config.settlement_finality_blocks));
        for ticket_id in &bundle.ticket_ids {
            if let Some(ticket) = self.admission_tickets.get_mut(ticket_id) {
                ticket.status = TicketStatus::Settled;
            }
        }
        let updated = bundle.clone();
        self.counters.settled_bundles = self.counters.settled_bundles.saturating_add(1);
        self.recompute_roots();
        Ok(updated)
    }

    pub fn issue_rebate(
        &mut self,
        ticket_id: &str,
        bundle_id: &str,
        settled_fee_bps: u64,
        height: u64,
    ) -> Result<RebateRecord> {
        if self.rebates.len() >= self.config.max_rebates {
            return Err("coordinator rebate limit exceeded".to_string());
        }
        let ticket = self
            .admission_tickets
            .get(ticket_id)
            .ok_or_else(|| "coordinator ticket missing for rebate".to_string())?;
        let bundle = self
            .settlement_bundles
            .get(bundle_id)
            .ok_or_else(|| "coordinator bundle missing for rebate".to_string())?;
        if bundle.status != BundleStatus::Settled {
            return Err("coordinator bundle must be settled before rebate".to_string());
        }
        if !bundle.ticket_ids.iter().any(|id| id == ticket_id) {
            return Err("coordinator rebate ticket not in bundle".to_string());
        }
        let rebate_bps = ticket
            .quoted_fee_bps
            .saturating_sub(settled_fee_bps)
            .min(self.config.target_rebate_bps);
        let rebate_id = rebate_id(ticket_id, bundle_id, &ticket.account_commitment, height);
        if self.rebates.contains_key(&rebate_id) {
            return Err("coordinator rebate already exists".to_string());
        }
        let record = RebateRecord {
            rebate_id: rebate_id.clone(),
            ticket_id: ticket_id.to_string(),
            bundle_id: bundle_id.to_string(),
            lane_id: ticket.lane_id.clone(),
            account_commitment: ticket.account_commitment.clone(),
            quoted_fee_bps: ticket.quoted_fee_bps,
            settled_fee_bps,
            rebate_bps,
            issued_height: height,
        };
        self.rebates.insert(rebate_id, record.clone());
        self.counters.rebates = self.counters.rebates.saturating_add(1);
        self.recompute_roots();
        Ok(record)
    }

    pub fn submit_challenge(
        &mut self,
        bundle_id: &str,
        ticket_id: Option<String>,
        challenger_commitment: &str,
        kind: ChallengeKind,
        evidence_payload: &Value,
        height: u64,
    ) -> Result<ChallengeRecord> {
        if self.challenges.len() >= self.config.max_challenges {
            return Err("coordinator challenge limit exceeded".to_string());
        }
        if challenger_commitment.is_empty() {
            return Err("coordinator challenger commitment cannot be empty".to_string());
        }
        let bundle = self
            .settlement_bundles
            .get_mut(bundle_id)
            .ok_or_else(|| "coordinator bundle missing for challenge".to_string())?;
        if let Some(ticket_id) = &ticket_id {
            if !bundle.ticket_ids.iter().any(|id| id == ticket_id) {
                return Err("coordinator challenge ticket not in bundle".to_string());
            }
            if let Some(ticket) = self.admission_tickets.get_mut(ticket_id) {
                ticket.status = TicketStatus::Challenged;
            }
        }
        let evidence_root = payload_root(CHALLENGE_SCHEME, evidence_payload);
        let challenge_id = challenge_id(
            bundle_id,
            ticket_id.as_deref().unwrap_or("bundle"),
            challenger_commitment,
            kind,
            &evidence_root,
            height,
        );
        if self.challenges.contains_key(&challenge_id) {
            return Err("coordinator challenge already exists".to_string());
        }
        bundle.status = BundleStatus::Challenged;
        let record = ChallengeRecord {
            challenge_id: challenge_id.clone(),
            bundle_id: bundle_id.to_string(),
            ticket_id,
            challenger_commitment: challenger_commitment.to_string(),
            kind,
            evidence_root,
            slash_bps: kind.default_slash_bps(&self.config).min(MAX_BPS),
            opened_height: height,
            resolved_height: None,
            upheld: None,
        };
        self.challenges.insert(challenge_id, record.clone());
        self.counters.challenges = self.counters.challenges.saturating_add(1);
        self.recompute_roots();
        Ok(record)
    }

    pub fn resolve_challenge(
        &mut self,
        challenge_id: &str,
        upheld: bool,
        height: u64,
    ) -> Result<ChallengeRecord> {
        let challenge = self
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| "coordinator challenge not found".to_string())?;
        if challenge.upheld.is_some() {
            return Err("coordinator challenge already resolved".to_string());
        }
        challenge.upheld = Some(upheld);
        challenge.resolved_height = Some(height);
        if let Some(bundle) = self.settlement_bundles.get_mut(&challenge.bundle_id) {
            bundle.status = if upheld {
                BundleStatus::Rejected
            } else if bundle.settled_height.is_some() {
                BundleStatus::Settled
            } else {
                BundleStatus::Sealed
            };
        }
        if let Some(ticket_id) = &challenge.ticket_id {
            if let Some(ticket) = self.admission_tickets.get_mut(ticket_id) {
                ticket.status = if upheld {
                    TicketStatus::Rejected
                } else {
                    TicketStatus::Bundled
                };
            }
        }
        let updated = challenge.clone();
        self.counters.resolved_challenges = self.counters.resolved_challenges.saturating_add(1);
        self.recompute_roots();
        Ok(updated)
    }

    pub fn expire_admissions(&mut self, height: u64) -> Vec<AdmissionTicket> {
        let mut expired = Vec::new();
        for ticket in self.admission_tickets.values_mut() {
            if ticket.status.live() && height > ticket.expires_at_height {
                ticket.status = TicketStatus::Expired;
                expired.push(ticket.clone());
            }
        }
        self.counters.expired_tickets = self
            .counters
            .expired_tickets
            .saturating_add(expired.len() as u64);
        if !expired.is_empty() {
            self.recompute_roots();
        }
        expired
    }

    pub fn live_ticket_ids_by_lane(&self, lane_id: &str) -> Vec<String> {
        self.admission_tickets
            .values()
            .filter(|ticket| ticket.lane_id == lane_id && ticket.status.live())
            .map(|ticket| ticket.ticket_id.clone())
            .collect()
    }

    pub fn bundle_pressure(&self, lane_id: &str) -> u64 {
        let live_weight = self
            .admission_tickets
            .values()
            .filter(|ticket| ticket.lane_id == lane_id && ticket.status.live())
            .map(|ticket| ticket.execution_weight)
            .fold(0_u64, u64::saturating_add);
        live_weight
            .saturating_mul(10_000)
            .checked_div(self.config.max_bundle_weight.max(1))
            .unwrap_or(0)
            .min(10_000)
    }

    pub fn privacy_shortfall_ticket_ids(&self) -> Vec<String> {
        let satisfied = self
            .privacy_records
            .values()
            .map(|record| record.ticket_id.clone())
            .collect::<BTreeSet<_>>();
        self.admission_tickets
            .values()
            .filter(|ticket| ticket.status.live() && !satisfied.contains(&ticket.ticket_id))
            .map(|ticket| ticket.ticket_id.clone())
            .collect()
    }

    pub fn recompute_roots(&mut self) {
        self.roots = Roots {
            lane_policy_root: public_record_root(
                LANE_POLICY_SCHEME,
                &self
                    .lane_policies
                    .values()
                    .map(LanePolicy::public_record)
                    .collect::<Vec<_>>(),
            ),
            pq_authorization_root: public_record_root(
                PQ_AUTH_SUITE,
                &self
                    .pq_authorizations
                    .values()
                    .map(PqAuthorization::public_record)
                    .collect::<Vec<_>>(),
            ),
            admission_ticket_root: public_record_root(
                ADMISSION_SCHEME,
                &self
                    .admission_tickets
                    .values()
                    .map(AdmissionTicket::public_record)
                    .collect::<Vec<_>>(),
            ),
            fee_quote_root: public_record_root(
                FEE_QUOTE_SCHEME,
                &self
                    .fee_quotes
                    .values()
                    .map(FeeQuote::public_record)
                    .collect::<Vec<_>>(),
            ),
            privacy_budget_root: public_record_root(
                PRIVACY_BUDGET_SCHEME,
                &self
                    .privacy_records
                    .values()
                    .map(PrivacyBudgetRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            settlement_bundle_root: public_record_root(
                SETTLEMENT_BUNDLE_SCHEME,
                &self
                    .settlement_bundles
                    .values()
                    .map(SettlementBundle::public_record)
                    .collect::<Vec<_>>(),
            ),
            preconfirmation_root: public_record_root(
                PRECONFIRMATION_SCHEME,
                &self
                    .preconfirmations
                    .values()
                    .map(PreconfirmationReceipt::public_record)
                    .collect::<Vec<_>>(),
            ),
            rebate_root: public_record_root(
                REBATE_SCHEME,
                &self
                    .rebates
                    .values()
                    .map(RebateRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            challenge_root: public_record_root(
                CHALLENGE_SCHEME,
                &self
                    .challenges
                    .values()
                    .map(ChallengeRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
        };
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_pq_policy_settlement_coordinator_state",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_auth_suite": PQ_AUTH_SUITE,
            "config": self.config,
            "counters": self.counters,
            "roots": self.roots,
            "lane_policies": self.lane_policies.values().map(LanePolicy::public_record).collect::<Vec<_>>(),
            "pq_authorizations": self.pq_authorizations.values().map(PqAuthorization::public_record).collect::<Vec<_>>(),
            "admission_tickets": self.admission_tickets.values().map(AdmissionTicket::public_record).collect::<Vec<_>>(),
            "fee_quotes": self.fee_quotes.values().map(FeeQuote::public_record).collect::<Vec<_>>(),
            "privacy_records": self.privacy_records.values().map(PrivacyBudgetRecord::public_record).collect::<Vec<_>>(),
            "settlement_bundles": self.settlement_bundles.values().map(SettlementBundle::public_record).collect::<Vec<_>>(),
            "preconfirmations": self.preconfirmations.values().map(PreconfirmationReceipt::public_record).collect::<Vec<_>>(),
            "rebates": self.rebates.values().map(RebateRecord::public_record).collect::<Vec<_>>(),
            "challenges": self.challenges.values().map(ChallengeRecord::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        let state_root = state_root_from_record(&record);
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), json!(state_root));
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    fn estimate_fee_bps(
        &self,
        lane: &LanePolicy,
        admission_mode: AdmissionMode,
        fee_policy: FeePolicy,
        privacy_class: PrivacyClass,
        max_fee_bps: u64,
    ) -> u64 {
        if fee_policy == FeePolicy::EmergencyWaived || admission_mode == AdmissionMode::Emergency {
            return 0;
        }
        let base = lane
            .max_fee_bps
            .min(max_fee_bps)
            .min(self.config.max_user_fee_bps);
        let surcharge = if admission_mode == AdmissionMode::Fast {
            self.config.fast_lane_surcharge_bps
        } else {
            0
        };
        let discount = if matches!(fee_policy, FeePolicy::BatchDiscount | FeePolicy::Sponsored)
            || admission_mode == AdmissionMode::BatchCheap
        {
            self.config.batch_discount_bps
        } else {
            0
        };
        let privacy_penalty = if privacy_class.min_set_multiplier() > 4 {
            self.config.privacy_shortfall_penalty_bps
        } else {
            0
        };
        base.saturating_add(surcharge)
            .saturating_add(privacy_penalty)
            .saturating_sub(discount)
            .min(self.config.max_user_fee_bps)
    }

    fn make_fee_quote(&self, ticket: &AdmissionTicket, lane: &LanePolicy, height: u64) -> FeeQuote {
        let surcharge_bps = if ticket.admission_mode == AdmissionMode::Fast {
            self.config.fast_lane_surcharge_bps
        } else {
            0
        };
        let discount_bps = if matches!(
            ticket.fee_policy,
            FeePolicy::BatchDiscount | FeePolicy::Sponsored
        ) || ticket.admission_mode == AdmissionMode::BatchCheap
        {
            self.config.batch_discount_bps
        } else {
            0
        };
        let privacy_penalty_bps = if ticket.privacy_class.min_set_multiplier() > 4 {
            self.config.privacy_shortfall_penalty_bps
        } else {
            0
        };
        FeeQuote {
            quote_id: fee_quote_id(&ticket.ticket_id, &ticket.lane_id, height),
            ticket_id: ticket.ticket_id.clone(),
            lane_id: ticket.lane_id.clone(),
            base_fee_bps: lane.max_fee_bps,
            surcharge_bps,
            discount_bps,
            privacy_penalty_bps,
            final_fee_bps: ticket.quoted_fee_bps,
            fee_asset_id: self.config.fee_asset_id.clone(),
            rebate_eligible: matches!(
                ticket.fee_policy,
                FeePolicy::RebateEligible | FeePolicy::BatchDiscount | FeePolicy::Sponsored
            ),
            quoted_height: height,
        }
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn lane_policy_id(
    lane: CoordinatorLane,
    operator_commitment: &str,
    policy_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-COORDINATOR-LANE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str(operator_commitment),
            HashPart::Str(policy_root),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn pq_authorization_id(
    subject_root: &str,
    signer_commitment: &str,
    lane_id: &str,
    pq_signature_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-COORDINATOR-AUTHORIZATION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject_root),
            HashPart::Str(signer_commitment),
            HashPart::Str(lane_id),
            HashPart::Str(pq_signature_root),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn admission_ticket_id(
    lane_id: &str,
    sealed_intent_root: &str,
    authorization_id: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-COORDINATOR-ADMISSION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane_id),
            HashPart::Str(sealed_intent_root),
            HashPart::Str(authorization_id),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn fee_quote_id(ticket_id: &str, lane_id: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-COORDINATOR-FEE-QUOTE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(ticket_id),
            HashPart::Str(lane_id),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn privacy_budget_id(
    ticket_id: &str,
    lane_id: &str,
    nullifier_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-COORDINATOR-PRIVACY-BUDGET-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(ticket_id),
            HashPart::Str(lane_id),
            HashPart::Str(nullifier_root),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn settlement_bundle_id(
    lane_id: &str,
    sequencer_commitment: &str,
    pre_state_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-COORDINATOR-BUNDLE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane_id),
            HashPart::Str(sequencer_commitment),
            HashPart::Str(pre_state_root),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn preconfirmation_id(
    bundle_id: &str,
    lane_id: &str,
    ticket_root: &str,
    pq_attestation_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-COORDINATOR-PRECONFIRMATION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(bundle_id),
            HashPart::Str(lane_id),
            HashPart::Str(ticket_root),
            HashPart::Str(pq_attestation_root),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn rebate_id(
    ticket_id: &str,
    bundle_id: &str,
    account_commitment: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-COORDINATOR-REBATE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(ticket_id),
            HashPart::Str(bundle_id),
            HashPart::Str(account_commitment),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn challenge_id(
    bundle_id: &str,
    ticket_id: &str,
    challenger_commitment: &str,
    kind: ChallengeKind,
    evidence_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-COORDINATOR-CHALLENGE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(bundle_id),
            HashPart::Str(ticket_id),
            HashPart::Str(challenger_commitment),
            HashPart::Str(kind.as_str()),
            HashPart::Str(evidence_root),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn deterministic_root(label: &str, subject: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-COORDINATOR-DETERMINISTIC-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(subject),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-COORDINATOR-PAYLOAD-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-POLICY-SETTLEMENT-COORDINATOR-STATE-ROOT",
        record,
    )
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}
