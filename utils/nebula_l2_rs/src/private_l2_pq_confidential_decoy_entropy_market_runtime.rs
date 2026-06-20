use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialDecoyEntropyMarketRuntimeResult<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_DECOY_ENTROPY_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-decoy-entropy-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_DECOY_ENTROPY_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_CURATOR_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-decoy-entropy-curator-v1";
pub const RING_MEMBER_COMMITMENT_SUITE: &str = "monero-ring-member-quality-commitment-root-v1";
pub const WALLET_SAMPLING_LANE_SUITE: &str = "monero-wallet-decoy-sampling-lane-root-v1";
pub const LOW_FEE_ENTROPY_CREDIT_SUITE: &str = "private-l2-low-fee-decoy-entropy-credit-root-v1";
pub const LINKABILITY_QUARANTINE_SUITE: &str =
    "private-l2-linkability-regression-quarantine-root-v1";
pub const PRIVACY_REDACTION_BUDGET_SUITE: &str =
    "private-l2-decoy-entropy-redaction-budget-root-v1";
pub const PUBLIC_RECORD_SUITE: &str = "roots-only-deterministic-public-record-v1";
pub const DEFAULT_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEFAULT_MONERO_NETWORK: &str = "monero-devnet";
pub const DEFAULT_MARKET_ID: &str = "pq-confidential-decoy-entropy-market-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_252_400;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_945_600;
pub const DEVNET_EPOCH: u64 = 12_044;
pub const DEFAULT_MIN_RING_MEMBERS: u16 = 128;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_MIN_ENTROPY_BPS: u64 = 8_650;
pub const DEFAULT_MIN_QUALITY_BPS: u64 = 8_250;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_LOT_TTL_BLOCKS: u64 = 72;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 216;
pub const DEFAULT_CREDIT_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_QUARANTINE_TTL_BLOCKS: u64 = 17_280;
pub const DEFAULT_REDACTION_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_REDACTIONS_PER_WINDOW: u64 = 16;
pub const DEFAULT_MAX_CREDIT_MICRO_UNITS: u64 = 12_000;
pub const DEFAULT_TARGET_LOW_FEE_DISCOUNT_BPS: u64 = 1_100;
pub const DEFAULT_LINKABILITY_THRESHOLD_BPS: u64 = 275;
pub const DEFAULT_REGRESSION_QUARANTINE_THRESHOLD_BPS: u64 = 450;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_DECOY_LOTS: usize = 8_388_608;
pub const MAX_RING_MEMBER_COMMITMENTS: usize = 16_777_216;
pub const MAX_CURATOR_ATTESTATIONS: usize = 8_388_608;
pub const MAX_WALLET_SAMPLING_LANES: usize = 2_097_152;
pub const MAX_LOW_FEE_CREDITS: usize = 8_388_608;
pub const MAX_LINKABILITY_QUARANTINES: usize = 2_097_152;
pub const MAX_REDACTION_BUDGETS: usize = 2_097_152;
pub const MAX_PUBLIC_EVENTS: usize = 16_777_216;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntropyLane {
    WalletSpend,
    BridgeWithdrawal,
    MerchantPayment,
    DexSettlement,
    TokenReceipt,
    WatchtowerAudit,
    MobileFastSync,
    EmergencyEscape,
}

impl EntropyLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletSpend => "wallet_spend",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::MerchantPayment => "merchant_payment",
            Self::DexSettlement => "dex_settlement",
            Self::TokenReceipt => "token_receipt",
            Self::WatchtowerAudit => "watchtower_audit",
            Self::MobileFastSync => "mobile_fast_sync",
            Self::EmergencyEscape => "emergency_escape",
        }
    }

    pub fn default_fee_cap_micro_units(self) -> u64 {
        match self {
            Self::WalletSpend => 1_800,
            Self::BridgeWithdrawal => 5_800,
            Self::MerchantPayment => 2_200,
            Self::DexSettlement => 6_400,
            Self::TokenReceipt => 2_900,
            Self::WatchtowerAudit => 3_600,
            Self::MobileFastSync => 1_200,
            Self::EmergencyEscape => 8_000,
        }
    }

    pub fn sampling_weight(self) -> u64 {
        match self {
            Self::WalletSpend => 24,
            Self::BridgeWithdrawal => 18,
            Self::MerchantPayment => 14,
            Self::DexSettlement => 16,
            Self::TokenReceipt => 10,
            Self::WatchtowerAudit => 8,
            Self::MobileFastSync => 6,
            Self::EmergencyEscape => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LotStatus {
    Drafted,
    Open,
    Sampled,
    Committed,
    Attested,
    CreditIssued,
    Settled,
    Expired,
    Quarantined,
    Rejected,
}

impl LotStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Sampled | Self::Committed | Self::Attested | Self::CreditIssued
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentStatus {
    Submitted,
    Verified,
    Attested,
    Consumed,
    Quarantined,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Verified,
    Linked,
    Expired,
    Disputed,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SamplingLaneStatus {
    Registered,
    Active,
    Saturated,
    LowFeePreferred,
    Quarantined,
    Paused,
    Retired,
}

impl SamplingLaneStatus {
    pub fn accepts_lots(self) -> bool {
        matches!(self, Self::Active | Self::Saturated | Self::LowFeePreferred)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CreditStatus {
    Minted,
    Reserved,
    Applied,
    Refunded,
    Expired,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    LinkabilityRegression,
    RingMemberReuse,
    AgeDistributionSkew,
    ViewTagCorrelation,
    CuratorDispute,
    RedactionBudgetExceeded,
    FeePatternLeakage,
}

impl QuarantineReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LinkabilityRegression => "linkability_regression",
            Self::RingMemberReuse => "ring_member_reuse",
            Self::AgeDistributionSkew => "age_distribution_skew",
            Self::ViewTagCorrelation => "view_tag_correlation",
            Self::CuratorDispute => "curator_dispute",
            Self::RedactionBudgetExceeded => "redaction_budget_exceeded",
            Self::FeePatternLeakage => "fee_pattern_leakage",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub market_id: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub min_ring_members: u16,
    pub min_privacy_set_size: u64,
    pub min_entropy_bps: u64,
    pub min_quality_bps: u64,
    pub min_pq_security_bits: u16,
    pub lot_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub credit_ttl_blocks: u64,
    pub quarantine_ttl_blocks: u64,
    pub redaction_window_blocks: u64,
    pub max_redactions_per_window: u64,
    pub max_credit_micro_units: u64,
    pub target_low_fee_discount_bps: u64,
    pub linkability_threshold_bps: u64,
    pub regression_quarantine_threshold_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEFAULT_L2_NETWORK.to_string(),
            monero_network: DEFAULT_MONERO_NETWORK.to_string(),
            market_id: DEFAULT_MARKET_ID.to_string(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            epoch: DEVNET_EPOCH,
            min_ring_members: DEFAULT_MIN_RING_MEMBERS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_entropy_bps: DEFAULT_MIN_ENTROPY_BPS,
            min_quality_bps: DEFAULT_MIN_QUALITY_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            lot_ttl_blocks: DEFAULT_LOT_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            credit_ttl_blocks: DEFAULT_CREDIT_TTL_BLOCKS,
            quarantine_ttl_blocks: DEFAULT_QUARANTINE_TTL_BLOCKS,
            redaction_window_blocks: DEFAULT_REDACTION_WINDOW_BLOCKS,
            max_redactions_per_window: DEFAULT_MAX_REDACTIONS_PER_WINDOW,
            max_credit_micro_units: DEFAULT_MAX_CREDIT_MICRO_UNITS,
            target_low_fee_discount_bps: DEFAULT_TARGET_LOW_FEE_DISCOUNT_BPS,
            linkability_threshold_bps: DEFAULT_LINKABILITY_THRESHOLD_BPS,
            regression_quarantine_threshold_bps: DEFAULT_REGRESSION_QUARANTINE_THRESHOLD_BPS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "market_id": self.market_id,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
            "min_ring_members": self.min_ring_members,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_entropy_bps": self.min_entropy_bps,
            "min_quality_bps": self.min_quality_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "lot_ttl_blocks": self.lot_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "credit_ttl_blocks": self.credit_ttl_blocks,
            "quarantine_ttl_blocks": self.quarantine_ttl_blocks,
            "redaction_window_blocks": self.redaction_window_blocks,
            "max_redactions_per_window": self.max_redactions_per_window,
            "max_credit_micro_units": self.max_credit_micro_units,
            "target_low_fee_discount_bps": self.target_low_fee_discount_bps,
            "linkability_threshold_bps": self.linkability_threshold_bps,
            "regression_quarantine_threshold_bps": self.regression_quarantine_threshold_bps,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub decoy_lots: u64,
    pub ring_member_commitments: u64,
    pub curator_attestations: u64,
    pub wallet_sampling_lanes: u64,
    pub low_fee_entropy_credits: u64,
    pub linkability_quarantines: u64,
    pub redaction_budgets: u64,
    pub public_events: u64,
    pub settled_lots: u64,
    pub rejected_lots: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "decoy_lots": self.decoy_lots,
            "ring_member_commitments": self.ring_member_commitments,
            "curator_attestations": self.curator_attestations,
            "wallet_sampling_lanes": self.wallet_sampling_lanes,
            "low_fee_entropy_credits": self.low_fee_entropy_credits,
            "linkability_quarantines": self.linkability_quarantines,
            "redaction_budgets": self.redaction_budgets,
            "public_events": self.public_events,
            "settled_lots": self.settled_lots,
            "rejected_lots": self.rejected_lots,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub decoy_lot_root: String,
    pub ring_member_commitment_root: String,
    pub curator_attestation_root: String,
    pub wallet_sampling_lane_root: String,
    pub low_fee_entropy_credit_root: String,
    pub linkability_quarantine_root: String,
    pub redaction_budget_root: String,
    pub public_event_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        let mut roots = Self {
            config_root: record_root("config", &config.public_record()),
            counters_root: record_root("counters", &counters.public_record()),
            decoy_lot_root: empty_root("decoy_lots"),
            ring_member_commitment_root: empty_root("ring_member_commitments"),
            curator_attestation_root: empty_root("curator_attestations"),
            wallet_sampling_lane_root: empty_root("wallet_sampling_lanes"),
            low_fee_entropy_credit_root: empty_root("low_fee_entropy_credits"),
            linkability_quarantine_root: empty_root("linkability_quarantines"),
            redaction_budget_root: empty_root("redaction_budgets"),
            public_event_root: empty_root("public_events"),
            state_root: String::new(),
        };
        roots.state_root = state_root_from_record(&roots.public_record_without_state_root());
        roots
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "decoy_lot_root": self.decoy_lot_root,
            "ring_member_commitment_root": self.ring_member_commitment_root,
            "curator_attestation_root": self.curator_attestation_root,
            "wallet_sampling_lane_root": self.wallet_sampling_lane_root,
            "low_fee_entropy_credit_root": self.low_fee_entropy_credit_root,
            "linkability_quarantine_root": self.linkability_quarantine_root,
            "redaction_budget_root": self.redaction_budget_root,
            "public_event_root": self.public_event_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root.clone());
        record
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletSamplingLane {
    pub lane_id: String,
    pub lane: EntropyLane,
    pub wallet_policy_root: String,
    pub sampler_root: String,
    pub fee_asset_id: String,
    pub capacity_lots: u64,
    pub available_lots: u64,
    pub min_entropy_bps: u64,
    pub max_fee_micro_units: u64,
    pub pq_security_bits: u16,
    pub status: SamplingLaneStatus,
}

impl WalletSamplingLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "lane": self.lane.as_str(),
            "wallet_policy_root": self.wallet_policy_root,
            "sampler_root": self.sampler_root,
            "fee_asset_id": self.fee_asset_id,
            "capacity_lots": self.capacity_lots,
            "available_lots": self.available_lots,
            "min_entropy_bps": self.min_entropy_bps,
            "max_fee_micro_units": self.max_fee_micro_units,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DecoyEntropyLot {
    pub lot_id: String,
    pub lane_id: String,
    pub lane: EntropyLane,
    pub wallet_context_root: String,
    pub output_age_histogram_root: String,
    pub decoy_selection_root: String,
    pub view_tag_redaction_root: String,
    pub ring_member_count: u16,
    pub privacy_set_size: u64,
    pub median_age_blocks: u64,
    pub p95_age_blocks: u64,
    pub entropy_bps: u64,
    pub quality_bps: u64,
    pub linkability_bps: u64,
    pub fee_cap_micro_units: u64,
    pub expires_at_monero_height: u64,
    pub status: LotStatus,
}

impl DecoyEntropyLot {
    pub fn public_record(&self) -> Value {
        json!({
            "lot_id": self.lot_id,
            "lane_id": self.lane_id,
            "lane": self.lane.as_str(),
            "wallet_context_root": self.wallet_context_root,
            "output_age_histogram_root": self.output_age_histogram_root,
            "decoy_selection_root": self.decoy_selection_root,
            "view_tag_redaction_root": self.view_tag_redaction_root,
            "ring_member_count": self.ring_member_count,
            "privacy_set_size": self.privacy_set_size,
            "median_age_blocks": self.median_age_blocks,
            "p95_age_blocks": self.p95_age_blocks,
            "entropy_bps": self.entropy_bps,
            "quality_bps": self.quality_bps,
            "linkability_bps": self.linkability_bps,
            "fee_cap_micro_units": self.fee_cap_micro_units,
            "expires_at_monero_height": self.expires_at_monero_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RingMemberQualityCommitment {
    pub commitment_id: String,
    pub lot_id: String,
    pub ring_member_root: String,
    pub spend_age_bucket_root: String,
    pub quality_commitment_root: String,
    pub entropy_witness_root: String,
    pub member_count: u16,
    pub entropy_bps: u64,
    pub quality_bps: u64,
    pub linkability_bps: u64,
    pub status: CommitmentStatus,
}

impl RingMemberQualityCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "lot_id": self.lot_id,
            "ring_member_root": self.ring_member_root,
            "spend_age_bucket_root": self.spend_age_bucket_root,
            "quality_commitment_root": self.quality_commitment_root,
            "entropy_witness_root": self.entropy_witness_root,
            "member_count": self.member_count,
            "entropy_bps": self.entropy_bps,
            "quality_bps": self.quality_bps,
            "linkability_bps": self.linkability_bps,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqCuratorAttestation {
    pub attestation_id: String,
    pub lot_id: String,
    pub commitment_id: String,
    pub curator_id: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub disclosure_root: String,
    pub attested_entropy_bps: u64,
    pub attested_quality_bps: u64,
    pub attested_linkability_bps: u64,
    pub pq_security_bits: u16,
    pub expires_at_l2_height: u64,
    pub status: AttestationStatus,
}

impl PqCuratorAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "lot_id": self.lot_id,
            "commitment_id": self.commitment_id,
            "curator_id": self.curator_id,
            "pq_public_key_root": self.pq_public_key_root,
            "pq_signature_root": self.pq_signature_root,
            "transcript_root": self.transcript_root,
            "disclosure_root": self.disclosure_root,
            "attested_entropy_bps": self.attested_entropy_bps,
            "attested_quality_bps": self.attested_quality_bps,
            "attested_linkability_bps": self.attested_linkability_bps,
            "pq_security_bits": self.pq_security_bits,
            "expires_at_l2_height": self.expires_at_l2_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeEntropyCredit {
    pub credit_id: String,
    pub lot_id: String,
    pub lane_id: String,
    pub beneficiary_commitment_root: String,
    pub credit_asset_id: String,
    pub credit_micro_units: u64,
    pub discount_bps: u64,
    pub expires_at_l2_height: u64,
    pub status: CreditStatus,
}

impl LowFeeEntropyCredit {
    pub fn public_record(&self) -> Value {
        json!({
            "credit_id": self.credit_id,
            "lot_id": self.lot_id,
            "lane_id": self.lane_id,
            "beneficiary_commitment_root": self.beneficiary_commitment_root,
            "credit_asset_id": self.credit_asset_id,
            "credit_micro_units": self.credit_micro_units,
            "discount_bps": self.discount_bps,
            "expires_at_l2_height": self.expires_at_l2_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LinkabilityRegressionQuarantine {
    pub quarantine_id: String,
    pub lot_id: String,
    pub lane_id: String,
    pub reason: QuarantineReason,
    pub evidence_root: String,
    pub regression_bps: u64,
    pub released_at_l2_height: u64,
    pub active: bool,
}

impl LinkabilityRegressionQuarantine {
    pub fn public_record(&self) -> Value {
        json!({
            "quarantine_id": self.quarantine_id,
            "lot_id": self.lot_id,
            "lane_id": self.lane_id,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "regression_bps": self.regression_bps,
            "released_at_l2_height": self.released_at_l2_height,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub subject_root: String,
    pub lane_id: String,
    pub disclosed_field_root: String,
    pub window_start_l2_height: u64,
    pub window_end_l2_height: u64,
    pub redactions_allowed: u64,
    pub redactions_used: u64,
    pub remaining_privacy_set_size: u64,
}

impl PrivacyRedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "subject_root": self.subject_root,
            "lane_id": self.lane_id,
            "disclosed_field_root": self.disclosed_field_root,
            "window_start_l2_height": self.window_start_l2_height,
            "window_end_l2_height": self.window_end_l2_height,
            "redactions_allowed": self.redactions_allowed,
            "redactions_used": self.redactions_used,
            "remaining_privacy_set_size": self.remaining_privacy_set_size,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub lane: EntropyLane,
    pub event_root: String,
    pub l2_height: u64,
    pub monero_height: u64,
}

impl PublicEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "lane": self.lane.as_str(),
            "event_root": self.event_root,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SamplingLaneRegistrationRequest {
    pub lane: EntropyLane,
    pub wallet_policy_root: String,
    pub sampler_root: String,
    pub fee_asset_id: String,
    pub capacity_lots: u64,
    pub min_entropy_bps: u64,
    pub max_fee_micro_units: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DecoyEntropyLotRequest {
    pub lane_id: String,
    pub lane: EntropyLane,
    pub wallet_context_root: String,
    pub output_age_histogram_root: String,
    pub decoy_selection_root: String,
    pub view_tag_redaction_root: String,
    pub ring_member_count: u16,
    pub privacy_set_size: u64,
    pub median_age_blocks: u64,
    pub p95_age_blocks: u64,
    pub linkability_bps: u64,
    pub fee_cap_micro_units: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RingMemberCommitmentRequest {
    pub lot_id: String,
    pub ring_member_root: String,
    pub spend_age_bucket_root: String,
    pub quality_commitment_root: String,
    pub entropy_witness_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqCuratorAttestationRequest {
    pub lot_id: String,
    pub commitment_id: String,
    pub curator_id: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub disclosure_root: String,
    pub attested_entropy_bps: u64,
    pub attested_quality_bps: u64,
    pub attested_linkability_bps: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedactionBudgetRequest {
    pub subject_root: String,
    pub lane_id: String,
    pub disclosed_field_root: String,
    pub redactions_used: u64,
    pub remaining_privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub wallet_sampling_lanes: BTreeMap<String, WalletSamplingLane>,
    pub decoy_lots: BTreeMap<String, DecoyEntropyLot>,
    pub ring_member_commitments: BTreeMap<String, RingMemberQualityCommitment>,
    pub curator_attestations: BTreeMap<String, PqCuratorAttestation>,
    pub low_fee_entropy_credits: BTreeMap<String, LowFeeEntropyCredit>,
    pub linkability_quarantines: BTreeMap<String, LinkabilityRegressionQuarantine>,
    pub redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub public_events: BTreeMap<String, PublicEvent>,
    pub quarantined_lots: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::devnet())
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        let counters = Counters::default();
        let roots = Roots::empty(&config, &counters);
        Self {
            config,
            counters,
            roots,
            wallet_sampling_lanes: BTreeMap::new(),
            decoy_lots: BTreeMap::new(),
            ring_member_commitments: BTreeMap::new(),
            curator_attestations: BTreeMap::new(),
            low_fee_entropy_credits: BTreeMap::new(),
            linkability_quarantines: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            public_events: BTreeMap::new(),
            quarantined_lots: BTreeSet::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::default();
        seed_devnet(&mut state);
        state.refresh_roots();
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        seed_demo(&mut state);
        state.refresh_roots();
        state
    }

    pub fn register_sampling_lane(
        &mut self,
        request: SamplingLaneRegistrationRequest,
    ) -> PrivateL2PqConfidentialDecoyEntropyMarketRuntimeResult<String> {
        ensure!(
            self.wallet_sampling_lanes.len() < MAX_WALLET_SAMPLING_LANES,
            "wallet sampling lane capacity exceeded"
        );
        ensure!(
            request.capacity_lots > 0,
            "wallet sampling lane capacity must be positive"
        );
        ensure!(
            request.min_entropy_bps >= self.config.min_entropy_bps,
            "wallet sampling lane entropy floor below config"
        );
        ensure!(
            request.max_fee_micro_units <= self.config.max_credit_micro_units,
            "wallet sampling lane fee cap exceeds config"
        );
        ensure!(
            request.pq_security_bits >= self.config.min_pq_security_bits,
            "wallet sampling lane pq security below config"
        );
        let lane_record = json!({
            "lane": request.lane.as_str(),
            "wallet_policy_root": request.wallet_policy_root,
            "sampler_root": request.sampler_root,
            "fee_asset_id": request.fee_asset_id,
            "capacity_lots": request.capacity_lots,
            "min_entropy_bps": request.min_entropy_bps,
            "max_fee_micro_units": request.max_fee_micro_units,
            "pq_security_bits": request.pq_security_bits,
        });
        let lane_id = id_from_record("wallet_sampling_lane", &lane_record);
        let lane = WalletSamplingLane {
            lane_id: lane_id.clone(),
            lane: request.lane,
            wallet_policy_root: request.wallet_policy_root,
            sampler_root: request.sampler_root,
            fee_asset_id: request.fee_asset_id,
            capacity_lots: request.capacity_lots,
            available_lots: request.capacity_lots,
            min_entropy_bps: request.min_entropy_bps,
            max_fee_micro_units: request.max_fee_micro_units,
            pq_security_bits: request.pq_security_bits,
            status: SamplingLaneStatus::Active,
        };
        self.wallet_sampling_lanes.insert(lane_id.clone(), lane);
        self.counters.wallet_sampling_lanes = self.wallet_sampling_lanes.len() as u64;
        self.push_event("wallet_sampling_lane_registered", &lane_id, request.lane);
        self.refresh_roots();
        Ok(lane_id)
    }

    pub fn open_decoy_lot(
        &mut self,
        request: DecoyEntropyLotRequest,
    ) -> PrivateL2PqConfidentialDecoyEntropyMarketRuntimeResult<String> {
        ensure!(
            self.decoy_lots.len() < MAX_DECOY_LOTS,
            "decoy lot capacity exceeded"
        );
        let lane = self
            .wallet_sampling_lanes
            .get_mut(&request.lane_id)
            .ok_or_else(|| format!("unknown wallet sampling lane {}", request.lane_id))?;
        ensure!(
            lane.status.accepts_lots(),
            "wallet sampling lane unavailable"
        );
        ensure!(lane.available_lots > 0, "wallet sampling lane exhausted");
        ensure!(lane.lane == request.lane, "decoy entropy lot lane mismatch");
        ensure!(
            request.ring_member_count >= self.config.min_ring_members,
            "decoy entropy lot ring member floor not met"
        );
        ensure!(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "decoy entropy lot privacy set floor not met"
        );
        ensure!(
            request.linkability_bps <= self.config.regression_quarantine_threshold_bps,
            "decoy entropy lot linkability exceeds quarantine threshold"
        );
        ensure!(
            request.fee_cap_micro_units <= lane.max_fee_micro_units,
            "decoy entropy lot fee cap exceeds lane cap"
        );
        let entropy_bps = entropy_score(request.ring_member_count, request.privacy_set_size);
        let freshness_bps = freshness_score(request.median_age_blocks, request.p95_age_blocks);
        let quality_bps = quality_score(entropy_bps, freshness_bps, request.linkability_bps);
        ensure!(
            entropy_bps >= self.config.min_entropy_bps,
            "decoy entropy lot entropy floor not met"
        );
        ensure!(
            quality_bps >= self.config.min_quality_bps,
            "decoy entropy lot quality floor not met"
        );
        let lot_record = json!({
            "lane_id": request.lane_id,
            "lane": request.lane.as_str(),
            "wallet_context_root": request.wallet_context_root,
            "output_age_histogram_root": request.output_age_histogram_root,
            "decoy_selection_root": request.decoy_selection_root,
            "view_tag_redaction_root": request.view_tag_redaction_root,
            "ring_member_count": request.ring_member_count,
            "privacy_set_size": request.privacy_set_size,
            "median_age_blocks": request.median_age_blocks,
            "p95_age_blocks": request.p95_age_blocks,
            "linkability_bps": request.linkability_bps,
        });
        let lot_id = id_from_record("decoy_entropy_lot", &lot_record);
        let lot = DecoyEntropyLot {
            lot_id: lot_id.clone(),
            lane_id: request.lane_id.clone(),
            lane: request.lane,
            wallet_context_root: request.wallet_context_root,
            output_age_histogram_root: request.output_age_histogram_root,
            decoy_selection_root: request.decoy_selection_root,
            view_tag_redaction_root: request.view_tag_redaction_root,
            ring_member_count: request.ring_member_count,
            privacy_set_size: request.privacy_set_size,
            median_age_blocks: request.median_age_blocks,
            p95_age_blocks: request.p95_age_blocks,
            entropy_bps,
            quality_bps,
            linkability_bps: request.linkability_bps,
            fee_cap_micro_units: request.fee_cap_micro_units,
            expires_at_monero_height: self.config.monero_height + self.config.lot_ttl_blocks,
            status: LotStatus::Open,
        };
        lane.available_lots = lane.available_lots.saturating_sub(1);
        self.decoy_lots.insert(lot_id.clone(), lot);
        self.counters.decoy_lots = self.decoy_lots.len() as u64;
        self.push_event("decoy_entropy_lot_opened", &lot_id, request.lane);
        self.refresh_roots();
        Ok(lot_id)
    }

    pub fn commit_ring_members(
        &mut self,
        request: RingMemberCommitmentRequest,
    ) -> PrivateL2PqConfidentialDecoyEntropyMarketRuntimeResult<String> {
        ensure!(
            self.ring_member_commitments.len() < MAX_RING_MEMBER_COMMITMENTS,
            "ring member commitment capacity exceeded"
        );
        let lot = self
            .decoy_lots
            .get_mut(&request.lot_id)
            .ok_or_else(|| format!("unknown decoy entropy lot {}", request.lot_id))?;
        ensure!(lot.status.live(), "decoy entropy lot is not live");
        let record = json!({
            "lot_id": request.lot_id,
            "ring_member_root": request.ring_member_root,
            "spend_age_bucket_root": request.spend_age_bucket_root,
            "quality_commitment_root": request.quality_commitment_root,
            "entropy_witness_root": request.entropy_witness_root,
        });
        let commitment_id = id_from_record("ring_member_quality_commitment", &record);
        let commitment = RingMemberQualityCommitment {
            commitment_id: commitment_id.clone(),
            lot_id: request.lot_id.clone(),
            ring_member_root: request.ring_member_root,
            spend_age_bucket_root: request.spend_age_bucket_root,
            quality_commitment_root: request.quality_commitment_root,
            entropy_witness_root: request.entropy_witness_root,
            member_count: lot.ring_member_count,
            entropy_bps: lot.entropy_bps,
            quality_bps: lot.quality_bps,
            linkability_bps: lot.linkability_bps,
            status: CommitmentStatus::Verified,
        };
        lot.status = LotStatus::Committed;
        let event_lane = lot.lane;
        self.ring_member_commitments
            .insert(commitment_id.clone(), commitment);
        self.counters.ring_member_commitments = self.ring_member_commitments.len() as u64;
        self.push_event("ring_member_quality_committed", &commitment_id, event_lane);
        self.refresh_roots();
        Ok(commitment_id)
    }

    pub fn attest_curator(
        &mut self,
        request: PqCuratorAttestationRequest,
    ) -> PrivateL2PqConfidentialDecoyEntropyMarketRuntimeResult<String> {
        ensure!(
            self.curator_attestations.len() < MAX_CURATOR_ATTESTATIONS,
            "curator attestation capacity exceeded"
        );
        let lot = self
            .decoy_lots
            .get_mut(&request.lot_id)
            .ok_or_else(|| format!("unknown decoy entropy lot {}", request.lot_id))?;
        let commitment = self
            .ring_member_commitments
            .get_mut(&request.commitment_id)
            .ok_or_else(|| format!("unknown ring member commitment {}", request.commitment_id))?;
        ensure!(
            commitment.lot_id == request.lot_id,
            "curator attestation commitment lot mismatch"
        );
        ensure!(
            request.pq_security_bits >= self.config.min_pq_security_bits,
            "curator attestation pq security below config"
        );
        ensure!(
            request.attested_entropy_bps >= self.config.min_entropy_bps,
            "curator attestation entropy floor not met"
        );
        ensure!(
            request.attested_quality_bps >= self.config.min_quality_bps,
            "curator attestation quality floor not met"
        );
        ensure!(
            request.attested_linkability_bps <= self.config.linkability_threshold_bps,
            "curator attestation linkability exceeds threshold"
        );
        let record = json!({
            "lot_id": request.lot_id,
            "commitment_id": request.commitment_id,
            "curator_id": request.curator_id,
            "pq_public_key_root": request.pq_public_key_root,
            "pq_signature_root": request.pq_signature_root,
            "transcript_root": request.transcript_root,
            "disclosure_root": request.disclosure_root,
        });
        let attestation_id = id_from_record("pq_curator_attestation", &record);
        let attestation = PqCuratorAttestation {
            attestation_id: attestation_id.clone(),
            lot_id: request.lot_id.clone(),
            commitment_id: request.commitment_id.clone(),
            curator_id: request.curator_id,
            pq_public_key_root: request.pq_public_key_root,
            pq_signature_root: request.pq_signature_root,
            transcript_root: request.transcript_root,
            disclosure_root: request.disclosure_root,
            attested_entropy_bps: request.attested_entropy_bps,
            attested_quality_bps: request.attested_quality_bps,
            attested_linkability_bps: request.attested_linkability_bps,
            pq_security_bits: request.pq_security_bits,
            expires_at_l2_height: self.config.l2_height + self.config.attestation_ttl_blocks,
            status: AttestationStatus::Verified,
        };
        commitment.status = CommitmentStatus::Attested;
        lot.status = LotStatus::Attested;
        let event_lane = lot.lane;
        self.curator_attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.curator_attestations = self.curator_attestations.len() as u64;
        self.push_event("pq_curator_attested", &attestation_id, event_lane);
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn issue_low_fee_entropy_credit(
        &mut self,
        lot_id: &str,
        beneficiary_commitment_root: String,
        credit_asset_id: String,
    ) -> PrivateL2PqConfidentialDecoyEntropyMarketRuntimeResult<String> {
        ensure!(
            self.low_fee_entropy_credits.len() < MAX_LOW_FEE_CREDITS,
            "low fee entropy credit capacity exceeded"
        );
        let lot = self
            .decoy_lots
            .get_mut(lot_id)
            .ok_or_else(|| format!("unknown decoy entropy lot {lot_id}"))?;
        ensure!(lot.status == LotStatus::Attested, "lot must be attested");
        let record = json!({
            "lot_id": lot_id,
            "lane_id": lot.lane_id,
            "beneficiary_commitment_root": beneficiary_commitment_root,
            "credit_asset_id": credit_asset_id,
        });
        let credit_id = id_from_record("low_fee_entropy_credit", &record);
        let credit_micro_units = entropy_credit_micro_units(
            lot.fee_cap_micro_units,
            lot.quality_bps,
            self.config.target_low_fee_discount_bps,
            self.config.max_credit_micro_units,
        );
        let credit = LowFeeEntropyCredit {
            credit_id: credit_id.clone(),
            lot_id: lot_id.to_string(),
            lane_id: lot.lane_id.clone(),
            beneficiary_commitment_root,
            credit_asset_id,
            credit_micro_units,
            discount_bps: self.config.target_low_fee_discount_bps,
            expires_at_l2_height: self.config.l2_height + self.config.credit_ttl_blocks,
            status: CreditStatus::Minted,
        };
        lot.status = LotStatus::CreditIssued;
        let event_lane = lot.lane;
        self.low_fee_entropy_credits
            .insert(credit_id.clone(), credit);
        self.counters.low_fee_entropy_credits = self.low_fee_entropy_credits.len() as u64;
        self.push_event("low_fee_entropy_credit_issued", &credit_id, event_lane);
        self.refresh_roots();
        Ok(credit_id)
    }

    pub fn quarantine_linkability_regression(
        &mut self,
        lot_id: &str,
        reason: QuarantineReason,
        evidence_root: String,
        regression_bps: u64,
    ) -> PrivateL2PqConfidentialDecoyEntropyMarketRuntimeResult<String> {
        ensure!(
            self.linkability_quarantines.len() < MAX_LINKABILITY_QUARANTINES,
            "linkability quarantine capacity exceeded"
        );
        let lot = self
            .decoy_lots
            .get_mut(lot_id)
            .ok_or_else(|| format!("unknown decoy entropy lot {lot_id}"))?;
        ensure!(
            regression_bps >= self.config.linkability_threshold_bps,
            "regression below quarantine threshold"
        );
        let record = json!({
            "lot_id": lot_id,
            "lane_id": lot.lane_id,
            "reason": reason.as_str(),
            "evidence_root": evidence_root,
            "regression_bps": regression_bps,
        });
        let quarantine_id = id_from_record("linkability_regression_quarantine", &record);
        let quarantine = LinkabilityRegressionQuarantine {
            quarantine_id: quarantine_id.clone(),
            lot_id: lot_id.to_string(),
            lane_id: lot.lane_id.clone(),
            reason,
            evidence_root,
            regression_bps,
            released_at_l2_height: self.config.l2_height + self.config.quarantine_ttl_blocks,
            active: true,
        };
        lot.status = LotStatus::Quarantined;
        let event_lane = lot.lane;
        self.quarantined_lots.insert(lot_id.to_string());
        self.linkability_quarantines
            .insert(quarantine_id.clone(), quarantine);
        self.counters.linkability_quarantines = self.linkability_quarantines.len() as u64;
        self.push_event(
            "linkability_regression_quarantined",
            &quarantine_id,
            event_lane,
        );
        self.refresh_roots();
        Ok(quarantine_id)
    }

    pub fn record_redaction_budget(
        &mut self,
        request: RedactionBudgetRequest,
    ) -> PrivateL2PqConfidentialDecoyEntropyMarketRuntimeResult<String> {
        ensure!(
            self.redaction_budgets.len() < MAX_REDACTION_BUDGETS,
            "redaction budget capacity exceeded"
        );
        ensure!(
            request.redactions_used <= self.config.max_redactions_per_window,
            "redaction budget exceeded"
        );
        ensure!(
            request.remaining_privacy_set_size >= self.config.min_privacy_set_size,
            "redaction budget privacy set floor not met"
        );
        let lane = self
            .wallet_sampling_lanes
            .get(&request.lane_id)
            .ok_or_else(|| format!("unknown wallet sampling lane {}", request.lane_id))?;
        let record = json!({
            "subject_root": request.subject_root,
            "lane_id": request.lane_id,
            "disclosed_field_root": request.disclosed_field_root,
            "window_start_l2_height": self.config.l2_height,
            "redactions_used": request.redactions_used,
            "remaining_privacy_set_size": request.remaining_privacy_set_size,
        });
        let budget_id = id_from_record("privacy_redaction_budget", &record);
        let budget = PrivacyRedactionBudget {
            budget_id: budget_id.clone(),
            subject_root: request.subject_root,
            lane_id: request.lane_id,
            disclosed_field_root: request.disclosed_field_root,
            window_start_l2_height: self.config.l2_height,
            window_end_l2_height: self.config.l2_height + self.config.redaction_window_blocks,
            redactions_allowed: self.config.max_redactions_per_window,
            redactions_used: request.redactions_used,
            remaining_privacy_set_size: request.remaining_privacy_set_size,
        };
        let event_lane = lane.lane;
        self.redaction_budgets.insert(budget_id.clone(), budget);
        self.counters.redaction_budgets = self.redaction_budgets.len() as u64;
        self.push_event("privacy_redaction_budget_recorded", &budget_id, event_lane);
        self.refresh_roots();
        Ok(budget_id)
    }

    pub fn settle_lot(
        &mut self,
        lot_id: &str,
    ) -> PrivateL2PqConfidentialDecoyEntropyMarketRuntimeResult<()> {
        let lot = self
            .decoy_lots
            .get_mut(lot_id)
            .ok_or_else(|| format!("unknown decoy entropy lot {lot_id}"))?;
        ensure!(
            lot.status == LotStatus::CreditIssued || lot.status == LotStatus::Attested,
            "decoy entropy lot cannot settle from current status"
        );
        lot.status = LotStatus::Settled;
        let event_lane = lot.lane;
        self.counters.settled_lots = self.counters.settled_lots.saturating_add(1);
        self.push_event("decoy_entropy_lot_settled", lot_id, event_lane);
        self.refresh_roots();
        Ok(())
    }

    pub fn refresh_roots(&mut self) {
        self.counters.decoy_lots = self.decoy_lots.len() as u64;
        self.counters.ring_member_commitments = self.ring_member_commitments.len() as u64;
        self.counters.curator_attestations = self.curator_attestations.len() as u64;
        self.counters.wallet_sampling_lanes = self.wallet_sampling_lanes.len() as u64;
        self.counters.low_fee_entropy_credits = self.low_fee_entropy_credits.len() as u64;
        self.counters.linkability_quarantines = self.linkability_quarantines.len() as u64;
        self.counters.redaction_budgets = self.redaction_budgets.len() as u64;
        self.counters.public_events = self.public_events.len() as u64;
        self.roots.config_root = record_root("config", &self.config.public_record());
        self.roots.counters_root = record_root("counters", &self.counters.public_record());
        self.roots.decoy_lot_root =
            map_root("decoy_lots", &self.decoy_lots, |lot| lot.public_record());
        self.roots.ring_member_commitment_root = map_root(
            "ring_member_commitments",
            &self.ring_member_commitments,
            |commitment| commitment.public_record(),
        );
        self.roots.curator_attestation_root = map_root(
            "curator_attestations",
            &self.curator_attestations,
            |attestation| attestation.public_record(),
        );
        self.roots.wallet_sampling_lane_root = map_root(
            "wallet_sampling_lanes",
            &self.wallet_sampling_lanes,
            |lane| lane.public_record(),
        );
        self.roots.low_fee_entropy_credit_root = map_root(
            "low_fee_entropy_credits",
            &self.low_fee_entropy_credits,
            |credit| credit.public_record(),
        );
        self.roots.linkability_quarantine_root = map_root(
            "linkability_quarantines",
            &self.linkability_quarantines,
            |quarantine| quarantine.public_record(),
        );
        self.roots.redaction_budget_root =
            map_root("redaction_budgets", &self.redaction_budgets, |budget| {
                budget.public_record()
            });
        self.roots.public_event_root = map_root("public_events", &self.public_events, |event| {
            event.public_record()
        });
        self.roots.state_root = state_root_from_record(&self.public_record_without_state_root());
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "hash_suite": HASH_SUITE,
            "pq_curator_attestation_suite": PQ_CURATOR_ATTESTATION_SUITE,
            "ring_member_commitment_suite": RING_MEMBER_COMMITMENT_SUITE,
            "wallet_sampling_lane_suite": WALLET_SAMPLING_LANE_SUITE,
            "low_fee_entropy_credit_suite": LOW_FEE_ENTROPY_CREDIT_SUITE,
            "linkability_quarantine_suite": LINKABILITY_QUARANTINE_SUITE,
            "privacy_redaction_budget_suite": PRIVACY_REDACTION_BUDGET_SUITE,
            "public_record_suite": PUBLIC_RECORD_SUITE,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record_without_state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root());
        record
    }

    fn push_event(&mut self, event_kind: &str, subject_id: &str, lane: EntropyLane) {
        if self.public_events.len() >= MAX_PUBLIC_EVENTS {
            return;
        }
        let event_root = deterministic_root(event_kind, subject_id);
        let event_record = json!({
            "event_kind": event_kind,
            "subject_id": subject_id,
            "lane": lane.as_str(),
            "event_root": event_root,
            "l2_height": self.config.l2_height,
            "monero_height": self.config.monero_height,
        });
        let event_id = id_from_record("public_event", &event_record);
        self.public_events.insert(
            event_id.clone(),
            PublicEvent {
                event_id,
                event_kind: event_kind.to_string(),
                subject_id: subject_id.to_string(),
                lane,
                event_root,
                l2_height: self.config.l2_height,
                monero_height: self.config.monero_height,
            },
        );
        self.counters.public_events = self.public_events.len() as u64;
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
    devnet().state_root()
}

pub fn devnet_public_record() -> Value {
    devnet().public_record()
}

pub fn state_root_from_public_record(record: &Value) -> String {
    state_root_from_record(record)
}

fn seed_devnet(state: &mut State) {
    let lane_id = state
        .register_sampling_lane(SamplingLaneRegistrationRequest {
            lane: EntropyLane::BridgeWithdrawal,
            wallet_policy_root: deterministic_root("wallet_policy", "bridge-wallet-a"),
            sampler_root: deterministic_root("sampler", "bridge-withdrawal-a"),
            fee_asset_id: "piconero-devnet".to_string(),
            capacity_lots: 256,
            min_entropy_bps: 8_800,
            max_fee_micro_units: 7_500,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        })
        .expect("devnet sampling lane");
    let lot_id = state
        .open_decoy_lot(DecoyEntropyLotRequest {
            lane_id: lane_id.clone(),
            lane: EntropyLane::BridgeWithdrawal,
            wallet_context_root: deterministic_root("wallet_context", "bridge-wallet-a"),
            output_age_histogram_root: deterministic_root("age_histogram", "bridge-window-a"),
            decoy_selection_root: deterministic_root("decoy_selection", "bridge-window-a"),
            view_tag_redaction_root: deterministic_root("view_tag_redaction", "bridge-window-a"),
            ring_member_count: 192,
            privacy_set_size: 262_144,
            median_age_blocks: 1_440,
            p95_age_blocks: 8_400,
            linkability_bps: 120,
            fee_cap_micro_units: 6_800,
        })
        .expect("devnet decoy lot");
    let commitment_id = state
        .commit_ring_members(RingMemberCommitmentRequest {
            lot_id: lot_id.clone(),
            ring_member_root: deterministic_root("ring_members", "bridge-window-a"),
            spend_age_bucket_root: deterministic_root("spend_age", "bridge-window-a"),
            quality_commitment_root: deterministic_root("quality_commitment", "bridge-window-a"),
            entropy_witness_root: deterministic_root("entropy_witness", "bridge-window-a"),
        })
        .expect("devnet commitment");
    state
        .attest_curator(PqCuratorAttestationRequest {
            lot_id: lot_id.clone(),
            commitment_id,
            curator_id: "pq-decoy-curator-a".to_string(),
            pq_public_key_root: deterministic_root("pq_public_key", "curator-a"),
            pq_signature_root: deterministic_root("pq_signature", "curator-a"),
            transcript_root: deterministic_root("transcript", "curator-a"),
            disclosure_root: deterministic_root("disclosure", "operator-safe-a"),
            attested_entropy_bps: 9_250,
            attested_quality_bps: 9_180,
            attested_linkability_bps: 120,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        })
        .expect("devnet curator attestation");
    state
        .issue_low_fee_entropy_credit(
            &lot_id,
            deterministic_root("beneficiary", "bridge-wallet-a"),
            "low-fee-entropy-credit-devnet".to_string(),
        )
        .expect("devnet entropy credit");
    state
        .record_redaction_budget(RedactionBudgetRequest {
            subject_root: deterministic_root("subject", "bridge-window-a"),
            lane_id,
            disclosed_field_root: deterministic_root("disclosed_fields", "roots-only"),
            redactions_used: 3,
            remaining_privacy_set_size: 262_144,
        })
        .expect("devnet redaction budget");
}

fn seed_demo(state: &mut State) {
    let lane_id = state
        .register_sampling_lane(SamplingLaneRegistrationRequest {
            lane: EntropyLane::WalletSpend,
            wallet_policy_root: deterministic_root("wallet_policy", "spend-wallet-b"),
            sampler_root: deterministic_root("sampler", "wallet-spend-b"),
            fee_asset_id: "piconero-devnet".to_string(),
            capacity_lots: 512,
            min_entropy_bps: 8_900,
            max_fee_micro_units: 4_000,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        })
        .expect("demo sampling lane");
    let lot_id = state
        .open_decoy_lot(DecoyEntropyLotRequest {
            lane_id: lane_id.clone(),
            lane: EntropyLane::WalletSpend,
            wallet_context_root: deterministic_root("wallet_context", "spend-wallet-b"),
            output_age_histogram_root: deterministic_root("age_histogram", "wallet-window-b"),
            decoy_selection_root: deterministic_root("decoy_selection", "wallet-window-b"),
            view_tag_redaction_root: deterministic_root("view_tag_redaction", "wallet-window-b"),
            ring_member_count: 160,
            privacy_set_size: 196_608,
            median_age_blocks: 2_000,
            p95_age_blocks: 10_800,
            linkability_bps: 180,
            fee_cap_micro_units: 3_500,
        })
        .expect("demo decoy lot");
    let commitment_id = state
        .commit_ring_members(RingMemberCommitmentRequest {
            lot_id: lot_id.clone(),
            ring_member_root: deterministic_root("ring_members", "wallet-window-b"),
            spend_age_bucket_root: deterministic_root("spend_age", "wallet-window-b"),
            quality_commitment_root: deterministic_root("quality_commitment", "wallet-window-b"),
            entropy_witness_root: deterministic_root("entropy_witness", "wallet-window-b"),
        })
        .expect("demo commitment");
    state
        .attest_curator(PqCuratorAttestationRequest {
            lot_id: lot_id.clone(),
            commitment_id,
            curator_id: "pq-decoy-curator-b".to_string(),
            pq_public_key_root: deterministic_root("pq_public_key", "curator-b"),
            pq_signature_root: deterministic_root("pq_signature", "curator-b"),
            transcript_root: deterministic_root("transcript", "curator-b"),
            disclosure_root: deterministic_root("disclosure", "operator-safe-b"),
            attested_entropy_bps: 9_030,
            attested_quality_bps: 8_980,
            attested_linkability_bps: 180,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        })
        .expect("demo curator attestation");
    state
        .quarantine_linkability_regression(
            &lot_id,
            QuarantineReason::FeePatternLeakage,
            deterministic_root("quarantine_evidence", "wallet-window-b"),
            320,
        )
        .expect("demo quarantine");
}

fn entropy_score(ring_member_count: u16, privacy_set_size: u64) -> u64 {
    let ring_component = (ring_member_count as u64)
        .saturating_mul(MAX_BPS)
        .saturating_div(DEFAULT_MIN_RING_MEMBERS as u64)
        .min(MAX_BPS);
    let set_component = privacy_set_size
        .saturating_mul(MAX_BPS)
        .saturating_div(DEFAULT_MIN_PRIVACY_SET_SIZE)
        .min(MAX_BPS);
    (ring_component.saturating_mul(48) + set_component.saturating_mul(52)) / 100
}

fn freshness_score(median_age_blocks: u64, p95_age_blocks: u64) -> u64 {
    let median_component =
        MAX_BPS.saturating_sub(median_age_blocks.saturating_mul(MAX_BPS) / 21_600);
    let tail_component = MAX_BPS.saturating_sub(p95_age_blocks.saturating_mul(MAX_BPS) / 86_400);
    (median_component.saturating_mul(62) + tail_component.saturating_mul(38)) / 100
}

fn quality_score(entropy_bps: u64, freshness_bps: u64, linkability_bps: u64) -> u64 {
    let raw = (entropy_bps.saturating_mul(56) + freshness_bps.saturating_mul(44)) / 100;
    raw.saturating_sub(linkability_bps / 2).min(MAX_BPS)
}

fn entropy_credit_micro_units(
    fee_cap_micro_units: u64,
    quality_bps: u64,
    discount_bps: u64,
    max_credit_micro_units: u64,
) -> u64 {
    let quality_bonus_bps = quality_bps
        .saturating_sub(DEFAULT_MIN_QUALITY_BPS)
        .min(2_000)
        / 2;
    fee_cap_micro_units
        .saturating_mul(discount_bps.saturating_add(quality_bonus_bps))
        .saturating_div(MAX_BPS)
        .min(max_credit_micro_units)
}

fn deterministic_root(domain: &str, label: &str) -> String {
    domain_hash(
        &format!("private-l2-pq-decoy-entropy-market:{domain}:root"),
        &[HashPart::Str(label)],
        32,
    )
}

fn empty_root(domain: &str) -> String {
    domain_hash(
        &format!("private-l2-pq-decoy-entropy-market:{domain}:empty"),
        &[HashPart::Str(PROTOCOL_VERSION)],
        32,
    )
}

fn id_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("private-l2-pq-decoy-entropy-market:{domain}:id"),
        &[HashPart::Json(record)],
        16,
    )
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("private-l2-pq-decoy-entropy-market:{domain}:record"),
        &[HashPart::Json(record)],
        32,
    )
}

fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "private-l2-pq-decoy-entropy-market:state-root",
        &[HashPart::Json(record)],
        32,
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| json!({"key": key, "record": public(value)}))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("private-l2-pq-decoy-entropy-market:{domain}"),
        &leaves,
    )
}
