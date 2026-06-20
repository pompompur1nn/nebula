use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateRingMemberLiquidityScoreOracleRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_RING_MEMBER_LIQUIDITY_SCORE_ORACLE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-ring-member-liquidity-score-oracle-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_RING_MEMBER_LIQUIDITY_SCORE_ORACLE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_ORACLE_ID: &str = "monero-l2-pq-private-ring-member-liquidity-score-oracle-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_SCORE_ASSET_ID: &str = "ring-member-liquidity-score-devnet";
pub const DEVNET_HEIGHT: u64 = 976_640;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-ring-member-liquidity-score-oracle-v1";
pub const RING_COHORT_SCHEME: &str = "private-ring-member-liquidity-cohort-root-v1";
pub const SCORE_FEED_SCHEME: &str = "pq-private-ring-member-score-feed-root-v1";
pub const LIQUIDITY_OBSERVATION_SCHEME: &str = "decoy-liquidity-observation-root-v1";
pub const PQ_ATTESTATION_SCHEME: &str = "pq-ring-member-liquidity-oracle-attestation-root-v1";
pub const SETTLEMENT_SCHEME: &str = "low-fee-ring-member-score-settlement-root-v1";
pub const REBATE_SCHEME: &str = "wallet-privacy-score-market-rebate-root-v1";
pub const REDACTION_BUDGET_SCHEME: &str = "ring-member-liquidity-redaction-budget-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str = "redacted-ring-member-liquidity-operator-summary-root-v1";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_RING_MEMBERS: u64 = 65_536;
pub const DEFAULT_MIN_DECOY_MEMBERS: u64 = 32_768;
pub const DEFAULT_MIN_LIQUIDITY_SAMPLES: u64 = 512;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_LOW_FEE_BPS: u64 = 3;
pub const DEFAULT_FAST_FEE_BPS: u64 = 8;
pub const DEFAULT_REBATE_BPS: u64 = 5;
pub const DEFAULT_MIN_SCORE: u64 = 1;
pub const DEFAULT_MAX_SCORE: u64 = 1_000;
pub const DEFAULT_MARKET_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_REDACTION_TTL_BLOCKS: u64 = 10_080;
pub const DEFAULT_MAX_FEED_ITEMS: usize = 4_096;
pub const MAX_RING_COHORTS: usize = 1_048_576;
pub const MAX_SCORE_FEEDS: usize = 524_288;
pub const MAX_LIQUIDITY_OBSERVATIONS: usize = 2_097_152;
pub const MAX_PQ_ATTESTATIONS: usize = 2_097_152;
pub const MAX_SCORING_SETTLEMENTS: usize = 1_048_576;
pub const MAX_REBATES: usize = 1_048_576;
pub const MAX_REDACTION_BUDGETS: usize = 524_288;
pub const MAX_OPERATOR_SUMMARIES: usize = 262_144;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RingCohortKind {
    WalletSpend,
    BridgeExit,
    SwapInput,
    MerchantPayment,
    LiquidityRebalance,
    RecoverySweep,
    AuditSample,
}

impl RingCohortKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletSpend => "wallet_spend",
            Self::BridgeExit => "bridge_exit",
            Self::SwapInput => "swap_input",
            Self::MerchantPayment => "merchant_payment",
            Self::LiquidityRebalance => "liquidity_rebalance",
            Self::RecoverySweep => "recovery_sweep",
            Self::AuditSample => "audit_sample",
        }
    }

    pub fn quality_weight(self) -> u64 {
        match self {
            Self::LiquidityRebalance => 1_000,
            Self::SwapInput => 960,
            Self::BridgeExit => 930,
            Self::WalletSpend => 900,
            Self::MerchantPayment => 860,
            Self::RecoverySweep => 760,
            Self::AuditSample => 700,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScoreFeedLane {
    LowFee,
    WalletPrivacy,
    BridgeExit,
    DexRouting,
    OperatorSummary,
    EmergencyRedaction,
}

impl ScoreFeedLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::WalletPrivacy => "wallet_privacy",
            Self::BridgeExit => "bridge_exit",
            Self::DexRouting => "dex_routing",
            Self::OperatorSummary => "operator_summary",
            Self::EmergencyRedaction => "emergency_redaction",
        }
    }

    pub fn fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::LowFee | Self::WalletPrivacy => config.low_fee_bps,
            Self::EmergencyRedaction | Self::BridgeExit => config.fast_fee_bps,
            Self::DexRouting | Self::OperatorSummary => config.low_fee_bps + 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationSource {
    WalletScan,
    OutputSampler,
    BridgeWatcher,
    DexRouter,
    LiquidityMirror,
    OperatorProbe,
}

impl ObservationSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletScan => "wallet_scan",
            Self::OutputSampler => "output_sampler",
            Self::BridgeWatcher => "bridge_watcher",
            Self::DexRouter => "dex_router",
            Self::LiquidityMirror => "liquidity_mirror",
            Self::OperatorProbe => "operator_probe",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    ScoreFeed,
    LiquidityObservation,
    CohortQuality,
    Settlement,
    Rebate,
    Redaction,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ScoreFeed => "score_feed",
            Self::LiquidityObservation => "liquidity_observation",
            Self::CohortQuality => "cohort_quality",
            Self::Settlement => "settlement",
            Self::Rebate => "rebate",
            Self::Redaction => "redaction",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordStatus {
    Draft,
    Submitted,
    Attested,
    Active,
    Settled,
    Rebated,
    Published,
    Redacted,
    Rejected,
    Expired,
}

impl RecordStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Submitted => "submitted",
            Self::Attested => "attested",
            Self::Active => "active",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Published => "published",
            Self::Redacted => "redacted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::Attested | Self::Active | Self::Settled | Self::Published
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub oracle_id: String,
    pub fee_asset_id: String,
    pub score_asset_id: String,
    pub devnet_height: u64,
    pub hash_suite: String,
    pub pq_attestation_suite: String,
    pub min_ring_members: u64,
    pub min_decoy_members: u64,
    pub min_liquidity_samples: u64,
    pub min_privacy_set_size: u64,
    pub target_pq_security_bits: u16,
    pub low_fee_bps: u64,
    pub fast_fee_bps: u64,
    pub rebate_bps: u64,
    pub min_score: u64,
    pub max_score: u64,
    pub market_ttl_blocks: u64,
    pub redaction_ttl_blocks: u64,
    pub max_feed_items: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            oracle_id: DEVNET_ORACLE_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            score_asset_id: DEVNET_SCORE_ASSET_ID.to_string(),
            devnet_height: DEVNET_HEIGHT,
            hash_suite: HASH_SUITE.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
            min_ring_members: DEFAULT_MIN_RING_MEMBERS,
            min_decoy_members: DEFAULT_MIN_DECOY_MEMBERS,
            min_liquidity_samples: DEFAULT_MIN_LIQUIDITY_SAMPLES,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            low_fee_bps: DEFAULT_LOW_FEE_BPS,
            fast_fee_bps: DEFAULT_FAST_FEE_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            min_score: DEFAULT_MIN_SCORE,
            max_score: DEFAULT_MAX_SCORE,
            market_ttl_blocks: DEFAULT_MARKET_TTL_BLOCKS,
            redaction_ttl_blocks: DEFAULT_REDACTION_TTL_BLOCKS,
            max_feed_items: DEFAULT_MAX_FEED_ITEMS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_sequence: u64,
    pub ring_cohorts: usize,
    pub score_feeds: usize,
    pub liquidity_observations: usize,
    pub pq_attestations: usize,
    pub scoring_settlements: usize,
    pub rebates: usize,
    pub redaction_budgets: usize,
    pub operator_summaries: usize,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub ring_cohort_root: String,
    pub score_feed_root: String,
    pub liquidity_observation_root: String,
    pub pq_attestation_root: String,
    pub scoring_settlement_root: String,
    pub rebate_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub wallet_privacy_index_root: String,
    pub decoy_liquidity_index_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RingCohortRequest {
    pub cohort_id: String,
    pub cohort_kind: RingCohortKind,
    pub monero_start_height: u64,
    pub monero_end_height: u64,
    pub ring_member_count: u64,
    pub decoy_member_count: u64,
    pub wallet_privacy_set_size: u64,
    pub ring_member_commitment_root: String,
    pub decoy_distribution_root: String,
    pub key_image_guard_root: String,
    pub allowed_lanes: BTreeSet<ScoreFeedLane>,
    pub status: RecordStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RingCohortRecord {
    pub cohort_id: String,
    pub sequence: u64,
    pub cohort_kind: RingCohortKind,
    pub monero_start_height: u64,
    pub monero_end_height: u64,
    pub ring_member_count: u64,
    pub decoy_member_count: u64,
    pub wallet_privacy_set_size: u64,
    pub ring_member_commitment_root: String,
    pub decoy_distribution_root: String,
    pub key_image_guard_root: String,
    pub allowed_lanes: BTreeSet<ScoreFeedLane>,
    pub cohort_quality_score: u64,
    pub status: RecordStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScoreFeedRequest {
    pub feed_id: String,
    pub cohort_id: String,
    pub lane: ScoreFeedLane,
    pub publisher_id: String,
    pub score_epoch: u64,
    pub score_floor: u64,
    pub score_ceiling: u64,
    pub scored_member_count: u64,
    pub feed_commitment_root: String,
    pub feed_nullifier_root: String,
    pub wallet_hint_root: String,
    pub max_fee_bps: u64,
    pub status: RecordStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScoreFeedRecord {
    pub feed_id: String,
    pub sequence: u64,
    pub cohort_id: String,
    pub lane: ScoreFeedLane,
    pub publisher_id: String,
    pub score_epoch: u64,
    pub score_floor: u64,
    pub score_ceiling: u64,
    pub scored_member_count: u64,
    pub feed_commitment_root: String,
    pub feed_nullifier_root: String,
    pub wallet_hint_root: String,
    pub max_fee_bps: u64,
    pub market_fee_piconero: u64,
    pub status: RecordStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityObservationRequest {
    pub observation_id: String,
    pub cohort_id: String,
    pub feed_id: String,
    pub source: ObservationSource,
    pub observer_id: String,
    pub observed_height: u64,
    pub liquid_decoy_count: u64,
    pub illiquid_decoy_count: u64,
    pub median_liquidity_piconero: u64,
    pub p95_liquidity_piconero: u64,
    pub observation_root: String,
    pub sealed_wallet_context_root: String,
    pub status: RecordStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityObservationRecord {
    pub observation_id: String,
    pub sequence: u64,
    pub cohort_id: String,
    pub feed_id: String,
    pub source: ObservationSource,
    pub observer_id: String,
    pub observed_height: u64,
    pub liquid_decoy_count: u64,
    pub illiquid_decoy_count: u64,
    pub median_liquidity_piconero: u64,
    pub p95_liquidity_piconero: u64,
    pub observation_root: String,
    pub sealed_wallet_context_root: String,
    pub decoy_liquidity_score: u64,
    pub status: RecordStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestationRequest {
    pub attestation_id: String,
    pub attestor_id: String,
    pub subject_id: String,
    pub kind: AttestationKind,
    pub lane: ScoreFeedLane,
    pub observed_root: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub pq_security_bits: u16,
    pub attested_height: u64,
    pub status: RecordStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestationRecord {
    pub attestation_id: String,
    pub sequence: u64,
    pub attestor_id: String,
    pub subject_id: String,
    pub kind: AttestationKind,
    pub lane: ScoreFeedLane,
    pub observed_root: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub pq_security_bits: u16,
    pub attested_height: u64,
    pub status: RecordStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScoringSettlementRequest {
    pub settlement_id: String,
    pub feed_id: String,
    pub cohort_id: String,
    pub settlement_operator_id: String,
    pub lane: ScoreFeedLane,
    pub settled_member_count: u64,
    pub average_score: u64,
    pub low_fee_volume_piconero: u64,
    pub fee_paid_piconero: u64,
    pub settlement_root: String,
    pub wallet_privacy_receipt_root: String,
    pub status: RecordStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScoringSettlementRecord {
    pub settlement_id: String,
    pub sequence: u64,
    pub feed_id: String,
    pub cohort_id: String,
    pub settlement_operator_id: String,
    pub lane: ScoreFeedLane,
    pub settled_member_count: u64,
    pub average_score: u64,
    pub low_fee_volume_piconero: u64,
    pub fee_paid_piconero: u64,
    pub settlement_root: String,
    pub wallet_privacy_receipt_root: String,
    pub rebate_eligible_piconero: u64,
    pub status: RecordStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateRequest {
    pub rebate_id: String,
    pub settlement_id: String,
    pub wallet_cohort_id: String,
    pub sponsor_id: String,
    pub eligible_fee_piconero: u64,
    pub rebate_bps: u64,
    pub rebate_commitment_root: String,
    pub claim_nullifier_root: String,
    pub status: RecordStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateRecord {
    pub rebate_id: String,
    pub sequence: u64,
    pub settlement_id: String,
    pub wallet_cohort_id: String,
    pub sponsor_id: String,
    pub eligible_fee_piconero: u64,
    pub rebate_bps: u64,
    pub rebate_amount_piconero: u64,
    pub rebate_commitment_root: String,
    pub claim_nullifier_root: String,
    pub status: RecordStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudgetRequest {
    pub budget_id: String,
    pub operator_id: String,
    pub subject_ids: BTreeSet<String>,
    pub reason_code: String,
    pub max_public_fields: u16,
    pub expires_l2_height: u64,
    pub redaction_root: String,
    pub status: RecordStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudgetRecord {
    pub budget_id: String,
    pub sequence: u64,
    pub operator_id: String,
    pub subject_ids: BTreeSet<String>,
    pub reason_code: String,
    pub max_public_fields: u16,
    pub created_l2_height: u64,
    pub expires_l2_height: u64,
    pub redaction_root: String,
    pub status: RecordStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummaryRequest {
    pub summary_id: String,
    pub operator_id: String,
    pub l2_height: u64,
    pub cohort_count: u64,
    pub feed_count: u64,
    pub observation_count: u64,
    pub attestation_count: u64,
    pub settlement_count: u64,
    pub redacted_subject_count: u64,
    pub average_public_score: u64,
    pub summary_root: String,
    pub redaction_budget_id: String,
    pub status: RecordStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummaryRecord {
    pub summary_id: String,
    pub sequence: u64,
    pub operator_id: String,
    pub l2_height: u64,
    pub cohort_count: u64,
    pub feed_count: u64,
    pub observation_count: u64,
    pub attestation_count: u64,
    pub settlement_count: u64,
    pub redacted_subject_count: u64,
    pub average_public_score: u64,
    pub summary_root: String,
    pub redaction_budget_id: String,
    pub status: RecordStatus,
}

macro_rules! impl_public_record {
    ($ty:ty, $domain:expr) => {
        impl $ty {
            pub fn public_record(&self) -> Value {
                json!(self)
            }

            pub fn digest(&self) -> String {
                stable_digest($domain, self.public_record())
            }
        }
    };
}

impl_public_record!(RingCohortRequest, "RingCohortRequest");
impl_public_record!(RingCohortRecord, "RingCohortRecord");
impl_public_record!(ScoreFeedRequest, "ScoreFeedRequest");
impl_public_record!(ScoreFeedRecord, "ScoreFeedRecord");
impl_public_record!(LiquidityObservationRequest, "LiquidityObservationRequest");
impl_public_record!(LiquidityObservationRecord, "LiquidityObservationRecord");
impl_public_record!(PqAttestationRequest, "PqAttestationRequest");
impl_public_record!(PqAttestationRecord, "PqAttestationRecord");
impl_public_record!(ScoringSettlementRequest, "ScoringSettlementRequest");
impl_public_record!(ScoringSettlementRecord, "ScoringSettlementRecord");
impl_public_record!(RebateRequest, "RebateRequest");
impl_public_record!(RebateRecord, "RebateRecord");
impl_public_record!(RedactionBudgetRequest, "RedactionBudgetRequest");
impl_public_record!(RedactionBudgetRecord, "RedactionBudgetRecord");
impl_public_record!(OperatorSummaryRequest, "OperatorSummaryRequest");
impl_public_record!(OperatorSummaryRecord, "OperatorSummaryRecord");

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub current_l2_height: u64,
    pub next_sequence: u64,
    pub ring_cohorts: BTreeMap<String, RingCohortRecord>,
    pub score_feeds: BTreeMap<String, ScoreFeedRecord>,
    pub liquidity_observations: BTreeMap<String, LiquidityObservationRecord>,
    pub pq_attestations: BTreeMap<String, PqAttestationRecord>,
    pub scoring_settlements: BTreeMap<String, ScoringSettlementRecord>,
    pub rebates: BTreeMap<String, RebateRecord>,
    pub redaction_budgets: BTreeMap<String, RedactionBudgetRecord>,
    pub operator_summaries: BTreeMap<String, OperatorSummaryRecord>,
    pub wallet_privacy_index: BTreeMap<String, BTreeSet<String>>,
    pub decoy_liquidity_index: BTreeMap<String, BTreeSet<String>>,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            current_l2_height: config.devnet_height,
            config,
            next_sequence: 1,
            ring_cohorts: BTreeMap::new(),
            score_feeds: BTreeMap::new(),
            liquidity_observations: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            scoring_settlements: BTreeMap::new(),
            rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            wallet_privacy_index: BTreeMap::new(),
            decoy_liquidity_index: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        Self::try_devnet().unwrap_or_else(|_| Self::new(Config::devnet()))
    }

    pub fn try_devnet() -> Result<Self> {
        let mut state = Self::new(Config::devnet());
        let mut lanes = BTreeSet::new();
        lanes.insert(ScoreFeedLane::LowFee);
        lanes.insert(ScoreFeedLane::WalletPrivacy);
        lanes.insert(ScoreFeedLane::BridgeExit);
        let cohort = state.register_ring_cohort(RingCohortRequest {
            cohort_id: "devnet-ring-liquidity-cohort-0".to_string(),
            cohort_kind: RingCohortKind::WalletSpend,
            monero_start_height: DEVNET_HEIGHT,
            monero_end_height: DEVNET_HEIGHT + 72,
            ring_member_count: state.config.min_ring_members * 2,
            decoy_member_count: state.config.min_decoy_members * 2,
            wallet_privacy_set_size: state.config.min_privacy_set_size,
            ring_member_commitment_root: demo_root("ring-members", 0),
            decoy_distribution_root: demo_root("decoy-distribution", 0),
            key_image_guard_root: demo_root("key-image-guard", 0),
            allowed_lanes: lanes,
            status: RecordStatus::Active,
        })?;
        let feed = state.publish_score_feed(ScoreFeedRequest {
            feed_id: "devnet-score-feed-0".to_string(),
            cohort_id: cohort.cohort_id.clone(),
            lane: ScoreFeedLane::WalletPrivacy,
            publisher_id: "devnet-pq-score-publisher-0".to_string(),
            score_epoch: 1,
            score_floor: 720,
            score_ceiling: 980,
            scored_member_count: cohort.decoy_member_count,
            feed_commitment_root: demo_root("score-feed", 0),
            feed_nullifier_root: demo_root("score-nullifiers", 0),
            wallet_hint_root: demo_root("wallet-hints", 0),
            max_fee_bps: state.config.low_fee_bps,
            status: RecordStatus::Attested,
        })?;
        let observation = state.record_liquidity_observation(LiquidityObservationRequest {
            observation_id: "devnet-liquidity-observation-0".to_string(),
            cohort_id: cohort.cohort_id.clone(),
            feed_id: feed.feed_id.clone(),
            source: ObservationSource::WalletScan,
            observer_id: "devnet-wallet-scan-oracle-0".to_string(),
            observed_height: DEVNET_HEIGHT + 80,
            liquid_decoy_count: 84_000,
            illiquid_decoy_count: 4_000,
            median_liquidity_piconero: 3_400_000,
            p95_liquidity_piconero: 12_800_000,
            observation_root: demo_root("liquidity-observation", 0),
            sealed_wallet_context_root: demo_root("sealed-wallet-context", 0),
            status: RecordStatus::Attested,
        })?;
        state.record_pq_attestation(PqAttestationRequest {
            attestation_id: "devnet-pq-attestation-0".to_string(),
            attestor_id: "devnet-pq-oracle-member-0".to_string(),
            subject_id: observation.observation_id.clone(),
            kind: AttestationKind::LiquidityObservation,
            lane: ScoreFeedLane::WalletPrivacy,
            observed_root: observation.observation_root.clone(),
            pq_public_key_root: demo_root("pq-public-key", 0),
            pq_signature_root: demo_root("pq-signature", 0),
            transcript_root: demo_root("pq-transcript", 0),
            pq_security_bits: state.config.target_pq_security_bits,
            attested_height: DEVNET_HEIGHT + 81,
            status: RecordStatus::Attested,
        })?;
        let settlement = state.settle_score_market(ScoringSettlementRequest {
            settlement_id: "devnet-score-settlement-0".to_string(),
            feed_id: feed.feed_id.clone(),
            cohort_id: cohort.cohort_id.clone(),
            settlement_operator_id: "devnet-score-market-operator-0".to_string(),
            lane: ScoreFeedLane::LowFee,
            settled_member_count: 64_000,
            average_score: 886,
            low_fee_volume_piconero: 240_000_000,
            fee_paid_piconero: 72_000,
            settlement_root: demo_root("score-settlement", 0),
            wallet_privacy_receipt_root: demo_root("wallet-privacy-receipts", 0),
            status: RecordStatus::Settled,
        })?;
        state.issue_rebate(RebateRequest {
            rebate_id: "devnet-score-rebate-0".to_string(),
            settlement_id: settlement.settlement_id.clone(),
            wallet_cohort_id: cohort.cohort_id.clone(),
            sponsor_id: "devnet-privacy-fee-sponsor-0".to_string(),
            eligible_fee_piconero: settlement.fee_paid_piconero,
            rebate_bps: state.config.rebate_bps,
            rebate_commitment_root: demo_root("rebate-commitment", 0),
            claim_nullifier_root: demo_root("rebate-nullifiers", 0),
            status: RecordStatus::Rebated,
        })?;
        let mut subjects = BTreeSet::new();
        subjects.insert(cohort.cohort_id.clone());
        subjects.insert(feed.feed_id.clone());
        let budget = state.allocate_redaction_budget(RedactionBudgetRequest {
            budget_id: "devnet-redaction-budget-0".to_string(),
            operator_id: "devnet-summary-operator-0".to_string(),
            subject_ids: subjects,
            reason_code: "operator_public_summary".to_string(),
            max_public_fields: 12,
            expires_l2_height: state.current_l2_height + state.config.redaction_ttl_blocks,
            redaction_root: demo_root("redaction-budget", 0),
            status: RecordStatus::Active,
        })?;
        state.publish_operator_summary(OperatorSummaryRequest {
            summary_id: "devnet-operator-summary-0".to_string(),
            operator_id: budget.operator_id.clone(),
            l2_height: state.current_l2_height,
            cohort_count: state.ring_cohorts.len() as u64,
            feed_count: state.score_feeds.len() as u64,
            observation_count: state.liquidity_observations.len() as u64,
            attestation_count: state.pq_attestations.len() as u64,
            settlement_count: state.scoring_settlements.len() as u64,
            redacted_subject_count: budget.subject_ids.len() as u64,
            average_public_score: 886,
            summary_root: demo_root("operator-summary", 0),
            redaction_budget_id: budget.budget_id,
            status: RecordStatus::Published,
        })?;
        Ok(state)
    }

    pub fn counters(&self) -> Counters {
        Counters {
            next_sequence: self.next_sequence,
            ring_cohorts: self.ring_cohorts.len(),
            score_feeds: self.score_feeds.len(),
            liquidity_observations: self.liquidity_observations.len(),
            pq_attestations: self.pq_attestations.len(),
            scoring_settlements: self.scoring_settlements.len(),
            rebates: self.rebates.len(),
            redaction_budgets: self.redaction_budgets.len(),
            operator_summaries: self.operator_summaries.len(),
        }
    }

    pub fn roots(&self) -> Roots {
        let mut roots = Roots {
            ring_cohort_root: records_root(
                RING_COHORT_SCHEME,
                self.ring_cohorts
                    .values()
                    .map(RingCohortRecord::public_record),
            ),
            score_feed_root: records_root(
                SCORE_FEED_SCHEME,
                self.score_feeds
                    .values()
                    .map(ScoreFeedRecord::public_record),
            ),
            liquidity_observation_root: records_root(
                LIQUIDITY_OBSERVATION_SCHEME,
                self.liquidity_observations
                    .values()
                    .map(LiquidityObservationRecord::public_record),
            ),
            pq_attestation_root: records_root(
                PQ_ATTESTATION_SCHEME,
                self.pq_attestations
                    .values()
                    .map(PqAttestationRecord::public_record),
            ),
            scoring_settlement_root: records_root(
                SETTLEMENT_SCHEME,
                self.scoring_settlements
                    .values()
                    .map(ScoringSettlementRecord::public_record),
            ),
            rebate_root: records_root(
                REBATE_SCHEME,
                self.rebates.values().map(RebateRecord::public_record),
            ),
            redaction_budget_root: records_root(
                REDACTION_BUDGET_SCHEME,
                self.redaction_budgets
                    .values()
                    .map(RedactionBudgetRecord::public_record),
            ),
            operator_summary_root: records_root(
                OPERATOR_SUMMARY_SCHEME,
                self.operator_summaries
                    .values()
                    .map(OperatorSummaryRecord::public_record),
            ),
            wallet_privacy_index_root: records_root(
                "wallet-privacy-ring-member-liquidity-index-root-v1",
                self.wallet_privacy_index
                    .iter()
                    .map(|(key, values)| json!({"wallet_cohort_id": key, "record_ids": values})),
            ),
            decoy_liquidity_index_root: records_root(
                "decoy-liquidity-score-feed-index-root-v1",
                self.decoy_liquidity_index
                    .iter()
                    .map(|(key, values)| json!({"cohort_id": key, "record_ids": values})),
            ),
            state_root: String::new(),
        };
        let root_view = json!({
            "ring_cohort_root": &roots.ring_cohort_root,
            "score_feed_root": &roots.score_feed_root,
            "liquidity_observation_root": &roots.liquidity_observation_root,
            "pq_attestation_root": &roots.pq_attestation_root,
            "scoring_settlement_root": &roots.scoring_settlement_root,
            "rebate_root": &roots.rebate_root,
            "redaction_budget_root": &roots.redaction_budget_root,
            "operator_summary_root": &roots.operator_summary_root,
            "wallet_privacy_index_root": &roots.wallet_privacy_index_root,
            "decoy_liquidity_index_root": &roots.decoy_liquidity_index_root,
        });
        roots.state_root = domain_hash(
            "MONERO-L2-PQ-PRIVATE-RING-MEMBER-LIQUIDITY-SCORE-ORACLE-ROOTS",
            &[
                HashPart::Str(&self.config.chain_id),
                HashPart::Str(&self.config.protocol_version),
                HashPart::U64(self.current_l2_height),
                HashPart::Json(&root_view),
            ],
            32,
        );
        roots
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "current_l2_height": self.current_l2_height,
            "counters": self.counters().public_record(),
            "roots": self.roots().public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn register_ring_cohort(&mut self, request: RingCohortRequest) -> Result<RingCohortRecord> {
        ensure_capacity(self.ring_cohorts.len(), MAX_RING_COHORTS, "ring cohorts")?;
        ensure_height_range(
            request.monero_start_height,
            request.monero_end_height,
            "ring cohort",
        )?;
        if request.ring_member_count < self.config.min_ring_members {
            return Err("ring cohort below minimum ring member floor".to_string());
        }
        if request.decoy_member_count < self.config.min_decoy_members {
            return Err("ring cohort below minimum decoy member floor".to_string());
        }
        if request.decoy_member_count > request.ring_member_count {
            return Err("decoy members exceed ring members".to_string());
        }
        if request.wallet_privacy_set_size < self.config.min_privacy_set_size {
            return Err("wallet privacy set below configured floor".to_string());
        }
        if request.allowed_lanes.is_empty() {
            return Err("ring cohort requires at least one score feed lane".to_string());
        }
        let sequence = self.next_sequence();
        let cohort_quality_score = cohort_quality_score(
            request.cohort_kind,
            request.ring_member_count,
            request.decoy_member_count,
            request.wallet_privacy_set_size,
            &self.config,
        );
        let record = RingCohortRecord {
            cohort_id: request.cohort_id,
            sequence,
            cohort_kind: request.cohort_kind,
            monero_start_height: request.monero_start_height,
            monero_end_height: request.monero_end_height,
            ring_member_count: request.ring_member_count,
            decoy_member_count: request.decoy_member_count,
            wallet_privacy_set_size: request.wallet_privacy_set_size,
            ring_member_commitment_root: request.ring_member_commitment_root,
            decoy_distribution_root: request.decoy_distribution_root,
            key_image_guard_root: request.key_image_guard_root,
            allowed_lanes: request.allowed_lanes,
            cohort_quality_score,
            status: request.status,
        };
        self.decoy_liquidity_index
            .entry(record.cohort_id.clone())
            .or_default()
            .insert(record.cohort_id.clone());
        self.ring_cohorts
            .insert(record.cohort_id.clone(), record.clone());
        Ok(record)
    }

    pub fn publish_score_feed(&mut self, request: ScoreFeedRequest) -> Result<ScoreFeedRecord> {
        ensure_capacity(self.score_feeds.len(), MAX_SCORE_FEEDS, "score feeds")?;
        let cohort = self
            .ring_cohorts
            .get(&request.cohort_id)
            .ok_or_else(|| "score feed references unknown ring cohort".to_string())?;
        if !cohort.allowed_lanes.contains(&request.lane) {
            return Err("score feed lane is not permitted for cohort".to_string());
        }
        if request.score_floor < self.config.min_score
            || request.score_ceiling > self.config.max_score
        {
            return Err("score feed outside configured score range".to_string());
        }
        if request.score_floor > request.score_ceiling {
            return Err("score floor exceeds score ceiling".to_string());
        }
        if request.scored_member_count == 0
            || request.scored_member_count > cohort.ring_member_count
        {
            return Err("scored member count is outside cohort bounds".to_string());
        }
        if request.max_fee_bps > request.lane.fee_bps(&self.config) || request.max_fee_bps > MAX_BPS
        {
            return Err("score feed fee exceeds lane cap".to_string());
        }
        let market_fee_piconero =
            fee_for_score_market(request.scored_member_count, request.max_fee_bps);
        let record = ScoreFeedRecord {
            feed_id: request.feed_id,
            sequence: self.next_sequence(),
            cohort_id: request.cohort_id,
            lane: request.lane,
            publisher_id: request.publisher_id,
            score_epoch: request.score_epoch,
            score_floor: request.score_floor,
            score_ceiling: request.score_ceiling,
            scored_member_count: request.scored_member_count,
            feed_commitment_root: request.feed_commitment_root,
            feed_nullifier_root: request.feed_nullifier_root,
            wallet_hint_root: request.wallet_hint_root,
            max_fee_bps: request.max_fee_bps,
            market_fee_piconero,
            status: request.status,
        };
        self.decoy_liquidity_index
            .entry(record.cohort_id.clone())
            .or_default()
            .insert(record.feed_id.clone());
        self.score_feeds
            .insert(record.feed_id.clone(), record.clone());
        Ok(record)
    }

    pub fn record_liquidity_observation(
        &mut self,
        request: LiquidityObservationRequest,
    ) -> Result<LiquidityObservationRecord> {
        ensure_capacity(
            self.liquidity_observations.len(),
            MAX_LIQUIDITY_OBSERVATIONS,
            "liquidity observations",
        )?;
        if !self.ring_cohorts.contains_key(&request.cohort_id) {
            return Err("liquidity observation references unknown cohort".to_string());
        }
        if !self.score_feeds.contains_key(&request.feed_id) {
            return Err("liquidity observation references unknown score feed".to_string());
        }
        let sample_count = request.liquid_decoy_count + request.illiquid_decoy_count;
        if sample_count < self.config.min_liquidity_samples {
            return Err("liquidity observation below sample floor".to_string());
        }
        let decoy_liquidity_score = decoy_liquidity_score(
            request.liquid_decoy_count,
            request.illiquid_decoy_count,
            request.median_liquidity_piconero,
            request.p95_liquidity_piconero,
            &self.config,
        );
        let record = LiquidityObservationRecord {
            observation_id: request.observation_id,
            sequence: self.next_sequence(),
            cohort_id: request.cohort_id,
            feed_id: request.feed_id,
            source: request.source,
            observer_id: request.observer_id,
            observed_height: request.observed_height,
            liquid_decoy_count: request.liquid_decoy_count,
            illiquid_decoy_count: request.illiquid_decoy_count,
            median_liquidity_piconero: request.median_liquidity_piconero,
            p95_liquidity_piconero: request.p95_liquidity_piconero,
            observation_root: request.observation_root,
            sealed_wallet_context_root: request.sealed_wallet_context_root,
            decoy_liquidity_score,
            status: request.status,
        };
        self.decoy_liquidity_index
            .entry(record.cohort_id.clone())
            .or_default()
            .insert(record.observation_id.clone());
        self.liquidity_observations
            .insert(record.observation_id.clone(), record.clone());
        Ok(record)
    }

    pub fn record_pq_attestation(
        &mut self,
        request: PqAttestationRequest,
    ) -> Result<PqAttestationRecord> {
        ensure_capacity(
            self.pq_attestations.len(),
            MAX_PQ_ATTESTATIONS,
            "pq attestations",
        )?;
        if request.pq_security_bits < self.config.target_pq_security_bits {
            return Err("pq attestation security below configured target".to_string());
        }
        if request.attestor_id.is_empty() || request.subject_id.is_empty() {
            return Err("pq attestation requires attestor and subject".to_string());
        }
        let record = PqAttestationRecord {
            attestation_id: request.attestation_id,
            sequence: self.next_sequence(),
            attestor_id: request.attestor_id,
            subject_id: request.subject_id,
            kind: request.kind,
            lane: request.lane,
            observed_root: request.observed_root,
            pq_public_key_root: request.pq_public_key_root,
            pq_signature_root: request.pq_signature_root,
            transcript_root: request.transcript_root,
            pq_security_bits: request.pq_security_bits,
            attested_height: request.attested_height,
            status: request.status,
        };
        self.pq_attestations
            .insert(record.attestation_id.clone(), record.clone());
        Ok(record)
    }

    pub fn settle_score_market(
        &mut self,
        request: ScoringSettlementRequest,
    ) -> Result<ScoringSettlementRecord> {
        ensure_capacity(
            self.scoring_settlements.len(),
            MAX_SCORING_SETTLEMENTS,
            "scoring settlements",
        )?;
        if !self.score_feeds.contains_key(&request.feed_id) {
            return Err("settlement references unknown score feed".to_string());
        }
        if !self.ring_cohorts.contains_key(&request.cohort_id) {
            return Err("settlement references unknown cohort".to_string());
        }
        if request.average_score < self.config.min_score
            || request.average_score > self.config.max_score
        {
            return Err("settlement average score outside configured range".to_string());
        }
        let rebate_eligible_piconero =
            fee_rebate_amount(request.fee_paid_piconero, self.config.rebate_bps);
        let record = ScoringSettlementRecord {
            settlement_id: request.settlement_id,
            sequence: self.next_sequence(),
            feed_id: request.feed_id,
            cohort_id: request.cohort_id,
            settlement_operator_id: request.settlement_operator_id,
            lane: request.lane,
            settled_member_count: request.settled_member_count,
            average_score: request.average_score,
            low_fee_volume_piconero: request.low_fee_volume_piconero,
            fee_paid_piconero: request.fee_paid_piconero,
            settlement_root: request.settlement_root,
            wallet_privacy_receipt_root: request.wallet_privacy_receipt_root,
            rebate_eligible_piconero,
            status: request.status,
        };
        self.wallet_privacy_index
            .entry(record.cohort_id.clone())
            .or_default()
            .insert(record.settlement_id.clone());
        self.scoring_settlements
            .insert(record.settlement_id.clone(), record.clone());
        Ok(record)
    }

    pub fn issue_rebate(&mut self, request: RebateRequest) -> Result<RebateRecord> {
        ensure_capacity(self.rebates.len(), MAX_REBATES, "rebates")?;
        if !self
            .scoring_settlements
            .contains_key(&request.settlement_id)
        {
            return Err("rebate references unknown settlement".to_string());
        }
        if request.rebate_bps > self.config.rebate_bps || request.rebate_bps > MAX_BPS {
            return Err("rebate exceeds configured cap".to_string());
        }
        let rebate_amount_piconero =
            fee_rebate_amount(request.eligible_fee_piconero, request.rebate_bps);
        let record = RebateRecord {
            rebate_id: request.rebate_id,
            sequence: self.next_sequence(),
            settlement_id: request.settlement_id,
            wallet_cohort_id: request.wallet_cohort_id,
            sponsor_id: request.sponsor_id,
            eligible_fee_piconero: request.eligible_fee_piconero,
            rebate_bps: request.rebate_bps,
            rebate_amount_piconero,
            rebate_commitment_root: request.rebate_commitment_root,
            claim_nullifier_root: request.claim_nullifier_root,
            status: request.status,
        };
        self.wallet_privacy_index
            .entry(record.wallet_cohort_id.clone())
            .or_default()
            .insert(record.rebate_id.clone());
        self.rebates
            .insert(record.rebate_id.clone(), record.clone());
        Ok(record)
    }

    pub fn allocate_redaction_budget(
        &mut self,
        request: RedactionBudgetRequest,
    ) -> Result<RedactionBudgetRecord> {
        ensure_capacity(
            self.redaction_budgets.len(),
            MAX_REDACTION_BUDGETS,
            "redaction budgets",
        )?;
        if request.subject_ids.is_empty() {
            return Err("redaction budget requires at least one subject".to_string());
        }
        if request.max_public_fields == 0 {
            return Err("redaction budget must allow at least one public field".to_string());
        }
        if request.expires_l2_height <= self.current_l2_height {
            return Err("redaction budget expiry must be in the future".to_string());
        }
        let record = RedactionBudgetRecord {
            budget_id: request.budget_id,
            sequence: self.next_sequence(),
            operator_id: request.operator_id,
            subject_ids: request.subject_ids,
            reason_code: request.reason_code,
            max_public_fields: request.max_public_fields,
            created_l2_height: self.current_l2_height,
            expires_l2_height: request.expires_l2_height,
            redaction_root: request.redaction_root,
            status: request.status,
        };
        self.redaction_budgets
            .insert(record.budget_id.clone(), record.clone());
        Ok(record)
    }

    pub fn publish_operator_summary(
        &mut self,
        request: OperatorSummaryRequest,
    ) -> Result<OperatorSummaryRecord> {
        ensure_capacity(
            self.operator_summaries.len(),
            MAX_OPERATOR_SUMMARIES,
            "operator summaries",
        )?;
        let budget = self
            .redaction_budgets
            .get(&request.redaction_budget_id)
            .ok_or_else(|| "operator summary references unknown redaction budget".to_string())?;
        if !budget.status.usable() {
            return Err("operator summary redaction budget is not usable".to_string());
        }
        if request.average_public_score > self.config.max_score {
            return Err("operator summary average score outside configured range".to_string());
        }
        let record = OperatorSummaryRecord {
            summary_id: request.summary_id,
            sequence: self.next_sequence(),
            operator_id: request.operator_id,
            l2_height: request.l2_height,
            cohort_count: request.cohort_count,
            feed_count: request.feed_count,
            observation_count: request.observation_count,
            attestation_count: request.attestation_count,
            settlement_count: request.settlement_count,
            redacted_subject_count: request.redacted_subject_count,
            average_public_score: request.average_public_score,
            summary_root: request.summary_root,
            redaction_budget_id: request.redaction_budget_id,
            status: request.status,
        };
        self.operator_summaries
            .insert(record.summary_id.clone(), record.clone());
        Ok(record)
    }

    fn next_sequence(&mut self) -> u64 {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        sequence
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

pub fn demo() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn root_from_parts(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

pub fn records_root(domain: &str, records: impl IntoIterator<Item = Value>) -> String {
    let values = records.into_iter().collect::<Vec<_>>();
    merkle_root(domain, &values)
}

pub fn deterministic_devnet_root(label: &str, index: u64) -> String {
    demo_root(label, index)
}

pub fn ring_cohort_id(sequence: u64, request: &RingCohortRequest) -> String {
    root_from_parts(
        "RING-MEMBER-LIQUIDITY-COHORT-ID",
        &[
            HashPart::U64(sequence),
            HashPart::Str(&request.cohort_id),
            HashPart::Str(request.cohort_kind.as_str()),
            HashPart::U64(request.monero_start_height),
            HashPart::U64(request.monero_end_height),
            HashPart::Str(&request.ring_member_commitment_root),
        ],
    )
}

pub fn score_feed_id(sequence: u64, request: &ScoreFeedRequest) -> String {
    root_from_parts(
        "RING-MEMBER-LIQUIDITY-SCORE-FEED-ID",
        &[
            HashPart::U64(sequence),
            HashPart::Str(&request.feed_id),
            HashPart::Str(&request.cohort_id),
            HashPart::Str(request.lane.as_str()),
            HashPart::U64(request.score_epoch),
            HashPart::Str(&request.feed_commitment_root),
        ],
    )
}

pub fn liquidity_observation_id(sequence: u64, request: &LiquidityObservationRequest) -> String {
    root_from_parts(
        "RING-MEMBER-LIQUIDITY-OBSERVATION-ID",
        &[
            HashPart::U64(sequence),
            HashPart::Str(&request.observation_id),
            HashPart::Str(&request.cohort_id),
            HashPart::Str(&request.feed_id),
            HashPart::Str(request.source.as_str()),
            HashPart::Str(&request.observation_root),
        ],
    )
}

pub fn pq_attestation_id(sequence: u64, request: &PqAttestationRequest) -> String {
    root_from_parts(
        "RING-MEMBER-LIQUIDITY-PQ-ATTESTATION-ID",
        &[
            HashPart::U64(sequence),
            HashPart::Str(&request.attestation_id),
            HashPart::Str(&request.attestor_id),
            HashPart::Str(&request.subject_id),
            HashPart::Str(request.kind.as_str()),
            HashPart::Str(&request.pq_signature_root),
        ],
    )
}

fn stable_digest(domain: &str, value: Value) -> String {
    let encoded = serde_json::to_string(&value).unwrap_or_else(|_| "null".to_string());
    domain_hash(domain, &[HashPart::Str(&encoded)], 32)
}

fn demo_root(label: &str, index: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-RING-MEMBER-LIQUIDITY-SCORE-ORACLE-DEVNET",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}

fn ensure_capacity(current: usize, max: usize, label: &str) -> Result<()> {
    if current >= max {
        Err(format!("{label} capacity reached"))
    } else {
        Ok(())
    }
}

fn ensure_height_range(start: u64, end: u64, label: &str) -> Result<()> {
    if start >= end {
        Err(format!("{label} height range is invalid"))
    } else {
        Ok(())
    }
}

fn cohort_quality_score(
    kind: RingCohortKind,
    ring_members: u64,
    decoy_members: u64,
    privacy_set_size: u64,
    config: &Config,
) -> u64 {
    let decoy_ratio = decoy_members.saturating_mul(1_000) / ring_members.max(1);
    let privacy_ratio = privacy_set_size.saturating_mul(1_000) / config.min_privacy_set_size.max(1);
    let raw = kind
        .quality_weight()
        .saturating_mul(45)
        .saturating_add(decoy_ratio.min(1_000).saturating_mul(35))
        .saturating_add(privacy_ratio.min(1_250).saturating_mul(20))
        / 100;
    raw.clamp(config.min_score, config.max_score)
}

fn decoy_liquidity_score(
    liquid_decoys: u64,
    illiquid_decoys: u64,
    median_liquidity_piconero: u64,
    p95_liquidity_piconero: u64,
    config: &Config,
) -> u64 {
    let sample_count = liquid_decoys.saturating_add(illiquid_decoys).max(1);
    let liquid_ratio = liquid_decoys.saturating_mul(1_000) / sample_count;
    let depth_score = median_liquidity_piconero
        .saturating_add(p95_liquidity_piconero / 4)
        .min(10_000_000)
        / 10_000;
    let raw = liquid_ratio
        .saturating_mul(7)
        .saturating_add(depth_score.saturating_mul(3))
        / 10;
    raw.clamp(config.min_score, config.max_score)
}

fn fee_for_score_market(scored_member_count: u64, fee_bps: u64) -> u64 {
    scored_member_count
        .saturating_mul(fee_bps)
        .saturating_add(999)
        / 1_000
}

fn fee_rebate_amount(fee_paid_piconero: u64, rebate_bps: u64) -> u64 {
    fee_paid_piconero.saturating_mul(rebate_bps) / MAX_BPS
}
