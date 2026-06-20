use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateOutputLinkabilityRegressionGuardRuntimeResult<T> = Result<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const MONERO_L2_PQ_PRIVATE_OUTPUT_LINKABILITY_REGRESSION_GUARD_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-output-linkability-regression-guard-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_OUTPUT_LINKABILITY_REGRESSION_GUARD_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_GUARD_ID: &str = "monero-l2-pq-private-output-linkability-regression-guard-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_DEFI_ASSET_ID: &str = "wxmr-devnet";
pub const DEVNET_HEIGHT: u64 = 1_552_640;
pub const DEVNET_EPOCH: u64 = 3_104;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_WATCHER_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-output-linkability-watch-v1";
pub const OUTPUT_COHORT_SCHEME: &str = "monero-output-cohort-privacy-root-v1";
pub const LINKABILITY_PROBE_SCHEME: &str = "decoy-output-linkability-risk-probe-root-v1";
pub const VIEW_TAG_SAMPLE_SCHEME: &str = "wallet-safe-view-tag-scan-sample-root-v1";
pub const RING_MEMBER_HEALTH_SCHEME: &str = "ring-member-health-public-root-v1";
pub const WALLET_REDACTION_SCHEME: &str = "wallet-safe-output-redaction-root-v1";
pub const PQ_WATCHER_ATTESTATION_SCHEME: &str = "pq-output-linkability-watcher-attestation-root-v1";
pub const QUARANTINE_SCHEME: &str = "output-linkability-quarantine-root-v1";
pub const ESCALATION_SCHEME: &str = "output-linkability-escalation-root-v1";
pub const PRIVACY_FLOOR_SCHEME: &str = "output-linkability-privacy-floor-metrics-root-v1";
pub const PUBLIC_ROOT_SCHEME: &str = "public-output-linkability-regression-guard-roots-v1";
pub const DEFAULT_COHORT_SPAN_BLOCKS: u64 = 720;
pub const DEFAULT_MIN_OUTPUTS_PER_COHORT: u64 = 65_536;
pub const DEFAULT_MIN_RING_SIZE: u16 = 16;
pub const DEFAULT_MIN_HEALTHY_DECOYS: u16 = 15;
pub const DEFAULT_MIN_VIEW_TAG_SAMPLE_RATE_BPS: u16 = 250;
pub const DEFAULT_MAX_LINKABILITY_SCORE_BPS: u16 = 125;
pub const DEFAULT_MAX_DECOY_AGE_SKEW_BPS: u16 = 400;
pub const DEFAULT_MAX_VIEW_TAG_CLUSTER_BPS: u16 = 150;
pub const DEFAULT_MIN_PRIVACY_FLOOR_SCORE_BPS: u16 = 9_600;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_QUARANTINE_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_ESCALATION_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_REDACTION_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_LOW_FEE_CAP_MICRO_UNITS: u64 = 2_500;
pub const DEFAULT_WATCHER_BOND_MICRO_UNITS: u64 = 50_000_000;
pub const MAX_BPS: u16 = 10_000;
pub const MAX_OUTPUT_COHORTS: usize = 1_048_576;
pub const MAX_LINKABILITY_PROBES: usize = 2_097_152;
pub const MAX_VIEW_TAG_SCAN_SAMPLES: usize = 2_097_152;
pub const MAX_RING_MEMBER_HEALTH_RECORDS: usize = 2_097_152;
pub const MAX_WALLET_REDACTIONS: usize = 524_288;
pub const MAX_PQ_WATCHER_ATTESTATIONS: usize = 2_097_152;
pub const MAX_QUARANTINES: usize = 262_144;
pub const MAX_ESCALATIONS: usize = 262_144;
pub const MAX_PRIVACY_FLOOR_METRICS: usize = 524_288;
pub const MAX_PUBLIC_ROOTS: usize = 524_288;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortKind {
    MinerReward,
    UserTransfer,
    BridgeDeposit,
    BridgeWithdrawal,
    DefiSettlement,
    ContractReceipt,
    TokenMintBurn,
    ChangeOutput,
    FeeSponsor,
    ReorgReplay,
}

impl CohortKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MinerReward => "miner_reward",
            Self::UserTransfer => "user_transfer",
            Self::BridgeDeposit => "bridge_deposit",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::DefiSettlement => "defi_settlement",
            Self::ContractReceipt => "contract_receipt",
            Self::TokenMintBurn => "token_mint_burn",
            Self::ChangeOutput => "change_output",
            Self::FeeSponsor => "fee_sponsor",
            Self::ReorgReplay => "reorg_replay",
        }
    }

    pub fn floor_weight_bps(self) -> u16 {
        match self {
            Self::UserTransfer => 10_000,
            Self::DefiSettlement => 9_850,
            Self::ContractReceipt => 9_750,
            Self::BridgeDeposit => 9_700,
            Self::BridgeWithdrawal => 9_650,
            Self::TokenMintBurn => 9_550,
            Self::FeeSponsor => 9_400,
            Self::ChangeOutput => 9_250,
            Self::MinerReward => 9_100,
            Self::ReorgReplay => 8_900,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeKind {
    DecoyAgeSkew,
    RingIntersection,
    ViewTagCluster,
    AmountBucketTiming,
    ContractReceiptBurst,
    BridgeBatchFingerprint,
    TokenFlowFingerprint,
    WalletChangeHeuristic,
    ReorgReplayCollision,
    WatcherChallenge,
}

impl ProbeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DecoyAgeSkew => "decoy_age_skew",
            Self::RingIntersection => "ring_intersection",
            Self::ViewTagCluster => "view_tag_cluster",
            Self::AmountBucketTiming => "amount_bucket_timing",
            Self::ContractReceiptBurst => "contract_receipt_burst",
            Self::BridgeBatchFingerprint => "bridge_batch_fingerprint",
            Self::TokenFlowFingerprint => "token_flow_fingerprint",
            Self::WalletChangeHeuristic => "wallet_change_heuristic",
            Self::ReorgReplayCollision => "reorg_replay_collision",
            Self::WatcherChallenge => "watcher_challenge",
        }
    }

    pub fn high_risk(self) -> bool {
        matches!(
            self,
            Self::RingIntersection
                | Self::WalletChangeHeuristic
                | Self::BridgeBatchFingerprint
                | Self::ReorgReplayCollision
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SampleLane {
    MobileWallet,
    WatchOnlyWallet,
    MerchantCheckout,
    BridgeExit,
    DefiRouter,
    ContractIndexer,
    TokenIndexer,
    OperatorCanary,
}

impl SampleLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MobileWallet => "mobile_wallet",
            Self::WatchOnlyWallet => "watch_only_wallet",
            Self::MerchantCheckout => "merchant_checkout",
            Self::BridgeExit => "bridge_exit",
            Self::DefiRouter => "defi_router",
            Self::ContractIndexer => "contract_indexer",
            Self::TokenIndexer => "token_indexer",
            Self::OperatorCanary => "operator_canary",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Unknown,
    Healthy,
    Watch,
    Degraded,
    Quarantined,
    Retired,
}

impl HealthStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Healthy => "healthy",
            Self::Watch => "watch",
            Self::Degraded => "degraded",
            Self::Quarantined => "quarantined",
            Self::Retired => "retired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Healthy | Self::Watch)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardStatus {
    Draft,
    Open,
    Sampled,
    Attested,
    Passed,
    Watch,
    Quarantined,
    Escalated,
    Mitigated,
    Rejected,
    Expired,
}

impl GuardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Open => "open",
            Self::Sampled => "sampled",
            Self::Attested => "attested",
            Self::Passed => "passed",
            Self::Watch => "watch",
            Self::Quarantined => "quarantined",
            Self::Escalated => "escalated",
            Self::Mitigated => "mitigated",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Sampled | Self::Attested | Self::Watch
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionScope {
    OutputKeyImage,
    StealthAddress,
    ViewTag,
    RingMemberSet,
    WalletLabel,
    SubaddressIndex,
    ContractCallHint,
    BridgeMemo,
    OperatorPanel,
}

impl RedactionScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OutputKeyImage => "output_key_image",
            Self::StealthAddress => "stealth_address",
            Self::ViewTag => "view_tag",
            Self::RingMemberSet => "ring_member_set",
            Self::WalletLabel => "wallet_label",
            Self::SubaddressIndex => "subaddress_index",
            Self::ContractCallHint => "contract_call_hint",
            Self::BridgeMemo => "bridge_memo",
            Self::OperatorPanel => "operator_panel",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationLevel {
    Informational,
    WatcherReview,
    OperatorReview,
    Quarantine,
    Governance,
    EmergencyStop,
}

impl EscalationLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::WatcherReview => "watcher_review",
            Self::OperatorReview => "operator_review",
            Self::Quarantine => "quarantine",
            Self::Governance => "governance",
            Self::EmergencyStop => "emergency_stop",
        }
    }

    pub fn severity_points(self) -> u64 {
        match self {
            Self::Informational => 1,
            Self::WatcherReview => 5,
            Self::OperatorReview => 20,
            Self::Quarantine => 80,
            Self::Governance => 160,
            Self::EmergencyStop => 320,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Pending,
    Clean,
    NeedsMoreSamples,
    Risky,
    Invalid,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Clean => "clean",
            Self::NeedsMoreSamples => "needs_more_samples",
            Self::Risky => "risky",
            Self::Invalid => "invalid",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub guard_id: String,
    pub fee_asset_id: String,
    pub defi_asset_id: String,
    pub hash_suite: String,
    pub pq_watcher_suite: String,
    pub devnet_height: u64,
    pub devnet_epoch: u64,
    pub cohort_span_blocks: u64,
    pub min_outputs_per_cohort: u64,
    pub min_ring_size: u16,
    pub min_healthy_decoys: u16,
    pub min_view_tag_sample_rate_bps: u16,
    pub max_linkability_score_bps: u16,
    pub max_decoy_age_skew_bps: u16,
    pub max_view_tag_cluster_bps: u16,
    pub min_privacy_floor_score_bps: u16,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub quarantine_ttl_blocks: u64,
    pub escalation_ttl_blocks: u64,
    pub redaction_ttl_blocks: u64,
    pub low_fee_cap_micro_units: u64,
    pub watcher_bond_micro_units: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            guard_id: DEVNET_GUARD_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            defi_asset_id: DEVNET_DEFI_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_watcher_suite: PQ_WATCHER_SUITE.to_string(),
            devnet_height: DEVNET_HEIGHT,
            devnet_epoch: DEVNET_EPOCH,
            cohort_span_blocks: DEFAULT_COHORT_SPAN_BLOCKS,
            min_outputs_per_cohort: DEFAULT_MIN_OUTPUTS_PER_COHORT,
            min_ring_size: DEFAULT_MIN_RING_SIZE,
            min_healthy_decoys: DEFAULT_MIN_HEALTHY_DECOYS,
            min_view_tag_sample_rate_bps: DEFAULT_MIN_VIEW_TAG_SAMPLE_RATE_BPS,
            max_linkability_score_bps: DEFAULT_MAX_LINKABILITY_SCORE_BPS,
            max_decoy_age_skew_bps: DEFAULT_MAX_DECOY_AGE_SKEW_BPS,
            max_view_tag_cluster_bps: DEFAULT_MAX_VIEW_TAG_CLUSTER_BPS,
            min_privacy_floor_score_bps: DEFAULT_MIN_PRIVACY_FLOOR_SCORE_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            quarantine_ttl_blocks: DEFAULT_QUARANTINE_TTL_BLOCKS,
            escalation_ttl_blocks: DEFAULT_ESCALATION_TTL_BLOCKS,
            redaction_ttl_blocks: DEFAULT_REDACTION_TTL_BLOCKS,
            low_fee_cap_micro_units: DEFAULT_LOW_FEE_CAP_MICRO_UNITS,
            watcher_bond_micro_units: DEFAULT_WATCHER_BOND_MICRO_UNITS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(!self.chain_id.is_empty(), "chain id is empty");
        ensure!(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol mismatch"
        );
        ensure!(self.schema_version == SCHEMA_VERSION, "schema mismatch");
        ensure!(!self.guard_id.is_empty(), "guard id is empty");
        ensure!(self.cohort_span_blocks > 0, "cohort span must be positive");
        ensure!(
            self.min_outputs_per_cohort >= self.min_ring_size as u64,
            "cohort output floor is below ring size"
        );
        ensure!(self.min_ring_size > 1, "ring size must exceed one");
        ensure!(
            self.min_healthy_decoys < self.min_ring_size,
            "healthy decoy floor must be below ring size"
        );
        ensure!(
            self.min_view_tag_sample_rate_bps <= MAX_BPS,
            "sample rate exceeds bps"
        );
        ensure!(
            self.max_linkability_score_bps <= MAX_BPS,
            "linkability score cap exceeds bps"
        );
        ensure!(
            self.max_decoy_age_skew_bps <= MAX_BPS,
            "decoy age skew cap exceeds bps"
        );
        ensure!(
            self.max_view_tag_cluster_bps <= MAX_BPS,
            "view tag cluster cap exceeds bps"
        );
        ensure!(
            self.min_privacy_floor_score_bps <= MAX_BPS,
            "privacy floor exceeds bps"
        );
        ensure!(
            self.min_pq_security_bits <= self.target_pq_security_bits,
            "minimum pq bits exceed target"
        );
        Ok(())
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
    pub output_cohorts: usize,
    pub live_output_cohorts: usize,
    pub linkability_probes: usize,
    pub high_risk_probes: usize,
    pub view_tag_scan_samples: usize,
    pub ring_member_health_records: usize,
    pub usable_ring_member_health_records: usize,
    pub wallet_redactions: usize,
    pub pq_watcher_attestations: usize,
    pub risky_watcher_attestations: usize,
    pub quarantines: usize,
    pub escalations: usize,
    pub privacy_floor_metrics: usize,
    pub public_roots: usize,
    pub total_outputs: u64,
    pub total_sampled_outputs: u64,
    pub total_ring_members: u64,
    pub total_healthy_decoys: u64,
    pub total_quarantined_outputs: u64,
    pub max_linkability_score_bps: u16,
    pub min_privacy_floor_score_bps: u16,
    pub watcher_bonded_micro_units: u64,
    pub low_fee_spend_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub output_cohort_root: String,
    pub linkability_probe_root: String,
    pub view_tag_scan_sample_root: String,
    pub ring_member_health_root: String,
    pub wallet_redaction_root: String,
    pub pq_watcher_attestation_root: String,
    pub quarantine_root: String,
    pub escalation_root: String,
    pub privacy_floor_metric_root: String,
    pub public_root: String,
    pub operator_safe_summary_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OutputCohort {
    pub cohort_id: String,
    pub kind: CohortKind,
    pub start_height: u64,
    pub end_height: u64,
    pub output_count: u64,
    pub sampled_output_count: u64,
    pub ring_size_floor: u16,
    pub view_tag_prefix_root: String,
    pub output_commitment_root: String,
    pub decoy_distribution_root: String,
    pub fee_bucket_root: String,
    pub linked_contract_root: String,
    pub wallet_safe_hint_root: String,
    pub status: GuardStatus,
}

impl OutputCohort {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(!self.cohort_id.is_empty(), "cohort id is empty");
        ensure!(
            self.start_height <= self.end_height,
            "cohort height range is inverted"
        );
        ensure!(
            self.end_height - self.start_height + 1 <= config.cohort_span_blocks * 4,
            "cohort span is unexpectedly wide"
        );
        ensure!(
            self.output_count >= config.min_ring_size as u64,
            "cohort output count below ring floor"
        );
        ensure!(
            self.sampled_output_count <= self.output_count,
            "sample count exceeds outputs"
        );
        ensure!(
            self.ring_size_floor >= config.min_ring_size,
            "ring floor below config"
        );
        Ok(())
    }
}

impl PublicRecord for OutputCohort {
    fn public_record(&self) -> Value {
        json!({
            "cohort_id": self.cohort_id,
            "kind": self.kind.as_str(),
            "start_height": self.start_height,
            "end_height": self.end_height,
            "output_count": self.output_count,
            "sampled_output_count": self.sampled_output_count,
            "ring_size_floor": self.ring_size_floor,
            "view_tag_prefix_root": self.view_tag_prefix_root,
            "output_commitment_root": self.output_commitment_root,
            "decoy_distribution_root": self.decoy_distribution_root,
            "fee_bucket_root": self.fee_bucket_root,
            "linked_contract_root": self.linked_contract_root,
            "wallet_safe_hint_root": self.wallet_safe_hint_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LinkabilityRiskProbe {
    pub probe_id: String,
    pub cohort_id: String,
    pub kind: ProbeKind,
    pub sampled_ring_count: u64,
    pub shared_ring_member_count: u64,
    pub decoy_age_skew_bps: u16,
    pub view_tag_cluster_bps: u16,
    pub linkability_score_bps: u16,
    pub risk_reason_root: String,
    pub mitigation_hint_root: String,
    pub status: GuardStatus,
}

impl LinkabilityRiskProbe {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(!self.probe_id.is_empty(), "probe id is empty");
        ensure!(!self.cohort_id.is_empty(), "probe cohort id is empty");
        ensure!(
            self.shared_ring_member_count <= self.sampled_ring_count,
            "shared ring members exceed sampled rings"
        );
        ensure!(self.decoy_age_skew_bps <= MAX_BPS, "decoy skew exceeds bps");
        ensure!(
            self.view_tag_cluster_bps <= MAX_BPS,
            "view tag cluster exceeds bps"
        );
        ensure!(
            self.linkability_score_bps <= MAX_BPS,
            "linkability score exceeds bps"
        );
        if self.kind.high_risk() {
            ensure!(
                self.linkability_score_bps <= config.max_linkability_score_bps * 8,
                "high risk probe score is beyond emergency bound"
            );
        }
        Ok(())
    }

    pub fn exceeds_floor(&self, config: &Config) -> bool {
        self.linkability_score_bps > config.max_linkability_score_bps
            || self.decoy_age_skew_bps > config.max_decoy_age_skew_bps
            || self.view_tag_cluster_bps > config.max_view_tag_cluster_bps
    }
}

impl PublicRecord for LinkabilityRiskProbe {
    fn public_record(&self) -> Value {
        json!({
            "probe_id": self.probe_id,
            "cohort_id": self.cohort_id,
            "kind": self.kind.as_str(),
            "sampled_ring_count": self.sampled_ring_count,
            "shared_ring_member_count": self.shared_ring_member_count,
            "decoy_age_skew_bps": self.decoy_age_skew_bps,
            "view_tag_cluster_bps": self.view_tag_cluster_bps,
            "linkability_score_bps": self.linkability_score_bps,
            "risk_reason_root": self.risk_reason_root,
            "mitigation_hint_root": self.mitigation_hint_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViewTagScanSample {
    pub sample_id: String,
    pub cohort_id: String,
    pub lane: SampleLane,
    pub sampled_height: u64,
    pub output_sample_count: u64,
    pub positive_view_tag_matches: u64,
    pub false_positive_matches: u64,
    pub scan_latency_p50_ms: u64,
    pub scan_latency_p95_ms: u64,
    pub wallet_safe_sample_root: String,
    pub redacted_view_tag_bucket_root: String,
    pub status: GuardStatus,
}

impl ViewTagScanSample {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(!self.sample_id.is_empty(), "sample id is empty");
        ensure!(!self.cohort_id.is_empty(), "sample cohort id is empty");
        ensure!(self.output_sample_count > 0, "sample count is zero");
        ensure!(
            self.positive_view_tag_matches <= self.output_sample_count,
            "positive view tag matches exceed sample count"
        );
        ensure!(
            self.false_positive_matches <= self.positive_view_tag_matches,
            "false positives exceed positive matches"
        );
        ensure!(
            self.scan_latency_p50_ms <= self.scan_latency_p95_ms,
            "latency percentiles are inverted"
        );
        let sample_bps = bps(
            self.output_sample_count,
            config.min_outputs_per_cohort.max(1),
        );
        ensure!(
            sample_bps >= config.min_view_tag_sample_rate_bps as u64
                || self.lane == SampleLane::OperatorCanary,
            "view tag sample below configured rate"
        );
        Ok(())
    }
}

impl PublicRecord for ViewTagScanSample {
    fn public_record(&self) -> Value {
        json!({
            "sample_id": self.sample_id,
            "cohort_id": self.cohort_id,
            "lane": self.lane.as_str(),
            "sampled_height": self.sampled_height,
            "output_sample_count": self.output_sample_count,
            "positive_view_tag_matches": self.positive_view_tag_matches,
            "false_positive_matches": self.false_positive_matches,
            "scan_latency_p50_ms": self.scan_latency_p50_ms,
            "scan_latency_p95_ms": self.scan_latency_p95_ms,
            "wallet_safe_sample_root": self.wallet_safe_sample_root,
            "redacted_view_tag_bucket_root": self.redacted_view_tag_bucket_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RingMemberHealth {
    pub health_id: String,
    pub cohort_id: String,
    pub ring_member_root: String,
    pub ring_size: u16,
    pub healthy_decoys: u16,
    pub stale_decoys: u16,
    pub repeated_decoys: u16,
    pub spent_member_hints: u16,
    pub age_distribution_root: String,
    pub health_score_bps: u16,
    pub status: HealthStatus,
}

impl RingMemberHealth {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(!self.health_id.is_empty(), "health id is empty");
        ensure!(!self.cohort_id.is_empty(), "health cohort id is empty");
        ensure!(
            self.ring_size >= config.min_ring_size,
            "ring size below floor"
        );
        ensure!(
            self.healthy_decoys <= self.ring_size,
            "healthy decoys exceed ring size"
        );
        ensure!(
            self.stale_decoys <= self.ring_size,
            "stale decoys exceed ring size"
        );
        ensure!(
            self.repeated_decoys <= self.ring_size,
            "repeated decoys exceed ring size"
        );
        ensure!(
            self.spent_member_hints <= self.ring_size,
            "spent hints exceed ring size"
        );
        ensure!(self.health_score_bps <= MAX_BPS, "health score exceeds bps");
        Ok(())
    }
}

impl PublicRecord for RingMemberHealth {
    fn public_record(&self) -> Value {
        json!({
            "health_id": self.health_id,
            "cohort_id": self.cohort_id,
            "ring_member_root": self.ring_member_root,
            "ring_size": self.ring_size,
            "healthy_decoys": self.healthy_decoys,
            "stale_decoys": self.stale_decoys,
            "repeated_decoys": self.repeated_decoys,
            "spent_member_hints": self.spent_member_hints,
            "age_distribution_root": self.age_distribution_root,
            "health_score_bps": self.health_score_bps,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletSafeRedaction {
    pub redaction_id: String,
    pub cohort_id: String,
    pub scopes: BTreeSet<RedactionScope>,
    pub redacted_payload_root: String,
    pub public_reason_root: String,
    pub operator_visible_fields: BTreeSet<String>,
    pub expires_at_height: u64,
    pub status: GuardStatus,
}

impl WalletSafeRedaction {
    pub fn validate(&self, current_height: u64) -> Result<()> {
        ensure!(!self.redaction_id.is_empty(), "redaction id is empty");
        ensure!(!self.cohort_id.is_empty(), "redaction cohort id is empty");
        ensure!(!self.scopes.is_empty(), "redaction scopes are empty");
        ensure!(
            self.expires_at_height >= current_height,
            "redaction already expired"
        );
        Ok(())
    }
}

impl PublicRecord for WalletSafeRedaction {
    fn public_record(&self) -> Value {
        let scopes = self
            .scopes
            .iter()
            .map(|scope| scope.as_str())
            .collect::<Vec<_>>();
        json!({
            "redaction_id": self.redaction_id,
            "cohort_id": self.cohort_id,
            "scopes": scopes,
            "redacted_payload_root": self.redacted_payload_root,
            "public_reason_root": self.public_reason_root,
            "operator_visible_fields": self.operator_visible_fields,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqWatcherAttestation {
    pub attestation_id: String,
    pub watcher_id: String,
    pub cohort_id: String,
    pub probe_ids: BTreeSet<String>,
    pub pq_scheme: String,
    pub pq_security_bits: u16,
    pub public_key_commitment: String,
    pub signature_root: String,
    pub bonded_micro_units: u64,
    pub verdict: AttestationVerdict,
    pub status: GuardStatus,
}

impl PqWatcherAttestation {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(!self.attestation_id.is_empty(), "attestation id is empty");
        ensure!(!self.watcher_id.is_empty(), "watcher id is empty");
        ensure!(!self.cohort_id.is_empty(), "attestation cohort id is empty");
        ensure!(!self.probe_ids.is_empty(), "attestation has no probes");
        ensure!(
            self.pq_security_bits >= config.min_pq_security_bits,
            "pq security bits below floor"
        );
        ensure!(
            self.bonded_micro_units >= config.watcher_bond_micro_units,
            "watcher bond below floor"
        );
        Ok(())
    }
}

impl PublicRecord for PqWatcherAttestation {
    fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "watcher_id": self.watcher_id,
            "cohort_id": self.cohort_id,
            "probe_ids": self.probe_ids,
            "pq_scheme": self.pq_scheme,
            "pq_security_bits": self.pq_security_bits,
            "public_key_commitment": self.public_key_commitment,
            "signature_root": self.signature_root,
            "bonded_micro_units": self.bonded_micro_units,
            "verdict": self.verdict.as_str(),
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuarantineRecord {
    pub quarantine_id: String,
    pub cohort_id: String,
    pub probe_id: String,
    pub affected_output_root: String,
    pub reason_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub quarantined_outputs: u64,
    pub status: GuardStatus,
}

impl QuarantineRecord {
    pub fn validate(&self) -> Result<()> {
        ensure!(!self.quarantine_id.is_empty(), "quarantine id is empty");
        ensure!(!self.cohort_id.is_empty(), "quarantine cohort id is empty");
        ensure!(!self.probe_id.is_empty(), "quarantine probe id is empty");
        ensure!(
            self.opened_at_height <= self.expires_at_height,
            "quarantine expiry precedes opening"
        );
        ensure!(self.quarantined_outputs > 0, "quarantine has no outputs");
        Ok(())
    }
}

impl PublicRecord for QuarantineRecord {
    fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EscalationRecord {
    pub escalation_id: String,
    pub cohort_id: String,
    pub source_record_id: String,
    pub level: EscalationLevel,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub operator_action_root: String,
    pub governance_packet_root: String,
    pub status: GuardStatus,
}

impl EscalationRecord {
    pub fn validate(&self) -> Result<()> {
        ensure!(!self.escalation_id.is_empty(), "escalation id is empty");
        ensure!(!self.cohort_id.is_empty(), "escalation cohort id is empty");
        ensure!(
            self.opened_at_height <= self.expires_at_height,
            "escalation expiry precedes opening"
        );
        Ok(())
    }
}

impl PublicRecord for EscalationRecord {
    fn public_record(&self) -> Value {
        json!({
            "escalation_id": self.escalation_id,
            "cohort_id": self.cohort_id,
            "source_record_id": self.source_record_id,
            "level": self.level.as_str(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "operator_action_root": self.operator_action_root,
            "governance_packet_root": self.governance_packet_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyFloorMetric {
    pub metric_id: String,
    pub cohort_id: String,
    pub output_count: u64,
    pub ring_size_floor: u16,
    pub healthy_decoy_floor: u16,
    pub view_tag_sample_rate_bps: u16,
    pub linkability_score_bps: u16,
    pub floor_score_bps: u16,
    pub pass: bool,
    pub metric_root: String,
}

impl PrivacyFloorMetric {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(!self.metric_id.is_empty(), "metric id is empty");
        ensure!(!self.cohort_id.is_empty(), "metric cohort id is empty");
        ensure!(
            self.output_count >= config.min_ring_size as u64,
            "metric output count below ring size"
        );
        ensure!(
            self.ring_size_floor >= config.min_ring_size,
            "metric ring floor below config"
        );
        ensure!(
            self.healthy_decoy_floor >= config.min_healthy_decoys,
            "metric healthy decoy floor below config"
        );
        ensure!(
            self.view_tag_sample_rate_bps <= MAX_BPS,
            "metric sample rate exceeds bps"
        );
        ensure!(
            self.linkability_score_bps <= MAX_BPS,
            "metric linkability exceeds bps"
        );
        ensure!(self.floor_score_bps <= MAX_BPS, "metric floor exceeds bps");
        Ok(())
    }
}

impl PublicRecord for PrivacyFloorMetric {
    fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicRootRecord {
    pub public_root_id: String,
    pub height: u64,
    pub epoch: u64,
    pub roots: Roots,
    pub counters: Counters,
    pub status: GuardStatus,
}

impl PublicRecord for PublicRootRecord {
    fn public_record(&self) -> Value {
        json!({
            "public_root_id": self.public_root_id,
            "height": self.height,
            "epoch": self.epoch,
            "roots": self.roots.public_record(),
            "counters": self.counters.public_record(),
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub output_cohorts: BTreeMap<String, OutputCohort>,
    pub linkability_probes: BTreeMap<String, LinkabilityRiskProbe>,
    pub view_tag_scan_samples: BTreeMap<String, ViewTagScanSample>,
    pub ring_member_health: BTreeMap<String, RingMemberHealth>,
    pub wallet_redactions: BTreeMap<String, WalletSafeRedaction>,
    pub pq_watcher_attestations: BTreeMap<String, PqWatcherAttestation>,
    pub quarantines: BTreeMap<String, QuarantineRecord>,
    pub escalations: BTreeMap<String, EscalationRecord>,
    pub privacy_floor_metrics: BTreeMap<String, PrivacyFloorMetric>,
    pub public_roots: BTreeMap<String, PublicRootRecord>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default(), DEVNET_HEIGHT, DEVNET_EPOCH)
    }
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64) -> Self {
        let mut state = Self {
            config,
            height,
            epoch,
            counters: Counters::default(),
            roots: Roots::default(),
            output_cohorts: BTreeMap::new(),
            linkability_probes: BTreeMap::new(),
            view_tag_scan_samples: BTreeMap::new(),
            ring_member_health: BTreeMap::new(),
            wallet_redactions: BTreeMap::new(),
            pq_watcher_attestations: BTreeMap::new(),
            quarantines: BTreeMap::new(),
            escalations: BTreeMap::new(),
            privacy_floor_metrics: BTreeMap::new(),
            public_roots: BTreeMap::new(),
        };
        state.refresh();
        state
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet(), DEVNET_HEIGHT, DEVNET_EPOCH)
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let cohort_id = "cohort-devnet-user-transfer-0001".to_string();
        state
            .insert_output_cohort(OutputCohort {
                cohort_id: cohort_id.clone(),
                kind: CohortKind::UserTransfer,
                start_height: DEVNET_HEIGHT - DEFAULT_COHORT_SPAN_BLOCKS + 1,
                end_height: DEVNET_HEIGHT,
                output_count: 94_208,
                sampled_output_count: 2_944,
                ring_size_floor: 16,
                view_tag_prefix_root: devnet_payload_root("view-tags", "user-transfer-0001"),
                output_commitment_root: devnet_payload_root("outputs", "user-transfer-0001"),
                decoy_distribution_root: devnet_payload_root("decoys", "user-transfer-0001"),
                fee_bucket_root: devnet_payload_root("fees", "user-transfer-0001"),
                linked_contract_root: devnet_payload_root("contracts", "none"),
                wallet_safe_hint_root: devnet_payload_root("wallet-hints", "redacted-0001"),
                status: GuardStatus::Open,
            })
            .expect("demo cohort is valid");

        let defi_cohort_id = "cohort-devnet-defi-settlement-0002".to_string();
        state
            .insert_output_cohort(OutputCohort {
                cohort_id: defi_cohort_id.clone(),
                kind: CohortKind::DefiSettlement,
                start_height: DEVNET_HEIGHT - 511,
                end_height: DEVNET_HEIGHT,
                output_count: 72_704,
                sampled_output_count: 2_048,
                ring_size_floor: 16,
                view_tag_prefix_root: devnet_payload_root("view-tags", "defi-settlement-0002"),
                output_commitment_root: devnet_payload_root("outputs", "defi-settlement-0002"),
                decoy_distribution_root: devnet_payload_root("decoys", "defi-settlement-0002"),
                fee_bucket_root: devnet_payload_root("fees", "low-fee-defi-0002"),
                linked_contract_root: devnet_payload_root("contracts", "vault-router-0002"),
                wallet_safe_hint_root: devnet_payload_root("wallet-hints", "redacted-0002"),
                status: GuardStatus::Watch,
            })
            .expect("demo defi cohort is valid");

        let probe_id = "probe-devnet-ring-intersection-0001".to_string();
        state
            .insert_linkability_probe(LinkabilityRiskProbe {
                probe_id: probe_id.clone(),
                cohort_id: cohort_id.clone(),
                kind: ProbeKind::RingIntersection,
                sampled_ring_count: 2_944,
                shared_ring_member_count: 7,
                decoy_age_skew_bps: 94,
                view_tag_cluster_bps: 61,
                linkability_score_bps: 72,
                risk_reason_root: devnet_payload_root("risk-reason", "ring-intersection-clean"),
                mitigation_hint_root: devnet_payload_root("mitigation", "refresh-decoy-cache"),
                status: GuardStatus::Passed,
            })
            .expect("demo probe is valid");

        let risky_probe_id = "probe-devnet-contract-burst-0002".to_string();
        state
            .insert_linkability_probe(LinkabilityRiskProbe {
                probe_id: risky_probe_id.clone(),
                cohort_id: defi_cohort_id.clone(),
                kind: ProbeKind::ContractReceiptBurst,
                sampled_ring_count: 2_048,
                shared_ring_member_count: 19,
                decoy_age_skew_bps: 290,
                view_tag_cluster_bps: 122,
                linkability_score_bps: 138,
                risk_reason_root: devnet_payload_root("risk-reason", "contract-receipt-burst"),
                mitigation_hint_root: devnet_payload_root("mitigation", "delay-and-remix"),
                status: GuardStatus::Watch,
            })
            .expect("demo risky probe is valid");

        state
            .insert_view_tag_scan_sample(ViewTagScanSample {
                sample_id: "sample-devnet-mobile-0001".to_string(),
                cohort_id: cohort_id.clone(),
                lane: SampleLane::MobileWallet,
                sampled_height: DEVNET_HEIGHT,
                output_sample_count: 2_944,
                positive_view_tag_matches: 86,
                false_positive_matches: 3,
                scan_latency_p50_ms: 38,
                scan_latency_p95_ms: 121,
                wallet_safe_sample_root: devnet_payload_root("sample", "mobile-0001"),
                redacted_view_tag_bucket_root: devnet_payload_root(
                    "view-tag-bucket",
                    "mobile-0001",
                ),
                status: GuardStatus::Sampled,
            })
            .expect("demo scan sample is valid");

        state
            .insert_ring_member_health(RingMemberHealth {
                health_id: "health-devnet-ring-0001".to_string(),
                cohort_id: cohort_id.clone(),
                ring_member_root: devnet_payload_root("ring-members", "user-transfer-0001"),
                ring_size: 16,
                healthy_decoys: 15,
                stale_decoys: 1,
                repeated_decoys: 0,
                spent_member_hints: 0,
                age_distribution_root: devnet_payload_root("age-dist", "balanced-0001"),
                health_score_bps: 9_812,
                status: HealthStatus::Healthy,
            })
            .expect("demo ring health is valid");

        let mut scopes = BTreeSet::new();
        scopes.insert(RedactionScope::OutputKeyImage);
        scopes.insert(RedactionScope::StealthAddress);
        scopes.insert(RedactionScope::SubaddressIndex);
        let mut operator_fields = BTreeSet::new();
        operator_fields.insert("cohort_id".to_string());
        operator_fields.insert("risk_level".to_string());
        operator_fields.insert("expires_at_height".to_string());
        state
            .insert_wallet_redaction(WalletSafeRedaction {
                redaction_id: "redaction-devnet-wallet-safe-0001".to_string(),
                cohort_id: cohort_id.clone(),
                scopes,
                redacted_payload_root: devnet_payload_root("redaction", "wallet-safe-0001"),
                public_reason_root: devnet_payload_root("redaction-reason", "protect-wallet-path"),
                operator_visible_fields: operator_fields,
                expires_at_height: DEVNET_HEIGHT + DEFAULT_REDACTION_TTL_BLOCKS,
                status: GuardStatus::Open,
            })
            .expect("demo redaction is valid");

        let mut probe_ids = BTreeSet::new();
        probe_ids.insert(probe_id);
        probe_ids.insert(risky_probe_id.clone());
        state
            .insert_pq_watcher_attestation(PqWatcherAttestation {
                attestation_id: "attestation-devnet-pq-watcher-0001".to_string(),
                watcher_id: "pq-watcher-alpha-devnet".to_string(),
                cohort_id: cohort_id.clone(),
                probe_ids,
                pq_scheme: PQ_WATCHER_SUITE.to_string(),
                pq_security_bits: 256,
                public_key_commitment: devnet_payload_root("pq-key", "watcher-alpha"),
                signature_root: devnet_payload_root("pq-signature", "watcher-alpha-0001"),
                bonded_micro_units: DEFAULT_WATCHER_BOND_MICRO_UNITS,
                verdict: AttestationVerdict::NeedsMoreSamples,
                status: GuardStatus::Attested,
            })
            .expect("demo attestation is valid");

        state
            .insert_quarantine(QuarantineRecord {
                quarantine_id: "quarantine-devnet-defi-0001".to_string(),
                cohort_id: defi_cohort_id.clone(),
                probe_id: risky_probe_id.clone(),
                affected_output_root: devnet_payload_root("affected-outputs", "defi-0002"),
                reason_root: devnet_payload_root("quarantine-reason", "linkability-watch"),
                opened_at_height: DEVNET_HEIGHT,
                expires_at_height: DEVNET_HEIGHT + DEFAULT_QUARANTINE_TTL_BLOCKS,
                quarantined_outputs: 512,
                status: GuardStatus::Quarantined,
            })
            .expect("demo quarantine is valid");

        state
            .insert_escalation(EscalationRecord {
                escalation_id: "escalation-devnet-operator-0001".to_string(),
                cohort_id: defi_cohort_id.clone(),
                source_record_id: risky_probe_id,
                level: EscalationLevel::OperatorReview,
                opened_at_height: DEVNET_HEIGHT,
                expires_at_height: DEVNET_HEIGHT + DEFAULT_ESCALATION_TTL_BLOCKS,
                operator_action_root: devnet_payload_root("operator-action", "delay-defi-burst"),
                governance_packet_root: devnet_payload_root("governance", "not-required"),
                status: GuardStatus::Escalated,
            })
            .expect("demo escalation is valid");

        state
            .insert_privacy_floor_metric(PrivacyFloorMetric {
                metric_id: "metric-devnet-floor-0001".to_string(),
                cohort_id,
                output_count: 94_208,
                ring_size_floor: 16,
                healthy_decoy_floor: 15,
                view_tag_sample_rate_bps: 312,
                linkability_score_bps: 72,
                floor_score_bps: 9_812,
                pass: true,
                metric_root: devnet_payload_root("metric", "user-transfer-floor-0001"),
            })
            .expect("demo metric is valid");

        state
            .insert_privacy_floor_metric(PrivacyFloorMetric {
                metric_id: "metric-devnet-floor-0002".to_string(),
                cohort_id: defi_cohort_id,
                output_count: 72_704,
                ring_size_floor: 16,
                healthy_decoy_floor: 15,
                view_tag_sample_rate_bps: 281,
                linkability_score_bps: 138,
                floor_score_bps: 9_512,
                pass: false,
                metric_root: devnet_payload_root("metric", "defi-floor-watch-0002"),
            })
            .expect("demo metric is valid");

        state
            .publish_public_root("public-root-devnet-0001", GuardStatus::Open)
            .expect("demo public root is valid");
        state
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        ensure!(
            self.output_cohorts.len() <= MAX_OUTPUT_COHORTS,
            "too many output cohorts"
        );
        ensure!(
            self.linkability_probes.len() <= MAX_LINKABILITY_PROBES,
            "too many linkability probes"
        );
        ensure!(
            self.view_tag_scan_samples.len() <= MAX_VIEW_TAG_SCAN_SAMPLES,
            "too many view tag scan samples"
        );
        ensure!(
            self.ring_member_health.len() <= MAX_RING_MEMBER_HEALTH_RECORDS,
            "too many ring member health records"
        );
        ensure!(
            self.wallet_redactions.len() <= MAX_WALLET_REDACTIONS,
            "too many wallet redactions"
        );
        ensure!(
            self.pq_watcher_attestations.len() <= MAX_PQ_WATCHER_ATTESTATIONS,
            "too many pq watcher attestations"
        );
        ensure!(
            self.quarantines.len() <= MAX_QUARANTINES,
            "too many quarantines"
        );
        ensure!(
            self.escalations.len() <= MAX_ESCALATIONS,
            "too many escalations"
        );
        ensure!(
            self.privacy_floor_metrics.len() <= MAX_PRIVACY_FLOOR_METRICS,
            "too many privacy floor metrics"
        );
        ensure!(
            self.public_roots.len() <= MAX_PUBLIC_ROOTS,
            "too many public roots"
        );
        for cohort in self.output_cohorts.values() {
            cohort.validate(&self.config)?;
        }
        for probe in self.linkability_probes.values() {
            probe.validate(&self.config)?;
            ensure!(
                self.output_cohorts.contains_key(&probe.cohort_id),
                "probe references missing cohort {}",
                probe.cohort_id
            );
        }
        for sample in self.view_tag_scan_samples.values() {
            sample.validate(&self.config)?;
            ensure!(
                self.output_cohorts.contains_key(&sample.cohort_id),
                "sample references missing cohort {}",
                sample.cohort_id
            );
        }
        for health in self.ring_member_health.values() {
            health.validate(&self.config)?;
            ensure!(
                self.output_cohorts.contains_key(&health.cohort_id),
                "health references missing cohort {}",
                health.cohort_id
            );
        }
        for redaction in self.wallet_redactions.values() {
            redaction.validate(self.height)?;
            ensure!(
                self.output_cohorts.contains_key(&redaction.cohort_id),
                "redaction references missing cohort {}",
                redaction.cohort_id
            );
        }
        for attestation in self.pq_watcher_attestations.values() {
            attestation.validate(&self.config)?;
            ensure!(
                self.output_cohorts.contains_key(&attestation.cohort_id),
                "attestation references missing cohort {}",
                attestation.cohort_id
            );
            for probe_id in &attestation.probe_ids {
                ensure!(
                    self.linkability_probes.contains_key(probe_id),
                    "attestation references missing probe {}",
                    probe_id
                );
            }
        }
        for quarantine in self.quarantines.values() {
            quarantine.validate()?;
            ensure!(
                self.output_cohorts.contains_key(&quarantine.cohort_id),
                "quarantine references missing cohort {}",
                quarantine.cohort_id
            );
            ensure!(
                self.linkability_probes.contains_key(&quarantine.probe_id),
                "quarantine references missing probe {}",
                quarantine.probe_id
            );
        }
        for escalation in self.escalations.values() {
            escalation.validate()?;
            ensure!(
                self.output_cohorts.contains_key(&escalation.cohort_id),
                "escalation references missing cohort {}",
                escalation.cohort_id
            );
        }
        for metric in self.privacy_floor_metrics.values() {
            metric.validate(&self.config)?;
            ensure!(
                self.output_cohorts.contains_key(&metric.cohort_id),
                "metric references missing cohort {}",
                metric.cohort_id
            );
        }
        Ok(())
    }

    pub fn insert_output_cohort(&mut self, record: OutputCohort) -> Result<String> {
        record.validate(&self.config)?;
        let id = record.cohort_id.clone();
        self.output_cohorts.insert(id.clone(), record);
        self.refresh();
        Ok(id)
    }

    pub fn insert_linkability_probe(&mut self, record: LinkabilityRiskProbe) -> Result<String> {
        record.validate(&self.config)?;
        ensure!(
            self.output_cohorts.contains_key(&record.cohort_id),
            "probe references missing cohort {}",
            record.cohort_id
        );
        let id = record.probe_id.clone();
        self.linkability_probes.insert(id.clone(), record);
        self.refresh();
        Ok(id)
    }

    pub fn insert_view_tag_scan_sample(&mut self, record: ViewTagScanSample) -> Result<String> {
        record.validate(&self.config)?;
        ensure!(
            self.output_cohorts.contains_key(&record.cohort_id),
            "sample references missing cohort {}",
            record.cohort_id
        );
        let id = record.sample_id.clone();
        self.view_tag_scan_samples.insert(id.clone(), record);
        self.refresh();
        Ok(id)
    }

    pub fn insert_ring_member_health(&mut self, record: RingMemberHealth) -> Result<String> {
        record.validate(&self.config)?;
        ensure!(
            self.output_cohorts.contains_key(&record.cohort_id),
            "health references missing cohort {}",
            record.cohort_id
        );
        let id = record.health_id.clone();
        self.ring_member_health.insert(id.clone(), record);
        self.refresh();
        Ok(id)
    }

    pub fn insert_wallet_redaction(&mut self, record: WalletSafeRedaction) -> Result<String> {
        record.validate(self.height)?;
        ensure!(
            self.output_cohorts.contains_key(&record.cohort_id),
            "redaction references missing cohort {}",
            record.cohort_id
        );
        let id = record.redaction_id.clone();
        self.wallet_redactions.insert(id.clone(), record);
        self.refresh();
        Ok(id)
    }

    pub fn insert_pq_watcher_attestation(
        &mut self,
        record: PqWatcherAttestation,
    ) -> Result<String> {
        record.validate(&self.config)?;
        ensure!(
            self.output_cohorts.contains_key(&record.cohort_id),
            "attestation references missing cohort {}",
            record.cohort_id
        );
        for probe_id in &record.probe_ids {
            ensure!(
                self.linkability_probes.contains_key(probe_id),
                "attestation references missing probe {}",
                probe_id
            );
        }
        let id = record.attestation_id.clone();
        self.pq_watcher_attestations.insert(id.clone(), record);
        self.refresh();
        Ok(id)
    }

    pub fn insert_quarantine(&mut self, record: QuarantineRecord) -> Result<String> {
        record.validate()?;
        ensure!(
            self.output_cohorts.contains_key(&record.cohort_id),
            "quarantine references missing cohort {}",
            record.cohort_id
        );
        ensure!(
            self.linkability_probes.contains_key(&record.probe_id),
            "quarantine references missing probe {}",
            record.probe_id
        );
        let id = record.quarantine_id.clone();
        self.quarantines.insert(id.clone(), record);
        self.refresh();
        Ok(id)
    }

    pub fn insert_escalation(&mut self, record: EscalationRecord) -> Result<String> {
        record.validate()?;
        ensure!(
            self.output_cohorts.contains_key(&record.cohort_id),
            "escalation references missing cohort {}",
            record.cohort_id
        );
        let id = record.escalation_id.clone();
        self.escalations.insert(id.clone(), record);
        self.refresh();
        Ok(id)
    }

    pub fn insert_privacy_floor_metric(&mut self, record: PrivacyFloorMetric) -> Result<String> {
        record.validate(&self.config)?;
        ensure!(
            self.output_cohorts.contains_key(&record.cohort_id),
            "metric references missing cohort {}",
            record.cohort_id
        );
        let id = record.metric_id.clone();
        self.privacy_floor_metrics.insert(id.clone(), record);
        self.refresh();
        Ok(id)
    }

    pub fn publish_public_root(
        &mut self,
        public_root_id: &str,
        status: GuardStatus,
    ) -> Result<String> {
        ensure!(!public_root_id.is_empty(), "public root id is empty");
        self.refresh();
        let record = PublicRootRecord {
            public_root_id: public_root_id.to_string(),
            height: self.height,
            epoch: self.epoch,
            roots: self.roots.clone(),
            counters: self.counters.clone(),
            status,
        };
        self.public_roots.insert(public_root_id.to_string(), record);
        self.refresh();
        Ok(public_root_id.to_string())
    }

    pub fn refresh(&mut self) {
        self.counters = self.compute_counters();
        self.roots = self.compute_roots();
    }

    pub fn compute_counters(&self) -> Counters {
        let mut counters = Counters {
            output_cohorts: self.output_cohorts.len(),
            live_output_cohorts: self
                .output_cohorts
                .values()
                .filter(|record| record.status.live())
                .count(),
            linkability_probes: self.linkability_probes.len(),
            high_risk_probes: self
                .linkability_probes
                .values()
                .filter(|record| record.exceeds_floor(&self.config))
                .count(),
            view_tag_scan_samples: self.view_tag_scan_samples.len(),
            ring_member_health_records: self.ring_member_health.len(),
            usable_ring_member_health_records: self
                .ring_member_health
                .values()
                .filter(|record| record.status.usable())
                .count(),
            wallet_redactions: self.wallet_redactions.len(),
            pq_watcher_attestations: self.pq_watcher_attestations.len(),
            risky_watcher_attestations: self
                .pq_watcher_attestations
                .values()
                .filter(|record| {
                    matches!(
                        record.verdict,
                        AttestationVerdict::Risky | AttestationVerdict::Invalid
                    )
                })
                .count(),
            quarantines: self.quarantines.len(),
            escalations: self.escalations.len(),
            privacy_floor_metrics: self.privacy_floor_metrics.len(),
            public_roots: self.public_roots.len(),
            total_outputs: 0,
            total_sampled_outputs: 0,
            total_ring_members: 0,
            total_healthy_decoys: 0,
            total_quarantined_outputs: 0,
            max_linkability_score_bps: 0,
            min_privacy_floor_score_bps: MAX_BPS,
            watcher_bonded_micro_units: 0,
            low_fee_spend_micro_units: 0,
        };
        for cohort in self.output_cohorts.values() {
            counters.total_outputs = counters.total_outputs.saturating_add(cohort.output_count);
            counters.total_sampled_outputs = counters
                .total_sampled_outputs
                .saturating_add(cohort.sampled_output_count);
        }
        for health in self.ring_member_health.values() {
            counters.total_ring_members = counters
                .total_ring_members
                .saturating_add(health.ring_size as u64);
            counters.total_healthy_decoys = counters
                .total_healthy_decoys
                .saturating_add(health.healthy_decoys as u64);
        }
        for probe in self.linkability_probes.values() {
            counters.max_linkability_score_bps = counters
                .max_linkability_score_bps
                .max(probe.linkability_score_bps);
        }
        for quarantine in self.quarantines.values() {
            counters.total_quarantined_outputs = counters
                .total_quarantined_outputs
                .saturating_add(quarantine.quarantined_outputs);
        }
        for attestation in self.pq_watcher_attestations.values() {
            counters.watcher_bonded_micro_units = counters
                .watcher_bonded_micro_units
                .saturating_add(attestation.bonded_micro_units);
        }
        for metric in self.privacy_floor_metrics.values() {
            counters.min_privacy_floor_score_bps = counters
                .min_privacy_floor_score_bps
                .min(metric.floor_score_bps);
        }
        if self.privacy_floor_metrics.is_empty() {
            counters.min_privacy_floor_score_bps = 0;
        }
        counters.low_fee_spend_micro_units =
            counters.linkability_probes as u64 * self.config.low_fee_cap_micro_units;
        counters
    }

    pub fn compute_roots(&self) -> Roots {
        let config_root = root_json("OUTPUT-LINKABILITY-CONFIG", self.config.public_record());
        let output_cohort_root = records_root(
            OUTPUT_COHORT_SCHEME,
            values_public_records(&self.output_cohorts),
        );
        let linkability_probe_root = records_root(
            LINKABILITY_PROBE_SCHEME,
            values_public_records(&self.linkability_probes),
        );
        let view_tag_scan_sample_root = records_root(
            VIEW_TAG_SAMPLE_SCHEME,
            values_public_records(&self.view_tag_scan_samples),
        );
        let ring_member_health_root = records_root(
            RING_MEMBER_HEALTH_SCHEME,
            values_public_records(&self.ring_member_health),
        );
        let wallet_redaction_root = records_root(
            WALLET_REDACTION_SCHEME,
            values_public_records(&self.wallet_redactions),
        );
        let pq_watcher_attestation_root = records_root(
            PQ_WATCHER_ATTESTATION_SCHEME,
            values_public_records(&self.pq_watcher_attestations),
        );
        let quarantine_root =
            records_root(QUARANTINE_SCHEME, values_public_records(&self.quarantines));
        let escalation_root =
            records_root(ESCALATION_SCHEME, values_public_records(&self.escalations));
        let privacy_floor_metric_root = records_root(
            PRIVACY_FLOOR_SCHEME,
            values_public_records(&self.privacy_floor_metrics),
        );
        let public_root = records_root(
            PUBLIC_ROOT_SCHEME,
            values_public_records(&self.public_roots),
        );
        let operator_safe_summary_root = root_json(
            "OUTPUT-LINKABILITY-OPERATOR-SAFE-SUMMARY",
            json!({
                "height": self.height,
                "epoch": self.epoch,
                "counters": self.compute_counters().public_record(),
                "output_cohort_root": output_cohort_root,
                "linkability_probe_root": linkability_probe_root,
                "privacy_floor_metric_root": privacy_floor_metric_root,
            }),
        );
        let state_root = root_json(
            "OUTPUT-LINKABILITY-STATE",
            json!({
                "protocol_version": PROTOCOL_VERSION,
                "height": self.height,
                "epoch": self.epoch,
                "config_root": config_root,
                "output_cohort_root": output_cohort_root,
                "linkability_probe_root": linkability_probe_root,
                "view_tag_scan_sample_root": view_tag_scan_sample_root,
                "ring_member_health_root": ring_member_health_root,
                "wallet_redaction_root": wallet_redaction_root,
                "pq_watcher_attestation_root": pq_watcher_attestation_root,
                "quarantine_root": quarantine_root,
                "escalation_root": escalation_root,
                "privacy_floor_metric_root": privacy_floor_metric_root,
                "public_root": public_root,
                "operator_safe_summary_root": operator_safe_summary_root,
            }),
        );
        Roots {
            config_root,
            output_cohort_root,
            linkability_probe_root,
            view_tag_scan_sample_root,
            ring_member_health_root,
            wallet_redaction_root,
            pq_watcher_attestation_root,
            quarantine_root,
            escalation_root,
            privacy_floor_metric_root,
            public_root,
            operator_safe_summary_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "output_cohorts": values_public_records(&self.output_cohorts),
            "linkability_probes": values_public_records(&self.linkability_probes),
            "view_tag_scan_samples": values_public_records(&self.view_tag_scan_samples),
            "ring_member_health": values_public_records(&self.ring_member_health),
            "wallet_redactions": values_public_records(&self.wallet_redactions),
            "pq_watcher_attestations": values_public_records(&self.pq_watcher_attestations),
            "quarantines": values_public_records(&self.quarantines),
            "escalations": values_public_records(&self.escalations),
            "privacy_floor_metrics": values_public_records(&self.privacy_floor_metrics),
            "public_roots": values_public_records(&self.public_roots),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
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

pub fn values_public_records<T: PublicRecord>(records: &BTreeMap<String, T>) -> Vec<Value> {
    records.values().map(PublicRecord::public_record).collect()
}

pub fn records_root(domain: &str, records: impl IntoIterator<Item = Value>) -> String {
    let values = records.into_iter().collect::<Vec<_>>();
    merkle_root(domain, &values)
}

pub fn root_json(domain: &str, value: Value) -> String {
    domain_hash(domain, &[HashPart::Str(&canonical_json(&value))], 32)
}

pub fn root_from_parts(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

pub fn stable_id(domain: &str, label: &str, sequence: u64) -> String {
    root_from_parts(
        domain,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(sequence),
        ],
    )
}

pub fn devnet_payload_root(kind: &str, label: &str) -> String {
    root_from_parts(
        "OUTPUT-LINKABILITY-DEVNET-PAYLOAD",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(label),
        ],
    )
}

pub fn canonical_json(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".to_string())
}

pub fn bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    numerator.saturating_mul(MAX_BPS as u64) / denominator
}
