use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateRingctOutputDecoyReputationCacheRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_RINGCT_OUTPUT_DECOY_REPUTATION_CACHE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-ringct-output-decoy-reputation-cache-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_RINGCT_OUTPUT_DECOY_REPUTATION_CACHE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RINGCT_OUTPUT_COHORT_SCHEME: &str = "monero-ringct-output-decoy-reputation-cache-root-v1";
pub const DECOY_REPUTATION_SHARD_SCHEME: &str =
    "low-fee-private-ringct-output-decoy-reputation-cache-shard-root-v1";
pub const OUTPUT_AGE_BUCKET_SCHEME: &str = "monero-ringct-output-age-bucket-root-v1";
pub const PQ_CACHE_ATTESTATION_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-ringct-output-decoy-reputation-cache-attestation-v1";
pub const WALLET_SCAN_HINT_SCHEME: &str = "view-key-safe-ringct-decoy-wallet-scan-hint-root-v1";
pub const CACHE_INVALIDATION_SCHEME: &str =
    "privacy-preserving-ringct-decoy-cache-invalidation-root-v1";
pub const LOW_FEE_REBATE_SCHEME: &str = "low-fee-private-ringct-decoy-cache-rebate-root-v1";
pub const PRIVACY_REDACTION_BUDGET_SCHEME: &str =
    "ringct-output-decoy-reputation-cache-redaction-budget-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str =
    "redacted-ringct-output-decoy-reputation-cache-operator-summary-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "deterministic-public-ringct-output-decoy-reputation-cache-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_addresses_view_keys_key_images_amounts_ring_indices_or_decoy_graph_edges";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 2_960_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_620_000;
pub const DEVNET_EPOCH: u64 = 13_104;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_RING_SIZE: u16 = 16;
pub const DEFAULT_TARGET_RING_SIZE: u16 = 32;
pub const DEFAULT_MIN_COHORT_OUTPUTS: u64 = 65_536;
pub const DEFAULT_TARGET_COHORT_OUTPUTS: u64 = 262_144;
pub const DEFAULT_MAX_COHORT_AGE_BLOCKS: u64 = 7_200;
pub const DEFAULT_OUTPUT_AGE_BUCKET_BLOCKS: u64 = 720;
pub const DEFAULT_CACHE_TTL_BLOCKS: u64 = 360;
pub const DEFAULT_SHARD_SPAN_BLOCKS: u64 = 36;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_INVALIDATION_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_SCAN_HINT_TTL_BLOCKS: u64 = 240;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 6;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 4;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_400;
pub const DEFAULT_OPERATOR_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_OPERATOR_SUPERMAJORITY_BPS: u64 = 8_000;
pub const DEFAULT_PUBLIC_BUCKET_SIZE: u64 = 64;
pub const DEFAULT_MAX_REDACTION_UNITS_PER_HINT: u64 = 24;
pub const DEFAULT_MAX_COHORTS: usize = 2_097_152;
pub const DEFAULT_MAX_SHARDS: usize = 2_097_152;
pub const DEFAULT_MAX_OUTPUT_AGE_BUCKETS: usize = 4_194_304;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_SCAN_HINTS: usize = 4_194_304;
pub const DEFAULT_MAX_INVALIDATIONS: usize = 1_048_576;
pub const DEFAULT_MAX_REBATES: usize = 4_194_304;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 1_048_576;
pub const DEFAULT_MAX_OPERATOR_SUMMARIES: usize = 524_288;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 4_194_304;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    Devnet,
    Canary,
    MainnetCandidate,
}

impl RuntimeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Devnet => "devnet",
            Self::Canary => "canary",
            Self::MainnetCandidate => "mainnet_candidate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecoyCohortKind {
    WalletSpend,
    BridgeWithdrawal,
    SwapSettlement,
    LiquidityRebalance,
    MerchantPayment,
    MicropaymentNetting,
    EmergencyExit,
    AuditCanary,
}

impl DecoyCohortKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletSpend => "wallet_spend",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::SwapSettlement => "swap_settlement",
            Self::LiquidityRebalance => "liquidity_rebalance",
            Self::MerchantPayment => "merchant_payment",
            Self::MicropaymentNetting => "micropayment_netting",
            Self::EmergencyExit => "emergency_exit",
            Self::AuditCanary => "audit_canary",
        }
    }

    pub fn privacy_weight(self) -> u64 {
        match self {
            Self::EmergencyExit => 1_000,
            Self::BridgeWithdrawal => 960,
            Self::SwapSettlement => 900,
            Self::LiquidityRebalance => 840,
            Self::MerchantPayment => 760,
            Self::WalletSpend => 720,
            Self::MicropaymentNetting => 680,
            Self::AuditCanary => 600,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortStatus {
    Draft,
    Open,
    Warm,
    Attested,
    RebateEligible,
    Quarantined,
    Expired,
    Sealed,
}

impl CohortStatus {
    pub fn accepts_members(self) -> bool {
        matches!(self, Self::Draft | Self::Open | Self::Warm)
    }

    pub fn public_usable(self) -> bool {
        matches!(
            self,
            Self::Warm | Self::Attested | Self::RebateEligible | Self::Sealed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecoyReputationShardStatus {
    Open,
    Warm,
    Saturated,
    Sealed,
    Invalidating,
    Invalidated,
    Expired,
}

impl DecoyReputationShardStatus {
    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Warm | Self::Saturated | Self::Invalidating
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputAgeBucketStatus {
    Candidate,
    Fresh,
    Aging,
    Stale,
    Quarantined,
    SpentUnknown,
}

impl OutputAgeBucketStatus {
    pub fn selectable(self) -> bool {
        matches!(self, Self::Candidate | Self::Fresh | Self::Aging)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    Quorum,
    Superseded,
    Revoked,
    Expired,
    Rejected,
}

impl AttestationStatus {
    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Accepted | Self::Quorum)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanHintStatus {
    Draft,
    Published,
    Consumed,
    Superseded,
    Throttled,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvalidationReason {
    StaleRingctOutput,
    FeeSpike,
    Reorg,
    AttestationRevoked,
    PrivacyBudgetExhausted,
    OperatorSlashed,
    ManualQuarantine,
}

impl InvalidationReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaleRingctOutput => "stale_ringct_output",
            Self::FeeSpike => "fee_spike",
            Self::Reorg => "reorg",
            Self::AttestationRevoked => "attestation_revoked",
            Self::PrivacyBudgetExhausted => "privacy_budget_exhausted",
            Self::OperatorSlashed => "operator_slashed",
            Self::ManualQuarantine => "manual_quarantine",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Queued,
    Sponsored,
    Claimed,
    Expired,
    Rejected,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionScope {
    Cohort,
    Shard,
    OutputAge,
    Attestation,
    ScanHint,
    Rebate,
    OperatorSummary,
}

impl RedactionScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cohort => "cohort",
            Self::Shard => "shard",
            Self::OutputAge => "output_age",
            Self::Attestation => "attestation",
            Self::ScanHint => "scan_hint",
            Self::Rebate => "rebate",
            Self::OperatorSummary => "operator_summary",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorRole {
    Sequencer,
    Watchtower,
    CacheProvider,
    WalletRelay,
    FeeSponsor,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub mode: RuntimeMode,
    pub min_ring_size: u16,
    pub target_ring_size: u16,
    pub min_cohort_outputs: u64,
    pub target_cohort_outputs: u64,
    pub max_cohort_age_blocks: u64,
    pub output_age_bucket_blocks: u64,
    pub cache_ttl_blocks: u64,
    pub shard_span_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub invalidation_ttl_blocks: u64,
    pub scan_hint_ttl_blocks: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub operator_quorum_bps: u64,
    pub operator_supermajority_bps: u64,
    pub public_bucket_size: u64,
    pub max_redaction_units_per_hint: u64,
    pub max_cohorts: usize,
    pub max_shards: usize,
    pub max_output_age_buckets: usize,
    pub max_attestations: usize,
    pub max_scan_hints: usize,
    pub max_invalidations: usize,
    pub max_rebates: usize,
    pub max_redaction_budgets: usize,
    pub max_operator_summaries: usize,
    pub max_public_records: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            mode: RuntimeMode::Devnet,
            min_ring_size: DEFAULT_MIN_RING_SIZE,
            target_ring_size: DEFAULT_TARGET_RING_SIZE,
            min_cohort_outputs: DEFAULT_MIN_COHORT_OUTPUTS,
            target_cohort_outputs: DEFAULT_TARGET_COHORT_OUTPUTS,
            max_cohort_age_blocks: DEFAULT_MAX_COHORT_AGE_BLOCKS,
            output_age_bucket_blocks: DEFAULT_OUTPUT_AGE_BUCKET_BLOCKS,
            cache_ttl_blocks: DEFAULT_CACHE_TTL_BLOCKS,
            shard_span_blocks: DEFAULT_SHARD_SPAN_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            invalidation_ttl_blocks: DEFAULT_INVALIDATION_TTL_BLOCKS,
            scan_hint_ttl_blocks: DEFAULT_SCAN_HINT_TTL_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            operator_quorum_bps: DEFAULT_OPERATOR_QUORUM_BPS,
            operator_supermajority_bps: DEFAULT_OPERATOR_SUPERMAJORITY_BPS,
            public_bucket_size: DEFAULT_PUBLIC_BUCKET_SIZE,
            max_redaction_units_per_hint: DEFAULT_MAX_REDACTION_UNITS_PER_HINT,
            max_cohorts: DEFAULT_MAX_COHORTS,
            max_shards: DEFAULT_MAX_SHARDS,
            max_output_age_buckets: DEFAULT_MAX_OUTPUT_AGE_BUCKETS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_scan_hints: DEFAULT_MAX_SCAN_HINTS,
            max_invalidations: DEFAULT_MAX_INVALIDATIONS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
            max_operator_summaries: DEFAULT_MAX_OPERATOR_SUMMARIES,
            max_public_records: DEFAULT_MAX_PUBLIC_RECORDS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure(
            self.min_ring_size >= 16 && self.target_ring_size >= self.min_ring_size,
            "ring size must preserve Monero decoy privacy",
        )?;
        ensure(
            self.min_cohort_outputs <= self.target_cohort_outputs,
            "target cohort output count must be at least the minimum",
        )?;
        ensure(
            self.min_pq_security_bits >= 128
                && self.target_pq_security_bits >= self.min_pq_security_bits,
            "post-quantum security bits are below policy",
        )?;
        ensure(
            self.max_user_fee_bps <= 100 && self.target_rebate_bps <= self.max_user_fee_bps,
            "fee policy must keep RINGCT decoy cache usage low-fee",
        )?;
        ensure(
            self.operator_quorum_bps <= MAX_BPS
                && self.operator_supermajority_bps <= MAX_BPS
                && self.operator_supermajority_bps >= self.operator_quorum_bps,
            "operator quorum thresholds are invalid",
        )?;
        ensure(
            self.public_bucket_size > 0,
            "public bucket size cannot be zero",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "mode": self.mode.as_str(),
            "min_ring_size": self.min_ring_size,
            "target_ring_size": self.target_ring_size,
            "min_cohort_outputs": self.min_cohort_outputs,
            "target_cohort_outputs": self.target_cohort_outputs,
            "max_cohort_age_blocks": self.max_cohort_age_blocks,
            "output_age_bucket_blocks": self.output_age_bucket_blocks,
            "cache_ttl_blocks": self.cache_ttl_blocks,
            "shard_span_blocks": self.shard_span_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "invalidation_ttl_blocks": self.invalidation_ttl_blocks,
            "scan_hint_ttl_blocks": self.scan_hint_ttl_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "operator_quorum_bps": self.operator_quorum_bps,
            "operator_supermajority_bps": self.operator_supermajority_bps,
            "public_bucket_size": self.public_bucket_size,
            "max_redaction_units_per_hint": self.max_redaction_units_per_hint,
            "privacy_boundary": PRIVACY_BOUNDARY,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub cohorts_opened: u64,
    pub cohorts_attested: u64,
    pub cohorts_quarantined: u64,
    pub shards_opened: u64,
    pub shards_invalidated: u64,
    pub output_age_buckets: u64,
    pub output_age_members: u64,
    pub pq_attestations: u64,
    pub scan_hints: u64,
    pub invalidations: u64,
    pub rebates_queued: u64,
    pub rebates_claimed: u64,
    pub redaction_budgets: u64,
    pub redaction_units_reserved: u64,
    pub operator_summaries: u64,
    pub public_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "cohorts_opened": self.cohorts_opened,
            "cohorts_attested": self.cohorts_attested,
            "cohorts_quarantined": self.cohorts_quarantined,
            "shards_opened": self.shards_opened,
            "shards_invalidated": self.shards_invalidated,
            "output_age_buckets": self.output_age_buckets,
            "output_age_members": self.output_age_members,
            "pq_attestations": self.pq_attestations,
            "scan_hints": self.scan_hints,
            "invalidations": self.invalidations,
            "rebates_queued": self.rebates_queued,
            "rebates_claimed": self.rebates_claimed,
            "redaction_budgets": self.redaction_budgets,
            "redaction_units_reserved": self.redaction_units_reserved,
            "operator_summaries": self.operator_summaries,
            "public_records": self.public_records,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub cohorts_root: String,
    pub shards_root: String,
    pub output_age_root: String,
    pub attestations_root: String,
    pub scan_hints_root: String,
    pub invalidations_root: String,
    pub rebates_root: String,
    pub redaction_budgets_root: String,
    pub operator_summaries_root: String,
    pub public_records_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "cohorts_root": self.cohorts_root,
            "shards_root": self.shards_root,
            "output_age_root": self.output_age_root,
            "attestations_root": self.attestations_root,
            "scan_hints_root": self.scan_hints_root,
            "invalidations_root": self.invalidations_root,
            "rebates_root": self.rebates_root,
            "redaction_budgets_root": self.redaction_budgets_root,
            "operator_summaries_root": self.operator_summaries_root,
            "public_records_root": self.public_records_root,
            "state_root": self.state_root,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("roots", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RingctDecoyCohort {
    pub cohort_id: String,
    pub kind: DecoyCohortKind,
    pub status: CohortStatus,
    pub shard_id: String,
    pub epoch: u64,
    pub monero_height_opened: u64,
    pub monero_height_expires: u64,
    pub output_bucket_start: u64,
    pub output_bucket_end: u64,
    pub ring_size_floor: u16,
    pub target_ring_size: u16,
    pub decoy_count: u64,
    pub spendable_output_count: u64,
    pub output_age_bucket_id: String,
    pub fee_quote_piconero: u64,
    pub max_fee_bps: u64,
    pub rebate_bps: u64,
    pub pq_attestation_root: String,
    pub redacted_member_commitment_root: String,
    pub nullifier_set_root: String,
    pub scan_hint_root: String,
    pub operator_set_root: String,
    pub privacy_score_bps: u64,
    pub latency_target_ms: u64,
}

impl RingctDecoyCohort {
    pub fn new(
        cohort_id: impl Into<String>,
        shard_id: impl Into<String>,
        kind: DecoyCohortKind,
        epoch: u64,
        monero_height_opened: u64,
    ) -> Self {
        let cohort_id = cohort_id.into();
        let shard_id = shard_id.into();
        let output_age_bucket_id = scoped_id("output_age", &cohort_id);
        Self {
            cohort_id: cohort_id.clone(),
            kind,
            status: CohortStatus::Open,
            shard_id,
            epoch,
            monero_height_opened,
            monero_height_expires: monero_height_opened + DEFAULT_MAX_COHORT_AGE_BLOCKS,
            output_bucket_start: monero_height_opened
                .saturating_sub(DEFAULT_OUTPUT_AGE_BUCKET_BLOCKS),
            output_bucket_end: monero_height_opened,
            ring_size_floor: DEFAULT_MIN_RING_SIZE,
            target_ring_size: DEFAULT_TARGET_RING_SIZE,
            decoy_count: DEFAULT_TARGET_COHORT_OUTPUTS,
            spendable_output_count: DEFAULT_MIN_COHORT_OUTPUTS,
            output_age_bucket_id,
            fee_quote_piconero: 18_000,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            pq_attestation_root: empty_root("cohort-pq-attestation"),
            redacted_member_commitment_root: root_from_parts(
                "cohort-member-commitments",
                &[HashPart::Str(&cohort_id), HashPart::U64(epoch)],
            ),
            nullifier_set_root: empty_root("cohort-nullifiers"),
            scan_hint_root: empty_root("cohort-scan-hints"),
            operator_set_root: empty_root("cohort-operators"),
            privacy_score_bps: 9_650,
            latency_target_ms: 18,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure(!self.cohort_id.is_empty(), "cohort id cannot be empty")?;
        ensure(!self.shard_id.is_empty(), "cohort shard id cannot be empty")?;
        ensure(
            self.ring_size_floor >= config.min_ring_size
                && self.target_ring_size >= self.ring_size_floor,
            "cohort ring size is below policy",
        )?;
        ensure(
            self.decoy_count >= config.min_cohort_outputs,
            "cohort has too few decoy outputs",
        )?;
        ensure(
            self.spendable_output_count <= self.decoy_count,
            "spendable outputs cannot exceed decoy count",
        )?;
        ensure(
            self.max_fee_bps <= config.max_user_fee_bps,
            "cohort fee quote exceeds low-fee policy",
        )?;
        ensure(
            self.privacy_score_bps >= 8_000,
            "cohort privacy score is below admission threshold",
        )
    }

    pub fn mark_attested(&mut self, pq_attestation_root: impl Into<String>) {
        self.status = CohortStatus::Attested;
        self.pq_attestation_root = pq_attestation_root.into();
    }

    pub fn quarantine(&mut self, nullifier_set_root: impl Into<String>) {
        self.status = CohortStatus::Quarantined;
        self.nullifier_set_root = nullifier_set_root.into();
    }

    pub fn public_record(&self) -> Value {
        json!({
            "cohort_id": self.cohort_id,
            "kind": self.kind.as_str(),
            "status": self.status,
            "shard_id": self.shard_id,
            "epoch": self.epoch,
            "monero_height_opened": self.monero_height_opened,
            "monero_height_expires": self.monero_height_expires,
            "output_bucket_start": bucket(self.output_bucket_start, DEFAULT_PUBLIC_BUCKET_SIZE),
            "output_bucket_end": bucket(self.output_bucket_end, DEFAULT_PUBLIC_BUCKET_SIZE),
            "ring_size_floor": self.ring_size_floor,
            "target_ring_size": self.target_ring_size,
            "decoy_count_bucket": bucket(self.decoy_count, DEFAULT_PUBLIC_BUCKET_SIZE),
            "spendable_output_count_bucket": bucket(self.spendable_output_count, DEFAULT_PUBLIC_BUCKET_SIZE),
            "output_age_bucket_id": self.output_age_bucket_id,
            "fee_quote_piconero_bucket": bucket(self.fee_quote_piconero, 1_000),
            "max_fee_bps": self.max_fee_bps,
            "rebate_bps": self.rebate_bps,
            "pq_attestation_root": self.pq_attestation_root,
            "redacted_member_commitment_root": self.redacted_member_commitment_root,
            "nullifier_set_root": self.nullifier_set_root,
            "scan_hint_root": self.scan_hint_root,
            "operator_set_root": self.operator_set_root,
            "privacy_score_bps": self.privacy_score_bps,
            "latency_target_ms": self.latency_target_ms,
            "privacy_boundary": PRIVACY_BOUNDARY,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(RINGCT_OUTPUT_COHORT_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCacheShard {
    pub shard_id: String,
    pub status: DecoyReputationShardStatus,
    pub epoch: u64,
    pub monero_height_start: u64,
    pub monero_height_end: u64,
    pub fee_floor_piconero: u64,
    pub fee_ceiling_piconero: u64,
    pub median_fee_piconero: u64,
    pub capacity_units: u64,
    pub reserved_units: u64,
    pub cohort_ids: BTreeSet<String>,
    pub cache_commitment_root: String,
    pub fee_quote_root: String,
    pub output_age_root: String,
    pub pq_attestation_root: String,
    pub invalidation_root: String,
    pub sponsor_pool_piconero: u64,
    pub sponsor_cover_bps: u64,
}

impl FeeCacheShard {
    pub fn new(shard_id: impl Into<String>, epoch: u64, monero_height_start: u64) -> Self {
        let shard_id = shard_id.into();
        Self {
            shard_id: shard_id.clone(),
            status: DecoyReputationShardStatus::Open,
            epoch,
            monero_height_start,
            monero_height_end: monero_height_start + DEFAULT_SHARD_SPAN_BLOCKS,
            fee_floor_piconero: 8_000,
            fee_ceiling_piconero: 32_000,
            median_fee_piconero: 16_000,
            capacity_units: 1_048_576,
            reserved_units: 0,
            cohort_ids: BTreeSet::new(),
            cache_commitment_root: root_from_parts(
                "fee-cache-shard-commitments",
                &[HashPart::Str(&shard_id), HashPart::U64(epoch)],
            ),
            fee_quote_root: empty_root("fee-quotes"),
            output_age_root: empty_root("shard-output_age"),
            pq_attestation_root: empty_root("shard-pq-attestations"),
            invalidation_root: empty_root("shard-invalidations"),
            sponsor_pool_piconero: 8_000_000,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
        }
    }

    pub fn reserve_units(&mut self, cohort_id: impl Into<String>, units: u64) -> Result<()> {
        ensure(self.status.active(), "reputation cache shard is not active")?;
        ensure(
            self.reserved_units.saturating_add(units) <= self.capacity_units,
            "reputation cache shard capacity exceeded",
        )?;
        self.reserved_units = self.reserved_units.saturating_add(units);
        self.cohort_ids.insert(cohort_id.into());
        if self.reserved_units.saturating_mul(MAX_BPS) / self.capacity_units >= 9_000 {
            self.status = DecoyReputationShardStatus::Saturated;
        } else if self.reserved_units > 0 {
            self.status = DecoyReputationShardStatus::Warm;
        }
        Ok(())
    }

    pub fn invalidate(&mut self, invalidation_root: impl Into<String>) {
        self.status = DecoyReputationShardStatus::Invalidated;
        self.invalidation_root = invalidation_root.into();
    }

    pub fn utilization_bps(&self) -> u64 {
        if self.capacity_units == 0 {
            0
        } else {
            self.reserved_units.saturating_mul(MAX_BPS) / self.capacity_units
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "shard_id": self.shard_id,
            "status": self.status,
            "epoch": self.epoch,
            "monero_height_start": self.monero_height_start,
            "monero_height_end": self.monero_height_end,
            "fee_floor_piconero_bucket": bucket(self.fee_floor_piconero, 1_000),
            "fee_ceiling_piconero_bucket": bucket(self.fee_ceiling_piconero, 1_000),
            "median_fee_piconero_bucket": bucket(self.median_fee_piconero, 1_000),
            "capacity_units_bucket": bucket(self.capacity_units, DEFAULT_PUBLIC_BUCKET_SIZE),
            "reserved_units_bucket": bucket(self.reserved_units, DEFAULT_PUBLIC_BUCKET_SIZE),
            "utilization_bps": self.utilization_bps(),
            "cohort_count": self.cohort_ids.len(),
            "cohort_root": root_from_strings("shard-cohorts", self.cohort_ids.iter()),
            "cache_commitment_root": self.cache_commitment_root,
            "fee_quote_root": self.fee_quote_root,
            "output_age_root": self.output_age_root,
            "pq_attestation_root": self.pq_attestation_root,
            "invalidation_root": self.invalidation_root,
            "sponsor_pool_piconero_bucket": bucket(self.sponsor_pool_piconero, 1_000),
            "sponsor_cover_bps": self.sponsor_cover_bps,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(DECOY_REPUTATION_SHARD_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RingctOutputAgeBucket {
    pub output_age_id: String,
    pub cohort_id: String,
    pub status: OutputAgeBucketStatus,
    pub monero_height_observed: u64,
    pub monero_height_expires: u64,
    pub output_age_floor_blocks: u64,
    pub output_age_ceiling_blocks: u64,
    pub member_count: u64,
    pub selectable_count: u64,
    pub spent_unknown_count: u64,
    pub ring_position_commitment_root: String,
    pub output_public_key_commitment_root: String,
    pub key_image_nullifier_root: String,
    pub output_age_proof_root: String,
    pub entropy_bits: u16,
}

impl RingctOutputAgeBucket {
    pub fn new(
        output_age_id: impl Into<String>,
        cohort_id: impl Into<String>,
        height: u64,
    ) -> Self {
        let output_age_id = output_age_id.into();
        let cohort_id = cohort_id.into();
        Self {
            output_age_id: output_age_id.clone(),
            cohort_id,
            status: OutputAgeBucketStatus::Fresh,
            monero_height_observed: height,
            monero_height_expires: height + DEFAULT_OUTPUT_AGE_BUCKET_BLOCKS,
            output_age_floor_blocks: 10,
            output_age_ceiling_blocks: DEFAULT_MAX_COHORT_AGE_BLOCKS,
            member_count: DEFAULT_TARGET_COHORT_OUTPUTS,
            selectable_count: DEFAULT_TARGET_COHORT_OUTPUTS - 512,
            spent_unknown_count: 512,
            ring_position_commitment_root: empty_root("ring-positions"),
            output_public_key_commitment_root: root_from_parts(
                "output-public-key-commitments",
                &[HashPart::Str(&output_age_id)],
            ),
            key_image_nullifier_root: empty_root("output_age-key-image-nullifiers"),
            output_age_proof_root: empty_root("output_age-proofs"),
            entropy_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
        }
    }

    pub fn stale_at(&self, height: u64) -> bool {
        height >= self.monero_height_expires || self.status == OutputAgeBucketStatus::Stale
    }

    pub fn selectable_bps(&self) -> u64 {
        if self.member_count == 0 {
            0
        } else {
            self.selectable_count.saturating_mul(MAX_BPS) / self.member_count
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "output_age_id": self.output_age_id,
            "cohort_id": self.cohort_id,
            "status": self.status,
            "monero_height_observed": self.monero_height_observed,
            "monero_height_expires": self.monero_height_expires,
            "output_age_floor_blocks": self.output_age_floor_blocks,
            "output_age_ceiling_blocks": self.output_age_ceiling_blocks,
            "member_count_bucket": bucket(self.member_count, DEFAULT_PUBLIC_BUCKET_SIZE),
            "selectable_count_bucket": bucket(self.selectable_count, DEFAULT_PUBLIC_BUCKET_SIZE),
            "spent_unknown_count_bucket": bucket(self.spent_unknown_count, DEFAULT_PUBLIC_BUCKET_SIZE),
            "selectable_bps": self.selectable_bps(),
            "ring_position_commitment_root": self.ring_position_commitment_root,
            "output_public_key_commitment_root": self.output_public_key_commitment_root,
            "key_image_nullifier_root": self.key_image_nullifier_root,
            "output_age_proof_root": self.output_age_proof_root,
            "entropy_bits": self.entropy_bits,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(OUTPUT_AGE_BUCKET_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqCacheAttestation {
    pub attestation_id: String,
    pub subject_id: String,
    pub operator_id: String,
    pub status: AttestationStatus,
    pub monero_height: u64,
    pub expires_at_height: u64,
    pub pq_scheme: String,
    pub pq_security_bits: u16,
    pub signature_root: String,
    pub transcript_root: String,
    pub cache_root: String,
    pub output_age_root: String,
    pub fee_quote_root: String,
    pub operator_weight_bps: u64,
}

impl PqCacheAttestation {
    pub fn new(
        attestation_id: impl Into<String>,
        subject_id: impl Into<String>,
        operator_id: impl Into<String>,
        height: u64,
    ) -> Self {
        let attestation_id = attestation_id.into();
        let subject_id = subject_id.into();
        Self {
            attestation_id: attestation_id.clone(),
            subject_id,
            operator_id: operator_id.into(),
            status: AttestationStatus::Accepted,
            monero_height: height,
            expires_at_height: height + DEFAULT_ATTESTATION_TTL_BLOCKS,
            pq_scheme: PQ_CACHE_ATTESTATION_SCHEME.to_string(),
            pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            signature_root: root_from_parts(
                "pq-cache-signature",
                &[HashPart::Str(&attestation_id)],
            ),
            transcript_root: empty_root("pq-cache-transcript"),
            cache_root: empty_root("pq-cache-subject"),
            output_age_root: empty_root("pq-cache-output_age"),
            fee_quote_root: empty_root("pq-cache-fee-quote"),
            operator_weight_bps: 3_400,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure(
            self.pq_security_bits >= config.min_pq_security_bits,
            "PQ cache attestation security bits below policy",
        )?;
        ensure(
            self.operator_weight_bps <= MAX_BPS,
            "operator attestation weight exceeds 100%",
        )?;
        ensure(
            !self.signature_root.is_empty(),
            "signature root cannot be empty",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "subject_id": self.subject_id,
            "operator_id": self.operator_id,
            "status": self.status,
            "monero_height": self.monero_height,
            "expires_at_height": self.expires_at_height,
            "pq_scheme": self.pq_scheme,
            "pq_security_bits": self.pq_security_bits,
            "signature_root": self.signature_root,
            "transcript_root": self.transcript_root,
            "cache_root": self.cache_root,
            "output_age_root": self.output_age_root,
            "fee_quote_root": self.fee_quote_root,
            "operator_weight_bps": self.operator_weight_bps,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(PQ_CACHE_ATTESTATION_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletScanHint {
    pub hint_id: String,
    pub cohort_id: String,
    pub shard_id: String,
    pub status: ScanHintStatus,
    pub monero_height: u64,
    pub expires_at_height: u64,
    pub view_tag_bucket_root: String,
    pub encrypted_hint_root: String,
    pub scan_lane_root: String,
    pub decoy_density_bps: u64,
    pub expected_scan_ms: u64,
    pub redaction_units: u64,
}

impl WalletScanHint {
    pub fn new(
        hint_id: impl Into<String>,
        cohort_id: impl Into<String>,
        shard_id: impl Into<String>,
        height: u64,
    ) -> Self {
        let hint_id = hint_id.into();
        let cohort_id = cohort_id.into();
        let shard_id = shard_id.into();
        Self {
            hint_id: hint_id.clone(),
            cohort_id,
            shard_id,
            status: ScanHintStatus::Published,
            monero_height: height,
            expires_at_height: height + DEFAULT_SCAN_HINT_TTL_BLOCKS,
            view_tag_bucket_root: root_from_parts("view-tag-buckets", &[HashPart::Str(&hint_id)]),
            encrypted_hint_root: empty_root("encrypted-wallet-scan-hints"),
            scan_lane_root: empty_root("scan-lanes"),
            decoy_density_bps: 9_700,
            expected_scan_ms: 11,
            redaction_units: 12,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure(
            self.redaction_units <= config.max_redaction_units_per_hint,
            "wallet scan hint exceeds privacy redaction budget",
        )?;
        ensure(
            self.decoy_density_bps >= 8_000,
            "wallet scan hint decoy density below threshold",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "cohort_id": self.cohort_id,
            "shard_id": self.shard_id,
            "status": self.status,
            "monero_height": self.monero_height,
            "expires_at_height": self.expires_at_height,
            "view_tag_bucket_root": self.view_tag_bucket_root,
            "encrypted_hint_root": self.encrypted_hint_root,
            "scan_lane_root": self.scan_lane_root,
            "decoy_density_bps": self.decoy_density_bps,
            "expected_scan_ms": self.expected_scan_ms,
            "redaction_units": self.redaction_units,
            "privacy_boundary": PRIVACY_BOUNDARY,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(WALLET_SCAN_HINT_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CacheInvalidation {
    pub invalidation_id: String,
    pub subject_id: String,
    pub shard_id: String,
    pub reason: InvalidationReason,
    pub monero_height: u64,
    pub expires_at_height: u64,
    pub affected_cohort_count: u64,
    pub affected_hint_count: u64,
    pub replacement_shard_id: Option<String>,
    pub evidence_root: String,
    pub operator_vote_root: String,
    pub status_root: String,
}

impl CacheInvalidation {
    pub fn new(
        invalidation_id: impl Into<String>,
        subject_id: impl Into<String>,
        shard_id: impl Into<String>,
        reason: InvalidationReason,
        height: u64,
    ) -> Self {
        let invalidation_id = invalidation_id.into();
        Self {
            invalidation_id: invalidation_id.clone(),
            subject_id: subject_id.into(),
            shard_id: shard_id.into(),
            reason,
            monero_height: height,
            expires_at_height: height + DEFAULT_INVALIDATION_TTL_BLOCKS,
            affected_cohort_count: 1,
            affected_hint_count: 3,
            replacement_shard_id: None,
            evidence_root: root_from_parts(
                "cache-invalidation-evidence",
                &[HashPart::Str(&invalidation_id)],
            ),
            operator_vote_root: empty_root("cache-invalidation-votes"),
            status_root: empty_root("cache-invalidation-status"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "invalidation_id": self.invalidation_id,
            "subject_id": self.subject_id,
            "shard_id": self.shard_id,
            "reason": self.reason.as_str(),
            "monero_height": self.monero_height,
            "expires_at_height": self.expires_at_height,
            "affected_cohort_count": self.affected_cohort_count,
            "affected_hint_count": self.affected_hint_count,
            "replacement_shard_id": self.replacement_shard_id,
            "evidence_root": self.evidence_root,
            "operator_vote_root": self.operator_vote_root,
            "status_root": self.status_root,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(CACHE_INVALIDATION_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub cohort_id: String,
    pub shard_id: String,
    pub status: RebateStatus,
    pub fee_asset_id: String,
    pub gross_fee_piconero: u64,
    pub rebate_piconero: u64,
    pub sponsor_cover_bps: u64,
    pub claim_window_start: u64,
    pub claim_window_end: u64,
    pub recipient_commitment_root: String,
    pub claim_nullifier_root: String,
    pub sponsor_receipt_root: String,
}

impl FeeRebate {
    pub fn new(
        rebate_id: impl Into<String>,
        cohort_id: impl Into<String>,
        shard_id: impl Into<String>,
        gross_fee_piconero: u64,
        height: u64,
    ) -> Self {
        let rebate_id = rebate_id.into();
        let rebate_piconero =
            gross_fee_piconero.saturating_mul(DEFAULT_TARGET_REBATE_BPS) / MAX_BPS;
        Self {
            rebate_id: rebate_id.clone(),
            cohort_id: cohort_id.into(),
            shard_id: shard_id.into(),
            status: RebateStatus::Queued,
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            gross_fee_piconero,
            rebate_piconero,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            claim_window_start: height,
            claim_window_end: height + DEFAULT_CACHE_TTL_BLOCKS,
            recipient_commitment_root: empty_root("rebate-recipient-commitments"),
            claim_nullifier_root: root_from_parts(
                "rebate-claim-nullifiers",
                &[HashPart::Str(&rebate_id)],
            ),
            sponsor_receipt_root: empty_root("rebate-sponsor-receipts"),
        }
    }

    pub fn claim(&mut self, sponsor_receipt_root: impl Into<String>) {
        self.status = RebateStatus::Claimed;
        self.sponsor_receipt_root = sponsor_receipt_root.into();
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "cohort_id": self.cohort_id,
            "shard_id": self.shard_id,
            "status": self.status,
            "fee_asset_id": self.fee_asset_id,
            "gross_fee_piconero_bucket": bucket(self.gross_fee_piconero, 1_000),
            "rebate_piconero_bucket": bucket(self.rebate_piconero, 1_000),
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "claim_window_start": self.claim_window_start,
            "claim_window_end": self.claim_window_end,
            "recipient_commitment_root": self.recipient_commitment_root,
            "claim_nullifier_root": self.claim_nullifier_root,
            "sponsor_receipt_root": self.sponsor_receipt_root,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(LOW_FEE_REBATE_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub scope: RedactionScope,
    pub subject_id: String,
    pub epoch: u64,
    pub max_units: u64,
    pub reserved_units: u64,
    pub consumed_units: u64,
    pub redacted_field_root: String,
    pub disclosure_policy_root: String,
}

impl PrivacyRedactionBudget {
    pub fn new(
        budget_id: impl Into<String>,
        scope: RedactionScope,
        subject_id: impl Into<String>,
        epoch: u64,
        max_units: u64,
    ) -> Self {
        let budget_id = budget_id.into();
        Self {
            budget_id: budget_id.clone(),
            scope,
            subject_id: subject_id.into(),
            epoch,
            max_units,
            reserved_units: 0,
            consumed_units: 0,
            redacted_field_root: root_from_parts("redacted-fields", &[HashPart::Str(&budget_id)]),
            disclosure_policy_root: empty_root("redaction-disclosure-policy"),
        }
    }

    pub fn reserve(&mut self, units: u64) -> Result<()> {
        ensure(
            self.reserved_units
                .saturating_add(self.consumed_units)
                .saturating_add(units)
                <= self.max_units,
            "privacy redaction budget exceeded",
        )?;
        self.reserved_units = self.reserved_units.saturating_add(units);
        Ok(())
    }

    pub fn consume(&mut self, units: u64) -> Result<()> {
        ensure(
            self.reserved_units >= units,
            "redaction units were not reserved",
        )?;
        self.reserved_units -= units;
        self.consumed_units = self.consumed_units.saturating_add(units);
        Ok(())
    }

    pub fn remaining_units(&self) -> u64 {
        self.max_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.consumed_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "scope": self.scope.as_str(),
            "subject_id": self.subject_id,
            "epoch": self.epoch,
            "max_units": self.max_units,
            "reserved_units": self.reserved_units,
            "consumed_units": self.consumed_units,
            "remaining_units": self.remaining_units(),
            "redacted_field_root": self.redacted_field_root,
            "disclosure_policy_root": self.disclosure_policy_root,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(PRIVACY_REDACTION_BUDGET_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub operator_id: String,
    pub role: OperatorRole,
    pub epoch: u64,
    pub weight_bps: u64,
    pub cohorts_attested: u64,
    pub shards_served: u64,
    pub hints_served: u64,
    pub median_latency_ms: u64,
    pub fee_sponsored_piconero: u64,
    pub slash_count: u64,
    pub availability_bps: u64,
    pub pq_key_root: String,
    pub performance_root: String,
}

impl OperatorSummary {
    pub fn new(operator_id: impl Into<String>, role: OperatorRole, epoch: u64) -> Self {
        let operator_id = operator_id.into();
        Self {
            operator_id: operator_id.clone(),
            role,
            epoch,
            weight_bps: 3_400,
            cohorts_attested: 1,
            shards_served: 1,
            hints_served: 3,
            median_latency_ms: 14,
            fee_sponsored_piconero: 40_000,
            slash_count: 0,
            availability_bps: 9_950,
            pq_key_root: root_from_parts("operator-pq-keys", &[HashPart::Str(&operator_id)]),
            performance_root: empty_root("operator-performance"),
        }
    }

    pub fn reliable(&self) -> bool {
        self.availability_bps >= 9_000 && self.slash_count == 0
    }

    pub fn public_record(&self) -> Value {
        json!({
            "operator_id": self.operator_id,
            "role": self.role,
            "epoch": self.epoch,
            "weight_bps": self.weight_bps,
            "cohorts_attested": self.cohorts_attested,
            "shards_served": self.shards_served,
            "hints_served": self.hints_served,
            "median_latency_ms": self.median_latency_ms,
            "fee_sponsored_piconero_bucket": bucket(self.fee_sponsored_piconero, 1_000),
            "slash_count": self.slash_count,
            "availability_bps": self.availability_bps,
            "pq_key_root": self.pq_key_root,
            "performance_root": self.performance_root,
            "reliable": self.reliable(),
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(OPERATOR_SUMMARY_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicRuntimeRecord {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub monero_height: u64,
    pub payload_root: String,
    pub state_root_after: String,
}

impl PublicRuntimeRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "subject_id": self.subject_id,
            "monero_height": self.monero_height,
            "payload_root": self.payload_root,
            "state_root_after": self.state_root_after,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(PUBLIC_RECORD_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub protocol_version: String,
    pub schema_version: u64,
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub cohorts: BTreeMap<String, RingctDecoyCohort>,
    pub shards: BTreeMap<String, FeeCacheShard>,
    pub output_age_buckets: BTreeMap<String, RingctOutputAgeBucket>,
    pub pq_attestations: BTreeMap<String, PqCacheAttestation>,
    pub scan_hints: BTreeMap<String, WalletScanHint>,
    pub invalidations: BTreeMap<String, CacheInvalidation>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub public_records: BTreeMap<String, PublicRuntimeRecord>,
}

impl State {
    pub fn new(config: Config, l2_height: u64, monero_height: u64, epoch: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            l2_height,
            monero_height,
            epoch,
            cohorts: BTreeMap::new(),
            shards: BTreeMap::new(),
            output_age_buckets: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            scan_hints: BTreeMap::new(),
            invalidations: BTreeMap::new(),
            rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            public_records: BTreeMap::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        devnet()
    }

    pub fn open_shard(&mut self, shard: FeeCacheShard) -> Result<String> {
        ensure(
            self.shards.len() < self.config.max_shards,
            "too many reputation cache shards",
        )?;
        ensure(
            !self.shards.contains_key(&shard.shard_id),
            "reputation cache shard already exists",
        )?;
        let shard_id = shard.shard_id.clone();
        self.shards.insert(shard_id.clone(), shard);
        self.counters.shards_opened = self.counters.shards_opened.saturating_add(1);
        self.emit_public_record(
            "reputation_cache_shard_opened",
            &shard_id,
            self.monero_height,
        )?;
        self.refresh_roots();
        Ok(shard_id)
    }

    pub fn open_cohort(&mut self, cohort: RingctDecoyCohort) -> Result<String> {
        cohort.validate(&self.config)?;
        ensure(
            self.cohorts.len() < self.config.max_cohorts,
            "too many RINGCT decoy cohorts",
        )?;
        ensure(
            self.shards.contains_key(&cohort.shard_id),
            "cohort shard does not exist",
        )?;
        ensure(
            !self.cohorts.contains_key(&cohort.cohort_id),
            "cohort already exists",
        )?;
        let cohort_id = cohort.cohort_id.clone();
        let shard_id = cohort.shard_id.clone();
        let reserve_units = cohort.decoy_count / u64::from(cohort.target_ring_size.max(1));
        self.shards
            .get_mut(&shard_id)
            .ok_or_else(|| "cohort shard does not exist".to_string())?
            .reserve_units(cohort_id.clone(), reserve_units)?;
        self.cohorts.insert(cohort_id.clone(), cohort);
        self.counters.cohorts_opened = self.counters.cohorts_opened.saturating_add(1);
        self.emit_public_record("ringct_decoy_cohort_opened", &cohort_id, self.monero_height)?;
        self.refresh_roots();
        Ok(cohort_id)
    }

    pub fn record_output_age(&mut self, output_age: RingctOutputAgeBucket) -> Result<String> {
        ensure(
            self.output_age_buckets.len() < self.config.max_output_age_buckets,
            "too many ringct output output age buckets",
        )?;
        ensure(
            self.cohorts.contains_key(&output_age.cohort_id),
            "output age cohort does not exist",
        )?;
        let output_age_id = output_age.output_age_id.clone();
        self.counters.output_age_buckets = self.counters.output_age_buckets.saturating_add(1);
        self.counters.output_age_members = self
            .counters
            .output_age_members
            .saturating_add(output_age.member_count);
        self.output_age_buckets
            .insert(output_age_id.clone(), output_age);
        self.emit_public_record(
            "ringct_output_output_age_recorded",
            &output_age_id,
            self.monero_height,
        )?;
        self.refresh_roots();
        Ok(output_age_id)
    }

    pub fn attest_cache(&mut self, attestation: PqCacheAttestation) -> Result<String> {
        attestation.validate(&self.config)?;
        ensure(
            self.pq_attestations.len() < self.config.max_attestations,
            "too many PQ cache attestations",
        )?;
        let attestation_id = attestation.attestation_id.clone();
        let subject_id = attestation.subject_id.clone();
        let subject_root = attestation.state_root();
        self.pq_attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.pq_attestations = self.counters.pq_attestations.saturating_add(1);
        if let Some(cohort) = self.cohorts.get_mut(&subject_id) {
            cohort.mark_attested(subject_root);
            self.counters.cohorts_attested = self.counters.cohorts_attested.saturating_add(1);
        }
        self.emit_public_record(
            "pq_cache_attestation_accepted",
            &attestation_id,
            self.monero_height,
        )?;
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn publish_scan_hint(&mut self, hint: WalletScanHint) -> Result<String> {
        hint.validate(&self.config)?;
        ensure(
            self.scan_hints.len() < self.config.max_scan_hints,
            "too many wallet scan hints",
        )?;
        ensure(
            self.cohorts.contains_key(&hint.cohort_id),
            "scan hint cohort does not exist",
        )?;
        let hint_id = hint.hint_id.clone();
        let cohort_id = hint.cohort_id.clone();
        let hint_root = hint.state_root();
        let redaction_units = hint.redaction_units;
        self.scan_hints.insert(hint_id.clone(), hint);
        if let Some(cohort) = self.cohorts.get_mut(&cohort_id) {
            cohort.scan_hint_root = hint_root;
        }
        self.counters.scan_hints = self.counters.scan_hints.saturating_add(1);
        self.counters.redaction_units_reserved = self
            .counters
            .redaction_units_reserved
            .saturating_add(redaction_units);
        self.emit_public_record("wallet_scan_hint_published", &hint_id, self.monero_height)?;
        self.refresh_roots();
        Ok(hint_id)
    }

    pub fn invalidate_cache(&mut self, invalidation: CacheInvalidation) -> Result<String> {
        ensure(
            self.invalidations.len() < self.config.max_invalidations,
            "too many cache invalidations",
        )?;
        let invalidation_id = invalidation.invalidation_id.clone();
        let shard_id = invalidation.shard_id.clone();
        let subject_id = invalidation.subject_id.clone();
        let invalidation_root = invalidation.state_root();
        self.invalidations
            .insert(invalidation_id.clone(), invalidation);
        if let Some(shard) = self.shards.get_mut(&shard_id) {
            shard.invalidate(invalidation_root.clone());
            self.counters.shards_invalidated = self.counters.shards_invalidated.saturating_add(1);
        }
        if let Some(cohort) = self.cohorts.get_mut(&subject_id) {
            cohort.quarantine(invalidation_root);
            self.counters.cohorts_quarantined = self.counters.cohorts_quarantined.saturating_add(1);
        }
        self.counters.invalidations = self.counters.invalidations.saturating_add(1);
        self.emit_public_record(
            "cache_invalidation_recorded",
            &invalidation_id,
            self.monero_height,
        )?;
        self.refresh_roots();
        Ok(invalidation_id)
    }

    pub fn queue_rebate(&mut self, rebate: FeeRebate) -> Result<String> {
        ensure(
            self.rebates.len() < self.config.max_rebates,
            "too many fee rebates",
        )?;
        ensure(
            rebate.sponsor_cover_bps >= self.config.sponsor_cover_bps,
            "fee rebate sponsor cover is below policy",
        )?;
        let rebate_id = rebate.rebate_id.clone();
        self.rebates.insert(rebate_id.clone(), rebate);
        self.counters.rebates_queued = self.counters.rebates_queued.saturating_add(1);
        self.emit_public_record("low_fee_rebate_queued", &rebate_id, self.monero_height)?;
        self.refresh_roots();
        Ok(rebate_id)
    }

    pub fn claim_rebate(
        &mut self,
        rebate_id: &str,
        sponsor_receipt_root: impl Into<String>,
    ) -> Result<String> {
        let rebate = self
            .rebates
            .get_mut(rebate_id)
            .ok_or_else(|| format!("unknown fee rebate: {rebate_id}"))?;
        rebate.claim(sponsor_receipt_root);
        self.counters.rebates_claimed = self.counters.rebates_claimed.saturating_add(1);
        self.emit_public_record("low_fee_rebate_claimed", rebate_id, self.monero_height)?;
        self.refresh_roots();
        Ok(rebate_id.to_string())
    }

    pub fn add_redaction_budget(&mut self, budget: PrivacyRedactionBudget) -> Result<String> {
        ensure(
            self.redaction_budgets.len() < self.config.max_redaction_budgets,
            "too many privacy redaction budgets",
        )?;
        let budget_id = budget.budget_id.clone();
        self.redaction_budgets.insert(budget_id.clone(), budget);
        self.counters.redaction_budgets = self.counters.redaction_budgets.saturating_add(1);
        self.emit_public_record(
            "privacy_redaction_budget_added",
            &budget_id,
            self.monero_height,
        )?;
        self.refresh_roots();
        Ok(budget_id)
    }

    pub fn reserve_redaction_budget(&mut self, budget_id: &str, units: u64) -> Result<String> {
        let budget = self
            .redaction_budgets
            .get_mut(budget_id)
            .ok_or_else(|| format!("unknown privacy redaction budget: {budget_id}"))?;
        budget.reserve(units)?;
        self.counters.redaction_units_reserved =
            self.counters.redaction_units_reserved.saturating_add(units);
        self.emit_public_record(
            "privacy_redaction_budget_reserved",
            budget_id,
            self.monero_height,
        )?;
        self.refresh_roots();
        Ok(budget_id.to_string())
    }

    pub fn add_operator_summary(&mut self, summary: OperatorSummary) -> Result<String> {
        ensure(
            self.operator_summaries.len() < self.config.max_operator_summaries,
            "too many operator summaries",
        )?;
        ensure(
            summary.weight_bps <= MAX_BPS,
            "operator weight exceeds 100%",
        )?;
        let operator_id = summary.operator_id.clone();
        self.operator_summaries.insert(operator_id.clone(), summary);
        self.counters.operator_summaries = self.counters.operator_summaries.saturating_add(1);
        self.emit_public_record("operator_summary_added", &operator_id, self.monero_height)?;
        self.refresh_roots();
        Ok(operator_id)
    }

    pub fn expire_stale_output_age(&mut self, height: u64) -> Result<Vec<String>> {
        let mut expired = Vec::new();
        for output_age in self.output_age_buckets.values_mut() {
            if output_age.stale_at(height) && output_age.status != OutputAgeBucketStatus::Stale {
                output_age.status = OutputAgeBucketStatus::Stale;
                expired.push(output_age.output_age_id.clone());
            }
        }
        if !expired.is_empty() {
            self.emit_public_record(
                "ringct_output_output_age_expired",
                &root_from_strings("expired-output_age", expired.iter()),
                height,
            )?;
            self.refresh_roots();
        }
        Ok(expired)
    }

    pub fn operator_quorum_bps(&self, subject_id: &str) -> u64 {
        self.pq_attestations
            .values()
            .filter(|attestation| {
                attestation.subject_id == subject_id && attestation.status.counts_for_quorum()
            })
            .map(|attestation| attestation.operator_weight_bps)
            .sum::<u64>()
            .min(MAX_BPS)
    }

    pub fn fee_pressure_bps(&self) -> u64 {
        if self.shards.is_empty() {
            return 0;
        }
        let total = self
            .shards
            .values()
            .map(FeeCacheShard::utilization_bps)
            .sum::<u64>();
        total / self.shards.len() as u64
    }

    pub fn privacy_health_bps(&self) -> u64 {
        if self.cohorts.is_empty() {
            return MAX_BPS;
        }
        let score = self
            .cohorts
            .values()
            .map(|cohort| {
                let status_penalty = if cohort.status == CohortStatus::Quarantined {
                    2_500
                } else if cohort.status == CohortStatus::Expired {
                    1_000
                } else {
                    0
                };
                cohort.privacy_score_bps.saturating_sub(status_penalty)
            })
            .sum::<u64>();
        score / self.cohorts.len() as u64
    }

    pub fn low_fee_health_bps(&self) -> u64 {
        MAX_BPS.saturating_sub(self.fee_pressure_bps() / 2)
    }

    pub fn speed_health_bps(&self) -> u64 {
        let hint_latency = self
            .scan_hints
            .values()
            .map(|hint| hint.expected_scan_ms)
            .max()
            .unwrap_or(0);
        if hint_latency <= 16 {
            MAX_BPS
        } else {
            MAX_BPS.saturating_sub((hint_latency - 16).saturating_mul(100))
        }
    }

    pub fn pq_health_bps(&self) -> u64 {
        if self.pq_attestations.is_empty() {
            return 0;
        }
        let accepted = self
            .pq_attestations
            .values()
            .filter(|attestation| attestation.status.counts_for_quorum())
            .count() as u64;
        accepted.saturating_mul(MAX_BPS) / self.pq_attestations.len() as u64
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.state_root(),
            counters_root: self.counters.state_root(),
            cohorts_root: map_root(
                "cohorts",
                self.cohorts
                    .iter()
                    .map(|(id, cohort)| (id.as_str(), cohort.state_root())),
            ),
            shards_root: map_root(
                "shards",
                self.shards
                    .iter()
                    .map(|(id, shard)| (id.as_str(), shard.state_root())),
            ),
            output_age_root: map_root(
                "output_age",
                self.output_age_buckets
                    .iter()
                    .map(|(id, output_age)| (id.as_str(), output_age.state_root())),
            ),
            attestations_root: map_root(
                "attestations",
                self.pq_attestations
                    .iter()
                    .map(|(id, attestation)| (id.as_str(), attestation.state_root())),
            ),
            scan_hints_root: map_root(
                "scan-hints",
                self.scan_hints
                    .iter()
                    .map(|(id, hint)| (id.as_str(), hint.state_root())),
            ),
            invalidations_root: map_root(
                "invalidations",
                self.invalidations
                    .iter()
                    .map(|(id, invalidation)| (id.as_str(), invalidation.state_root())),
            ),
            rebates_root: map_root(
                "rebates",
                self.rebates
                    .iter()
                    .map(|(id, rebate)| (id.as_str(), rebate.state_root())),
            ),
            redaction_budgets_root: map_root(
                "redaction-budgets",
                self.redaction_budgets
                    .iter()
                    .map(|(id, budget)| (id.as_str(), budget.state_root())),
            ),
            operator_summaries_root: map_root(
                "operator-summaries",
                self.operator_summaries
                    .iter()
                    .map(|(id, summary)| (id.as_str(), summary.state_root())),
            ),
            public_records_root: map_root(
                "public-records",
                self.public_records
                    .iter()
                    .map(|(id, record)| (id.as_str(), record.state_root())),
            ),
            state_root: self.state_root_without_cached_roots(),
        }
    }

    pub fn refresh_roots(&mut self) {
        self.roots = self.roots();
        self.roots.state_root = self.state_root_without_cached_roots();
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": HASH_SUITE,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "cohort_count": self.cohorts.len(),
            "shard_count": self.shards.len(),
            "output_age_bucket_count": self.output_age_buckets.len(),
            "pq_attestation_count": self.pq_attestations.len(),
            "scan_hint_count": self.scan_hints.len(),
            "invalidation_count": self.invalidations.len(),
            "rebate_count": self.rebates.len(),
            "redaction_budget_count": self.redaction_budgets.len(),
            "operator_summary_count": self.operator_summaries.len(),
            "public_record_count": self.public_records.len(),
            "privacy_health_bps": self.privacy_health_bps(),
            "low_fee_health_bps": self.low_fee_health_bps(),
            "speed_health_bps": self.speed_health_bps(),
            "pq_health_bps": self.pq_health_bps(),
            "privacy_boundary": PRIVACY_BOUNDARY,
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        self.state_root_without_cached_roots()
    }

    fn state_root_without_cached_roots(&self) -> String {
        root_from_parts(
            "state",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(self.schema_version),
                HashPart::U64(self.l2_height),
                HashPart::U64(self.monero_height),
                HashPart::U64(self.epoch),
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.counters.state_root()),
                HashPart::Str(&map_root(
                    "state-cohorts",
                    self.cohorts
                        .iter()
                        .map(|(id, cohort)| (id.as_str(), cohort.state_root())),
                )),
                HashPart::Str(&map_root(
                    "state-shards",
                    self.shards
                        .iter()
                        .map(|(id, shard)| (id.as_str(), shard.state_root())),
                )),
                HashPart::Str(&map_root(
                    "state-output_age",
                    self.output_age_buckets
                        .iter()
                        .map(|(id, output_age)| (id.as_str(), output_age.state_root())),
                )),
                HashPart::Str(&map_root(
                    "state-attestations",
                    self.pq_attestations
                        .iter()
                        .map(|(id, attestation)| (id.as_str(), attestation.state_root())),
                )),
                HashPart::Str(&map_root(
                    "state-scan-hints",
                    self.scan_hints
                        .iter()
                        .map(|(id, hint)| (id.as_str(), hint.state_root())),
                )),
                HashPart::Str(&map_root(
                    "state-invalidations",
                    self.invalidations
                        .iter()
                        .map(|(id, invalidation)| (id.as_str(), invalidation.state_root())),
                )),
                HashPart::Str(&map_root(
                    "state-rebates",
                    self.rebates
                        .iter()
                        .map(|(id, rebate)| (id.as_str(), rebate.state_root())),
                )),
                HashPart::Str(&map_root(
                    "state-redaction-budgets",
                    self.redaction_budgets
                        .iter()
                        .map(|(id, budget)| (id.as_str(), budget.state_root())),
                )),
                HashPart::Str(&map_root(
                    "state-operator-summaries",
                    self.operator_summaries
                        .iter()
                        .map(|(id, summary)| (id.as_str(), summary.state_root())),
                )),
                HashPart::Str(&map_root(
                    "state-public-records",
                    self.public_records
                        .iter()
                        .map(|(id, record)| (id.as_str(), record.state_root())),
                )),
            ],
        )
    }

    fn emit_public_record(
        &mut self,
        record_kind: &str,
        subject_id: &str,
        monero_height: u64,
    ) -> Result<String> {
        ensure(
            self.public_records.len() < self.config.max_public_records,
            "too many public runtime records",
        )?;
        let payload_root = root_from_parts(
            "public-record-payload",
            &[
                HashPart::Str(record_kind),
                HashPart::Str(subject_id),
                HashPart::U64(monero_height),
            ],
        );
        let record_id = scoped_id(record_kind, &payload_root);
        let record = PublicRuntimeRecord {
            record_id: record_id.clone(),
            record_kind: record_kind.to_string(),
            subject_id: subject_id.to_string(),
            monero_height,
            payload_root,
            state_root_after: self.state_root_without_cached_roots(),
        };
        self.public_records.insert(record_id.clone(), record);
        self.counters.public_records = self.counters.public_records.saturating_add(1);
        Ok(record_id)
    }
}

pub fn devnet() -> State {
    let mut state = State::new(
        Config::devnet(),
        DEVNET_L2_HEIGHT,
        DEVNET_MONERO_HEIGHT,
        DEVNET_EPOCH,
    )
    .expect("devnet RINGCT decoy reputation cache config is valid");

    let shard = FeeCacheShard::new(
        "ringct-fee-shard-devnet-0",
        DEVNET_EPOCH,
        DEVNET_MONERO_HEIGHT,
    );
    let shard_id = state.open_shard(shard).expect("devnet shard opens");

    let cohort = RingctDecoyCohort::new(
        "ringct-decoy-cohort-devnet-0",
        shard_id.clone(),
        DecoyCohortKind::BridgeWithdrawal,
        DEVNET_EPOCH,
        DEVNET_MONERO_HEIGHT,
    );
    let cohort_id = state.open_cohort(cohort).expect("devnet cohort opens");

    let output_age = RingctOutputAgeBucket::new(
        scoped_id("output_age", &cohort_id),
        cohort_id.clone(),
        DEVNET_MONERO_HEIGHT,
    );
    state
        .record_output_age(output_age)
        .expect("devnet output age buckets");

    let attestation = PqCacheAttestation::new(
        "pq-cache-attestation-devnet-0",
        cohort_id.clone(),
        "operator-devnet-watchtower-0",
        DEVNET_MONERO_HEIGHT,
    );
    state
        .attest_cache(attestation)
        .expect("devnet attestation records");

    let hint = WalletScanHint::new(
        "wallet-scan-hint-devnet-0",
        cohort_id.clone(),
        shard_id.clone(),
        DEVNET_MONERO_HEIGHT,
    );
    state
        .publish_scan_hint(hint)
        .expect("devnet scan hint publishes");

    let rebate = FeeRebate::new(
        "ringct-fee-rebate-devnet-0",
        cohort_id.clone(),
        shard_id.clone(),
        18_000,
        DEVNET_MONERO_HEIGHT,
    );
    state.queue_rebate(rebate).expect("devnet rebate queues");

    let mut budget = PrivacyRedactionBudget::new(
        "redaction-budget-devnet-0",
        RedactionScope::ScanHint,
        cohort_id.clone(),
        DEVNET_EPOCH,
        128,
    );
    budget.reserve(12).expect("devnet budget reserves");
    state
        .add_redaction_budget(budget)
        .expect("devnet redaction budget adds");

    let operator = OperatorSummary::new(
        "operator-devnet-watchtower-0",
        OperatorRole::Watchtower,
        DEVNET_EPOCH,
    );
    state
        .add_operator_summary(operator)
        .expect("devnet operator summary adds");

    state.refresh_roots();
    state
}

pub fn demo() -> State {
    devnet()
}

pub fn demo_record() -> Value {
    let mut state = devnet();
    let invalidation = CacheInvalidation::new(
        "cache-invalidation-demo-0",
        "ringct-decoy-cohort-devnet-0",
        "ringct-fee-shard-devnet-0",
        InvalidationReason::FeeSpike,
        DEVNET_MONERO_HEIGHT + 12,
    );
    state
        .invalidate_cache(invalidation)
        .expect("demo invalidation records");
    let _ = state.claim_rebate(
        "ringct-fee-rebate-devnet-0",
        root_from_parts("demo-sponsor-receipt", &[HashPart::Str("claimed")]),
    );
    json!({
        "runtime": "monero_l2_pq_private_ringct_decoy_reputation_cache_runtime",
        "protocol_version": PROTOCOL_VERSION,
        "priorities": {
            "monero_privacy": state.privacy_health_bps(),
            "low_fees": state.low_fee_health_bps(),
            "speed": state.speed_health_bps(),
            "quantum_resistance": state.pq_health_bps(),
        },
        "public_record": state.public_record(),
        "state_root": state.state_root(),
    })
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn monero_l2_pq_private_ringct_decoy_reputation_cache_runtime_public_record(
    state: &State,
) -> Value {
    state.public_record()
}

pub fn monero_l2_pq_private_ringct_decoy_reputation_cache_runtime_state_root(
    state: &State,
) -> String {
    state.state_root()
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn bucket(value: u64, bucket_size: u64) -> u64 {
    if bucket_size == 0 {
        value
    } else {
        (value / bucket_size) * bucket_size
    }
}

fn scoped_id(scope: &str, subject: &str) -> String {
    root_from_parts("scoped-id", &[HashPart::Str(scope), HashPart::Str(subject)])
}

fn empty_root(domain: &str) -> String {
    root_from_parts(domain, &[HashPart::Str("empty")])
}

fn root_from_record(domain: &str, record: &Value) -> String {
    root_from_parts(domain, &[HashPart::Json(record)])
}

fn root_from_parts(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts)
}

fn root_from_strings<'a>(domain: &str, values: impl Iterator<Item = &'a String>) -> String {
    let leaves = values
        .map(|value| root_from_parts(domain, &[HashPart::Str(value)]))
        .collect::<Vec<_>>();
    merkle_root(domain, leaves.iter().map(String::as_str))
}

fn map_root<'a>(domain: &str, entries: impl Iterator<Item = (&'a str, String)>) -> String {
    let leaves = entries
        .map(|(id, root)| root_from_parts(domain, &[HashPart::Str(id), HashPart::Str(&root)]))
        .collect::<Vec<_>>();
    merkle_root(domain, leaves.iter().map(String::as_str))
}
