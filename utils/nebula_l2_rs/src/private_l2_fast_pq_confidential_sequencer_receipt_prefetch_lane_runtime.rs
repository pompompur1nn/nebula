use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialSequencerReceiptPrefetchLaneRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_SEQUENCER_RECEIPT_PREFETCH_LANE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-fast-pq-confidential-sequencer-receipt-prefetch-lane-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_SEQUENCER_RECEIPT_PREFETCH_LANE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_SIGNATURE_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-confidential-sequencer-receipt-prefetch-v1";
pub const PQ_KEM_SUITE: &str = "ML-KEM-1024+hybrid-x25519-confidential-receipt-hints-v1";
pub const RECEIPT_HINT_SCHEME: &str = "private-l2-confidential-receipt-hint-root-v1";
pub const PREFETCH_LANE_SCHEME: &str = "private-l2-sequencer-prefetch-lane-root-v1";
pub const RECEIPT_WINDOW_SCHEME: &str = "private-l2-sequencer-receipt-window-root-v1";
pub const ATTESTATION_SCHEME: &str = "pq-sequencer-prefetch-attestation-root-v1";
pub const INVALIDATION_FENCE_SCHEME: &str = "private-l2-prefetch-invalidation-fence-root-v1";
pub const LOW_FEE_REBATE_SCHEME: &str = "private-l2-prefetch-low-fee-rebate-root-v1";
pub const PRIVACY_REDACTION_SCHEME: &str = "private-l2-prefetch-privacy-redaction-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str = "private-l2-prefetch-operator-summary-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 2_160_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MAX_LANES: usize = 4_096;
pub const DEFAULT_MAX_WINDOWS: usize = 262_144;
pub const DEFAULT_MAX_HINTS: usize = 8_388_608;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_FENCES: usize = 2_097_152;
pub const DEFAULT_MAX_REBATES: usize = 4_194_304;
pub const DEFAULT_MAX_REDACTIONS: usize = 4_194_304;
pub const DEFAULT_WINDOW_BLOCK_SPAN: u64 = 6;
pub const DEFAULT_PREFETCH_DEPTH: u64 = 48;
pub const DEFAULT_TARGET_LATENCY_MS: u64 = 220;
pub const DEFAULT_HARD_LATENCY_MS: u64 = 900;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 10;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 7;
pub const DEFAULT_BATCH_DISCOUNT_BPS: u64 = 6;
pub const DEFAULT_HINT_TTL_BLOCKS: u64 = 16;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_FENCE_TTL_BLOCKS: u64 = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneClass {
    Receipts,
    BridgeReceipts,
    DefiReceipts,
    PaymentReceipts,
    ContractReceipts,
    ProofReceipts,
    EmergencyReceipts,
    OperatorControl,
}

impl LaneClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Receipts => "receipts",
            Self::BridgeReceipts => "bridge_receipts",
            Self::DefiReceipts => "defi_receipts",
            Self::PaymentReceipts => "payment_receipts",
            Self::ContractReceipts => "contract_receipts",
            Self::ProofReceipts => "proof_receipts",
            Self::EmergencyReceipts => "emergency_receipts",
            Self::OperatorControl => "operator_control",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyReceipts => 10_000,
            Self::BridgeReceipts => 9_400,
            Self::DefiReceipts => 9_100,
            Self::PaymentReceipts => 8_800,
            Self::ContractReceipts => 8_500,
            Self::ProofReceipts => 8_200,
            Self::Receipts => 7_900,
            Self::OperatorControl => 7_500,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneMode {
    Fast,
    PrivacyFirst,
    LowFeeBatch,
    QuantumHardened,
    Emergency,
    Paused,
}

impl LaneMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::PrivacyFirst => "privacy_first",
            Self::LowFeeBatch => "low_fee_batch",
            Self::QuantumHardened => "quantum_hardened",
            Self::Emergency => "emergency",
            Self::Paused => "paused",
        }
    }

    pub fn accepts_hints(self) -> bool {
        !matches!(self, Self::Paused)
    }

    pub fn target_multiplier(self) -> u64 {
        match self {
            Self::Emergency => 5,
            Self::Fast => 4,
            Self::QuantumHardened => 3,
            Self::PrivacyFirst => 2,
            Self::LowFeeBatch => 1,
            Self::Paused => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptWindowStatus {
    Planned,
    Open,
    Prefetching,
    Sealed,
    Settled,
    Invalidated,
    Expired,
}

impl ReceiptWindowStatus {
    pub fn live(self) -> bool {
        matches!(self, Self::Open | Self::Prefetching | Self::Sealed)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Open => "open",
            Self::Prefetching => "prefetching",
            Self::Sealed => "sealed",
            Self::Settled => "settled",
            Self::Invalidated => "invalidated",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptHintStatus {
    Encrypted,
    Prefetched,
    Attested,
    Consumed,
    Rebated,
    Redacted,
    Invalidated,
    Expired,
}

impl ReceiptHintStatus {
    pub fn billable(self) -> bool {
        matches!(
            self,
            Self::Prefetched | Self::Attested | Self::Consumed | Self::Rebated
        )
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Encrypted | Self::Prefetched | Self::Attested)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Proposed,
    Verified,
    Aggregated,
    Challenged,
    Slashed,
    Expired,
}

impl AttestationStatus {
    pub fn accepted(self) -> bool {
        matches!(self, Self::Verified | Self::Aggregated)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LatencyBucketKind {
    Under50Ms,
    Under100Ms,
    Under250Ms,
    Under500Ms,
    Under1000Ms,
    Over1000Ms,
}

impl LatencyBucketKind {
    pub fn upper_bound_ms(self) -> u64 {
        match self {
            Self::Under50Ms => 50,
            Self::Under100Ms => 100,
            Self::Under250Ms => 250,
            Self::Under500Ms => 500,
            Self::Under1000Ms => 1_000,
            Self::Over1000Ms => u64::MAX,
        }
    }

    pub fn classify(latency_ms: u64) -> Self {
        if latency_ms <= 50 {
            Self::Under50Ms
        } else if latency_ms <= 100 {
            Self::Under100Ms
        } else if latency_ms <= 250 {
            Self::Under250Ms
        } else if latency_ms <= 500 {
            Self::Under500Ms
        } else if latency_ms <= 1_000 {
            Self::Under1000Ms
        } else {
            Self::Over1000Ms
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Under50Ms => "under_50_ms",
            Self::Under100Ms => "under_100_ms",
            Self::Under250Ms => "under_250_ms",
            Self::Under500Ms => "under_500_ms",
            Self::Under1000Ms => "under_1000_ms",
            Self::Over1000Ms => "over_1000_ms",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceReason {
    Reorg,
    DuplicateReceipt,
    SequencerRotation,
    PrivacyLeak,
    StaleHint,
    InvalidPqAttestation,
    OperatorPause,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionScope {
    Account,
    Amount,
    Route,
    ContractCalldata,
    SequencerIdentity,
    Timing,
    FullReceipt,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Quoted,
    Accrued,
    Claimed,
    Cancelled,
    Expired,
}

impl RebateStatus {
    pub fn payable(self) -> bool {
        matches!(self, Self::Accrued)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub network: String,
    pub fee_asset_id: String,
    pub max_lanes: usize,
    pub max_windows: usize,
    pub max_hints: usize,
    pub max_attestations: usize,
    pub max_fences: usize,
    pub max_rebates: usize,
    pub max_redactions: usize,
    pub window_block_span: u64,
    pub prefetch_depth: u64,
    pub target_latency_ms: u64,
    pub hard_latency_ms: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub batch_discount_bps: u64,
    pub hint_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub fence_ttl_blocks: u64,
    pub require_pq_attestation: bool,
    pub require_privacy_redaction: bool,
    pub deterministic_operator_order: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            max_lanes: DEFAULT_MAX_LANES,
            max_windows: DEFAULT_MAX_WINDOWS,
            max_hints: DEFAULT_MAX_HINTS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_fences: DEFAULT_MAX_FENCES,
            max_rebates: DEFAULT_MAX_REBATES,
            max_redactions: DEFAULT_MAX_REDACTIONS,
            window_block_span: DEFAULT_WINDOW_BLOCK_SPAN,
            prefetch_depth: DEFAULT_PREFETCH_DEPTH,
            target_latency_ms: DEFAULT_TARGET_LATENCY_MS,
            hard_latency_ms: DEFAULT_HARD_LATENCY_MS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            batch_discount_bps: DEFAULT_BATCH_DISCOUNT_BPS,
            hint_ttl_blocks: DEFAULT_HINT_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            fence_ttl_blocks: DEFAULT_FENCE_TTL_BLOCKS,
            require_pq_attestation: true,
            require_privacy_redaction: true,
            deterministic_operator_order: true,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> Result<()> {
        if self.max_lanes == 0 {
            return Err("max_lanes must be non-zero".to_string());
        }
        if self.window_block_span == 0 {
            return Err("window_block_span must be non-zero".to_string());
        }
        if self.prefetch_depth == 0 {
            return Err("prefetch_depth must be non-zero".to_string());
        }
        if self.target_latency_ms > self.hard_latency_ms {
            return Err("target latency cannot exceed hard latency".to_string());
        }
        if self.min_privacy_set_size > self.target_privacy_set_size {
            return Err("min privacy set cannot exceed target privacy set".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("min pq security bits must be at least 192".to_string());
        }
        if self.max_user_fee_bps > MAX_BPS
            || self.target_rebate_bps > MAX_BPS
            || self.batch_discount_bps > MAX_BPS
        {
            return Err("fee basis points exceed maximum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "network": self.network,
            "fee_asset_id": self.fee_asset_id,
            "max_lanes": self.max_lanes,
            "max_windows": self.max_windows,
            "max_hints": self.max_hints,
            "max_attestations": self.max_attestations,
            "max_fences": self.max_fences,
            "max_rebates": self.max_rebates,
            "max_redactions": self.max_redactions,
            "window_block_span": self.window_block_span,
            "prefetch_depth": self.prefetch_depth,
            "target_latency_ms": self.target_latency_ms,
            "hard_latency_ms": self.hard_latency_ms,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "batch_discount_bps": self.batch_discount_bps,
            "hint_ttl_blocks": self.hint_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "fence_ttl_blocks": self.fence_ttl_blocks,
            "require_pq_attestation": self.require_pq_attestation,
            "require_privacy_redaction": self.require_privacy_redaction,
            "deterministic_operator_order": self.deterministic_operator_order,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub lanes: u64,
    pub active_lanes: u64,
    pub windows: u64,
    pub live_windows: u64,
    pub encrypted_hints: u64,
    pub prefetched_hints: u64,
    pub consumed_hints: u64,
    pub pq_attestations: u64,
    pub accepted_attestations: u64,
    pub invalidation_fences: u64,
    pub low_fee_rebates: u64,
    pub payable_rebates: u64,
    pub privacy_redactions: u64,
    pub redacted_hints: u64,
    pub operator_summaries: u64,
    pub target_latency_hits: u64,
    pub hard_latency_misses: u64,
    pub total_prefetch_weight: u128,
    pub total_fee_charged: u128,
    pub total_rebate_amount: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "lanes": self.lanes,
            "active_lanes": self.active_lanes,
            "windows": self.windows,
            "live_windows": self.live_windows,
            "encrypted_hints": self.encrypted_hints,
            "prefetched_hints": self.prefetched_hints,
            "consumed_hints": self.consumed_hints,
            "pq_attestations": self.pq_attestations,
            "accepted_attestations": self.accepted_attestations,
            "invalidation_fences": self.invalidation_fences,
            "low_fee_rebates": self.low_fee_rebates,
            "payable_rebates": self.payable_rebates,
            "privacy_redactions": self.privacy_redactions,
            "redacted_hints": self.redacted_hints,
            "operator_summaries": self.operator_summaries,
            "target_latency_hits": self.target_latency_hits,
            "hard_latency_misses": self.hard_latency_misses,
            "total_prefetch_weight": self.total_prefetch_weight.to_string(),
            "total_fee_charged": self.total_fee_charged.to_string(),
            "total_rebate_amount": self.total_rebate_amount.to_string(),
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub lane_root: String,
    pub window_root: String,
    pub hint_root: String,
    pub attestation_root: String,
    pub latency_root: String,
    pub fence_root: String,
    pub rebate_root: String,
    pub redaction_root: String,
    pub operator_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "lane_root": self.lane_root,
            "window_root": self.window_root,
            "hint_root": self.hint_root,
            "attestation_root": self.attestation_root,
            "latency_root": self.latency_root,
            "fence_root": self.fence_root,
            "rebate_root": self.rebate_root,
            "redaction_root": self.redaction_root,
            "operator_root": self.operator_root,
            "nullifier_root": self.nullifier_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrefetchLane {
    pub lane_id: String,
    pub class: LaneClass,
    pub mode: LaneMode,
    pub operator_id: String,
    pub sequencer_committee_id: String,
    pub capacity_units: u64,
    pub reserved_units: u64,
    pub prefetch_depth: u64,
    pub target_latency_ms: u64,
    pub min_privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub rebate_bps: u64,
    pub pq_security_bits: u16,
    pub encrypted_policy_commitment: String,
    pub admission_root: String,
    pub created_height: u64,
    pub updated_height: u64,
}

impl PrefetchLane {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_id: impl Into<String>,
        class: LaneClass,
        mode: LaneMode,
        operator_id: impl Into<String>,
        sequencer_committee_id: impl Into<String>,
        capacity_units: u64,
        prefetch_depth: u64,
        target_latency_ms: u64,
        min_privacy_set_size: u64,
        max_fee_bps: u64,
        rebate_bps: u64,
        pq_security_bits: u16,
        encrypted_policy_commitment: impl Into<String>,
        admission_root: impl Into<String>,
        height: u64,
    ) -> Self {
        Self {
            lane_id: lane_id.into(),
            class,
            mode,
            operator_id: operator_id.into(),
            sequencer_committee_id: sequencer_committee_id.into(),
            capacity_units,
            reserved_units: 0,
            prefetch_depth,
            target_latency_ms,
            min_privacy_set_size,
            max_fee_bps,
            rebate_bps,
            pq_security_bits,
            encrypted_policy_commitment: encrypted_policy_commitment.into(),
            admission_root: admission_root.into(),
            created_height: height,
            updated_height: height,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.lane_id.is_empty() {
            return Err("lane id is empty".to_string());
        }
        if !self.mode.accepts_hints() {
            return Ok(());
        }
        if self.capacity_units == 0 {
            return Err(format!("lane {} has zero capacity", self.lane_id));
        }
        if self.reserved_units > self.capacity_units {
            return Err(format!("lane {} is over-reserved", self.lane_id));
        }
        if self.prefetch_depth > config.prefetch_depth.saturating_mul(4) {
            return Err(format!(
                "lane {} exceeds prefetch depth guard",
                self.lane_id
            ));
        }
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err(format!(
                "lane {} privacy set below config minimum",
                self.lane_id
            ));
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err(format!(
                "lane {} pq security below config minimum",
                self.lane_id
            ));
        }
        if self.max_fee_bps > config.max_user_fee_bps || self.rebate_bps > MAX_BPS {
            return Err(format!("lane {} fee policy exceeds limit", self.lane_id));
        }
        Ok(())
    }

    pub fn available_units(&self) -> u64 {
        self.capacity_units.saturating_sub(self.reserved_units)
    }

    pub fn reserve(&mut self, units: u64, height: u64) -> Result<()> {
        if !self.mode.accepts_hints() {
            return Err(format!("lane {} is paused", self.lane_id));
        }
        if units > self.available_units() {
            return Err(format!("lane {} capacity exhausted", self.lane_id));
        }
        self.reserved_units = self.reserved_units.saturating_add(units);
        self.updated_height = height;
        Ok(())
    }

    pub fn release(&mut self, units: u64, height: u64) {
        self.reserved_units = self.reserved_units.saturating_sub(units);
        self.updated_height = height;
    }

    pub fn priority_score(&self) -> u128 {
        let latency = self.target_latency_ms.max(1) as u128;
        let privacy = self.min_privacy_set_size as u128;
        let speed = self.class.priority_weight() as u128 * self.mode.target_multiplier() as u128;
        let fee_discount = MAX_BPS.saturating_sub(self.max_fee_bps) as u128;
        (speed * 1_000_000 + privacy + fee_discount * 1_000) / latency
    }

    pub fn root(&self) -> String {
        let record = self.public_record();
        domain_hash(PREFETCH_LANE_SCHEME, &[HashPart::Json(&record)], 32)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "class": self.class.as_str(),
            "mode": self.mode.as_str(),
            "operator_id": self.operator_id,
            "sequencer_committee_id": self.sequencer_committee_id,
            "capacity_units": self.capacity_units,
            "reserved_units": self.reserved_units,
            "available_units": self.available_units(),
            "prefetch_depth": self.prefetch_depth,
            "target_latency_ms": self.target_latency_ms,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "rebate_bps": self.rebate_bps,
            "pq_security_bits": self.pq_security_bits,
            "encrypted_policy_commitment": self.encrypted_policy_commitment,
            "admission_root": self.admission_root,
            "priority_score": self.priority_score().to_string(),
            "created_height": self.created_height,
            "updated_height": self.updated_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SequencerReceiptWindow {
    pub window_id: String,
    pub lane_id: String,
    pub status: ReceiptWindowStatus,
    pub start_height: u64,
    pub end_height: u64,
    pub receipt_commitment_root: String,
    pub hint_root: String,
    pub attestation_root: String,
    pub privacy_set_size: u64,
    pub reserved_units: u64,
    pub consumed_units: u64,
    pub target_latency_ms: u64,
    pub observed_p50_ms: u64,
    pub observed_p95_ms: u64,
    pub max_fee_bps: u64,
    pub sealed_by: Option<String>,
}

impl SequencerReceiptWindow {
    pub fn new(
        window_id: impl Into<String>,
        lane_id: impl Into<String>,
        start_height: u64,
        span: u64,
        target_latency_ms: u64,
        max_fee_bps: u64,
    ) -> Self {
        let end_height = start_height.saturating_add(span.saturating_sub(1));
        Self {
            window_id: window_id.into(),
            lane_id: lane_id.into(),
            status: ReceiptWindowStatus::Planned,
            start_height,
            end_height,
            receipt_commitment_root: "receipt-window-empty".to_string(),
            hint_root: "hint-window-empty".to_string(),
            attestation_root: "attestation-window-empty".to_string(),
            privacy_set_size: 0,
            reserved_units: 0,
            consumed_units: 0,
            target_latency_ms,
            observed_p50_ms: 0,
            observed_p95_ms: 0,
            max_fee_bps,
            sealed_by: None,
        }
    }

    pub fn contains_height(&self, height: u64) -> bool {
        self.start_height <= height && height <= self.end_height
    }

    pub fn open(&mut self) {
        if matches!(self.status, ReceiptWindowStatus::Planned) {
            self.status = ReceiptWindowStatus::Open;
        }
    }

    pub fn mark_prefetching(&mut self) {
        if matches!(self.status, ReceiptWindowStatus::Open) {
            self.status = ReceiptWindowStatus::Prefetching;
        }
    }

    pub fn seal(
        &mut self,
        receipt_commitment_root: impl Into<String>,
        hint_root: impl Into<String>,
        attestation_root: impl Into<String>,
        sealed_by: impl Into<String>,
    ) {
        self.receipt_commitment_root = receipt_commitment_root.into();
        self.hint_root = hint_root.into();
        self.attestation_root = attestation_root.into();
        self.sealed_by = Some(sealed_by.into());
        self.status = ReceiptWindowStatus::Sealed;
    }

    pub fn settle(&mut self) {
        if matches!(self.status, ReceiptWindowStatus::Sealed) {
            self.status = ReceiptWindowStatus::Settled;
        }
    }

    pub fn invalidate(&mut self) {
        self.status = ReceiptWindowStatus::Invalidated;
    }

    pub fn update_latency(&mut self, p50_ms: u64, p95_ms: u64) {
        self.observed_p50_ms = p50_ms;
        self.observed_p95_ms = p95_ms;
    }

    pub fn target_met(&self) -> bool {
        self.observed_p95_ms != 0 && self.observed_p95_ms <= self.target_latency_ms
    }

    pub fn root(&self) -> String {
        let record = self.public_record();
        domain_hash(RECEIPT_WINDOW_SCHEME, &[HashPart::Json(&record)], 32)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "start_height": self.start_height,
            "end_height": self.end_height,
            "receipt_commitment_root": self.receipt_commitment_root,
            "hint_root": self.hint_root,
            "attestation_root": self.attestation_root,
            "privacy_set_size": self.privacy_set_size,
            "reserved_units": self.reserved_units,
            "consumed_units": self.consumed_units,
            "target_latency_ms": self.target_latency_ms,
            "observed_p50_ms": self.observed_p50_ms,
            "observed_p95_ms": self.observed_p95_ms,
            "target_met": self.target_met(),
            "max_fee_bps": self.max_fee_bps,
            "sealed_by": self.sealed_by,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedReceiptHint {
    pub hint_id: String,
    pub lane_id: String,
    pub window_id: String,
    pub status: ReceiptHintStatus,
    pub receipt_nullifier: String,
    pub encrypted_hint_ciphertext: String,
    pub hint_commitment: String,
    pub receiver_view_tag: String,
    pub prefetch_weight: u64,
    pub privacy_set_size: u64,
    pub fee_limit: u128,
    pub fee_charged: u128,
    pub rebate_quote_id: Option<String>,
    pub created_height: u64,
    pub expires_height: u64,
    pub consumed_height: Option<u64>,
}

impl EncryptedReceiptHint {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        hint_id: impl Into<String>,
        lane_id: impl Into<String>,
        window_id: impl Into<String>,
        receipt_nullifier: impl Into<String>,
        encrypted_hint_ciphertext: impl Into<String>,
        hint_commitment: impl Into<String>,
        receiver_view_tag: impl Into<String>,
        prefetch_weight: u64,
        privacy_set_size: u64,
        fee_limit: u128,
        created_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        Self {
            hint_id: hint_id.into(),
            lane_id: lane_id.into(),
            window_id: window_id.into(),
            status: ReceiptHintStatus::Encrypted,
            receipt_nullifier: receipt_nullifier.into(),
            encrypted_hint_ciphertext: encrypted_hint_ciphertext.into(),
            hint_commitment: hint_commitment.into(),
            receiver_view_tag: receiver_view_tag.into(),
            prefetch_weight,
            privacy_set_size,
            fee_limit,
            fee_charged: 0,
            rebate_quote_id: None,
            created_height,
            expires_height: created_height.saturating_add(ttl_blocks),
            consumed_height: None,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.hint_id.is_empty() || self.lane_id.is_empty() || self.window_id.is_empty() {
            return Err("hint identifiers must be non-empty".to_string());
        }
        if self.encrypted_hint_ciphertext.is_empty() {
            return Err(format!("hint {} has empty ciphertext", self.hint_id));
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!("hint {} privacy set below minimum", self.hint_id));
        }
        if self.prefetch_weight == 0 {
            return Err(format!("hint {} has zero prefetch weight", self.hint_id));
        }
        if self.fee_charged > self.fee_limit {
            return Err(format!("hint {} exceeds fee limit", self.hint_id));
        }
        Ok(())
    }

    pub fn is_expired(&self, height: u64) -> bool {
        height > self.expires_height && self.status.live()
    }

    pub fn mark_prefetched(&mut self, fee_charged: u128) -> Result<()> {
        if fee_charged > self.fee_limit {
            return Err(format!("hint {} fee exceeds limit", self.hint_id));
        }
        self.fee_charged = fee_charged;
        self.status = ReceiptHintStatus::Prefetched;
        Ok(())
    }

    pub fn mark_attested(&mut self) {
        if matches!(self.status, ReceiptHintStatus::Prefetched) {
            self.status = ReceiptHintStatus::Attested;
        }
    }

    pub fn consume(&mut self, height: u64) {
        self.status = ReceiptHintStatus::Consumed;
        self.consumed_height = Some(height);
    }

    pub fn attach_rebate(&mut self, rebate_id: impl Into<String>) {
        self.rebate_quote_id = Some(rebate_id.into());
        if matches!(self.status, ReceiptHintStatus::Consumed) {
            self.status = ReceiptHintStatus::Rebated;
        }
    }

    pub fn redact(&mut self) {
        self.status = ReceiptHintStatus::Redacted;
        self.encrypted_hint_ciphertext = "redacted".to_string();
        self.receiver_view_tag = "redacted".to_string();
    }

    pub fn root(&self) -> String {
        let record = self.public_record();
        domain_hash(RECEIPT_HINT_SCHEME, &[HashPart::Json(&record)], 32)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "lane_id": self.lane_id,
            "window_id": self.window_id,
            "status": self.status,
            "receipt_nullifier": self.receipt_nullifier,
            "encrypted_hint_ciphertext": self.encrypted_hint_ciphertext,
            "hint_commitment": self.hint_commitment,
            "receiver_view_tag": self.receiver_view_tag,
            "prefetch_weight": self.prefetch_weight,
            "privacy_set_size": self.privacy_set_size,
            "fee_limit": self.fee_limit.to_string(),
            "fee_charged": self.fee_charged.to_string(),
            "rebate_quote_id": self.rebate_quote_id,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
            "consumed_height": self.consumed_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSequencerAttestation {
    pub attestation_id: String,
    pub lane_id: String,
    pub window_id: String,
    pub hint_ids: Vec<String>,
    pub sequencer_id: String,
    pub committee_id: String,
    pub status: AttestationStatus,
    pub pq_signature_scheme: String,
    pub pq_public_key_commitment: String,
    pub transcript_root: String,
    pub aggregate_signature: String,
    pub security_bits: u16,
    pub signed_height: u64,
    pub expires_height: u64,
}

impl PqSequencerAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        attestation_id: impl Into<String>,
        lane_id: impl Into<String>,
        window_id: impl Into<String>,
        hint_ids: Vec<String>,
        sequencer_id: impl Into<String>,
        committee_id: impl Into<String>,
        pq_public_key_commitment: impl Into<String>,
        transcript_root: impl Into<String>,
        aggregate_signature: impl Into<String>,
        security_bits: u16,
        signed_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        Self {
            attestation_id: attestation_id.into(),
            lane_id: lane_id.into(),
            window_id: window_id.into(),
            hint_ids,
            sequencer_id: sequencer_id.into(),
            committee_id: committee_id.into(),
            status: AttestationStatus::Proposed,
            pq_signature_scheme: PQ_SIGNATURE_SUITE.to_string(),
            pq_public_key_commitment: pq_public_key_commitment.into(),
            transcript_root: transcript_root.into(),
            aggregate_signature: aggregate_signature.into(),
            security_bits,
            signed_height,
            expires_height: signed_height.saturating_add(ttl_blocks),
        }
    }

    pub fn verify(&mut self, config: &Config) -> Result<()> {
        if self.security_bits < config.min_pq_security_bits {
            self.status = AttestationStatus::Challenged;
            return Err(format!(
                "attestation {} below pq security minimum",
                self.attestation_id
            ));
        }
        if self.hint_ids.is_empty() {
            self.status = AttestationStatus::Challenged;
            return Err(format!("attestation {} has no hints", self.attestation_id));
        }
        if self.aggregate_signature.is_empty() || self.transcript_root.is_empty() {
            self.status = AttestationStatus::Challenged;
            return Err(format!(
                "attestation {} missing signature data",
                self.attestation_id
            ));
        }
        self.status = AttestationStatus::Verified;
        Ok(())
    }

    pub fn aggregate(&mut self) {
        if matches!(self.status, AttestationStatus::Verified) {
            self.status = AttestationStatus::Aggregated;
        }
    }

    pub fn is_expired(&self, height: u64) -> bool {
        height > self.expires_height && !self.status.accepted()
    }

    pub fn root(&self) -> String {
        let record = self.public_record();
        domain_hash(ATTESTATION_SCHEME, &[HashPart::Json(&record)], 32)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "lane_id": self.lane_id,
            "window_id": self.window_id,
            "hint_ids": self.hint_ids,
            "hint_count": self.hint_ids.len(),
            "sequencer_id": self.sequencer_id,
            "committee_id": self.committee_id,
            "status": self.status,
            "pq_signature_scheme": self.pq_signature_scheme,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "transcript_root": self.transcript_root,
            "aggregate_signature": self.aggregate_signature,
            "security_bits": self.security_bits,
            "signed_height": self.signed_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct LatencySloBucket {
    pub lane_id: String,
    pub bucket: Option<LatencyBucketKind>,
    pub samples: u64,
    pub target_hits: u64,
    pub hard_misses: u64,
    pub total_latency_ms: u128,
    pub max_latency_ms: u64,
}

impl LatencySloBucket {
    pub fn new(lane_id: impl Into<String>, bucket: LatencyBucketKind) -> Self {
        Self {
            lane_id: lane_id.into(),
            bucket: Some(bucket),
            samples: 0,
            target_hits: 0,
            hard_misses: 0,
            total_latency_ms: 0,
            max_latency_ms: 0,
        }
    }

    pub fn observe(&mut self, latency_ms: u64, target_ms: u64, hard_ms: u64) {
        self.samples = self.samples.saturating_add(1);
        self.total_latency_ms = self.total_latency_ms.saturating_add(latency_ms as u128);
        self.max_latency_ms = self.max_latency_ms.max(latency_ms);
        if latency_ms <= target_ms {
            self.target_hits = self.target_hits.saturating_add(1);
        }
        if latency_ms > hard_ms {
            self.hard_misses = self.hard_misses.saturating_add(1);
        }
    }

    pub fn average_latency_ms(&self) -> u64 {
        if self.samples == 0 {
            0
        } else {
            (self.total_latency_ms / self.samples as u128) as u64
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "bucket": self.bucket.map(LatencyBucketKind::as_str),
            "samples": self.samples,
            "target_hits": self.target_hits,
            "hard_misses": self.hard_misses,
            "average_latency_ms": self.average_latency_ms(),
            "max_latency_ms": self.max_latency_ms,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvalidationFence {
    pub fence_id: String,
    pub lane_id: String,
    pub window_id: Option<String>,
    pub reason: FenceReason,
    pub receipt_nullifier_root: String,
    pub invalidated_hint_ids: Vec<String>,
    pub created_height: u64,
    pub expires_height: u64,
    pub operator_id: String,
}

impl InvalidationFence {
    pub fn new(
        fence_id: impl Into<String>,
        lane_id: impl Into<String>,
        window_id: Option<String>,
        reason: FenceReason,
        receipt_nullifier_root: impl Into<String>,
        invalidated_hint_ids: Vec<String>,
        height: u64,
        ttl_blocks: u64,
        operator_id: impl Into<String>,
    ) -> Self {
        Self {
            fence_id: fence_id.into(),
            lane_id: lane_id.into(),
            window_id,
            reason,
            receipt_nullifier_root: receipt_nullifier_root.into(),
            invalidated_hint_ids,
            created_height: height,
            expires_height: height.saturating_add(ttl_blocks),
            operator_id: operator_id.into(),
        }
    }

    pub fn covers_hint(&self, hint_id: &str) -> bool {
        self.invalidated_hint_ids.iter().any(|id| id == hint_id)
    }

    pub fn is_active(&self, height: u64) -> bool {
        height <= self.expires_height
    }

    pub fn root(&self) -> String {
        let record = self.public_record();
        domain_hash(INVALIDATION_FENCE_SCHEME, &[HashPart::Json(&record)], 32)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "lane_id": self.lane_id,
            "window_id": self.window_id,
            "reason": self.reason,
            "receipt_nullifier_root": self.receipt_nullifier_root,
            "invalidated_hint_ids": self.invalidated_hint_ids,
            "invalidated_hint_count": self.invalidated_hint_ids.len(),
            "created_height": self.created_height,
            "expires_height": self.expires_height,
            "operator_id": self.operator_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub hint_id: String,
    pub lane_id: String,
    pub account_commitment: String,
    pub status: RebateStatus,
    pub fee_asset_id: String,
    pub quoted_fee: u128,
    pub charged_fee: u128,
    pub rebate_amount: u128,
    pub rebate_bps: u64,
    pub privacy_set_size: u64,
    pub created_height: u64,
    pub claimed_height: Option<u64>,
}

impl LowFeeRebate {
    #[allow(clippy::too_many_arguments)]
    pub fn quote(
        rebate_id: impl Into<String>,
        hint_id: impl Into<String>,
        lane_id: impl Into<String>,
        account_commitment: impl Into<String>,
        fee_asset_id: impl Into<String>,
        quoted_fee: u128,
        charged_fee: u128,
        rebate_bps: u64,
        privacy_set_size: u64,
        created_height: u64,
    ) -> Self {
        let rebate_amount = charged_fee.saturating_mul(rebate_bps as u128) / MAX_BPS as u128;
        Self {
            rebate_id: rebate_id.into(),
            hint_id: hint_id.into(),
            lane_id: lane_id.into(),
            account_commitment: account_commitment.into(),
            status: RebateStatus::Quoted,
            fee_asset_id: fee_asset_id.into(),
            quoted_fee,
            charged_fee,
            rebate_amount,
            rebate_bps,
            privacy_set_size,
            created_height,
            claimed_height: None,
        }
    }

    pub fn accrue(&mut self) {
        if matches!(self.status, RebateStatus::Quoted) {
            self.status = RebateStatus::Accrued;
        }
    }

    pub fn claim(&mut self, height: u64) -> Result<u128> {
        if !self.status.payable() {
            return Err(format!("rebate {} is not payable", self.rebate_id));
        }
        self.status = RebateStatus::Claimed;
        self.claimed_height = Some(height);
        Ok(self.rebate_amount)
    }

    pub fn root(&self) -> String {
        let record = self.public_record();
        domain_hash(LOW_FEE_REBATE_SCHEME, &[HashPart::Json(&record)], 32)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "hint_id": self.hint_id,
            "lane_id": self.lane_id,
            "account_commitment": self.account_commitment,
            "status": self.status,
            "fee_asset_id": self.fee_asset_id,
            "quoted_fee": self.quoted_fee.to_string(),
            "charged_fee": self.charged_fee.to_string(),
            "rebate_amount": self.rebate_amount.to_string(),
            "rebate_bps": self.rebate_bps,
            "privacy_set_size": self.privacy_set_size,
            "created_height": self.created_height,
            "claimed_height": self.claimed_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedaction {
    pub redaction_id: String,
    pub hint_id: String,
    pub lane_id: String,
    pub scopes: BTreeSet<RedactionScope>,
    pub redacted_record_root: String,
    pub disclosure_policy_commitment: String,
    pub privacy_set_size: u64,
    pub created_height: u64,
}

impl PrivacyRedaction {
    pub fn new(
        redaction_id: impl Into<String>,
        hint_id: impl Into<String>,
        lane_id: impl Into<String>,
        scopes: BTreeSet<RedactionScope>,
        redacted_record_root: impl Into<String>,
        disclosure_policy_commitment: impl Into<String>,
        privacy_set_size: u64,
        created_height: u64,
    ) -> Self {
        Self {
            redaction_id: redaction_id.into(),
            hint_id: hint_id.into(),
            lane_id: lane_id.into(),
            scopes,
            redacted_record_root: redacted_record_root.into(),
            disclosure_policy_commitment: disclosure_policy_commitment.into(),
            privacy_set_size,
            created_height,
        }
    }

    pub fn covers_full_receipt(&self) -> bool {
        self.scopes.contains(&RedactionScope::FullReceipt)
    }

    pub fn root(&self) -> String {
        let record = self.public_record();
        domain_hash(PRIVACY_REDACTION_SCHEME, &[HashPart::Json(&record)], 32)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "redaction_id": self.redaction_id,
            "hint_id": self.hint_id,
            "lane_id": self.lane_id,
            "scopes": self.scopes,
            "redacted_record_root": self.redacted_record_root,
            "disclosure_policy_commitment": self.disclosure_policy_commitment,
            "privacy_set_size": self.privacy_set_size,
            "created_height": self.created_height,
            "covers_full_receipt": self.covers_full_receipt(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub operator_id: String,
    pub lane_ids: Vec<String>,
    pub windows_sealed: u64,
    pub hints_prefetched: u64,
    pub hints_consumed: u64,
    pub attestations_accepted: u64,
    pub fences_posted: u64,
    pub rebates_paid: u128,
    pub average_latency_ms: u64,
    pub hard_latency_misses: u64,
    pub privacy_set_floor: u64,
    pub last_height: u64,
}

impl OperatorSummary {
    pub fn new(operator_id: impl Into<String>, last_height: u64) -> Self {
        Self {
            operator_id: operator_id.into(),
            lane_ids: Vec::new(),
            windows_sealed: 0,
            hints_prefetched: 0,
            hints_consumed: 0,
            attestations_accepted: 0,
            fences_posted: 0,
            rebates_paid: 0,
            average_latency_ms: 0,
            hard_latency_misses: 0,
            privacy_set_floor: u64::MAX,
            last_height,
        }
    }

    pub fn attach_lane(&mut self, lane_id: impl Into<String>) {
        let lane_id = lane_id.into();
        if !self.lane_ids.iter().any(|id| id == &lane_id) {
            self.lane_ids.push(lane_id);
            self.lane_ids.sort();
        }
    }

    pub fn record_hint(&mut self, hint: &EncryptedReceiptHint) {
        if matches!(
            hint.status,
            ReceiptHintStatus::Prefetched | ReceiptHintStatus::Attested
        ) {
            self.hints_prefetched = self.hints_prefetched.saturating_add(1);
        }
        if matches!(
            hint.status,
            ReceiptHintStatus::Consumed | ReceiptHintStatus::Rebated
        ) {
            self.hints_consumed = self.hints_consumed.saturating_add(1);
        }
        self.privacy_set_floor = self.privacy_set_floor.min(hint.privacy_set_size);
    }

    pub fn record_latency(&mut self, bucket: &LatencySloBucket) {
        self.average_latency_ms = bucket.average_latency_ms();
        self.hard_latency_misses = self.hard_latency_misses.saturating_add(bucket.hard_misses);
    }

    pub fn public_record(&self) -> Value {
        json!({
            "operator_id": self.operator_id,
            "lane_ids": self.lane_ids,
            "windows_sealed": self.windows_sealed,
            "hints_prefetched": self.hints_prefetched,
            "hints_consumed": self.hints_consumed,
            "attestations_accepted": self.attestations_accepted,
            "fences_posted": self.fences_posted,
            "rebates_paid": self.rebates_paid.to_string(),
            "average_latency_ms": self.average_latency_ms,
            "hard_latency_misses": self.hard_latency_misses,
            "privacy_set_floor": if self.privacy_set_floor == u64::MAX { 0 } else { self.privacy_set_floor },
            "last_height": self.last_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub height: u64,
    pub config: Config,
    pub lanes: BTreeMap<String, PrefetchLane>,
    pub windows: BTreeMap<String, SequencerReceiptWindow>,
    pub encrypted_hints: BTreeMap<String, EncryptedReceiptHint>,
    pub pq_attestations: BTreeMap<String, PqSequencerAttestation>,
    pub latency_buckets: BTreeMap<String, LatencySloBucket>,
    pub invalidation_fences: BTreeMap<String, InvalidationFence>,
    pub low_fee_rebates: BTreeMap<String, LowFeeRebate>,
    pub privacy_redactions: BTreeMap<String, PrivacyRedaction>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub spent_receipt_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config, height: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            height,
            config,
            lanes: BTreeMap::new(),
            windows: BTreeMap::new(),
            encrypted_hints: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            latency_buckets: BTreeMap::new(),
            invalidation_fences: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            privacy_redactions: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            spent_receipt_nullifiers: BTreeSet::new(),
        })
    }

    pub fn devnet() -> Self {
        devnet()
    }

    pub fn demo() -> Self {
        demo()
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("protocol version mismatch".to_string());
        }
        self.config.validate()?;
        if self.lanes.len() > self.config.max_lanes {
            return Err("lane count exceeds configured maximum".to_string());
        }
        if self.windows.len() > self.config.max_windows {
            return Err("window count exceeds configured maximum".to_string());
        }
        if self.encrypted_hints.len() > self.config.max_hints {
            return Err("hint count exceeds configured maximum".to_string());
        }
        if self.pq_attestations.len() > self.config.max_attestations {
            return Err("attestation count exceeds configured maximum".to_string());
        }
        for lane in self.lanes.values() {
            lane.validate(&self.config)?;
        }
        for hint in self.encrypted_hints.values() {
            hint.validate(&self.config)?;
            if !self.lanes.contains_key(&hint.lane_id) {
                return Err(format!("hint {} references missing lane", hint.hint_id));
            }
            if !self.windows.contains_key(&hint.window_id) {
                return Err(format!("hint {} references missing window", hint.hint_id));
            }
        }
        Ok(())
    }

    pub fn register_lane(&mut self, lane: PrefetchLane) -> Result<()> {
        if self.lanes.len() >= self.config.max_lanes && !self.lanes.contains_key(&lane.lane_id) {
            return Err("max lane count reached".to_string());
        }
        lane.validate(&self.config)?;
        self.operator_summary_mut(&lane.operator_id)
            .attach_lane(lane.lane_id.clone());
        self.lanes.insert(lane.lane_id.clone(), lane);
        Ok(())
    }

    pub fn open_window(&mut self, mut window: SequencerReceiptWindow) -> Result<()> {
        if self.windows.len() >= self.config.max_windows
            && !self.windows.contains_key(&window.window_id)
        {
            return Err("max window count reached".to_string());
        }
        let lane = self
            .lanes
            .get(&window.lane_id)
            .ok_or_else(|| format!("missing lane {}", window.lane_id))?;
        window.target_latency_ms = lane.target_latency_ms;
        window.max_fee_bps = lane.max_fee_bps;
        window.open();
        self.windows.insert(window.window_id.clone(), window);
        Ok(())
    }

    pub fn submit_encrypted_hint(&mut self, hint: EncryptedReceiptHint) -> Result<()> {
        if self.encrypted_hints.len() >= self.config.max_hints
            && !self.encrypted_hints.contains_key(&hint.hint_id)
        {
            return Err("max encrypted hint count reached".to_string());
        }
        hint.validate(&self.config)?;
        if self
            .spent_receipt_nullifiers
            .contains(&hint.receipt_nullifier)
        {
            return Err(format!(
                "duplicate receipt nullifier {}",
                hint.receipt_nullifier
            ));
        }
        let lane = self
            .lanes
            .get_mut(&hint.lane_id)
            .ok_or_else(|| format!("missing lane {}", hint.lane_id))?;
        lane.reserve(hint.prefetch_weight, self.height)?;
        let window = self
            .windows
            .get_mut(&hint.window_id)
            .ok_or_else(|| format!("missing window {}", hint.window_id))?;
        window.mark_prefetching();
        window.reserved_units = window.reserved_units.saturating_add(hint.prefetch_weight);
        window.privacy_set_size = window.privacy_set_size.max(hint.privacy_set_size);
        self.spent_receipt_nullifiers
            .insert(hint.receipt_nullifier.clone());
        self.encrypted_hints.insert(hint.hint_id.clone(), hint);
        Ok(())
    }

    pub fn mark_hint_prefetched(&mut self, hint_id: &str, fee_charged: u128) -> Result<()> {
        let (lane_id, prefetch_weight, fee) = {
            let hint = self
                .encrypted_hints
                .get_mut(hint_id)
                .ok_or_else(|| format!("missing hint {hint_id}"))?;
            hint.mark_prefetched(fee_charged)?;
            (hint.lane_id.clone(), hint.prefetch_weight, hint.fee_charged)
        };
        if let Some(lane) = self.lanes.get_mut(&lane_id) {
            lane.release(prefetch_weight, self.height);
        }
        let operator_id = self
            .lanes
            .get(&lane_id)
            .map(|lane| lane.operator_id.clone())
            .unwrap_or_else(|| "unknown".to_string());
        if let Some(hint) = self.encrypted_hints.get(hint_id).cloned() {
            self.operator_summary_mut(&operator_id).record_hint(&hint);
        }
        if fee > 0 {
            self.accrue_rebate_for_hint(hint_id)?;
        }
        Ok(())
    }

    pub fn consume_hint(&mut self, hint_id: &str, latency_ms: u64) -> Result<()> {
        let (lane_id, window_id, operator_id) = {
            let hint = self
                .encrypted_hints
                .get_mut(hint_id)
                .ok_or_else(|| format!("missing hint {hint_id}"))?;
            hint.consume(self.height);
            let operator_id = self
                .lanes
                .get(&hint.lane_id)
                .map(|lane| lane.operator_id.clone())
                .unwrap_or_else(|| "unknown".to_string());
            (hint.lane_id.clone(), hint.window_id.clone(), operator_id)
        };
        let (target, hard) = self
            .lanes
            .get(&lane_id)
            .map(|lane| (lane.target_latency_ms, self.config.hard_latency_ms))
            .unwrap_or((self.config.target_latency_ms, self.config.hard_latency_ms));
        let bucket_key = latency_bucket_key(&lane_id, LatencyBucketKind::classify(latency_ms));
        let bucket = self.latency_buckets.entry(bucket_key).or_insert_with(|| {
            LatencySloBucket::new(&lane_id, LatencyBucketKind::classify(latency_ms))
        });
        bucket.observe(latency_ms, target, hard);
        if let Some(window) = self.windows.get_mut(&window_id) {
            window.consumed_units = window.consumed_units.saturating_add(1);
            window.update_latency(bucket.average_latency_ms(), bucket.max_latency_ms);
        }
        let bucket_snapshot = bucket.clone();
        if let Some(hint) = self.encrypted_hints.get(hint_id).cloned() {
            let summary = self.operator_summary_mut(&operator_id);
            summary.record_hint(&hint);
            summary.record_latency(&bucket_snapshot);
        }
        Ok(())
    }

    pub fn add_attestation(&mut self, mut attestation: PqSequencerAttestation) -> Result<()> {
        if self.pq_attestations.len() >= self.config.max_attestations
            && !self
                .pq_attestations
                .contains_key(&attestation.attestation_id)
        {
            return Err("max attestation count reached".to_string());
        }
        attestation.verify(&self.config)?;
        for hint_id in &attestation.hint_ids {
            if let Some(hint) = self.encrypted_hints.get_mut(hint_id) {
                hint.mark_attested();
            }
        }
        let operator_id = self
            .lanes
            .get(&attestation.lane_id)
            .map(|lane| lane.operator_id.clone())
            .unwrap_or_else(|| "unknown".to_string());
        self.operator_summary_mut(&operator_id)
            .attestations_accepted = self
            .operator_summaries
            .get(&operator_id)
            .map(|summary| summary.attestations_accepted.saturating_add(1))
            .unwrap_or(1);
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        Ok(())
    }

    pub fn post_invalidation_fence(&mut self, fence: InvalidationFence) -> Result<()> {
        if self.invalidation_fences.len() >= self.config.max_fences
            && !self.invalidation_fences.contains_key(&fence.fence_id)
        {
            return Err("max invalidation fence count reached".to_string());
        }
        for hint_id in &fence.invalidated_hint_ids {
            if let Some(hint) = self.encrypted_hints.get_mut(hint_id) {
                hint.status = ReceiptHintStatus::Invalidated;
            }
        }
        if let Some(window_id) = &fence.window_id {
            if let Some(window) = self.windows.get_mut(window_id) {
                window.invalidate();
            }
        }
        self.operator_summary_mut(&fence.operator_id).fences_posted = self
            .operator_summaries
            .get(&fence.operator_id)
            .map(|summary| summary.fences_posted.saturating_add(1))
            .unwrap_or(1);
        self.invalidation_fences
            .insert(fence.fence_id.clone(), fence);
        Ok(())
    }

    pub fn add_privacy_redaction(&mut self, redaction: PrivacyRedaction) -> Result<()> {
        if self.privacy_redactions.len() >= self.config.max_redactions
            && !self
                .privacy_redactions
                .contains_key(&redaction.redaction_id)
        {
            return Err("max privacy redaction count reached".to_string());
        }
        if redaction.privacy_set_size < self.config.min_privacy_set_size {
            return Err(format!(
                "redaction {} privacy set below minimum",
                redaction.redaction_id
            ));
        }
        if let Some(hint) = self.encrypted_hints.get_mut(&redaction.hint_id) {
            if redaction.covers_full_receipt() {
                hint.redact();
            }
        }
        self.privacy_redactions
            .insert(redaction.redaction_id.clone(), redaction);
        Ok(())
    }

    pub fn seal_window(&mut self, window_id: &str, sealed_by: impl Into<String>) -> Result<()> {
        let hint_values: Vec<Value> = self
            .encrypted_hints
            .values()
            .filter(|hint| hint.window_id == window_id)
            .map(EncryptedReceiptHint::public_record)
            .collect();
        let attestation_values: Vec<Value> = self
            .pq_attestations
            .values()
            .filter(|attestation| attestation.window_id == window_id)
            .map(PqSequencerAttestation::public_record)
            .collect();
        let window = self
            .windows
            .get_mut(window_id)
            .ok_or_else(|| format!("missing window {window_id}"))?;
        let hint_root = merkle_root("PREFETCH-WINDOW-HINTS", &hint_values);
        let attestation_root = merkle_root("PREFETCH-WINDOW-ATTESTATIONS", &attestation_values);
        let receipt_commitment_root = domain_hash(
            "PREFETCH-WINDOW-RECEIPTS",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(window_id),
                HashPart::Str(&hint_root),
                HashPart::Str(&attestation_root),
            ],
            32,
        );
        window.seal(
            receipt_commitment_root,
            hint_root,
            attestation_root,
            sealed_by,
        );
        let operator_id = window
            .sealed_by
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        self.operator_summary_mut(&operator_id).windows_sealed = self
            .operator_summaries
            .get(&operator_id)
            .map(|summary| summary.windows_sealed.saturating_add(1))
            .unwrap_or(1);
        Ok(())
    }

    pub fn settle_window(&mut self, window_id: &str) -> Result<()> {
        let window = self
            .windows
            .get_mut(window_id)
            .ok_or_else(|| format!("missing window {window_id}"))?;
        window.settle();
        Ok(())
    }

    pub fn expire_stale(&mut self, height: u64) {
        self.height = height;
        for hint in self.encrypted_hints.values_mut() {
            if hint.is_expired(height) {
                hint.status = ReceiptHintStatus::Expired;
            }
        }
        for attestation in self.pq_attestations.values_mut() {
            if attestation.is_expired(height) {
                attestation.status = AttestationStatus::Expired;
            }
        }
        for window in self.windows.values_mut() {
            if window.status.live() && height > window.end_height.saturating_add(1) {
                window.status = ReceiptWindowStatus::Expired;
            }
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            lanes: self.lanes.len() as u64,
            active_lanes: self
                .lanes
                .values()
                .filter(|lane| lane.mode.accepts_hints())
                .count() as u64,
            windows: self.windows.len() as u64,
            live_windows: self
                .windows
                .values()
                .filter(|window| window.status.live())
                .count() as u64,
            encrypted_hints: self.encrypted_hints.len() as u64,
            prefetched_hints: self
                .encrypted_hints
                .values()
                .filter(|hint| {
                    matches!(
                        hint.status,
                        ReceiptHintStatus::Prefetched | ReceiptHintStatus::Attested
                    )
                })
                .count() as u64,
            consumed_hints: self
                .encrypted_hints
                .values()
                .filter(|hint| {
                    matches!(
                        hint.status,
                        ReceiptHintStatus::Consumed | ReceiptHintStatus::Rebated
                    )
                })
                .count() as u64,
            pq_attestations: self.pq_attestations.len() as u64,
            accepted_attestations: self
                .pq_attestations
                .values()
                .filter(|attestation| attestation.status.accepted())
                .count() as u64,
            invalidation_fences: self.invalidation_fences.len() as u64,
            low_fee_rebates: self.low_fee_rebates.len() as u64,
            payable_rebates: self
                .low_fee_rebates
                .values()
                .filter(|rebate| rebate.status.payable())
                .count() as u64,
            privacy_redactions: self.privacy_redactions.len() as u64,
            redacted_hints: self
                .encrypted_hints
                .values()
                .filter(|hint| matches!(hint.status, ReceiptHintStatus::Redacted))
                .count() as u64,
            operator_summaries: self.operator_summaries.len() as u64,
            target_latency_hits: self
                .latency_buckets
                .values()
                .map(|bucket| bucket.target_hits)
                .sum(),
            hard_latency_misses: self
                .latency_buckets
                .values()
                .map(|bucket| bucket.hard_misses)
                .sum(),
            total_prefetch_weight: self
                .encrypted_hints
                .values()
                .map(|hint| hint.prefetch_weight as u128)
                .sum(),
            total_fee_charged: self
                .encrypted_hints
                .values()
                .map(|hint| hint.fee_charged)
                .sum(),
            total_rebate_amount: self
                .low_fee_rebates
                .values()
                .map(|rebate| rebate.rebate_amount)
                .sum(),
        }
    }

    pub fn roots(&self) -> Roots {
        let config_record = self.config.public_record();
        let config_root = domain_hash(
            "PREFETCH-CONFIG",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&config_record),
            ],
            32,
        );
        let lane_root = merkle_root(
            "PREFETCH-LANES",
            &self
                .lanes
                .values()
                .map(PrefetchLane::public_record)
                .collect::<Vec<_>>(),
        );
        let window_root = merkle_root(
            "PREFETCH-WINDOWS",
            &self
                .windows
                .values()
                .map(SequencerReceiptWindow::public_record)
                .collect::<Vec<_>>(),
        );
        let hint_root = merkle_root(
            "PREFETCH-HINTS",
            &self
                .encrypted_hints
                .values()
                .map(EncryptedReceiptHint::public_record)
                .collect::<Vec<_>>(),
        );
        let attestation_root = merkle_root(
            "PREFETCH-ATTESTATIONS",
            &self
                .pq_attestations
                .values()
                .map(PqSequencerAttestation::public_record)
                .collect::<Vec<_>>(),
        );
        let latency_root = merkle_root(
            "PREFETCH-LATENCY",
            &self
                .latency_buckets
                .values()
                .map(LatencySloBucket::public_record)
                .collect::<Vec<_>>(),
        );
        let fence_root = merkle_root(
            "PREFETCH-FENCES",
            &self
                .invalidation_fences
                .values()
                .map(InvalidationFence::public_record)
                .collect::<Vec<_>>(),
        );
        let rebate_root = merkle_root(
            "PREFETCH-REBATES",
            &self
                .low_fee_rebates
                .values()
                .map(LowFeeRebate::public_record)
                .collect::<Vec<_>>(),
        );
        let redaction_root = merkle_root(
            "PREFETCH-REDACTIONS",
            &self
                .privacy_redactions
                .values()
                .map(PrivacyRedaction::public_record)
                .collect::<Vec<_>>(),
        );
        let operator_root = merkle_root(
            "PREFETCH-OPERATORS",
            &self
                .operator_summaries
                .values()
                .map(OperatorSummary::public_record)
                .collect::<Vec<_>>(),
        );
        let nullifier_root = merkle_root(
            "PREFETCH-SPENT-NULLIFIERS",
            &self
                .spent_receipt_nullifiers
                .iter()
                .map(|nullifier| json!(nullifier))
                .collect::<Vec<_>>(),
        );
        let state_root = domain_hash(
            "PREFETCH-STATE",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config_root),
                HashPart::Str(&lane_root),
                HashPart::Str(&window_root),
                HashPart::Str(&hint_root),
                HashPart::Str(&attestation_root),
                HashPart::Str(&latency_root),
                HashPart::Str(&fence_root),
                HashPart::Str(&rebate_root),
                HashPart::Str(&redaction_root),
                HashPart::Str(&operator_root),
                HashPart::Str(&nullifier_root),
            ],
            32,
        );
        Roots {
            config_root,
            lane_root,
            window_root,
            hint_root,
            attestation_root,
            latency_root,
            fence_root,
            rebate_root,
            redaction_root,
            operator_root,
            nullifier_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "height": self.height,
            "hash_suite": HASH_SUITE,
            "pq_signature_suite": PQ_SIGNATURE_SUITE,
            "pq_kem_suite": PQ_KEM_SUITE,
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "roots": self.roots().public_record(),
            "lanes": self.lanes.values().map(PrefetchLane::public_record).collect::<Vec<_>>(),
            "windows": self.windows.values().map(SequencerReceiptWindow::public_record).collect::<Vec<_>>(),
            "encrypted_hints": self.encrypted_hints.values().map(EncryptedReceiptHint::public_record).collect::<Vec<_>>(),
            "pq_attestations": self.pq_attestations.values().map(PqSequencerAttestation::public_record).collect::<Vec<_>>(),
            "latency_buckets": self.latency_buckets.values().map(LatencySloBucket::public_record).collect::<Vec<_>>(),
            "invalidation_fences": self.invalidation_fences.values().map(InvalidationFence::public_record).collect::<Vec<_>>(),
            "low_fee_rebates": self.low_fee_rebates.values().map(LowFeeRebate::public_record).collect::<Vec<_>>(),
            "privacy_redactions": self.privacy_redactions.values().map(PrivacyRedaction::public_record).collect::<Vec<_>>(),
            "operator_summaries": self.operator_summaries.values().map(OperatorSummary::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn operator_summary_mut(&mut self, operator_id: &str) -> &mut OperatorSummary {
        self.operator_summaries
            .entry(operator_id.to_string())
            .or_insert_with(|| OperatorSummary::new(operator_id, self.height))
    }

    fn accrue_rebate_for_hint(&mut self, hint_id: &str) -> Result<()> {
        if self.low_fee_rebates.len() >= self.config.max_rebates {
            return Err("max low fee rebate count reached".to_string());
        }
        let hint = self
            .encrypted_hints
            .get(hint_id)
            .ok_or_else(|| format!("missing hint {hint_id}"))?
            .clone();
        let lane = self
            .lanes
            .get(&hint.lane_id)
            .ok_or_else(|| format!("missing lane {}", hint.lane_id))?;
        let rebate_id = deterministic_id("rebate", &[&hint.hint_id, &hint.lane_id]);
        let mut rebate = LowFeeRebate::quote(
            &rebate_id,
            &hint.hint_id,
            &hint.lane_id,
            format!("acct-{}", hint.receiver_view_tag),
            self.config.fee_asset_id.clone(),
            hint.fee_limit,
            hint.fee_charged,
            lane.rebate_bps,
            hint.privacy_set_size,
            self.height,
        );
        rebate.accrue();
        if let Some(hint) = self.encrypted_hints.get_mut(hint_id) {
            hint.attach_rebate(rebate_id.clone());
        }
        let operator_id = lane.operator_id.clone();
        self.operator_summary_mut(&operator_id).rebates_paid = self
            .operator_summaries
            .get(&operator_id)
            .map(|summary| summary.rebates_paid.saturating_add(rebate.rebate_amount))
            .unwrap_or(rebate.rebate_amount);
        self.low_fee_rebates.insert(rebate_id, rebate);
        Ok(())
    }
}

pub fn devnet() -> State {
    let mut state = State::new(Config::devnet(), DEVNET_HEIGHT).expect("devnet config is valid");
    let fast_lane = PrefetchLane::new(
        "lane-fast-receipts",
        LaneClass::PaymentReceipts,
        LaneMode::Fast,
        "operator-alpha",
        "committee-pq-alpha",
        100_000,
        DEFAULT_PREFETCH_DEPTH,
        120,
        DEFAULT_TARGET_PRIVACY_SET_SIZE,
        8,
        7,
        DEFAULT_MIN_PQ_SECURITY_BITS,
        "enc-policy-alpha",
        "admission-root-alpha",
        DEVNET_HEIGHT,
    );
    let bridge_lane = PrefetchLane::new(
        "lane-bridge-receipts",
        LaneClass::BridgeReceipts,
        LaneMode::QuantumHardened,
        "operator-beta",
        "committee-pq-beta",
        80_000,
        DEFAULT_PREFETCH_DEPTH / 2,
        180,
        DEFAULT_TARGET_PRIVACY_SET_SIZE.saturating_mul(2),
        9,
        8,
        DEFAULT_MIN_PQ_SECURITY_BITS,
        "enc-policy-beta",
        "admission-root-beta",
        DEVNET_HEIGHT,
    );
    state.register_lane(fast_lane).expect("devnet lane");
    state.register_lane(bridge_lane).expect("devnet lane");
    let window_a = SequencerReceiptWindow::new(
        "window-fast-2160000",
        "lane-fast-receipts",
        DEVNET_HEIGHT,
        DEFAULT_WINDOW_BLOCK_SPAN,
        DEFAULT_TARGET_LATENCY_MS,
        DEFAULT_MAX_USER_FEE_BPS,
    );
    let window_b = SequencerReceiptWindow::new(
        "window-bridge-2160000",
        "lane-bridge-receipts",
        DEVNET_HEIGHT,
        DEFAULT_WINDOW_BLOCK_SPAN,
        DEFAULT_TARGET_LATENCY_MS,
        DEFAULT_MAX_USER_FEE_BPS,
    );
    state.open_window(window_a).expect("devnet window");
    state.open_window(window_b).expect("devnet window");
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    let hint_a = EncryptedReceiptHint::new(
        "hint-fast-a",
        "lane-fast-receipts",
        "window-fast-2160000",
        "nullifier-fast-a",
        "mlkem1024:ciphertext-fast-a",
        "commitment-fast-a",
        "viewtag-fast-a",
        8,
        DEFAULT_TARGET_PRIVACY_SET_SIZE,
        1_000,
        DEVNET_HEIGHT,
        DEFAULT_HINT_TTL_BLOCKS,
    );
    let hint_b = EncryptedReceiptHint::new(
        "hint-bridge-a",
        "lane-bridge-receipts",
        "window-bridge-2160000",
        "nullifier-bridge-a",
        "mlkem1024:ciphertext-bridge-a",
        "commitment-bridge-a",
        "viewtag-bridge-a",
        12,
        DEFAULT_TARGET_PRIVACY_SET_SIZE.saturating_mul(2),
        1_800,
        DEVNET_HEIGHT,
        DEFAULT_HINT_TTL_BLOCKS,
    );
    state.submit_encrypted_hint(hint_a).expect("demo hint");
    state.submit_encrypted_hint(hint_b).expect("demo hint");
    state
        .mark_hint_prefetched("hint-fast-a", 700)
        .expect("demo prefetch");
    state
        .mark_hint_prefetched("hint-bridge-a", 1_200)
        .expect("demo prefetch");
    state.consume_hint("hint-fast-a", 96).expect("demo consume");
    state
        .consume_hint("hint-bridge-a", 164)
        .expect("demo consume");
    let attestation = PqSequencerAttestation::new(
        "attestation-fast-a",
        "lane-fast-receipts",
        "window-fast-2160000",
        vec!["hint-fast-a".to_string()],
        "sequencer-alpha-0",
        "committee-pq-alpha",
        "pq-pubkey-commit-alpha",
        "transcript-root-fast-a",
        "ml-dsa-87+slh-dsa-signature-fast-a",
        DEFAULT_MIN_PQ_SECURITY_BITS,
        DEVNET_HEIGHT,
        DEFAULT_ATTESTATION_TTL_BLOCKS,
    );
    state
        .add_attestation(attestation)
        .expect("demo attestation");
    let mut scopes = BTreeSet::new();
    scopes.insert(RedactionScope::Account);
    scopes.insert(RedactionScope::Amount);
    scopes.insert(RedactionScope::Timing);
    let redaction = PrivacyRedaction::new(
        "redaction-fast-a",
        "hint-fast-a",
        "lane-fast-receipts",
        scopes,
        "redacted-root-fast-a",
        "policy-commit-fast-a",
        DEFAULT_TARGET_PRIVACY_SET_SIZE,
        DEVNET_HEIGHT,
    );
    state
        .add_privacy_redaction(redaction)
        .expect("demo redaction");
    state
        .seal_window("window-fast-2160000", "operator-alpha")
        .expect("demo seal");
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn latency_bucket_key(lane_id: &str, bucket: LatencyBucketKind) -> String {
    format!("{}:{}", lane_id, bucket.as_str())
}

fn deterministic_id(prefix: &str, parts: &[&str]) -> String {
    let mut hash_parts = Vec::with_capacity(parts.len() + 2);
    hash_parts.push(HashPart::Str(PROTOCOL_VERSION));
    hash_parts.push(HashPart::Str(prefix));
    for part in parts {
        hash_parts.push(HashPart::Str(part));
    }
    format!("{}-{}", prefix, domain_hash("PREFETCH-ID", &hash_parts, 16))
}
