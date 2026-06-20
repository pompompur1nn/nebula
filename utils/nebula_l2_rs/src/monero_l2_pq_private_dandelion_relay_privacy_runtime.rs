use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateDandelionRelayPrivacyRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_DANDELION_RELAY_PRIVACY_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-dandelion-relay-privacy-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_DANDELION_RELAY_PRIVACY_RUNTIME_PROTOCOL_VERSION;
pub const MODULE_PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_DANDELION_RELAY_PRIVACY_RUNTIME_PROTOCOL_VERSION;
pub const MONERO_L2_PQ_PRIVATE_DANDELION_RELAY_PRIVACY_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const MONERO_L2_PQ_PRIVATE_DANDELION_RELAY_PRIVACY_RUNTIME_MONERO_NETWORK: &str =
    "monero-devnet";
pub const MONERO_L2_PQ_PRIVATE_DANDELION_RELAY_PRIVACY_RUNTIME_L2_NETWORK: &str = "nebula-devnet";
pub const MONERO_L2_PQ_PRIVATE_DANDELION_RELAY_PRIVACY_RUNTIME_HASH_SUITE: &str =
    "deterministic-fnv1a128-canonical-json-devnet";
pub const MONERO_L2_PQ_PRIVATE_DANDELION_RELAY_PRIVACY_RUNTIME_STEM_SCHEME: &str =
    "monero-l2-private-dandelion-stem-bucket-v1";
pub const MONERO_L2_PQ_PRIVATE_DANDELION_RELAY_PRIVACY_RUNTIME_FLUFF_SCHEME: &str =
    "monero-l2-private-dandelion-fluff-diffusion-bucket-v1";
pub const MONERO_L2_PQ_PRIVATE_DANDELION_RELAY_PRIVACY_RUNTIME_SUBADDRESS_GROUP_SCHEME: &str =
    "monero-subaddress-privacy-group-root-v1";
pub const MONERO_L2_PQ_PRIVATE_DANDELION_RELAY_PRIVACY_RUNTIME_VIEW_TAG_SCHEME: &str =
    "view-tag-minimized-bridge-message-envelope-v1";
pub const MONERO_L2_PQ_PRIVATE_DANDELION_RELAY_PRIVACY_RUNTIME_PQ_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-192f-private-relay-attestation-v1";
pub const MONERO_L2_PQ_PRIVATE_DANDELION_RELAY_PRIVACY_RUNTIME_BATCH_SCHEME: &str =
    "low-fee-private-dandelion-relay-batch-v1";
pub const DEFAULT_MIN_STEM_HOPS: u16 = 2;
pub const DEFAULT_MAX_STEM_HOPS: u16 = 7;
pub const DEFAULT_STEM_BUCKETS: u16 = 16;
pub const DEFAULT_FLUFF_BUCKETS: u16 = 32;
pub const DEFAULT_MIN_SUBADDRESS_GROUP_SIZE: u64 = 64;
pub const DEFAULT_MIN_VIEW_TAG_ANONYMITY_SET: u64 = 4_096;
pub const DEFAULT_METADATA_LEAKAGE_BUDGET_UNITS: u64 = 1_000;
pub const DEFAULT_MAX_MESSAGE_BYTES: u64 = 96_000;
pub const DEFAULT_LOW_FEE_BATCH_TARGET_BYTES: u64 = 512_000;
pub const DEFAULT_LOW_FEE_BATCH_MAX_MESSAGES: u16 = 128;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_RELAY_FEE_FLOOR_MICRO_UNITS: u64 = 50;
pub const DEFAULT_RELAY_FEE_CEILING_MICRO_UNITS: u64 = 2_500;
pub const DEFAULT_OPERATOR_DISCLOSURE_FLOOR: u64 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayPhase {
    Stem,
    Fluff,
    Batched,
    Delivered,
    Quarantined,
    Expired,
}

impl RelayPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stem => "stem",
            Self::Fluff => "fluff",
            Self::Batched => "batched",
            Self::Delivered => "delivered",
            Self::Quarantined => "quarantined",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Stem | Self::Fluff | Self::Batched)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeDirection {
    MoneroToL2,
    L2ToMonero,
    ReserveRebalance,
    WatchtowerNotice,
    EmergencyExit,
}

impl BridgeDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroToL2 => "monero_to_l2",
            Self::L2ToMonero => "l2_to_monero",
            Self::ReserveRebalance => "reserve_rebalance",
            Self::WatchtowerNotice => "watchtower_notice",
            Self::EmergencyExit => "emergency_exit",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeakageKind {
    SizeClass,
    TimingClass,
    SubaddressCohort,
    ViewTagPrefix,
    FeeClass,
    OperatorAffinity,
    RetryPattern,
}

impl LeakageKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SizeClass => "size_class",
            Self::TimingClass => "timing_class",
            Self::SubaddressCohort => "subaddress_cohort",
            Self::ViewTagPrefix => "view_tag_prefix",
            Self::FeeClass => "fee_class",
            Self::OperatorAffinity => "operator_affinity",
            Self::RetryPattern => "retry_pattern",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    WeakSecurity,
    Replayed,
    Revoked,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::WeakSecurity => "weak_security",
            Self::Replayed => "replayed",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Sealed,
    Submitted,
    Delivered,
    Cancelled,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Submitted => "submitted",
            Self::Delivered => "delivered",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub monero_network: String,
    pub l2_network: String,
    pub stem_bucket_count: u16,
    pub fluff_bucket_count: u16,
    pub min_stem_hops: u16,
    pub max_stem_hops: u16,
    pub min_subaddress_group_size: u64,
    pub min_view_tag_anonymity_set: u64,
    pub metadata_leakage_budget_units: u64,
    pub max_message_bytes: u64,
    pub low_fee_batch_target_bytes: u64,
    pub low_fee_batch_max_messages: u16,
    pub min_pq_security_bits: u16,
    pub relay_fee_floor_micro_units: u64,
    pub relay_fee_ceiling_micro_units: u64,
    pub operator_disclosure_floor: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            monero_network: MONERO_L2_PQ_PRIVATE_DANDELION_RELAY_PRIVACY_RUNTIME_MONERO_NETWORK
                .to_string(),
            l2_network: MONERO_L2_PQ_PRIVATE_DANDELION_RELAY_PRIVACY_RUNTIME_L2_NETWORK.to_string(),
            stem_bucket_count: DEFAULT_STEM_BUCKETS,
            fluff_bucket_count: DEFAULT_FLUFF_BUCKETS,
            min_stem_hops: DEFAULT_MIN_STEM_HOPS,
            max_stem_hops: DEFAULT_MAX_STEM_HOPS,
            min_subaddress_group_size: DEFAULT_MIN_SUBADDRESS_GROUP_SIZE,
            min_view_tag_anonymity_set: DEFAULT_MIN_VIEW_TAG_ANONYMITY_SET,
            metadata_leakage_budget_units: DEFAULT_METADATA_LEAKAGE_BUDGET_UNITS,
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            low_fee_batch_target_bytes: DEFAULT_LOW_FEE_BATCH_TARGET_BYTES,
            low_fee_batch_max_messages: DEFAULT_LOW_FEE_BATCH_MAX_MESSAGES,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            relay_fee_floor_micro_units: DEFAULT_RELAY_FEE_FLOOR_MICRO_UNITS,
            relay_fee_ceiling_micro_units: DEFAULT_RELAY_FEE_CEILING_MICRO_UNITS,
            operator_disclosure_floor: DEFAULT_OPERATOR_DISCLOSURE_FLOOR,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("protocol version mismatch".to_string());
        }
        if self.stem_bucket_count == 0 || self.fluff_bucket_count == 0 {
            return Err("bucket counts must be nonzero".to_string());
        }
        if self.min_stem_hops == 0 || self.min_stem_hops > self.max_stem_hops {
            return Err("invalid stem hop range".to_string());
        }
        if self.min_subaddress_group_size == 0 {
            return Err("subaddress privacy group size must be nonzero".to_string());
        }
        if self.metadata_leakage_budget_units == 0 {
            return Err("metadata leakage budget must be nonzero".to_string());
        }
        if self.relay_fee_floor_micro_units > self.relay_fee_ceiling_micro_units {
            return Err("relay fee floor exceeds ceiling".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub bridge_messages: u64,
    pub active_stem_messages: u64,
    pub active_fluff_messages: u64,
    pub delivered_messages: u64,
    pub quarantined_messages: u64,
    pub expired_messages: u64,
    pub subaddress_groups: u64,
    pub view_tag_minimizers: u64,
    pub leakage_charges: u64,
    pub leakage_rejections: u64,
    pub pq_attestations: u64,
    pub accepted_pq_attestations: u64,
    pub low_fee_batches: u64,
    pub sealed_batches: u64,
    pub redacted_operator_summaries: u64,
    pub total_payload_bytes: u64,
    pub total_fee_micro_units: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub messages_root: String,
    pub stem_buckets_root: String,
    pub fluff_buckets_root: String,
    pub subaddress_groups_root: String,
    pub view_tag_minimizers_root: String,
    pub leakage_budget_root: String,
    pub pq_attestations_root: String,
    pub batches_root: String,
    pub operator_summaries_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeMessageRequest {
    pub message_id: String,
    pub direction: BridgeDirection,
    pub sealed_payload_commitment: String,
    pub subaddress_group_id: String,
    pub view_tag_domain: String,
    pub view_tag_prefix_bits: u8,
    pub payload_bytes: u64,
    pub fee_micro_units: u64,
    pub preferred_stem_bucket: Option<u16>,
    pub preferred_fluff_bucket: Option<u16>,
    pub min_pq_security_bits: u16,
    pub operator_hint_commitment: String,
    pub route_commitment: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeMessageRecord {
    pub message_id: String,
    pub direction: BridgeDirection,
    pub phase: RelayPhase,
    pub sealed_payload_commitment: String,
    pub subaddress_group_id: String,
    pub view_tag_domain: String,
    pub view_tag_prefix_bits: u8,
    pub payload_bytes: u64,
    pub fee_micro_units: u64,
    pub stem_bucket: u16,
    pub fluff_bucket: u16,
    pub stem_hops_remaining: u16,
    pub metadata_leakage_units: u64,
    pub pq_security_bits: u16,
    pub operator_hint_commitment: String,
    pub route_commitment: String,
    pub batch_id: Option<String>,
    pub delivery_commitment: Option<String>,
}

impl BridgeMessageRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "message_id": self.message_id,
            "direction": self.direction.as_str(),
            "phase": self.phase.as_str(),
            "subaddress_group_id": self.subaddress_group_id,
            "view_tag_domain": self.view_tag_domain,
            "view_tag_prefix_bits": self.view_tag_prefix_bits,
            "payload_size_class": size_class(self.payload_bytes),
            "fee_class": fee_class(self.fee_micro_units),
            "stem_bucket": self.stem_bucket,
            "fluff_bucket": self.fluff_bucket,
            "stem_hops_remaining": self.stem_hops_remaining,
            "metadata_leakage_units": self.metadata_leakage_units,
            "pq_security_bits": self.pq_security_bits,
            "batch_id": self.batch_id,
            "delivered": self.delivery_commitment.is_some(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayBucketRecord {
    pub bucket_id: u16,
    pub phase: RelayPhase,
    pub message_ids: BTreeSet<String>,
    pub total_payload_bytes: u64,
    pub total_fee_micro_units: u64,
    pub leakage_units: u64,
}

impl RelayBucketRecord {
    pub fn new(bucket_id: u16, phase: RelayPhase) -> Self {
        Self {
            bucket_id,
            phase,
            message_ids: BTreeSet::new(),
            total_payload_bytes: 0,
            total_fee_micro_units: 0,
            leakage_units: 0,
        }
    }

    pub fn add_message(&mut self, message: &BridgeMessageRecord) {
        self.message_ids.insert(message.message_id.clone());
        self.total_payload_bytes = self
            .total_payload_bytes
            .saturating_add(message.payload_bytes);
        self.total_fee_micro_units = self
            .total_fee_micro_units
            .saturating_add(message.fee_micro_units);
        self.leakage_units = self
            .leakage_units
            .saturating_add(message.metadata_leakage_units);
    }

    pub fn remove_message(&mut self, message: &BridgeMessageRecord) {
        self.message_ids.remove(&message.message_id);
        self.total_payload_bytes = self
            .total_payload_bytes
            .saturating_sub(message.payload_bytes);
        self.total_fee_micro_units = self
            .total_fee_micro_units
            .saturating_sub(message.fee_micro_units);
        self.leakage_units = self
            .leakage_units
            .saturating_sub(message.metadata_leakage_units);
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "phase": self.phase.as_str(),
            "message_count": self.message_ids.len(),
            "payload_size_class": size_class(self.total_payload_bytes),
            "fee_class": fee_class(self.total_fee_micro_units),
            "leakage_units": self.leakage_units,
            "message_root": digest_set(&self.message_ids),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubaddressPrivacyGroupRequest {
    pub group_id: String,
    pub spend_public_key_commitment: String,
    pub view_public_key_commitment: String,
    pub member_count: u64,
    pub rotation_epoch: u64,
    pub bridge_direction_mask: BTreeSet<BridgeDirection>,
    pub operator_set_commitment: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubaddressPrivacyGroupRecord {
    pub group_id: String,
    pub spend_public_key_commitment: String,
    pub view_public_key_commitment: String,
    pub member_count: u64,
    pub rotation_epoch: u64,
    pub bridge_direction_mask: BTreeSet<BridgeDirection>,
    pub operator_set_commitment: String,
    pub accepted: bool,
    pub rejection_reason: Option<String>,
}

impl SubaddressPrivacyGroupRecord {
    pub fn public_record(&self) -> Value {
        let directions: Vec<&str> = self
            .bridge_direction_mask
            .iter()
            .map(|direction| direction.as_str())
            .collect();
        json!({
            "group_id": self.group_id,
            "member_count": self.member_count,
            "rotation_epoch": self.rotation_epoch,
            "directions": directions,
            "accepted": self.accepted,
            "rejection_reason": self.rejection_reason,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewTagMinimizationRequest {
    pub minimizer_id: String,
    pub domain: String,
    pub prefix_bits: u8,
    pub anonymity_set_size: u64,
    pub scan_bucket_count: u16,
    pub disclosure_commitment: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewTagMinimizationRecord {
    pub minimizer_id: String,
    pub domain: String,
    pub prefix_bits: u8,
    pub anonymity_set_size: u64,
    pub scan_bucket_count: u16,
    pub disclosure_commitment: String,
    pub accepted: bool,
    pub leakage_units: u64,
}

impl ViewTagMinimizationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "minimizer_id": self.minimizer_id,
            "domain": self.domain,
            "prefix_bits": self.prefix_bits,
            "anonymity_set_size": self.anonymity_set_size,
            "scan_bucket_count": self.scan_bucket_count,
            "accepted": self.accepted,
            "leakage_units": self.leakage_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataLeakageChargeRequest {
    pub charge_id: String,
    pub subject_id: String,
    pub kind: LeakageKind,
    pub units: u64,
    pub mitigation_commitment: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataLeakageChargeRecord {
    pub charge_id: String,
    pub subject_id: String,
    pub kind: LeakageKind,
    pub units: u64,
    pub accepted: bool,
    pub budget_remaining: u64,
    pub mitigation_commitment: String,
}

impl MetadataLeakageChargeRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "charge_id": self.charge_id,
            "subject_id": self.subject_id,
            "kind": self.kind.as_str(),
            "units": self.units,
            "accepted": self.accepted,
            "budget_remaining": self.budget_remaining,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRelayAttestationRequest {
    pub attestation_id: String,
    pub operator_id: String,
    pub message_id: String,
    pub pq_scheme: String,
    pub security_bits: u16,
    pub transcript_commitment: String,
    pub signature_commitment: String,
    pub previous_attestation_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRelayAttestationRecord {
    pub attestation_id: String,
    pub operator_id: String,
    pub message_id: String,
    pub pq_scheme: String,
    pub security_bits: u16,
    pub transcript_commitment: String,
    pub signature_commitment: String,
    pub previous_attestation_id: Option<String>,
    pub status: AttestationStatus,
}

impl PqRelayAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "operator_id": self.operator_id,
            "message_id": self.message_id,
            "pq_scheme": self.pq_scheme,
            "security_bits": self.security_bits,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeBatchRequest {
    pub batch_id: String,
    pub operator_id: String,
    pub target_fluff_bucket: u16,
    pub max_messages: u16,
    pub max_payload_bytes: u64,
    pub fee_cap_micro_units: u64,
    pub settlement_commitment: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeBatchRecord {
    pub batch_id: String,
    pub operator_id: String,
    pub target_fluff_bucket: u16,
    pub message_ids: BTreeSet<String>,
    pub status: BatchStatus,
    pub total_payload_bytes: u64,
    pub total_fee_micro_units: u64,
    pub fee_cap_micro_units: u64,
    pub settlement_commitment: String,
    pub batch_root: String,
}

impl LowFeeBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "operator_id": self.operator_id,
            "target_fluff_bucket": self.target_fluff_bucket,
            "message_count": self.message_ids.len(),
            "status": self.status.as_str(),
            "payload_size_class": size_class(self.total_payload_bytes),
            "fee_class": fee_class(self.total_fee_micro_units),
            "fee_cap_micro_units": self.fee_cap_micro_units,
            "batch_root": self.batch_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorSummaryRequest {
    pub summary_id: String,
    pub operator_id: String,
    pub relay_epoch: u64,
    pub delivered_count: u64,
    pub failed_count: u64,
    pub stem_count: u64,
    pub fluff_count: u64,
    pub revenue_micro_units: u64,
    pub disclosure_commitment: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactedOperatorSummaryRecord {
    pub summary_id: String,
    pub operator_id: String,
    pub relay_epoch: u64,
    pub delivered_bucket: String,
    pub failed_bucket: String,
    pub active_bucket: String,
    pub revenue_bucket: String,
    pub disclosure_commitment: String,
    pub summary_root: String,
}

impl RedactedOperatorSummaryRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "operator_id": self.operator_id,
            "relay_epoch": self.relay_epoch,
            "delivered_bucket": self.delivered_bucket,
            "failed_bucket": self.failed_bucket,
            "active_bucket": self.active_bucket,
            "revenue_bucket": self.revenue_bucket,
            "summary_root": self.summary_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryRequest {
    pub message_id: String,
    pub delivery_commitment: String,
    pub operator_id: String,
    pub attestation_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayLaneClass {
    BridgeDeposit,
    BridgeWithdrawal,
    ReserveMaintenance,
    WatchtowerEvidence,
    EmergencyControl,
}

impl RelayLaneClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BridgeDeposit => "bridge_deposit",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::ReserveMaintenance => "reserve_maintenance",
            Self::WatchtowerEvidence => "watchtower_evidence",
            Self::EmergencyControl => "emergency_control",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyReportSeverity {
    Informational,
    Notice,
    Warning,
    Critical,
}

impl PrivacyReportSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Notice => "notice",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayLanePolicyRequest {
    pub policy_id: String,
    pub lane_class: RelayLaneClass,
    pub direction: BridgeDirection,
    pub min_group_members: u64,
    pub max_view_tag_prefix_bits: u8,
    pub max_payload_bytes: u64,
    pub max_fee_micro_units: u64,
    pub allowed_stem_buckets: BTreeSet<u16>,
    pub allowed_fluff_buckets: BTreeSet<u16>,
    pub policy_commitment: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayLanePolicyRecord {
    pub policy_id: String,
    pub lane_class: RelayLaneClass,
    pub direction: BridgeDirection,
    pub min_group_members: u64,
    pub max_view_tag_prefix_bits: u8,
    pub max_payload_bytes: u64,
    pub max_fee_micro_units: u64,
    pub allowed_stem_buckets: BTreeSet<u16>,
    pub allowed_fluff_buckets: BTreeSet<u16>,
    pub policy_commitment: String,
    pub accepted: bool,
    pub policy_root: String,
}

impl RelayLanePolicyRecord {
    pub fn from_request(request: RelayLanePolicyRequest, config: &Config) -> Self {
        let accepted = request.min_group_members >= config.min_subaddress_group_size
            && request.max_view_tag_prefix_bits <= 16
            && request.max_payload_bytes <= config.max_message_bytes
            && request.max_fee_micro_units <= config.relay_fee_ceiling_micro_units
            && !request.allowed_stem_buckets.is_empty()
            && !request.allowed_fluff_buckets.is_empty();
        let policy_root = canonical_digest(&json!({
            "policy_id": request.policy_id,
            "lane_class": request.lane_class.as_str(),
            "direction": request.direction.as_str(),
            "min_group_members": request.min_group_members,
            "max_view_tag_prefix_bits": request.max_view_tag_prefix_bits,
            "max_payload_bytes": request.max_payload_bytes,
            "max_fee_micro_units": request.max_fee_micro_units,
            "allowed_stem_buckets": request.allowed_stem_buckets,
            "allowed_fluff_buckets": request.allowed_fluff_buckets,
            "policy_commitment": request.policy_commitment,
            "accepted": accepted,
        }));
        Self {
            policy_id: request.policy_id,
            lane_class: request.lane_class,
            direction: request.direction,
            min_group_members: request.min_group_members,
            max_view_tag_prefix_bits: request.max_view_tag_prefix_bits,
            max_payload_bytes: request.max_payload_bytes,
            max_fee_micro_units: request.max_fee_micro_units,
            allowed_stem_buckets: request.allowed_stem_buckets,
            allowed_fluff_buckets: request.allowed_fluff_buckets,
            policy_commitment: request.policy_commitment,
            accepted,
            policy_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "lane_class": self.lane_class.as_str(),
            "direction": self.direction.as_str(),
            "min_group_members": self.min_group_members,
            "max_view_tag_prefix_bits": self.max_view_tag_prefix_bits,
            "max_payload_size_class": size_class(self.max_payload_bytes),
            "max_fee_class": fee_class(self.max_fee_micro_units),
            "stem_bucket_count": self.allowed_stem_buckets.len(),
            "fluff_bucket_count": self.allowed_fluff_buckets.len(),
            "accepted": self.accepted,
            "policy_root": self.policy_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BucketAuditSnapshot {
    pub snapshot_id: String,
    pub bucket_id: u16,
    pub phase: RelayPhase,
    pub message_count: u64,
    pub payload_size_class: String,
    pub fee_class: String,
    pub leakage_units: u64,
    pub message_root: String,
    pub audit_commitment: String,
}

impl BucketAuditSnapshot {
    pub fn from_bucket(
        snapshot_id: String,
        bucket: &RelayBucketRecord,
        audit_commitment: String,
    ) -> Self {
        Self {
            snapshot_id,
            bucket_id: bucket.bucket_id,
            phase: bucket.phase,
            message_count: bucket.message_ids.len() as u64,
            payload_size_class: size_class(bucket.total_payload_bytes),
            fee_class: fee_class(bucket.total_fee_micro_units),
            leakage_units: bucket.leakage_units,
            message_root: digest_set(&bucket.message_ids),
            audit_commitment,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "bucket_id": self.bucket_id,
            "phase": self.phase.as_str(),
            "message_count": self.message_count,
            "payload_size_class": self.payload_size_class,
            "fee_class": self.fee_class,
            "leakage_units": self.leakage_units,
            "message_root": self.message_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactedLeakageReportRequest {
    pub report_id: String,
    pub subject_prefix: String,
    pub severity: PrivacyReportSeverity,
    pub charged_units: u64,
    pub remaining_units: u64,
    pub affected_message_count: u64,
    pub affected_group_count: u64,
    pub mitigation_commitment: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactedLeakageReportRecord {
    pub report_id: String,
    pub subject_prefix: String,
    pub severity: PrivacyReportSeverity,
    pub charged_bucket: String,
    pub remaining_bucket: String,
    pub affected_message_bucket: String,
    pub affected_group_bucket: String,
    pub mitigation_commitment: String,
    pub report_root: String,
}

impl RedactedLeakageReportRecord {
    pub fn from_request(request: RedactedLeakageReportRequest) -> Self {
        let charged_bucket = leakage_unit_bucket(request.charged_units);
        let remaining_bucket = leakage_unit_bucket(request.remaining_units);
        let affected_message_bucket = count_bucket(request.affected_message_count, 4);
        let affected_group_bucket = count_bucket(request.affected_group_count, 2);
        let report_root = canonical_digest(&json!({
            "report_id": request.report_id,
            "subject_prefix": request.subject_prefix,
            "severity": request.severity.as_str(),
            "charged_bucket": charged_bucket,
            "remaining_bucket": remaining_bucket,
            "affected_message_bucket": affected_message_bucket,
            "affected_group_bucket": affected_group_bucket,
            "mitigation_commitment": request.mitigation_commitment,
        }));
        Self {
            report_id: request.report_id,
            subject_prefix: request.subject_prefix,
            severity: request.severity,
            charged_bucket,
            remaining_bucket,
            affected_message_bucket,
            affected_group_bucket,
            mitigation_commitment: request.mitigation_commitment,
            report_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "report_id": self.report_id,
            "subject_prefix": self.subject_prefix,
            "severity": self.severity.as_str(),
            "charged_bucket": self.charged_bucket,
            "remaining_bucket": self.remaining_bucket,
            "affected_message_bucket": self.affected_message_bucket,
            "affected_group_bucket": self.affected_group_bucket,
            "report_root": self.report_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DandelionPrivacySnapshot {
    pub snapshot_id: String,
    pub stem_bucket_root: String,
    pub fluff_bucket_root: String,
    pub active_stem_messages: u64,
    pub active_fluff_messages: u64,
    pub delivered_messages: u64,
    pub leakage_budget_spent: u64,
    pub leakage_budget_remaining: u64,
    pub accepted_pq_attestations: u64,
    pub low_fee_batches: u64,
    pub snapshot_root: String,
}

impl DandelionPrivacySnapshot {
    pub fn from_state(snapshot_id: String, state: &State) -> Self {
        let snapshot_root = canonical_digest(&json!({
            "snapshot_id": snapshot_id,
            "stem_bucket_root": state.roots.stem_buckets_root,
            "fluff_bucket_root": state.roots.fluff_buckets_root,
            "active_stem_messages": state.counters.active_stem_messages,
            "active_fluff_messages": state.counters.active_fluff_messages,
            "delivered_messages": state.counters.delivered_messages,
            "leakage_budget_spent": state.leakage_budget_spent,
            "leakage_budget_remaining": state.leakage_budget_remaining(),
            "accepted_pq_attestations": state.counters.accepted_pq_attestations,
            "low_fee_batches": state.counters.low_fee_batches,
        }));
        Self {
            snapshot_id,
            stem_bucket_root: state.roots.stem_buckets_root.clone(),
            fluff_bucket_root: state.roots.fluff_buckets_root.clone(),
            active_stem_messages: state.counters.active_stem_messages,
            active_fluff_messages: state.counters.active_fluff_messages,
            delivered_messages: state.counters.delivered_messages,
            leakage_budget_spent: state.leakage_budget_spent,
            leakage_budget_remaining: state.leakage_budget_remaining(),
            accepted_pq_attestations: state.counters.accepted_pq_attestations,
            low_fee_batches: state.counters.low_fee_batches,
            snapshot_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "stem_bucket_root": self.stem_bucket_root,
            "fluff_bucket_root": self.fluff_bucket_root,
            "active_stem_messages": self.active_stem_messages,
            "active_fluff_messages": self.active_fluff_messages,
            "delivered_messages": self.delivered_messages,
            "leakage_budget_spent": self.leakage_budget_spent,
            "leakage_budget_remaining": self.leakage_budget_remaining,
            "accepted_pq_attestations": self.accepted_pq_attestations,
            "low_fee_batches": self.low_fee_batches,
            "snapshot_root": self.snapshot_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub bridge_messages: BTreeMap<String, BridgeMessageRecord>,
    pub stem_buckets: BTreeMap<u16, RelayBucketRecord>,
    pub fluff_buckets: BTreeMap<u16, RelayBucketRecord>,
    pub subaddress_groups: BTreeMap<String, SubaddressPrivacyGroupRecord>,
    pub view_tag_minimizers: BTreeMap<String, ViewTagMinimizationRecord>,
    pub leakage_charges: BTreeMap<String, MetadataLeakageChargeRecord>,
    pub pq_attestations: BTreeMap<String, PqRelayAttestationRecord>,
    pub low_fee_batches: BTreeMap<String, LowFeeBatchRecord>,
    pub operator_summaries: BTreeMap<String, RedactedOperatorSummaryRecord>,
    pub consumed_attestation_transcripts: BTreeSet<String>,
    pub leakage_budget_spent: u64,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut stem_buckets = BTreeMap::new();
        let mut fluff_buckets = BTreeMap::new();
        for bucket_id in 0..config.stem_bucket_count {
            stem_buckets.insert(
                bucket_id,
                RelayBucketRecord::new(bucket_id, RelayPhase::Stem),
            );
        }
        for bucket_id in 0..config.fluff_bucket_count {
            fluff_buckets.insert(
                bucket_id,
                RelayBucketRecord::new(bucket_id, RelayPhase::Fluff),
            );
        }
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            bridge_messages: BTreeMap::new(),
            stem_buckets,
            fluff_buckets,
            subaddress_groups: BTreeMap::new(),
            view_tag_minimizers: BTreeMap::new(),
            leakage_charges: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            low_fee_batches: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            consumed_attestation_transcripts: BTreeSet::new(),
            leakage_budget_spent: 0,
        };
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet())
    }

    pub fn validate_config(&self) -> Result<()> {
        self.config.validate()
    }

    pub fn register_subaddress_group(
        &mut self,
        request: SubaddressPrivacyGroupRequest,
    ) -> Result<SubaddressPrivacyGroupRecord> {
        self.config.validate()?;
        if request.group_id.is_empty() {
            return Err("subaddress group id is empty".to_string());
        }
        if self.subaddress_groups.contains_key(&request.group_id) {
            return Err("subaddress group already exists".to_string());
        }
        let accepted = request.member_count >= self.config.min_subaddress_group_size
            && !request.bridge_direction_mask.is_empty();
        let rejection_reason = if accepted {
            None
        } else if request.bridge_direction_mask.is_empty() {
            Some("empty direction mask".to_string())
        } else {
            Some("insufficient group size".to_string())
        };
        let record = SubaddressPrivacyGroupRecord {
            group_id: request.group_id.clone(),
            spend_public_key_commitment: request.spend_public_key_commitment,
            view_public_key_commitment: request.view_public_key_commitment,
            member_count: request.member_count,
            rotation_epoch: request.rotation_epoch,
            bridge_direction_mask: request.bridge_direction_mask,
            operator_set_commitment: request.operator_set_commitment,
            accepted,
            rejection_reason,
        };
        self.subaddress_groups
            .insert(request.group_id, record.clone());
        self.counters.subaddress_groups = self.subaddress_groups.len() as u64;
        self.refresh_roots();
        Ok(record)
    }

    pub fn register_view_tag_minimizer(
        &mut self,
        request: ViewTagMinimizationRequest,
    ) -> Result<ViewTagMinimizationRecord> {
        self.config.validate()?;
        if request.minimizer_id.is_empty() || request.domain.is_empty() {
            return Err("view tag minimizer id and domain are required".to_string());
        }
        if self.view_tag_minimizers.contains_key(&request.minimizer_id) {
            return Err("view tag minimizer already exists".to_string());
        }
        if request.prefix_bits > 16 {
            return Err("view tag prefix bits exceed minimization bound".to_string());
        }
        let leakage_units = view_tag_leakage_units(request.prefix_bits, request.scan_bucket_count);
        let accepted = request.anonymity_set_size >= self.config.min_view_tag_anonymity_set
            && self.can_spend_leakage(leakage_units);
        if accepted {
            self.leakage_budget_spent = self.leakage_budget_spent.saturating_add(leakage_units);
        }
        let record = ViewTagMinimizationRecord {
            minimizer_id: request.minimizer_id.clone(),
            domain: request.domain,
            prefix_bits: request.prefix_bits,
            anonymity_set_size: request.anonymity_set_size,
            scan_bucket_count: request.scan_bucket_count,
            disclosure_commitment: request.disclosure_commitment,
            accepted,
            leakage_units,
        };
        self.view_tag_minimizers
            .insert(request.minimizer_id, record.clone());
        self.counters.view_tag_minimizers = self.view_tag_minimizers.len() as u64;
        if accepted {
            self.counters.leakage_charges = self.counters.leakage_charges.saturating_add(1);
        } else {
            self.counters.leakage_rejections = self.counters.leakage_rejections.saturating_add(1);
        }
        self.refresh_roots();
        Ok(record)
    }

    pub fn stage_bridge_message(
        &mut self,
        request: BridgeMessageRequest,
    ) -> Result<BridgeMessageRecord> {
        self.config.validate()?;
        if request.message_id.is_empty() {
            return Err("message id is empty".to_string());
        }
        if self.bridge_messages.contains_key(&request.message_id) {
            return Err("message already exists".to_string());
        }
        if request.payload_bytes == 0 || request.payload_bytes > self.config.max_message_bytes {
            return Err("payload bytes outside configured bounds".to_string());
        }
        if request.fee_micro_units < self.config.relay_fee_floor_micro_units
            || request.fee_micro_units > self.config.relay_fee_ceiling_micro_units
        {
            return Err("relay fee outside configured bounds".to_string());
        }
        let group = self
            .subaddress_groups
            .get(&request.subaddress_group_id)
            .ok_or_else(|| "subaddress group not registered".to_string())?;
        if !group.accepted {
            return Err("subaddress group is not accepted".to_string());
        }
        if !group.bridge_direction_mask.contains(&request.direction) {
            return Err("subaddress group does not allow direction".to_string());
        }
        let minimizer = self
            .view_tag_minimizers
            .values()
            .find(|record| {
                record.accepted
                    && record.domain == request.view_tag_domain
                    && record.prefix_bits <= request.view_tag_prefix_bits
            })
            .ok_or_else(|| "accepted view tag minimizer not found".to_string())?;
        let leakage_units = message_leakage_units(&request, minimizer);
        if !self.can_spend_leakage(leakage_units) {
            self.counters.leakage_rejections = self.counters.leakage_rejections.saturating_add(1);
            self.refresh_roots();
            return Err("metadata leakage budget exhausted".to_string());
        }
        let stem_bucket = request
            .preferred_stem_bucket
            .map(|bucket| bucket % self.config.stem_bucket_count)
            .unwrap_or_else(|| {
                deterministic_bucket(&request.message_id, self.config.stem_bucket_count)
            });
        let fluff_bucket = request
            .preferred_fluff_bucket
            .map(|bucket| bucket % self.config.fluff_bucket_count)
            .unwrap_or_else(|| {
                deterministic_bucket(&request.route_commitment, self.config.fluff_bucket_count)
            });
        let hop_span = self
            .config
            .max_stem_hops
            .saturating_sub(self.config.min_stem_hops)
            .saturating_add(1);
        let stem_hops_remaining = self
            .config
            .min_stem_hops
            .saturating_add(
                deterministic_bucket(&request.operator_hint_commitment, hop_span) as u16,
            );
        let pq_security_bits = request.min_pq_security_bits;
        let record = BridgeMessageRecord {
            message_id: request.message_id.clone(),
            direction: request.direction,
            phase: RelayPhase::Stem,
            sealed_payload_commitment: request.sealed_payload_commitment,
            subaddress_group_id: request.subaddress_group_id,
            view_tag_domain: request.view_tag_domain,
            view_tag_prefix_bits: request.view_tag_prefix_bits,
            payload_bytes: request.payload_bytes,
            fee_micro_units: request.fee_micro_units,
            stem_bucket,
            fluff_bucket,
            stem_hops_remaining,
            metadata_leakage_units: leakage_units,
            pq_security_bits,
            operator_hint_commitment: request.operator_hint_commitment,
            route_commitment: request.route_commitment,
            batch_id: None,
            delivery_commitment: None,
        };
        if let Some(bucket) = self.stem_buckets.get_mut(&stem_bucket) {
            bucket.add_message(&record);
        }
        self.leakage_budget_spent = self.leakage_budget_spent.saturating_add(leakage_units);
        self.counters.bridge_messages = self.counters.bridge_messages.saturating_add(1);
        self.counters.active_stem_messages = self.counters.active_stem_messages.saturating_add(1);
        self.counters.total_payload_bytes = self
            .counters
            .total_payload_bytes
            .saturating_add(record.payload_bytes);
        self.counters.total_fee_micro_units = self
            .counters
            .total_fee_micro_units
            .saturating_add(record.fee_micro_units);
        self.bridge_messages
            .insert(request.message_id, record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn advance_stem(&mut self, message_id: &str) -> Result<BridgeMessageRecord> {
        let current = self
            .bridge_messages
            .get(message_id)
            .cloned()
            .ok_or_else(|| "message not found".to_string())?;
        if current.phase != RelayPhase::Stem {
            return Err("message is not in stem phase".to_string());
        }
        let mut updated = current.clone();
        if updated.stem_hops_remaining > 1 {
            updated.stem_hops_remaining = updated.stem_hops_remaining.saturating_sub(1);
        } else {
            updated.stem_hops_remaining = 0;
            updated.phase = RelayPhase::Fluff;
            if let Some(bucket) = self.stem_buckets.get_mut(&current.stem_bucket) {
                bucket.remove_message(&current);
            }
            if let Some(bucket) = self.fluff_buckets.get_mut(&updated.fluff_bucket) {
                bucket.add_message(&updated);
            }
            self.counters.active_stem_messages =
                self.counters.active_stem_messages.saturating_sub(1);
            self.counters.active_fluff_messages =
                self.counters.active_fluff_messages.saturating_add(1);
        }
        self.bridge_messages
            .insert(message_id.to_string(), updated.clone());
        self.refresh_roots();
        Ok(updated)
    }

    pub fn record_metadata_leakage_charge(
        &mut self,
        request: MetadataLeakageChargeRequest,
    ) -> Result<MetadataLeakageChargeRecord> {
        if request.charge_id.is_empty() || request.subject_id.is_empty() {
            return Err("charge id and subject id are required".to_string());
        }
        if self.leakage_charges.contains_key(&request.charge_id) {
            return Err("metadata leakage charge already exists".to_string());
        }
        let accepted = self.can_spend_leakage(request.units);
        if accepted {
            self.leakage_budget_spent = self.leakage_budget_spent.saturating_add(request.units);
            self.counters.leakage_charges = self.counters.leakage_charges.saturating_add(1);
        } else {
            self.counters.leakage_rejections = self.counters.leakage_rejections.saturating_add(1);
        }
        let budget_remaining = self.leakage_budget_remaining();
        let record = MetadataLeakageChargeRecord {
            charge_id: request.charge_id.clone(),
            subject_id: request.subject_id,
            kind: request.kind,
            units: request.units,
            accepted,
            budget_remaining,
            mitigation_commitment: request.mitigation_commitment,
        };
        self.leakage_charges
            .insert(request.charge_id, record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn record_pq_relay_attestation(
        &mut self,
        request: PqRelayAttestationRequest,
    ) -> Result<PqRelayAttestationRecord> {
        if request.attestation_id.is_empty()
            || request.operator_id.is_empty()
            || request.message_id.is_empty()
        {
            return Err("attestation id, operator id, and message id are required".to_string());
        }
        if self.pq_attestations.contains_key(&request.attestation_id) {
            return Err("pq attestation already exists".to_string());
        }
        if !self.bridge_messages.contains_key(&request.message_id) {
            return Err("attested message not found".to_string());
        }
        let replay_key = canonical_digest(&json!({
            "operator_id": request.operator_id,
            "message_id": request.message_id,
            "transcript_commitment": request.transcript_commitment,
        }));
        let status = if self.consumed_attestation_transcripts.contains(&replay_key) {
            AttestationStatus::Replayed
        } else if request.security_bits < self.config.min_pq_security_bits {
            AttestationStatus::WeakSecurity
        } else {
            AttestationStatus::Accepted
        };
        if status == AttestationStatus::Accepted {
            self.consumed_attestation_transcripts.insert(replay_key);
            self.counters.accepted_pq_attestations =
                self.counters.accepted_pq_attestations.saturating_add(1);
        }
        let record = PqRelayAttestationRecord {
            attestation_id: request.attestation_id.clone(),
            operator_id: request.operator_id,
            message_id: request.message_id,
            pq_scheme: request.pq_scheme,
            security_bits: request.security_bits,
            transcript_commitment: request.transcript_commitment,
            signature_commitment: request.signature_commitment,
            previous_attestation_id: request.previous_attestation_id,
            status,
        };
        self.pq_attestations
            .insert(request.attestation_id, record.clone());
        self.counters.pq_attestations = self.pq_attestations.len() as u64;
        self.refresh_roots();
        Ok(record)
    }

    pub fn open_low_fee_batch(&mut self, request: LowFeeBatchRequest) -> Result<LowFeeBatchRecord> {
        if request.batch_id.is_empty() || request.operator_id.is_empty() {
            return Err("batch id and operator id are required".to_string());
        }
        if self.low_fee_batches.contains_key(&request.batch_id) {
            return Err("low fee batch already exists".to_string());
        }
        let target_fluff_bucket = request.target_fluff_bucket % self.config.fluff_bucket_count;
        let max_messages = if request.max_messages == 0 {
            self.config.low_fee_batch_max_messages
        } else {
            request
                .max_messages
                .min(self.config.low_fee_batch_max_messages)
        };
        let max_payload_bytes = if request.max_payload_bytes == 0 {
            self.config.low_fee_batch_target_bytes
        } else {
            request
                .max_payload_bytes
                .min(self.config.low_fee_batch_target_bytes)
        };
        let mut message_ids = BTreeSet::new();
        let mut total_payload_bytes = 0_u64;
        let mut total_fee_micro_units = 0_u64;
        for message in self.bridge_messages.values() {
            if message.phase != RelayPhase::Fluff || message.fluff_bucket != target_fluff_bucket {
                continue;
            }
            if message_ids.len() >= max_messages as usize {
                break;
            }
            let next_payload = total_payload_bytes.saturating_add(message.payload_bytes);
            let next_fee = total_fee_micro_units.saturating_add(message.fee_micro_units);
            if next_payload > max_payload_bytes || next_fee > request.fee_cap_micro_units {
                continue;
            }
            message_ids.insert(message.message_id.clone());
            total_payload_bytes = next_payload;
            total_fee_micro_units = next_fee;
        }
        let batch_root = digest_set(&message_ids);
        let record = LowFeeBatchRecord {
            batch_id: request.batch_id.clone(),
            operator_id: request.operator_id,
            target_fluff_bucket,
            message_ids,
            status: BatchStatus::Open,
            total_payload_bytes,
            total_fee_micro_units,
            fee_cap_micro_units: request.fee_cap_micro_units,
            settlement_commitment: request.settlement_commitment,
            batch_root,
        };
        self.low_fee_batches
            .insert(request.batch_id, record.clone());
        self.counters.low_fee_batches = self.low_fee_batches.len() as u64;
        self.refresh_roots();
        Ok(record)
    }

    pub fn seal_low_fee_batch(&mut self, batch_id: &str) -> Result<LowFeeBatchRecord> {
        let mut batch = self
            .low_fee_batches
            .get(batch_id)
            .cloned()
            .ok_or_else(|| "low fee batch not found".to_string())?;
        if batch.status != BatchStatus::Open {
            return Err("low fee batch is not open".to_string());
        }
        for message_id in &batch.message_ids {
            if let Some(message) = self.bridge_messages.get_mut(message_id) {
                message.phase = RelayPhase::Batched;
                message.batch_id = Some(batch_id.to_string());
            }
        }
        batch.status = BatchStatus::Sealed;
        batch.batch_root = digest_set(&batch.message_ids);
        self.low_fee_batches
            .insert(batch_id.to_string(), batch.clone());
        self.counters.sealed_batches = self.counters.sealed_batches.saturating_add(1);
        self.refresh_roots();
        Ok(batch)
    }

    pub fn record_delivery(&mut self, request: DeliveryRequest) -> Result<BridgeMessageRecord> {
        let attestation = self
            .pq_attestations
            .get(&request.attestation_id)
            .ok_or_else(|| "delivery attestation not found".to_string())?;
        if attestation.status != AttestationStatus::Accepted {
            return Err("delivery attestation is not accepted".to_string());
        }
        if attestation.message_id != request.message_id
            || attestation.operator_id != request.operator_id
        {
            return Err("delivery attestation does not match request".to_string());
        }
        let mut message = self
            .bridge_messages
            .get(&request.message_id)
            .cloned()
            .ok_or_else(|| "message not found".to_string())?;
        if !message.phase.active() {
            return Err("message is not active".to_string());
        }
        if message.phase == RelayPhase::Fluff {
            if let Some(bucket) = self.fluff_buckets.get_mut(&message.fluff_bucket) {
                bucket.remove_message(&message);
            }
            self.counters.active_fluff_messages =
                self.counters.active_fluff_messages.saturating_sub(1);
        }
        if message.phase == RelayPhase::Stem {
            if let Some(bucket) = self.stem_buckets.get_mut(&message.stem_bucket) {
                bucket.remove_message(&message);
            }
            self.counters.active_stem_messages =
                self.counters.active_stem_messages.saturating_sub(1);
        }
        message.phase = RelayPhase::Delivered;
        message.delivery_commitment = Some(request.delivery_commitment);
        self.counters.delivered_messages = self.counters.delivered_messages.saturating_add(1);
        if let Some(batch_id) = &message.batch_id {
            if let Some(batch) = self.low_fee_batches.get_mut(batch_id) {
                batch.status = BatchStatus::Delivered;
            }
        }
        self.bridge_messages
            .insert(request.message_id, message.clone());
        self.refresh_roots();
        Ok(message)
    }

    pub fn quarantine_message(
        &mut self,
        message_id: &str,
        reason_commitment: &str,
    ) -> Result<BridgeMessageRecord> {
        let mut message = self
            .bridge_messages
            .get(message_id)
            .cloned()
            .ok_or_else(|| "message not found".to_string())?;
        if message.phase == RelayPhase::Stem {
            if let Some(bucket) = self.stem_buckets.get_mut(&message.stem_bucket) {
                bucket.remove_message(&message);
            }
            self.counters.active_stem_messages =
                self.counters.active_stem_messages.saturating_sub(1);
        }
        if message.phase == RelayPhase::Fluff {
            if let Some(bucket) = self.fluff_buckets.get_mut(&message.fluff_bucket) {
                bucket.remove_message(&message);
            }
            self.counters.active_fluff_messages =
                self.counters.active_fluff_messages.saturating_sub(1);
        }
        message.phase = RelayPhase::Quarantined;
        message.delivery_commitment = Some(canonical_digest(&json!({
            "quarantine_reason_commitment": reason_commitment,
            "message_id": message_id,
        })));
        self.counters.quarantined_messages = self.counters.quarantined_messages.saturating_add(1);
        self.bridge_messages
            .insert(message_id.to_string(), message.clone());
        self.refresh_roots();
        Ok(message)
    }

    pub fn record_redacted_operator_summary(
        &mut self,
        request: OperatorSummaryRequest,
    ) -> Result<RedactedOperatorSummaryRecord> {
        if request.summary_id.is_empty() || request.operator_id.is_empty() {
            return Err("summary id and operator id are required".to_string());
        }
        if self.operator_summaries.contains_key(&request.summary_id) {
            return Err("operator summary already exists".to_string());
        }
        let active_count = request.stem_count.saturating_add(request.fluff_count);
        let summary_root = canonical_digest(&json!({
            "summary_id": request.summary_id,
            "operator_id": request.operator_id,
            "relay_epoch": request.relay_epoch,
            "delivered_bucket": count_bucket(request.delivered_count, self.config.operator_disclosure_floor),
            "failed_bucket": count_bucket(request.failed_count, self.config.operator_disclosure_floor),
            "active_bucket": count_bucket(active_count, self.config.operator_disclosure_floor),
            "revenue_bucket": revenue_bucket(request.revenue_micro_units),
            "disclosure_commitment": request.disclosure_commitment,
        }));
        let record = RedactedOperatorSummaryRecord {
            summary_id: request.summary_id.clone(),
            operator_id: request.operator_id,
            relay_epoch: request.relay_epoch,
            delivered_bucket: count_bucket(
                request.delivered_count,
                self.config.operator_disclosure_floor,
            ),
            failed_bucket: count_bucket(
                request.failed_count,
                self.config.operator_disclosure_floor,
            ),
            active_bucket: count_bucket(active_count, self.config.operator_disclosure_floor),
            revenue_bucket: revenue_bucket(request.revenue_micro_units),
            disclosure_commitment: request.disclosure_commitment,
            summary_root,
        };
        self.operator_summaries
            .insert(request.summary_id, record.clone());
        self.counters.redacted_operator_summaries = self.operator_summaries.len() as u64;
        self.refresh_roots();
        Ok(record)
    }

    pub fn leakage_budget_remaining(&self) -> u64 {
        self.config
            .metadata_leakage_budget_units
            .saturating_sub(self.leakage_budget_spent)
    }

    pub fn can_spend_leakage(&self, units: u64) -> bool {
        self.leakage_budget_spent.saturating_add(units) <= self.config.metadata_leakage_budget_units
    }

    pub fn public_record(&self) -> Value {
        let messages: Vec<Value> = self
            .bridge_messages
            .values()
            .map(BridgeMessageRecord::public_record)
            .collect();
        let stem_buckets: Vec<Value> = self
            .stem_buckets
            .values()
            .map(RelayBucketRecord::public_record)
            .collect();
        let fluff_buckets: Vec<Value> = self
            .fluff_buckets
            .values()
            .map(RelayBucketRecord::public_record)
            .collect();
        let subaddress_groups: Vec<Value> = self
            .subaddress_groups
            .values()
            .map(SubaddressPrivacyGroupRecord::public_record)
            .collect();
        let view_tag_minimizers: Vec<Value> = self
            .view_tag_minimizers
            .values()
            .map(ViewTagMinimizationRecord::public_record)
            .collect();
        let leakage_charges: Vec<Value> = self
            .leakage_charges
            .values()
            .map(MetadataLeakageChargeRecord::public_record)
            .collect();
        let pq_attestations: Vec<Value> = self
            .pq_attestations
            .values()
            .map(PqRelayAttestationRecord::public_record)
            .collect();
        let low_fee_batches: Vec<Value> = self
            .low_fee_batches
            .values()
            .map(LowFeeBatchRecord::public_record)
            .collect();
        let operator_summaries: Vec<Value> = self
            .operator_summaries
            .values()
            .map(RedactedOperatorSummaryRecord::public_record)
            .collect();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": MONERO_L2_PQ_PRIVATE_DANDELION_RELAY_PRIVACY_RUNTIME_SCHEMA_VERSION,
            "monero_network": self.config.monero_network,
            "l2_network": self.config.l2_network,
            "hash_suite": MONERO_L2_PQ_PRIVATE_DANDELION_RELAY_PRIVACY_RUNTIME_HASH_SUITE,
            "stem_scheme": MONERO_L2_PQ_PRIVATE_DANDELION_RELAY_PRIVACY_RUNTIME_STEM_SCHEME,
            "fluff_scheme": MONERO_L2_PQ_PRIVATE_DANDELION_RELAY_PRIVACY_RUNTIME_FLUFF_SCHEME,
            "subaddress_group_scheme": MONERO_L2_PQ_PRIVATE_DANDELION_RELAY_PRIVACY_RUNTIME_SUBADDRESS_GROUP_SCHEME,
            "view_tag_scheme": MONERO_L2_PQ_PRIVATE_DANDELION_RELAY_PRIVACY_RUNTIME_VIEW_TAG_SCHEME,
            "pq_attestation_scheme": MONERO_L2_PQ_PRIVATE_DANDELION_RELAY_PRIVACY_RUNTIME_PQ_ATTESTATION_SCHEME,
            "batch_scheme": MONERO_L2_PQ_PRIVATE_DANDELION_RELAY_PRIVACY_RUNTIME_BATCH_SCHEME,
            "counters": self.counters,
            "leakage_budget_spent": self.leakage_budget_spent,
            "leakage_budget_remaining": self.leakage_budget_remaining(),
            "roots": self.roots,
            "messages": messages,
            "stem_buckets": stem_buckets,
            "fluff_buckets": fluff_buckets,
            "subaddress_groups": subaddress_groups,
            "view_tag_minimizers": view_tag_minimizers,
            "leakage_charges": leakage_charges,
            "pq_attestations": pq_attestations,
            "low_fee_batches": low_fee_batches,
            "operator_summaries": operator_summaries,
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn refresh_roots(&mut self) {
        self.roots.messages_root = digest_map(&self.bridge_messages);
        self.roots.stem_buckets_root = digest_map(&self.stem_buckets);
        self.roots.fluff_buckets_root = digest_map(&self.fluff_buckets);
        self.roots.subaddress_groups_root = digest_map(&self.subaddress_groups);
        self.roots.view_tag_minimizers_root = digest_map(&self.view_tag_minimizers);
        self.roots.leakage_budget_root = digest_map(&self.leakage_charges);
        self.roots.pq_attestations_root = digest_map(&self.pq_attestations);
        self.roots.batches_root = digest_map(&self.low_fee_batches);
        self.roots.operator_summaries_root = digest_map(&self.operator_summaries);
        self.roots.state_root = canonical_digest(&json!({
            "protocol_version": self.config.protocol_version,
            "counters": self.counters,
            "leakage_budget_spent": self.leakage_budget_spent,
            "messages_root": self.roots.messages_root,
            "stem_buckets_root": self.roots.stem_buckets_root,
            "fluff_buckets_root": self.roots.fluff_buckets_root,
            "subaddress_groups_root": self.roots.subaddress_groups_root,
            "view_tag_minimizers_root": self.roots.view_tag_minimizers_root,
            "leakage_budget_root": self.roots.leakage_budget_root,
            "pq_attestations_root": self.roots.pq_attestations_root,
            "batches_root": self.roots.batches_root,
            "operator_summaries_root": self.roots.operator_summaries_root,
        }));
    }
}

pub fn devnet() -> Runtime {
    State::devnet()
}

pub fn demo() -> Runtime {
    let mut state = State::devnet();
    let mut directions = BTreeSet::new();
    directions.insert(BridgeDirection::MoneroToL2);
    directions.insert(BridgeDirection::L2ToMonero);
    let _ = state.register_subaddress_group(SubaddressPrivacyGroupRequest {
        group_id: "demo-subaddr-group-a".to_string(),
        spend_public_key_commitment: "spend-commitment-demo-a".to_string(),
        view_public_key_commitment: "view-commitment-demo-a".to_string(),
        member_count: 128,
        rotation_epoch: 1,
        bridge_direction_mask: directions,
        operator_set_commitment: "operator-set-demo-a".to_string(),
    });
    let _ = state.register_view_tag_minimizer(ViewTagMinimizationRequest {
        minimizer_id: "demo-viewtag-minimizer-a".to_string(),
        domain: "bridge-note-scan".to_string(),
        prefix_bits: 8,
        anonymity_set_size: 16_384,
        scan_bucket_count: 64,
        disclosure_commitment: "viewtag-disclosure-demo-a".to_string(),
    });
    let _ = state.stage_bridge_message(BridgeMessageRequest {
        message_id: "demo-message-a".to_string(),
        direction: BridgeDirection::MoneroToL2,
        sealed_payload_commitment: "sealed-payload-demo-a".to_string(),
        subaddress_group_id: "demo-subaddr-group-a".to_string(),
        view_tag_domain: "bridge-note-scan".to_string(),
        view_tag_prefix_bits: 8,
        payload_bytes: 42_000,
        fee_micro_units: 900,
        preferred_stem_bucket: Some(3),
        preferred_fluff_bucket: Some(11),
        min_pq_security_bits: 256,
        operator_hint_commitment: "operator-hint-demo-a".to_string(),
        route_commitment: "route-commitment-demo-a".to_string(),
    });
    let _ = state.advance_stem("demo-message-a");
    let _ = state.advance_stem("demo-message-a");
    let _ = state.record_pq_relay_attestation(PqRelayAttestationRequest {
        attestation_id: "demo-attestation-a".to_string(),
        operator_id: "demo-operator-a".to_string(),
        message_id: "demo-message-a".to_string(),
        pq_scheme: MONERO_L2_PQ_PRIVATE_DANDELION_RELAY_PRIVACY_RUNTIME_PQ_ATTESTATION_SCHEME
            .to_string(),
        security_bits: 256,
        transcript_commitment: "transcript-demo-a".to_string(),
        signature_commitment: "signature-demo-a".to_string(),
        previous_attestation_id: None,
    });
    let _ = state.open_low_fee_batch(LowFeeBatchRequest {
        batch_id: "demo-batch-a".to_string(),
        operator_id: "demo-operator-a".to_string(),
        target_fluff_bucket: 11,
        max_messages: 16,
        max_payload_bytes: 128_000,
        fee_cap_micro_units: 20_000,
        settlement_commitment: "settlement-demo-a".to_string(),
    });
    let _ = state.seal_low_fee_batch("demo-batch-a");
    let _ = state.record_delivery(DeliveryRequest {
        message_id: "demo-message-a".to_string(),
        delivery_commitment: "delivery-demo-a".to_string(),
        operator_id: "demo-operator-a".to_string(),
        attestation_id: "demo-attestation-a".to_string(),
    });
    let _ = state.record_redacted_operator_summary(OperatorSummaryRequest {
        summary_id: "demo-summary-a".to_string(),
        operator_id: "demo-operator-a".to_string(),
        relay_epoch: 1,
        delivered_count: 1,
        failed_count: 0,
        stem_count: 0,
        fluff_count: 0,
        revenue_micro_units: 900,
        disclosure_commitment: "summary-disclosure-demo-a".to_string(),
    });
    state.refresh_roots();
    state
}

pub fn public_record() -> Value {
    demo().public_record()
}

pub fn state_root() -> String {
    demo().state_root()
}

fn message_leakage_units(
    request: &BridgeMessageRequest,
    minimizer: &ViewTagMinimizationRecord,
) -> u64 {
    let size_units = match size_class(request.payload_bytes).as_str() {
        "tiny" => 4,
        "small" => 8,
        "medium" => 16,
        "large" => 32,
        _ => 64,
    };
    let fee_units = match fee_class(request.fee_micro_units).as_str() {
        "floor" => 2,
        "low" => 4,
        "standard" => 8,
        "priority" => 12,
        _ => 16,
    };
    let view_tag_units =
        view_tag_leakage_units(request.view_tag_prefix_bits, minimizer.scan_bucket_count);
    size_units + fee_units + view_tag_units
}

fn view_tag_leakage_units(prefix_bits: u8, scan_bucket_count: u16) -> u64 {
    let prefix_units = (prefix_bits as u64).saturating_mul(3);
    let bucket_units = if scan_bucket_count <= 16 {
        4
    } else if scan_bucket_count <= 64 {
        8
    } else {
        16
    };
    prefix_units.saturating_add(bucket_units)
}

fn deterministic_bucket(seed: &str, bucket_count: u16) -> u16 {
    if bucket_count == 0 {
        return 0;
    }
    let digest = deterministic_u64(seed.as_bytes());
    (digest % bucket_count as u64) as u16
}

fn size_class(bytes: u64) -> String {
    if bytes <= 1_024 {
        "tiny".to_string()
    } else if bytes <= 16_384 {
        "small".to_string()
    } else if bytes <= 96_000 {
        "medium".to_string()
    } else if bytes <= 512_000 {
        "large".to_string()
    } else {
        "bulk".to_string()
    }
}

fn fee_class(fee_micro_units: u64) -> String {
    if fee_micro_units <= DEFAULT_RELAY_FEE_FLOOR_MICRO_UNITS {
        "floor".to_string()
    } else if fee_micro_units <= 500 {
        "low".to_string()
    } else if fee_micro_units <= 1_500 {
        "standard".to_string()
    } else if fee_micro_units <= DEFAULT_RELAY_FEE_CEILING_MICRO_UNITS {
        "priority".to_string()
    } else {
        "out_of_policy".to_string()
    }
}

fn count_bucket(count: u64, floor: u64) -> String {
    if count == 0 {
        "zero".to_string()
    } else if count < floor {
        format!("lt_{}", floor)
    } else if count < floor.saturating_mul(4) {
        format!("{}-{}", floor, floor.saturating_mul(4).saturating_sub(1))
    } else if count < floor.saturating_mul(16) {
        format!(
            "{}-{}",
            floor.saturating_mul(4),
            floor.saturating_mul(16).saturating_sub(1)
        )
    } else {
        format!("gte_{}", floor.saturating_mul(16))
    }
}

fn revenue_bucket(revenue_micro_units: u64) -> String {
    if revenue_micro_units == 0 {
        "zero".to_string()
    } else if revenue_micro_units <= 1_000 {
        "micro".to_string()
    } else if revenue_micro_units <= 100_000 {
        "small".to_string()
    } else if revenue_micro_units <= 10_000_000 {
        "medium".to_string()
    } else {
        "large".to_string()
    }
}

fn leakage_unit_bucket(units: u64) -> String {
    if units == 0 {
        "zero".to_string()
    } else if units <= 16 {
        "trace".to_string()
    } else if units <= 64 {
        "low".to_string()
    } else if units <= 256 {
        "elevated".to_string()
    } else if units <= DEFAULT_METADATA_LEAKAGE_BUDGET_UNITS {
        "high".to_string()
    } else {
        "over_budget".to_string()
    }
}

fn digest_map<T: Serialize>(map: &BTreeMap<impl Serialize + Ord, T>) -> String {
    canonical_digest(&json!(map))
}

fn digest_set(set: &BTreeSet<String>) -> String {
    canonical_digest(&json!(set))
}

fn canonical_digest(value: &Value) -> String {
    let canonical = canonical_json(value);
    let first = deterministic_u64(canonical.as_bytes());
    let second_seed = format!("{}:{}", PROTOCOL_VERSION, canonical);
    let second = deterministic_u64(second_seed.as_bytes());
    format!("{:016x}{:016x}", first, second)
}

fn deterministic_u64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(flag) => {
            if *flag {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        Value::Number(number) => number.to_string(),
        Value::String(text) => json_escape(text),
        Value::Array(items) => {
            let rendered: Vec<String> = items.iter().map(canonical_json).collect();
            format!("[{}]", rendered.join(","))
        }
        Value::Object(object) => {
            let mut entries = Vec::new();
            for (key, item) in object {
                entries.push(format!("{}:{}", json_escape(key), canonical_json(item)));
            }
            format!("{{{}}}", entries.join(","))
        }
    }
}

fn json_escape(text: &str) -> String {
    let mut escaped = String::new();
    escaped.push('"');
    for ch in text.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '\u{08}' => escaped.push_str("\\b"),
            '\u{0c}' => escaped.push_str("\\f"),
            ch if ch < '\u{20}' => escaped.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => escaped.push(ch),
        }
    }
    escaped.push('"');
    escaped
}
