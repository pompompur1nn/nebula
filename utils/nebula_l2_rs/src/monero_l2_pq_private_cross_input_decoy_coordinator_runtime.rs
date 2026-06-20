use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateCrossInputDecoyCoordinatorRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_CROSS_INPUT_DECOY_COORDINATOR_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-cross-input-decoy-coordinator-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_CROSS_INPUT_DECOY_COORDINATOR_RUNTIME_PROTOCOL_VERSION;
pub const MONERO_L2_PQ_PRIVATE_CROSS_INPUT_DECOY_COORDINATOR_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const MONERO_L2_PQ_PRIVATE_CROSS_INPUT_DECOY_COORDINATOR_RUNTIME_DEVNET_HEIGHT: u64 = 812_480;
pub const MONERO_L2_PQ_PRIVATE_CROSS_INPUT_DECOY_COORDINATOR_RUNTIME_MONERO_NETWORK: &str =
    "monero-devnet";
pub const MONERO_L2_PQ_PRIVATE_CROSS_INPUT_DECOY_COORDINATOR_RUNTIME_L2_NETWORK: &str =
    "nebula-devnet";
pub const MONERO_L2_PQ_PRIVATE_CROSS_INPUT_DECOY_COORDINATOR_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_L2_PQ_PRIVATE_CROSS_INPUT_DECOY_COORDINATOR_RUNTIME_DECOY_BUCKET_SCHEME: &str =
    "zk-pq-cross-input-decoy-bucket-proof-v1";
pub const MONERO_L2_PQ_PRIVATE_CROSS_INPUT_DECOY_COORDINATOR_RUNTIME_SPEND_GRAPH_SCHEME: &str =
    "redacted-monero-cross-input-spend-graph-root-v1";
pub const MONERO_L2_PQ_PRIVATE_CROSS_INPUT_DECOY_COORDINATOR_RUNTIME_MIXIN_FLOOR_SCHEME: &str =
    "private-bridge-withdrawal-mixin-floor-policy-v1";
pub const MONERO_L2_PQ_PRIVATE_CROSS_INPUT_DECOY_COORDINATOR_RUNTIME_VIEW_TAG_SCHEME: &str =
    "view-tag-leak-control-window-v1";
pub const MONERO_L2_PQ_PRIVATE_CROSS_INPUT_DECOY_COORDINATOR_RUNTIME_DANDELION_SCHEME: &str =
    "dandelion-plus-plus-private-l2-relay-coordination-v1";
pub const MONERO_L2_PQ_PRIVATE_CROSS_INPUT_DECOY_COORDINATOR_RUNTIME_WATCHER_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-192f-decoy-watcher-attestation-v1";
pub const MONERO_L2_PQ_PRIVATE_CROSS_INPUT_DECOY_COORDINATOR_RUNTIME_INCIDENT_GATE_SCHEME: &str =
    "privacy-incident-quarantine-gate-v1";
pub const DEFAULT_MIN_DECOY_BUCKET_SIZE: u64 = 16_384;
pub const DEFAULT_MIN_DECOY_BUCKET_ENTROPY_BITS: u16 = 192;
pub const DEFAULT_MIN_BRIDGE_WITHDRAWAL_MIXIN: u16 = 48;
pub const DEFAULT_MIN_PLAIN_WITHDRAWAL_MIXIN: u16 = 32;
pub const DEFAULT_VIEW_TAG_WINDOW_BLOCKS: u64 = 72;
pub const DEFAULT_MAX_VIEW_TAG_REUSE: u16 = 2;
pub const DEFAULT_DANDELION_STEM_HOPS: u8 = 6;
pub const DEFAULT_DANDELION_FLUFF_FANOUT: u8 = 4;
pub const DEFAULT_WATCHER_QUORUM: u16 = 5;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_INCIDENT_COOLDOWN_BLOCKS: u64 = 144;
pub const MAX_DECOY_BUCKETS: usize = 1_048_576;
pub const MAX_BUCKET_PROOFS: usize = 2_097_152;
pub const MAX_SPEND_GRAPH_REDACTIONS: usize = 1_048_576;
pub const MAX_WITHDRAWAL_MIXIN_FLOORS: usize = 524_288;
pub const MAX_VIEW_TAG_CONTROLS: usize = 1_048_576;
pub const MAX_DANDELION_PLANS: usize = 1_048_576;
pub const MAX_WATCHER_ATTESTATIONS: usize = 2_097_152;
pub const MAX_PRIVACY_INCIDENT_GATES: usize = 262_144;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecoyBucketKind {
    RingMember,
    BridgeWithdrawal,
    VaultSweep,
    LiquidityRebalance,
    IncidentRecovery,
    AuditCanary,
}

impl DecoyBucketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RingMember => "ring_member",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::VaultSweep => "vault_sweep",
            Self::LiquidityRebalance => "liquidity_rebalance",
            Self::IncidentRecovery => "incident_recovery",
            Self::AuditCanary => "audit_canary",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecoyProofStatus {
    Committed,
    Verified,
    Rejected,
    Expired,
    Quarantined,
}

impl DecoyProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Verified => "verified",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpendGraphRedactionStatus {
    Draft,
    Committed,
    Attested,
    Released,
    Quarantined,
}

impl SpendGraphRedactionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Committed => "committed",
            Self::Attested => "attested",
            Self::Released => "released",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalClass {
    Plain,
    Bridge,
    Vault,
    Emergency,
    Watchtower,
}

impl WithdrawalClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Bridge => "bridge",
            Self::Vault => "vault",
            Self::Emergency => "emergency",
            Self::Watchtower => "watchtower",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewTagControlStatus {
    Open,
    Throttled,
    Sealed,
    Quarantined,
    Released,
}

impl ViewTagControlStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Throttled => "throttled",
            Self::Sealed => "sealed",
            Self::Quarantined => "quarantined",
            Self::Released => "released",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DandelionRelayPhase {
    Stem,
    Fluff,
    Hold,
    Dropped,
    Released,
}

impl DandelionRelayPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stem => "stem",
            Self::Fluff => "fluff",
            Self::Hold => "hold",
            Self::Dropped => "dropped",
            Self::Released => "released",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatcherAttestationStatus {
    Observed,
    Accepted,
    Superseded,
    Slashed,
    Expired,
}

impl WatcherAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Accepted => "accepted",
            Self::Superseded => "superseded",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyIncidentSeverity {
    Notice,
    Elevated,
    Severe,
    Critical,
}

impl PrivacyIncidentSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Notice => "notice",
            Self::Elevated => "elevated",
            Self::Severe => "severe",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyIncidentGateStatus {
    Open,
    Active,
    CoolingDown,
    Resolved,
    Rejected,
}

impl PrivacyIncidentGateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Active => "active",
            Self::CoolingDown => "cooling_down",
            Self::Resolved => "resolved",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub devnet_height: u64,
    pub min_decoy_bucket_size: u64,
    pub min_decoy_bucket_entropy_bits: u16,
    pub min_bridge_withdrawal_mixin: u16,
    pub min_plain_withdrawal_mixin: u16,
    pub view_tag_window_blocks: u64,
    pub max_view_tag_reuse: u16,
    pub dandelion_stem_hops: u8,
    pub dandelion_fluff_fanout: u8,
    pub watcher_quorum: u16,
    pub target_pq_security_bits: u16,
    pub incident_cooldown_blocks: u64,
    pub enforce_incident_gates: bool,
    pub require_pq_watcher_quorum: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            monero_network:
                MONERO_L2_PQ_PRIVATE_CROSS_INPUT_DECOY_COORDINATOR_RUNTIME_MONERO_NETWORK
                    .to_string(),
            l2_network: MONERO_L2_PQ_PRIVATE_CROSS_INPUT_DECOY_COORDINATOR_RUNTIME_L2_NETWORK
                .to_string(),
            devnet_height: MONERO_L2_PQ_PRIVATE_CROSS_INPUT_DECOY_COORDINATOR_RUNTIME_DEVNET_HEIGHT,
            min_decoy_bucket_size: DEFAULT_MIN_DECOY_BUCKET_SIZE,
            min_decoy_bucket_entropy_bits: DEFAULT_MIN_DECOY_BUCKET_ENTROPY_BITS,
            min_bridge_withdrawal_mixin: DEFAULT_MIN_BRIDGE_WITHDRAWAL_MIXIN,
            min_plain_withdrawal_mixin: DEFAULT_MIN_PLAIN_WITHDRAWAL_MIXIN,
            view_tag_window_blocks: DEFAULT_VIEW_TAG_WINDOW_BLOCKS,
            max_view_tag_reuse: DEFAULT_MAX_VIEW_TAG_REUSE,
            dandelion_stem_hops: DEFAULT_DANDELION_STEM_HOPS,
            dandelion_fluff_fanout: DEFAULT_DANDELION_FLUFF_FANOUT,
            watcher_quorum: DEFAULT_WATCHER_QUORUM,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            incident_cooldown_blocks: DEFAULT_INCIDENT_COOLDOWN_BLOCKS,
            enforce_incident_gates: true,
            require_pq_watcher_quorum: true,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub decoy_buckets: u64,
    pub bucket_proofs: u64,
    pub spend_graph_redactions: u64,
    pub withdrawal_mixin_floors: u64,
    pub view_tag_controls: u64,
    pub dandelion_plans: u64,
    pub watcher_attestations: u64,
    pub privacy_incident_gates: u64,
    pub accepted_watcher_attestations: u64,
    pub active_incident_gates: u64,
    pub rejected_records: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Roots {
    pub decoy_bucket_root: String,
    pub bucket_proof_root: String,
    pub spend_graph_redaction_root: String,
    pub withdrawal_mixin_floor_root: String,
    pub view_tag_control_root: String,
    pub dandelion_plan_root: String,
    pub watcher_attestation_root: String,
    pub privacy_incident_gate_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecoyBucketRequest {
    pub bucket_id: String,
    pub kind: DecoyBucketKind,
    pub anchor_height: u64,
    pub ring_member_count: u64,
    pub entropy_bits: u16,
    pub age_floor_blocks: u64,
    pub amount_class_commitment: String,
    pub membership_root: String,
    pub policy_digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecoyBucketRecord {
    pub bucket_id: String,
    pub kind: DecoyBucketKind,
    pub anchor_height: u64,
    pub ring_member_count: u64,
    pub entropy_bits: u16,
    pub age_floor_blocks: u64,
    pub amount_class_commitment: String,
    pub membership_root: String,
    pub policy_digest: String,
    pub accepted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BucketProofRequest {
    pub proof_id: String,
    pub bucket_id: String,
    pub input_set_id: String,
    pub proof_root: String,
    pub nullifier_root: String,
    pub decoy_count: u64,
    pub status: DecoyProofStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BucketProofRecord {
    pub proof_id: String,
    pub bucket_id: String,
    pub input_set_id: String,
    pub proof_root: String,
    pub nullifier_root: String,
    pub decoy_count: u64,
    pub status: DecoyProofStatus,
    pub accepted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpendGraphRedactionRequest {
    pub redaction_id: String,
    pub input_set_id: String,
    pub redacted_graph_root: String,
    pub edge_commitment_root: String,
    pub removed_edge_count: u64,
    pub preserved_component_count: u64,
    pub status: SpendGraphRedactionStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpendGraphRedactionRecord {
    pub redaction_id: String,
    pub input_set_id: String,
    pub redacted_graph_root: String,
    pub edge_commitment_root: String,
    pub removed_edge_count: u64,
    pub preserved_component_count: u64,
    pub status: SpendGraphRedactionStatus,
    pub accepted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WithdrawalMixinFloorRequest {
    pub floor_id: String,
    pub withdrawal_class: WithdrawalClass,
    pub asset_commitment: String,
    pub min_mixin: u16,
    pub effective_height: u64,
    pub expires_height: u64,
    pub reason_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WithdrawalMixinFloorRecord {
    pub floor_id: String,
    pub withdrawal_class: WithdrawalClass,
    pub asset_commitment: String,
    pub min_mixin: u16,
    pub effective_height: u64,
    pub expires_height: u64,
    pub reason_root: String,
    pub accepted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ViewTagControlRequest {
    pub control_id: String,
    pub view_tag_prefix: String,
    pub subaddress_domain: String,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub observed_reuse_count: u16,
    pub leak_score: u16,
    pub status: ViewTagControlStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ViewTagControlRecord {
    pub control_id: String,
    pub view_tag_prefix: String,
    pub subaddress_domain: String,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub observed_reuse_count: u16,
    pub leak_score: u16,
    pub status: ViewTagControlStatus,
    pub accepted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DandelionRelayPlanRequest {
    pub plan_id: String,
    pub input_set_id: String,
    pub stem_route_root: String,
    pub fluff_route_root: String,
    pub stem_hops: u8,
    pub fluff_fanout: u8,
    pub phase: DandelionRelayPhase,
    pub relay_epoch: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DandelionRelayPlanRecord {
    pub plan_id: String,
    pub input_set_id: String,
    pub stem_route_root: String,
    pub fluff_route_root: String,
    pub stem_hops: u8,
    pub fluff_fanout: u8,
    pub phase: DandelionRelayPhase,
    pub relay_epoch: u64,
    pub accepted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqWatcherAttestationRequest {
    pub attestation_id: String,
    pub watcher_id: String,
    pub subject_id: String,
    pub subject_root: String,
    pub signature_root: String,
    pub pq_security_bits: u16,
    pub status: WatcherAttestationStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqWatcherAttestationRecord {
    pub attestation_id: String,
    pub watcher_id: String,
    pub subject_id: String,
    pub subject_root: String,
    pub signature_root: String,
    pub pq_security_bits: u16,
    pub status: WatcherAttestationStatus,
    pub accepted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyIncidentGateRequest {
    pub gate_id: String,
    pub incident_root: String,
    pub severity: PrivacyIncidentSeverity,
    pub scope_root: String,
    pub opened_height: u64,
    pub cooldown_until_height: u64,
    pub status: PrivacyIncidentGateStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyIncidentGateRecord {
    pub gate_id: String,
    pub incident_root: String,
    pub severity: PrivacyIncidentSeverity,
    pub scope_root: String,
    pub opened_height: u64,
    pub cooldown_until_height: u64,
    pub status: PrivacyIncidentGateStatus,
    pub accepted: bool,
}

impl DecoyBucketRequest {
    pub fn digest(&self) -> String {
        stable_digest("DecoyBucketRequest", self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "kind": self.kind.as_str(),
            "anchor_height": self.anchor_height,
            "ring_member_count": self.ring_member_count,
            "entropy_bits": self.entropy_bits,
            "age_floor_blocks": self.age_floor_blocks,
            "amount_class_commitment": self.amount_class_commitment,
            "membership_root": self.membership_root,
            "policy_digest": self.policy_digest,
        })
    }
}

impl DecoyBucketRecord {
    pub fn digest(&self) -> String {
        stable_digest("DecoyBucketRecord", self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "kind": self.kind.as_str(),
            "anchor_height": self.anchor_height,
            "ring_member_count": self.ring_member_count,
            "entropy_bits": self.entropy_bits,
            "age_floor_blocks": self.age_floor_blocks,
            "amount_class_commitment": self.amount_class_commitment,
            "membership_root": self.membership_root,
            "policy_digest": self.policy_digest,
            "accepted": self.accepted,
        })
    }
}

impl BucketProofRequest {
    pub fn digest(&self) -> String {
        stable_digest("BucketProofRequest", self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "bucket_id": self.bucket_id,
            "input_set_id": self.input_set_id,
            "proof_root": self.proof_root,
            "nullifier_root": self.nullifier_root,
            "decoy_count": self.decoy_count,
            "status": self.status.as_str(),
        })
    }
}

impl BucketProofRecord {
    pub fn digest(&self) -> String {
        stable_digest("BucketProofRecord", self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "bucket_id": self.bucket_id,
            "input_set_id": self.input_set_id,
            "proof_root": self.proof_root,
            "nullifier_root": self.nullifier_root,
            "decoy_count": self.decoy_count,
            "status": self.status.as_str(),
            "accepted": self.accepted,
        })
    }
}

impl SpendGraphRedactionRequest {
    pub fn digest(&self) -> String {
        stable_digest("SpendGraphRedactionRequest", self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "redaction_id": self.redaction_id,
            "input_set_id": self.input_set_id,
            "redacted_graph_root": self.redacted_graph_root,
            "edge_commitment_root": self.edge_commitment_root,
            "removed_edge_count": self.removed_edge_count,
            "preserved_component_count": self.preserved_component_count,
            "status": self.status.as_str(),
        })
    }
}

impl SpendGraphRedactionRecord {
    pub fn digest(&self) -> String {
        stable_digest("SpendGraphRedactionRecord", self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "redaction_id": self.redaction_id,
            "input_set_id": self.input_set_id,
            "redacted_graph_root": self.redacted_graph_root,
            "edge_commitment_root": self.edge_commitment_root,
            "removed_edge_count": self.removed_edge_count,
            "preserved_component_count": self.preserved_component_count,
            "status": self.status.as_str(),
            "accepted": self.accepted,
        })
    }
}

impl WithdrawalMixinFloorRequest {
    pub fn digest(&self) -> String {
        stable_digest("WithdrawalMixinFloorRequest", self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "floor_id": self.floor_id,
            "withdrawal_class": self.withdrawal_class.as_str(),
            "asset_commitment": self.asset_commitment,
            "min_mixin": self.min_mixin,
            "effective_height": self.effective_height,
            "expires_height": self.expires_height,
            "reason_root": self.reason_root,
        })
    }
}

impl WithdrawalMixinFloorRecord {
    pub fn digest(&self) -> String {
        stable_digest("WithdrawalMixinFloorRecord", self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "floor_id": self.floor_id,
            "withdrawal_class": self.withdrawal_class.as_str(),
            "asset_commitment": self.asset_commitment,
            "min_mixin": self.min_mixin,
            "effective_height": self.effective_height,
            "expires_height": self.expires_height,
            "reason_root": self.reason_root,
            "accepted": self.accepted,
        })
    }
}

impl ViewTagControlRequest {
    pub fn digest(&self) -> String {
        stable_digest("ViewTagControlRequest", self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "control_id": self.control_id,
            "view_tag_prefix": self.view_tag_prefix,
            "subaddress_domain": self.subaddress_domain,
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "observed_reuse_count": self.observed_reuse_count,
            "leak_score": self.leak_score,
            "status": self.status.as_str(),
        })
    }
}

impl ViewTagControlRecord {
    pub fn digest(&self) -> String {
        stable_digest("ViewTagControlRecord", self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "control_id": self.control_id,
            "view_tag_prefix": self.view_tag_prefix,
            "subaddress_domain": self.subaddress_domain,
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "observed_reuse_count": self.observed_reuse_count,
            "leak_score": self.leak_score,
            "status": self.status.as_str(),
            "accepted": self.accepted,
        })
    }
}

impl DandelionRelayPlanRequest {
    pub fn digest(&self) -> String {
        stable_digest("DandelionRelayPlanRequest", self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "plan_id": self.plan_id,
            "input_set_id": self.input_set_id,
            "stem_route_root": self.stem_route_root,
            "fluff_route_root": self.fluff_route_root,
            "stem_hops": self.stem_hops,
            "fluff_fanout": self.fluff_fanout,
            "phase": self.phase.as_str(),
            "relay_epoch": self.relay_epoch,
        })
    }
}

impl DandelionRelayPlanRecord {
    pub fn digest(&self) -> String {
        stable_digest("DandelionRelayPlanRecord", self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "plan_id": self.plan_id,
            "input_set_id": self.input_set_id,
            "stem_route_root": self.stem_route_root,
            "fluff_route_root": self.fluff_route_root,
            "stem_hops": self.stem_hops,
            "fluff_fanout": self.fluff_fanout,
            "phase": self.phase.as_str(),
            "relay_epoch": self.relay_epoch,
            "accepted": self.accepted,
        })
    }
}

impl PqWatcherAttestationRequest {
    pub fn digest(&self) -> String {
        stable_digest("PqWatcherAttestationRequest", self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "watcher_id": self.watcher_id,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "signature_root": self.signature_root,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status.as_str(),
        })
    }
}

impl PqWatcherAttestationRecord {
    pub fn digest(&self) -> String {
        stable_digest("PqWatcherAttestationRecord", self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "watcher_id": self.watcher_id,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "signature_root": self.signature_root,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status.as_str(),
            "accepted": self.accepted,
        })
    }
}

impl PrivacyIncidentGateRequest {
    pub fn digest(&self) -> String {
        stable_digest("PrivacyIncidentGateRequest", self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "gate_id": self.gate_id,
            "incident_root": self.incident_root,
            "severity": self.severity.as_str(),
            "scope_root": self.scope_root,
            "opened_height": self.opened_height,
            "cooldown_until_height": self.cooldown_until_height,
            "status": self.status.as_str(),
        })
    }
}

impl PrivacyIncidentGateRecord {
    pub fn digest(&self) -> String {
        stable_digest("PrivacyIncidentGateRecord", self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "gate_id": self.gate_id,
            "incident_root": self.incident_root,
            "severity": self.severity.as_str(),
            "scope_root": self.scope_root,
            "opened_height": self.opened_height,
            "cooldown_until_height": self.cooldown_until_height,
            "status": self.status.as_str(),
            "accepted": self.accepted,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub decoy_buckets: BTreeMap<String, DecoyBucketRecord>,
    pub bucket_proofs: BTreeMap<String, BucketProofRecord>,
    pub spend_graph_redactions: BTreeMap<String, SpendGraphRedactionRecord>,
    pub withdrawal_mixin_floors: BTreeMap<String, WithdrawalMixinFloorRecord>,
    pub view_tag_controls: BTreeMap<String, ViewTagControlRecord>,
    pub dandelion_plans: BTreeMap<String, DandelionRelayPlanRecord>,
    pub watcher_attestations: BTreeMap<String, PqWatcherAttestationRecord>,
    pub privacy_incident_gates: BTreeMap<String, PrivacyIncidentGateRecord>,
    pub watcher_subject_index: BTreeMap<String, BTreeSet<String>>,
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            decoy_buckets: BTreeMap::new(),
            bucket_proofs: BTreeMap::new(),
            spend_graph_redactions: BTreeMap::new(),
            withdrawal_mixin_floors: BTreeMap::new(),
            view_tag_controls: BTreeMap::new(),
            dandelion_plans: BTreeMap::new(),
            watcher_attestations: BTreeMap::new(),
            privacy_incident_gates: BTreeMap::new(),
            watcher_subject_index: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet())
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let _ = state.record_decoy_bucket(DecoyBucketRequest {
            bucket_id: "bucket-demo-001".to_string(),
            kind: DecoyBucketKind::BridgeWithdrawal,
            anchor_height: state.config.devnet_height,
            ring_member_count: 65_536,
            entropy_bits: 224,
            age_floor_blocks: 720,
            amount_class_commitment: "amount-class-root-demo".to_string(),
            membership_root: "membership-root-demo".to_string(),
            policy_digest: "policy-digest-demo".to_string(),
        });
        let _ = state.record_bucket_proof(BucketProofRequest {
            proof_id: "proof-demo-001".to_string(),
            bucket_id: "bucket-demo-001".to_string(),
            input_set_id: "input-set-demo-001".to_string(),
            proof_root: "proof-root-demo".to_string(),
            nullifier_root: "nullifier-root-demo".to_string(),
            decoy_count: 64,
            status: DecoyProofStatus::Verified,
        });
        let _ = state.record_spend_graph_redaction(SpendGraphRedactionRequest {
            redaction_id: "redaction-demo-001".to_string(),
            input_set_id: "input-set-demo-001".to_string(),
            redacted_graph_root: "redacted-graph-root-demo".to_string(),
            edge_commitment_root: "edge-root-demo".to_string(),
            removed_edge_count: 17,
            preserved_component_count: 4,
            status: SpendGraphRedactionStatus::Attested,
        });
        let _ = state.record_withdrawal_mixin_floor(WithdrawalMixinFloorRequest {
            floor_id: "floor-demo-001".to_string(),
            withdrawal_class: WithdrawalClass::Bridge,
            asset_commitment: "xmr-asset-commitment-demo".to_string(),
            min_mixin: 64,
            effective_height: state.config.devnet_height,
            expires_height: state.config.devnet_height + 144,
            reason_root: "mixin-floor-reason-demo".to_string(),
        });
        let _ = state.record_view_tag_control(ViewTagControlRequest {
            control_id: "viewtag-demo-001".to_string(),
            view_tag_prefix: "7f".to_string(),
            subaddress_domain: "bridge-withdrawals".to_string(),
            window_start_height: state.config.devnet_height,
            window_end_height: state.config.devnet_height + state.config.view_tag_window_blocks,
            observed_reuse_count: 1,
            leak_score: 8,
            status: ViewTagControlStatus::Open,
        });
        let _ = state.record_dandelion_relay_plan(DandelionRelayPlanRequest {
            plan_id: "dandelion-demo-001".to_string(),
            input_set_id: "input-set-demo-001".to_string(),
            stem_route_root: "stem-route-root-demo".to_string(),
            fluff_route_root: "fluff-route-root-demo".to_string(),
            stem_hops: state.config.dandelion_stem_hops,
            fluff_fanout: state.config.dandelion_fluff_fanout,
            phase: DandelionRelayPhase::Stem,
            relay_epoch: 1,
        });
        for watcher in [
            "watcher-a",
            "watcher-b",
            "watcher-c",
            "watcher-d",
            "watcher-e",
        ] {
            let _ = state.record_pq_watcher_attestation(PqWatcherAttestationRequest {
                attestation_id: format!("attestation-demo-{}", watcher),
                watcher_id: watcher.to_string(),
                subject_id: "proof-demo-001".to_string(),
                subject_root: "proof-root-demo".to_string(),
                signature_root: format!("signature-root-demo-{}", watcher),
                pq_security_bits: state.config.target_pq_security_bits,
                status: WatcherAttestationStatus::Accepted,
            });
        }
        let _ = state.record_privacy_incident_gate(PrivacyIncidentGateRequest {
            gate_id: "gate-demo-001".to_string(),
            incident_root: "incident-root-demo".to_string(),
            severity: PrivacyIncidentSeverity::Notice,
            scope_root: "scope-root-demo".to_string(),
            opened_height: state.config.devnet_height,
            cooldown_until_height: state.config.devnet_height
                + state.config.incident_cooldown_blocks,
            status: PrivacyIncidentGateStatus::Resolved,
        });
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": MONERO_L2_PQ_PRIVATE_CROSS_INPUT_DECOY_COORDINATOR_RUNTIME_SCHEMA_VERSION,
            "config": self.config,
            "counters": self.counters,
            "roots": self.roots,
            "decoy_buckets": self.decoy_buckets.values().map(DecoyBucketRecord::public_record).collect::<Vec<_>>(),
            "bucket_proofs": self.bucket_proofs.values().map(BucketProofRecord::public_record).collect::<Vec<_>>(),
            "spend_graph_redactions": self.spend_graph_redactions.values().map(SpendGraphRedactionRecord::public_record).collect::<Vec<_>>(),
            "withdrawal_mixin_floors": self.withdrawal_mixin_floors.values().map(WithdrawalMixinFloorRecord::public_record).collect::<Vec<_>>(),
            "view_tag_controls": self.view_tag_controls.values().map(ViewTagControlRecord::public_record).collect::<Vec<_>>(),
            "dandelion_plans": self.dandelion_plans.values().map(DandelionRelayPlanRecord::public_record).collect::<Vec<_>>(),
            "watcher_attestations": self.watcher_attestations.values().map(PqWatcherAttestationRecord::public_record).collect::<Vec<_>>(),
            "privacy_incident_gates": self.privacy_incident_gates.values().map(PrivacyIncidentGateRecord::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn record_decoy_bucket(
        &mut self,
        request: DecoyBucketRequest,
    ) -> Result<DecoyBucketRecord> {
        if self.decoy_buckets.len() >= MAX_DECOY_BUCKETS {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
            return Err("decoy_buckets capacity reached".to_string());
        }
        if request.bucket_id.is_empty() {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
            return Err("record id must be non-empty".to_string());
        }
        let accepted = request.ring_member_count >= self.config.min_decoy_bucket_size
            && request.entropy_bits >= self.config.min_decoy_bucket_entropy_bits;
        let record = DecoyBucketRecord {
            bucket_id: request.bucket_id,
            kind: request.kind,
            anchor_height: request.anchor_height,
            ring_member_count: request.ring_member_count,
            entropy_bits: request.entropy_bits,
            age_floor_blocks: request.age_floor_blocks,
            amount_class_commitment: request.amount_class_commitment,
            membership_root: request.membership_root,
            policy_digest: request.policy_digest,
            accepted,
        };
        if accepted {
            self.counters.decoy_buckets = self.counters.decoy_buckets.saturating_add(1);
        } else {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
        }
        self.decoy_buckets
            .insert(record.bucket_id.clone(), record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn record_bucket_proof(
        &mut self,
        request: BucketProofRequest,
    ) -> Result<BucketProofRecord> {
        if self.bucket_proofs.len() >= MAX_BUCKET_PROOFS {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
            return Err("bucket_proofs capacity reached".to_string());
        }
        if request.proof_id.is_empty() {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
            return Err("record id must be non-empty".to_string());
        }
        let accepted = self.decoy_buckets.contains_key(&request.bucket_id)
            && matches!(
                request.status,
                DecoyProofStatus::Verified | DecoyProofStatus::Committed
            );
        let record = BucketProofRecord {
            proof_id: request.proof_id,
            bucket_id: request.bucket_id,
            input_set_id: request.input_set_id,
            proof_root: request.proof_root,
            nullifier_root: request.nullifier_root,
            decoy_count: request.decoy_count,
            status: request.status,
            accepted,
        };
        if accepted {
            self.counters.bucket_proofs = self.counters.bucket_proofs.saturating_add(1);
        } else {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
        }
        self.bucket_proofs
            .insert(record.proof_id.clone(), record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn record_spend_graph_redaction(
        &mut self,
        request: SpendGraphRedactionRequest,
    ) -> Result<SpendGraphRedactionRecord> {
        if self.spend_graph_redactions.len() >= MAX_SPEND_GRAPH_REDACTIONS {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
            return Err("spend_graph_redactions capacity reached".to_string());
        }
        if request.redaction_id.is_empty() {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
            return Err("record id must be non-empty".to_string());
        }
        let accepted = request.preserved_component_count > 0
            && matches!(
                request.status,
                SpendGraphRedactionStatus::Committed | SpendGraphRedactionStatus::Attested
            );
        let record = SpendGraphRedactionRecord {
            redaction_id: request.redaction_id,
            input_set_id: request.input_set_id,
            redacted_graph_root: request.redacted_graph_root,
            edge_commitment_root: request.edge_commitment_root,
            removed_edge_count: request.removed_edge_count,
            preserved_component_count: request.preserved_component_count,
            status: request.status,
            accepted,
        };
        if accepted {
            self.counters.spend_graph_redactions =
                self.counters.spend_graph_redactions.saturating_add(1);
        } else {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
        }
        self.spend_graph_redactions
            .insert(record.redaction_id.clone(), record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn record_withdrawal_mixin_floor(
        &mut self,
        request: WithdrawalMixinFloorRequest,
    ) -> Result<WithdrawalMixinFloorRecord> {
        if self.withdrawal_mixin_floors.len() >= MAX_WITHDRAWAL_MIXIN_FLOORS {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
            return Err("withdrawal_mixin_floors capacity reached".to_string());
        }
        if request.floor_id.is_empty() {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
            return Err("record id must be non-empty".to_string());
        }
        let required = self.required_mixin_floor(request.withdrawal_class);
        let accepted =
            request.min_mixin >= required && request.expires_height > request.effective_height;
        let record = WithdrawalMixinFloorRecord {
            floor_id: request.floor_id,
            withdrawal_class: request.withdrawal_class,
            asset_commitment: request.asset_commitment,
            min_mixin: request.min_mixin,
            effective_height: request.effective_height,
            expires_height: request.expires_height,
            reason_root: request.reason_root,
            accepted,
        };
        if accepted {
            self.counters.withdrawal_mixin_floors =
                self.counters.withdrawal_mixin_floors.saturating_add(1);
        } else {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
        }
        self.withdrawal_mixin_floors
            .insert(record.floor_id.clone(), record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn record_view_tag_control(
        &mut self,
        request: ViewTagControlRequest,
    ) -> Result<ViewTagControlRecord> {
        if self.view_tag_controls.len() >= MAX_VIEW_TAG_CONTROLS {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
            return Err("view_tag_controls capacity reached".to_string());
        }
        if request.control_id.is_empty() {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
            return Err("record id must be non-empty".to_string());
        }
        let accepted = request.window_end_height > request.window_start_height
            && request.window_end_height - request.window_start_height
                <= self.config.view_tag_window_blocks
            && request.observed_reuse_count <= self.config.max_view_tag_reuse;
        let record = ViewTagControlRecord {
            control_id: request.control_id,
            view_tag_prefix: request.view_tag_prefix,
            subaddress_domain: request.subaddress_domain,
            window_start_height: request.window_start_height,
            window_end_height: request.window_end_height,
            observed_reuse_count: request.observed_reuse_count,
            leak_score: request.leak_score,
            status: request.status,
            accepted,
        };
        if accepted {
            self.counters.view_tag_controls = self.counters.view_tag_controls.saturating_add(1);
        } else {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
        }
        self.view_tag_controls
            .insert(record.control_id.clone(), record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn record_dandelion_relay_plan(
        &mut self,
        request: DandelionRelayPlanRequest,
    ) -> Result<DandelionRelayPlanRecord> {
        if self.dandelion_plans.len() >= MAX_DANDELION_PLANS {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
            return Err("dandelion_plans capacity reached".to_string());
        }
        if request.plan_id.is_empty() {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
            return Err("record id must be non-empty".to_string());
        }
        let accepted = request.stem_hops >= self.config.dandelion_stem_hops
            && request.fluff_fanout >= self.config.dandelion_fluff_fanout
            && matches!(
                request.phase,
                DandelionRelayPhase::Stem | DandelionRelayPhase::Fluff | DandelionRelayPhase::Hold
            );
        let record = DandelionRelayPlanRecord {
            plan_id: request.plan_id,
            input_set_id: request.input_set_id,
            stem_route_root: request.stem_route_root,
            fluff_route_root: request.fluff_route_root,
            stem_hops: request.stem_hops,
            fluff_fanout: request.fluff_fanout,
            phase: request.phase,
            relay_epoch: request.relay_epoch,
            accepted,
        };
        if accepted {
            self.counters.dandelion_plans = self.counters.dandelion_plans.saturating_add(1);
        } else {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
        }
        self.dandelion_plans
            .insert(record.plan_id.clone(), record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn record_pq_watcher_attestation(
        &mut self,
        request: PqWatcherAttestationRequest,
    ) -> Result<PqWatcherAttestationRecord> {
        if self.watcher_attestations.len() >= MAX_WATCHER_ATTESTATIONS {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
            return Err("watcher_attestations capacity reached".to_string());
        }
        if request.attestation_id.is_empty() {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
            return Err("record id must be non-empty".to_string());
        }
        let accepted = request.pq_security_bits >= self.config.target_pq_security_bits
            && matches!(
                request.status,
                WatcherAttestationStatus::Accepted | WatcherAttestationStatus::Observed
            );
        let record = PqWatcherAttestationRecord {
            attestation_id: request.attestation_id,
            watcher_id: request.watcher_id,
            subject_id: request.subject_id,
            subject_root: request.subject_root,
            signature_root: request.signature_root,
            pq_security_bits: request.pq_security_bits,
            status: request.status,
            accepted,
        };
        if accepted {
            self.counters.accepted_watcher_attestations = self
                .counters
                .accepted_watcher_attestations
                .saturating_add(1);
            self.watcher_subject_index
                .entry(record.subject_id.clone())
                .or_default()
                .insert(record.watcher_id.clone());
        }
        if accepted {
            self.counters.watcher_attestations =
                self.counters.watcher_attestations.saturating_add(1);
        } else {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
        }
        self.watcher_attestations
            .insert(record.attestation_id.clone(), record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn record_privacy_incident_gate(
        &mut self,
        request: PrivacyIncidentGateRequest,
    ) -> Result<PrivacyIncidentGateRecord> {
        if self.privacy_incident_gates.len() >= MAX_PRIVACY_INCIDENT_GATES {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
            return Err("privacy_incident_gates capacity reached".to_string());
        }
        if request.gate_id.is_empty() {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
            return Err("record id must be non-empty".to_string());
        }
        let accepted = matches!(
            request.status,
            PrivacyIncidentGateStatus::Open
                | PrivacyIncidentGateStatus::Active
                | PrivacyIncidentGateStatus::CoolingDown
                | PrivacyIncidentGateStatus::Resolved
        ) && request.cooldown_until_height >= request.opened_height;
        let record = PrivacyIncidentGateRecord {
            gate_id: request.gate_id,
            incident_root: request.incident_root,
            severity: request.severity,
            scope_root: request.scope_root,
            opened_height: request.opened_height,
            cooldown_until_height: request.cooldown_until_height,
            status: request.status,
            accepted,
        };
        if accepted
            && matches!(
                record.status,
                PrivacyIncidentGateStatus::Active | PrivacyIncidentGateStatus::CoolingDown
            )
        {
            self.counters.active_incident_gates =
                self.counters.active_incident_gates.saturating_add(1);
        }
        if accepted {
            self.counters.privacy_incident_gates =
                self.counters.privacy_incident_gates.saturating_add(1);
        } else {
            self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
        }
        self.privacy_incident_gates
            .insert(record.gate_id.clone(), record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn required_mixin_floor(&self, withdrawal_class: WithdrawalClass) -> u16 {
        match withdrawal_class {
            WithdrawalClass::Bridge
            | WithdrawalClass::Vault
            | WithdrawalClass::Emergency
            | WithdrawalClass::Watchtower => self.config.min_bridge_withdrawal_mixin,
            WithdrawalClass::Plain => self.config.min_plain_withdrawal_mixin,
        }
    }

    pub fn watcher_quorum_met(&self, subject_id: &str) -> bool {
        match self.watcher_subject_index.get(subject_id) {
            Some(watchers) => watchers.len() >= usize::from(self.config.watcher_quorum),
            None => false,
        }
    }

    pub fn incident_gate_allows_release(&self, scope_root: &str) -> bool {
        if !self.config.enforce_incident_gates {
            return true;
        }
        !self.privacy_incident_gates.values().any(|gate| {
            gate.scope_root == scope_root
                && gate.accepted
                && matches!(
                    gate.status,
                    PrivacyIncidentGateStatus::Active | PrivacyIncidentGateStatus::CoolingDown
                )
        })
    }

    pub fn refresh_roots(&mut self) {
        self.roots.decoy_bucket_root = map_root(
            "decoy_buckets",
            self.decoy_buckets
                .values()
                .map(DecoyBucketRecord::digest)
                .collect(),
        );
        self.roots.bucket_proof_root = map_root(
            "bucket_proofs",
            self.bucket_proofs
                .values()
                .map(BucketProofRecord::digest)
                .collect(),
        );
        self.roots.spend_graph_redaction_root = map_root(
            "spend_graph_redactions",
            self.spend_graph_redactions
                .values()
                .map(SpendGraphRedactionRecord::digest)
                .collect(),
        );
        self.roots.withdrawal_mixin_floor_root = map_root(
            "withdrawal_mixin_floors",
            self.withdrawal_mixin_floors
                .values()
                .map(WithdrawalMixinFloorRecord::digest)
                .collect(),
        );
        self.roots.view_tag_control_root = map_root(
            "view_tag_controls",
            self.view_tag_controls
                .values()
                .map(ViewTagControlRecord::digest)
                .collect(),
        );
        self.roots.dandelion_plan_root = map_root(
            "dandelion_plans",
            self.dandelion_plans
                .values()
                .map(DandelionRelayPlanRecord::digest)
                .collect(),
        );
        self.roots.watcher_attestation_root = map_root(
            "watcher_attestations",
            self.watcher_attestations
                .values()
                .map(PqWatcherAttestationRecord::digest)
                .collect(),
        );
        self.roots.privacy_incident_gate_root = map_root(
            "privacy_incident_gates",
            self.privacy_incident_gates
                .values()
                .map(PrivacyIncidentGateRecord::digest)
                .collect(),
        );
        self.roots.state_root = stable_digest(
            "state",
            json!({
                "protocol_version": PROTOCOL_VERSION,
                "schema_version": MONERO_L2_PQ_PRIVATE_CROSS_INPUT_DECOY_COORDINATOR_RUNTIME_SCHEMA_VERSION,
                "decoy_bucket_root": self.roots.decoy_bucket_root,
                "bucket_proof_root": self.roots.bucket_proof_root,
                "spend_graph_redaction_root": self.roots.spend_graph_redaction_root,
                "withdrawal_mixin_floor_root": self.roots.withdrawal_mixin_floor_root,
                "view_tag_control_root": self.roots.view_tag_control_root,
                "dandelion_plan_root": self.roots.dandelion_plan_root,
                "watcher_attestation_root": self.roots.watcher_attestation_root,
                "privacy_incident_gate_root": self.roots.privacy_incident_gate_root,
                "counters": self.counters,
            }),
        );
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
    State::demo()
}

pub fn public_record() -> Value {
    demo().public_record()
}

pub fn state_root() -> String {
    demo().state_root()
}

fn stable_digest(domain: &str, value: Value) -> String {
    let encoded = canonical_json(value);
    domain_hash(
        domain,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(MONERO_L2_PQ_PRIVATE_CROSS_INPUT_DECOY_COORDINATOR_RUNTIME_HASH_SUITE),
            HashPart::Str(&encoded),
        ],
        32,
    )
}

fn map_root(domain: &str, mut leaves: Vec<String>) -> String {
    leaves.sort();
    if leaves.is_empty() {
        stable_digest(domain, json!({ "empty": true }))
    } else {
        let leaf_values = leaves.into_iter().map(Value::String).collect::<Vec<_>>();
        merkle_root(domain, &leaf_values)
    }
}

fn canonical_json(value: Value) -> String {
    match serde_json::to_string(&value) {
        Ok(encoded) => encoded,
        Err(error) => format!("serde-json-error:{error}"),
    }
}

pub fn privacy_policy_checkpoint_0001() -> Value {
    json!({
        "checkpoint": 1,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0002() -> Value {
    json!({
        "checkpoint": 2,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0003() -> Value {
    json!({
        "checkpoint": 3,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0004() -> Value {
    json!({
        "checkpoint": 4,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0005() -> Value {
    json!({
        "checkpoint": 5,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0006() -> Value {
    json!({
        "checkpoint": 6,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0007() -> Value {
    json!({
        "checkpoint": 7,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0008() -> Value {
    json!({
        "checkpoint": 8,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0009() -> Value {
    json!({
        "checkpoint": 9,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0010() -> Value {
    json!({
        "checkpoint": 10,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0011() -> Value {
    json!({
        "checkpoint": 11,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0012() -> Value {
    json!({
        "checkpoint": 12,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0013() -> Value {
    json!({
        "checkpoint": 13,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0014() -> Value {
    json!({
        "checkpoint": 14,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0015() -> Value {
    json!({
        "checkpoint": 15,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0016() -> Value {
    json!({
        "checkpoint": 16,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0017() -> Value {
    json!({
        "checkpoint": 17,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0018() -> Value {
    json!({
        "checkpoint": 18,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0019() -> Value {
    json!({
        "checkpoint": 19,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0020() -> Value {
    json!({
        "checkpoint": 20,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0021() -> Value {
    json!({
        "checkpoint": 21,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0022() -> Value {
    json!({
        "checkpoint": 22,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0023() -> Value {
    json!({
        "checkpoint": 23,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0024() -> Value {
    json!({
        "checkpoint": 24,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0025() -> Value {
    json!({
        "checkpoint": 25,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0026() -> Value {
    json!({
        "checkpoint": 26,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0027() -> Value {
    json!({
        "checkpoint": 27,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0028() -> Value {
    json!({
        "checkpoint": 28,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0029() -> Value {
    json!({
        "checkpoint": 29,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0030() -> Value {
    json!({
        "checkpoint": 30,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0031() -> Value {
    json!({
        "checkpoint": 31,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0032() -> Value {
    json!({
        "checkpoint": 32,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0033() -> Value {
    json!({
        "checkpoint": 33,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0034() -> Value {
    json!({
        "checkpoint": 34,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0035() -> Value {
    json!({
        "checkpoint": 35,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0036() -> Value {
    json!({
        "checkpoint": 36,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0037() -> Value {
    json!({
        "checkpoint": 37,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0038() -> Value {
    json!({
        "checkpoint": 38,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0039() -> Value {
    json!({
        "checkpoint": 39,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0040() -> Value {
    json!({
        "checkpoint": 40,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0041() -> Value {
    json!({
        "checkpoint": 41,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0042() -> Value {
    json!({
        "checkpoint": 42,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0043() -> Value {
    json!({
        "checkpoint": 43,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0044() -> Value {
    json!({
        "checkpoint": 44,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0045() -> Value {
    json!({
        "checkpoint": 45,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0046() -> Value {
    json!({
        "checkpoint": 46,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0047() -> Value {
    json!({
        "checkpoint": 47,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0048() -> Value {
    json!({
        "checkpoint": 48,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0049() -> Value {
    json!({
        "checkpoint": 49,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0050() -> Value {
    json!({
        "checkpoint": 50,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0051() -> Value {
    json!({
        "checkpoint": 51,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0052() -> Value {
    json!({
        "checkpoint": 52,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0053() -> Value {
    json!({
        "checkpoint": 53,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0054() -> Value {
    json!({
        "checkpoint": 54,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0055() -> Value {
    json!({
        "checkpoint": 55,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0056() -> Value {
    json!({
        "checkpoint": 56,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0057() -> Value {
    json!({
        "checkpoint": 57,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0058() -> Value {
    json!({
        "checkpoint": 58,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0059() -> Value {
    json!({
        "checkpoint": 59,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0060() -> Value {
    json!({
        "checkpoint": 60,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0061() -> Value {
    json!({
        "checkpoint": 61,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0062() -> Value {
    json!({
        "checkpoint": 62,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0063() -> Value {
    json!({
        "checkpoint": 63,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0064() -> Value {
    json!({
        "checkpoint": 64,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0065() -> Value {
    json!({
        "checkpoint": 65,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0066() -> Value {
    json!({
        "checkpoint": 66,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0067() -> Value {
    json!({
        "checkpoint": 67,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0068() -> Value {
    json!({
        "checkpoint": 68,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0069() -> Value {
    json!({
        "checkpoint": 69,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0070() -> Value {
    json!({
        "checkpoint": 70,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0071() -> Value {
    json!({
        "checkpoint": 71,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0072() -> Value {
    json!({
        "checkpoint": 72,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0073() -> Value {
    json!({
        "checkpoint": 73,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0074() -> Value {
    json!({
        "checkpoint": 74,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0075() -> Value {
    json!({
        "checkpoint": 75,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0076() -> Value {
    json!({
        "checkpoint": 76,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0077() -> Value {
    json!({
        "checkpoint": 77,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0078() -> Value {
    json!({
        "checkpoint": 78,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0079() -> Value {
    json!({
        "checkpoint": 79,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0080() -> Value {
    json!({
        "checkpoint": 80,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0081() -> Value {
    json!({
        "checkpoint": 81,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0082() -> Value {
    json!({
        "checkpoint": 82,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0083() -> Value {
    json!({
        "checkpoint": 83,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0084() -> Value {
    json!({
        "checkpoint": 84,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0085() -> Value {
    json!({
        "checkpoint": 85,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0086() -> Value {
    json!({
        "checkpoint": 86,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0087() -> Value {
    json!({
        "checkpoint": 87,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0088() -> Value {
    json!({
        "checkpoint": 88,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0089() -> Value {
    json!({
        "checkpoint": 89,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0090() -> Value {
    json!({
        "checkpoint": 90,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0091() -> Value {
    json!({
        "checkpoint": 91,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0092() -> Value {
    json!({
        "checkpoint": 92,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0093() -> Value {
    json!({
        "checkpoint": 93,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0094() -> Value {
    json!({
        "checkpoint": 94,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0095() -> Value {
    json!({
        "checkpoint": 95,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0096() -> Value {
    json!({
        "checkpoint": 96,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0097() -> Value {
    json!({
        "checkpoint": 97,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0098() -> Value {
    json!({
        "checkpoint": 98,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0099() -> Value {
    json!({
        "checkpoint": 99,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0100() -> Value {
    json!({
        "checkpoint": 100,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0101() -> Value {
    json!({
        "checkpoint": 101,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0102() -> Value {
    json!({
        "checkpoint": 102,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0103() -> Value {
    json!({
        "checkpoint": 103,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0104() -> Value {
    json!({
        "checkpoint": 104,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0105() -> Value {
    json!({
        "checkpoint": 105,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0106() -> Value {
    json!({
        "checkpoint": 106,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0107() -> Value {
    json!({
        "checkpoint": 107,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0108() -> Value {
    json!({
        "checkpoint": 108,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0109() -> Value {
    json!({
        "checkpoint": 109,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0110() -> Value {
    json!({
        "checkpoint": 110,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0111() -> Value {
    json!({
        "checkpoint": 111,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0112() -> Value {
    json!({
        "checkpoint": 112,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0113() -> Value {
    json!({
        "checkpoint": 113,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0114() -> Value {
    json!({
        "checkpoint": 114,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0115() -> Value {
    json!({
        "checkpoint": 115,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0116() -> Value {
    json!({
        "checkpoint": 116,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0117() -> Value {
    json!({
        "checkpoint": 117,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0118() -> Value {
    json!({
        "checkpoint": 118,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0119() -> Value {
    json!({
        "checkpoint": 119,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0120() -> Value {
    json!({
        "checkpoint": 120,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0121() -> Value {
    json!({
        "checkpoint": 121,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0122() -> Value {
    json!({
        "checkpoint": 122,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0123() -> Value {
    json!({
        "checkpoint": 123,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0124() -> Value {
    json!({
        "checkpoint": 124,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0125() -> Value {
    json!({
        "checkpoint": 125,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0126() -> Value {
    json!({
        "checkpoint": 126,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0127() -> Value {
    json!({
        "checkpoint": 127,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0128() -> Value {
    json!({
        "checkpoint": 128,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0129() -> Value {
    json!({
        "checkpoint": 129,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0130() -> Value {
    json!({
        "checkpoint": 130,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0131() -> Value {
    json!({
        "checkpoint": 131,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0132() -> Value {
    json!({
        "checkpoint": 132,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0133() -> Value {
    json!({
        "checkpoint": 133,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0134() -> Value {
    json!({
        "checkpoint": 134,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0135() -> Value {
    json!({
        "checkpoint": 135,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0136() -> Value {
    json!({
        "checkpoint": 136,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0137() -> Value {
    json!({
        "checkpoint": 137,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0138() -> Value {
    json!({
        "checkpoint": 138,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0139() -> Value {
    json!({
        "checkpoint": 139,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0140() -> Value {
    json!({
        "checkpoint": 140,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0141() -> Value {
    json!({
        "checkpoint": 141,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0142() -> Value {
    json!({
        "checkpoint": 142,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0143() -> Value {
    json!({
        "checkpoint": 143,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0144() -> Value {
    json!({
        "checkpoint": 144,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0145() -> Value {
    json!({
        "checkpoint": 145,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0146() -> Value {
    json!({
        "checkpoint": 146,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0147() -> Value {
    json!({
        "checkpoint": 147,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0148() -> Value {
    json!({
        "checkpoint": 148,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0149() -> Value {
    json!({
        "checkpoint": 149,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0150() -> Value {
    json!({
        "checkpoint": 150,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0151() -> Value {
    json!({
        "checkpoint": 151,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0152() -> Value {
    json!({
        "checkpoint": 152,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0153() -> Value {
    json!({
        "checkpoint": 153,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0154() -> Value {
    json!({
        "checkpoint": 154,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0155() -> Value {
    json!({
        "checkpoint": 155,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0156() -> Value {
    json!({
        "checkpoint": 156,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0157() -> Value {
    json!({
        "checkpoint": 157,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0158() -> Value {
    json!({
        "checkpoint": 158,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0159() -> Value {
    json!({
        "checkpoint": 159,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0160() -> Value {
    json!({
        "checkpoint": 160,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0161() -> Value {
    json!({
        "checkpoint": 161,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0162() -> Value {
    json!({
        "checkpoint": 162,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0163() -> Value {
    json!({
        "checkpoint": 163,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0164() -> Value {
    json!({
        "checkpoint": 164,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}

pub fn privacy_policy_checkpoint_0165() -> Value {
    json!({
        "checkpoint": 165,
        "domain": "cross_input_decoy_coordination",
        "requires_decoy_bucket_proof": true,
        "requires_spend_graph_redaction": true,
        "requires_bridge_mixin_floor": true,
        "requires_view_tag_control": true,
        "requires_dandelion_coordination": true,
        "requires_pq_watcher_attestation": true,
        "requires_privacy_incident_gate": true,
    })
}
