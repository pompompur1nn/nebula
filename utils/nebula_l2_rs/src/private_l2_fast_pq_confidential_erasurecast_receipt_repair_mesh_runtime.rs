use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialErasurecastReceiptRepairMeshRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_ERASURECAST_RECEIPT_REPAIR_MESH_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-fast-pq-confidential-erasurecast-receipt-repair-mesh-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_ERASURECAST_RECEIPT_REPAIR_MESH_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "shake256-domain-separated-canonical-json-v1";
pub const REPAIR_MESH_SUITE: &str =
    "private-l2-fast-confidential-erasurecast-receipt-repair-mesh-v1";
pub const PQ_REPAIR_TOPOLOGY_AUTH_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-256f-repair-topology-auth-v1";
pub const CONFIDENTIAL_SHARD_REPAIR_COHORT_SUITE: &str =
    "ml-kem-1024-confidential-receipt-shard-repair-cohort-v1";
pub const LOW_FEE_RETRY_CAP_SUITE: &str = "private-l2-low-fee-repair-mesh-retry-cap-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "operator-safe-confidential-erasurecast-receipt-repair-mesh-public-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_receipts_addresses_view_keys_cohort_members_or_shard_payload_bytes";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 5_380_000;
pub const DEVNET_EPOCH: u64 = 17_152;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MAX_TOPOLOGIES: usize = 128;
pub const DEFAULT_MAX_COHORTS: usize = 65_536;
pub const DEFAULT_MAX_REPAIR_JOBS: usize = 1_048_576;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 1_048_576;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 65_536;
pub const DEFAULT_MESH_FANOUT_WIDTH: u16 = 96;
pub const DEFAULT_MESH_QUORUM: u16 = 64;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_REPAIR_TTL_SLOTS: u64 = 48;
pub const DEFAULT_TARGET_REPAIR_MS: u64 = 18;
pub const DEFAULT_MAX_MISSING_SHARDS: u16 = 24;
pub const DEFAULT_MAX_RETRY_COUNT: u64 = 5;
pub const DEFAULT_BASE_RETRY_FEE_MICROS: u64 = 3;
pub const DEFAULT_RETRY_FEE_CAP_MICROS: u64 = 32;
pub const DEFAULT_CONGESTION_MULTIPLIER_BPS: u64 = 1_125;

const D_CONFIG: &str = "PL2-FAST-PQ-CONF-ERASURECAST-RECEIPT-REPAIR-MESH:CONFIG";
const D_COUNTERS: &str = "PL2-FAST-PQ-CONF-ERASURECAST-RECEIPT-REPAIR-MESH:COUNTERS";
const D_ROOTS: &str = "PL2-FAST-PQ-CONF-ERASURECAST-RECEIPT-REPAIR-MESH:ROOTS";
const D_STATE: &str = "PL2-FAST-PQ-CONF-ERASURECAST-RECEIPT-REPAIR-MESH:STATE";
const D_TOPOLOGIES: &str = "PL2-FAST-PQ-CONF-ERASURECAST-RECEIPT-REPAIR-MESH:TOPOLOGIES";
const D_COHORTS: &str = "PL2-FAST-PQ-CONF-ERASURECAST-RECEIPT-REPAIR-MESH:COHORTS";
const D_JOBS: &str = "PL2-FAST-PQ-CONF-ERASURECAST-RECEIPT-REPAIR-MESH:JOBS";
const D_ATTESTATIONS: &str = "PL2-FAST-PQ-CONF-ERASURECAST-RECEIPT-REPAIR-MESH:ATTESTATIONS";
const D_PUBLIC: &str = "PL2-FAST-PQ-CONF-ERASURECAST-RECEIPT-REPAIR-MESH:PUBLIC";
const D_DEVNET: &str = "PL2-FAST-PQ-CONF-ERASURECAST-RECEIPT-REPAIR-MESH:DEVNET";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshClass {
    WalletFast,
    MerchantFast,
    BridgeExit,
    DefiSettlement,
    OperatorMirror,
    RecoveryArchive,
}

impl MeshClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletFast => "wallet_fast",
            Self::MerchantFast => "merchant_fast",
            Self::BridgeExit => "bridge_exit",
            Self::DefiSettlement => "defi_settlement",
            Self::OperatorMirror => "operator_mirror",
            Self::RecoveryArchive => "recovery_archive",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::BridgeExit => 10_000,
            Self::OperatorMirror => 9_800,
            Self::DefiSettlement => 9_200,
            Self::MerchantFast => 8_600,
            Self::WalletFast => 8_100,
            Self::RecoveryArchive => 5_600,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologyStatus {
    Open,
    Hot,
    FeeCapped,
    Rebalancing,
    Paused,
    Retired,
}

impl TopologyStatus {
    pub fn accepts_repairs(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Hot | Self::FeeCapped | Self::Rebalancing
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortStatus {
    Open,
    Sealed,
    RotatingKeys,
    Suspended,
    Retired,
}

impl CohortStatus {
    pub fn accepts_repairs(self) -> bool {
        matches!(self, Self::Open | Self::Sealed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairJobStatus {
    Queued,
    TopologyAuthenticated,
    Routed,
    Delivered,
    RetryCapped,
    Expired,
}

impl RepairJobStatus {
    pub fn accepts_delivery(self) -> bool {
        matches!(self, Self::TopologyAuthenticated | Self::Routed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairReason {
    AvailabilityGap,
    FanoutTimeout,
    ShardDigestMismatch,
    CohortKeyRotation,
    MeshRebalance,
    LowFeeRetryPreserve,
}

impl RepairReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AvailabilityGap => "availability_gap",
            Self::FanoutTimeout => "fanout_timeout",
            Self::ShardDigestMismatch => "shard_digest_mismatch",
            Self::CohortKeyRotation => "cohort_key_rotation",
            Self::MeshRebalance => "mesh_rebalance",
            Self::LowFeeRetryPreserve => "low_fee_retry_preserve",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub repair_mesh_suite: String,
    pub pq_repair_topology_auth_suite: String,
    pub confidential_shard_repair_cohort_suite: String,
    pub low_fee_retry_cap_suite: String,
    pub public_record_scheme: String,
    pub privacy_boundary: String,
    pub max_topologies: usize,
    pub max_cohorts: usize,
    pub max_repair_jobs: usize,
    pub max_attestations: usize,
    pub max_public_records: usize,
    pub mesh_fanout_width: u16,
    pub mesh_quorum: u16,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub repair_ttl_slots: u64,
    pub target_repair_ms: u64,
    pub max_missing_shards: u16,
    pub max_retry_count: u64,
    pub base_retry_fee_micros: u64,
    pub retry_fee_cap_micros: u64,
    pub congestion_multiplier_bps: u64,
    pub require_pq_authenticated_repair_topology: bool,
    pub require_confidential_shard_repair_cohorts: bool,
    pub require_low_fee_retry_caps: bool,
    pub require_deterministic_roots: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            repair_mesh_suite: REPAIR_MESH_SUITE.to_string(),
            pq_repair_topology_auth_suite: PQ_REPAIR_TOPOLOGY_AUTH_SUITE.to_string(),
            confidential_shard_repair_cohort_suite: CONFIDENTIAL_SHARD_REPAIR_COHORT_SUITE
                .to_string(),
            low_fee_retry_cap_suite: LOW_FEE_RETRY_CAP_SUITE.to_string(),
            public_record_scheme: PUBLIC_RECORD_SCHEME.to_string(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            max_topologies: DEFAULT_MAX_TOPOLOGIES,
            max_cohorts: DEFAULT_MAX_COHORTS,
            max_repair_jobs: DEFAULT_MAX_REPAIR_JOBS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_public_records: DEFAULT_MAX_PUBLIC_RECORDS,
            mesh_fanout_width: DEFAULT_MESH_FANOUT_WIDTH,
            mesh_quorum: DEFAULT_MESH_QUORUM,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            repair_ttl_slots: DEFAULT_REPAIR_TTL_SLOTS,
            target_repair_ms: DEFAULT_TARGET_REPAIR_MS,
            max_missing_shards: DEFAULT_MAX_MISSING_SHARDS,
            max_retry_count: DEFAULT_MAX_RETRY_COUNT,
            base_retry_fee_micros: DEFAULT_BASE_RETRY_FEE_MICROS,
            retry_fee_cap_micros: DEFAULT_RETRY_FEE_CAP_MICROS,
            congestion_multiplier_bps: DEFAULT_CONGESTION_MULTIPLIER_BPS,
            require_pq_authenticated_repair_topology: true,
            require_confidential_shard_repair_cohorts: true,
            require_low_fee_retry_caps: true,
            require_deterministic_roots: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("protocol version mismatch".to_string());
        }
        if self.max_topologies == 0 || self.max_cohorts == 0 || self.max_repair_jobs == 0 {
            return Err("repair mesh capacities must be non-zero".to_string());
        }
        if self.mesh_quorum == 0 || self.mesh_quorum > self.mesh_fanout_width {
            return Err("repair mesh quorum must fit configured width".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("minimum PQ security below 192 bits".to_string());
        }
        if self.max_missing_shards == 0 {
            return Err("missing shard ceiling must be non-zero".to_string());
        }
        if self.base_retry_fee_micros > self.retry_fee_cap_micros {
            return Err("base retry fee exceeds retry cap".to_string());
        }
        if self.congestion_multiplier_bps > MAX_BPS {
            return Err("congestion multiplier exceeds basis point ceiling".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(D_CONFIG, &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub topologies_opened: u64,
    pub cohorts_opened: u64,
    pub repair_jobs_queued: u64,
    pub repair_jobs_routed: u64,
    pub repair_jobs_delivered: u64,
    pub missing_shards_routed: u64,
    pub pq_topology_attestations_verified: u64,
    pub authenticated_mesh_peers: u64,
    pub retry_fees_micros: u64,
    pub retry_fee_cap_savings_micros: u64,
    pub retry_caps_applied: u64,
    pub deterministic_roots_emitted: u64,
    pub public_records_emitted: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(D_COUNTERS, &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub repair_topologies_root: String,
    pub shard_repair_cohorts_root: String,
    pub repair_jobs_root: String,
    pub pq_topology_attestations_root: String,
    pub public_records_root: String,
    pub deterministic_state_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(D_ROOTS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepairTopology {
    pub topology_id: String,
    pub class: MeshClass,
    pub status: TopologyStatus,
    pub priority_weight: u64,
    pub fanout_width: u16,
    pub quorum_threshold: u16,
    pub routed_repairs: u64,
    pub delivered_repairs: u64,
    pub topology_commitment_root: String,
    pub topology_root: String,
}

impl RepairTopology {
    pub fn new(topology_id: impl Into<String>, class: MeshClass, config: &Config) -> Self {
        let topology_id = topology_id.into();
        let mut topology = Self {
            topology_commitment_root: topology_commitment_root(
                &topology_id,
                config.mesh_fanout_width,
                config.mesh_quorum,
            ),
            topology_id,
            class,
            status: TopologyStatus::Open,
            priority_weight: class.priority_weight(),
            fanout_width: config.mesh_fanout_width,
            quorum_threshold: config.mesh_quorum,
            routed_repairs: 0,
            delivered_repairs: 0,
            topology_root: String::new(),
        };
        topology.refresh_root();
        topology
    }

    pub fn public_record(&self) -> Value {
        json!({
            "topology_id": self.topology_id,
            "class": self.class.as_str(),
            "status": self.status,
            "priority_weight": self.priority_weight,
            "fanout_width": self.fanout_width,
            "quorum_threshold": self.quorum_threshold,
            "routed_repairs": self.routed_repairs,
            "delivered_repairs": self.delivered_repairs,
            "topology_commitment_root": self.topology_commitment_root,
            "topology_root": self.topology_root
        })
    }

    fn refresh_root(&mut self) {
        self.topology_root = record_root("REPAIR-TOPOLOGY", &self.public_record());
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShardRepairCohort {
    pub cohort_id: String,
    pub status: CohortStatus,
    pub class: MeshClass,
    pub receipt_commitment_count: u64,
    pub privacy_set_size: u64,
    pub epoch: u64,
    pub encrypted_cohort_key_root: String,
    pub membership_commitment_root: String,
    pub shard_custody_root: String,
    pub cohort_root: String,
}

impl ShardRepairCohort {
    pub fn public_record(&self) -> Value {
        json!({
            "cohort_id": self.cohort_id,
            "status": self.status,
            "class": self.class.as_str(),
            "receipt_commitment_count": self.receipt_commitment_count,
            "privacy_set_size": self.privacy_set_size,
            "epoch": self.epoch,
            "encrypted_cohort_key_root": self.encrypted_cohort_key_root,
            "membership_commitment_root": self.membership_commitment_root,
            "shard_custody_root": self.shard_custody_root,
            "cohort_root": self.cohort_root
        })
    }

    fn refresh_root(&mut self) {
        self.cohort_root = record_root("SHARD-REPAIR-COHORT", &self.public_record());
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepairJob {
    pub job_id: String,
    pub topology_id: String,
    pub cohort_id: String,
    pub reason: RepairReason,
    pub status: RepairJobStatus,
    pub missing_shards: u16,
    pub retry_count: u64,
    pub queued_slot: u64,
    pub routed_slot: u64,
    pub expires_at_slot: u64,
    pub uncapped_fee_micros: u64,
    pub charged_fee_micros: u64,
    pub fee_cap_micros: u64,
    pub receipt_commitment_root: String,
    pub missing_shard_set_root: String,
    pub mesh_route_root: String,
    pub deterministic_repair_root: String,
    pub job_root: String,
}

impl RepairJob {
    pub fn public_record(&self) -> Value {
        json!({
            "job_id": self.job_id,
            "topology_id": self.topology_id,
            "cohort_id": self.cohort_id,
            "reason": self.reason.as_str(),
            "status": self.status,
            "missing_shards": self.missing_shards,
            "retry_count": self.retry_count,
            "queued_slot": self.queued_slot,
            "routed_slot": self.routed_slot,
            "expires_at_slot": self.expires_at_slot,
            "uncapped_fee_micros": self.uncapped_fee_micros,
            "charged_fee_micros": self.charged_fee_micros,
            "fee_cap_micros": self.fee_cap_micros,
            "receipt_commitment_root": self.receipt_commitment_root,
            "missing_shard_set_root": self.missing_shard_set_root,
            "mesh_route_root": self.mesh_route_root,
            "deterministic_repair_root": self.deterministic_repair_root,
            "job_root": self.job_root
        })
    }

    fn refresh_root(&mut self) {
        self.job_root = record_root("REPAIR-JOB", &self.public_record());
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqTopologyAttestation {
    pub attestation_id: String,
    pub job_id: String,
    pub topology_id: String,
    pub status_accepted: bool,
    pub fanout_width: u16,
    pub quorum_threshold: u16,
    pub authenticated_peers: u16,
    pub pq_suite: String,
    pub security_bits: u16,
    pub attested_topology_root: String,
    pub attested_job_root: String,
    pub aggregate_signature_root: String,
    pub attestation_root: String,
}

impl PqTopologyAttestation {
    pub fn accepted(&self) -> bool {
        self.status_accepted
            && self.security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS
            && self.authenticated_peers >= self.quorum_threshold
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    fn refresh_root(&mut self) {
        self.attestation_root = record_root("PQ-TOPOLOGY-ATTESTATION", &self.public_record());
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorPublicRecord {
    pub record_id: String,
    pub height: u64,
    pub epoch: u64,
    pub repair_topology_count: usize,
    pub shard_repair_cohort_count: usize,
    pub repair_job_count: usize,
    pub pq_attestation_count: usize,
    pub missing_shards_routed: u64,
    pub roots: Roots,
    pub record_root: String,
}

impl OperatorPublicRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub height: u64,
    pub epoch: u64,
    pub current_slot: u64,
    pub repair_topologies: BTreeMap<String, RepairTopology>,
    pub shard_repair_cohorts: BTreeMap<String, ShardRepairCohort>,
    pub repair_jobs: BTreeMap<String, RepairJob>,
    pub pq_topology_attestations: BTreeMap<String, PqTopologyAttestation>,
    pub public_records: BTreeMap<String, OperatorPublicRecord>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            height: DEVNET_HEIGHT,
            epoch: DEVNET_EPOCH,
            current_slot: 0,
            repair_topologies: BTreeMap::new(),
            shard_repair_cohorts: BTreeMap::new(),
            repair_jobs: BTreeMap::new(),
            pq_topology_attestations: BTreeMap::new(),
            public_records: BTreeMap::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).expect("devnet config is valid");
        state.current_slot = 92;
        state.seed_devnet();
        state.refresh_roots();
        state.emit_public_record();
        state.refresh_roots();
        state
    }

    pub fn demo() -> Self {
        Self::devnet()
    }

    pub fn register_topology(&mut self, topology: RepairTopology) -> Result<()> {
        if self.repair_topologies.len() >= self.config.max_topologies {
            return Err("repair topology capacity exceeded".to_string());
        }
        self.repair_topologies
            .insert(topology.topology_id.clone(), topology);
        self.counters.topologies_opened = self.counters.topologies_opened.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn open_shard_repair_cohort(
        &mut self,
        cohort_id: impl Into<String>,
        class: MeshClass,
        receipt_commitment_count: u64,
    ) -> Result<String> {
        if self.shard_repair_cohorts.len() >= self.config.max_cohorts {
            return Err("confidential shard repair cohort capacity exceeded".to_string());
        }
        let cohort_id = cohort_id.into();
        let mut cohort = ShardRepairCohort {
            encrypted_cohort_key_root: cohort_key_root(&cohort_id, self.epoch),
            membership_commitment_root: membership_root(&cohort_id, receipt_commitment_count),
            shard_custody_root: shard_custody_root(&cohort_id, receipt_commitment_count),
            cohort_id: cohort_id.clone(),
            status: CohortStatus::Open,
            class,
            receipt_commitment_count,
            privacy_set_size: self.config.min_privacy_set_size,
            epoch: self.epoch,
            cohort_root: String::new(),
        };
        cohort.refresh_root();
        self.shard_repair_cohorts.insert(cohort_id.clone(), cohort);
        self.counters.cohorts_opened = self.counters.cohorts_opened.saturating_add(1);
        self.refresh_roots();
        Ok(cohort_id)
    }

    pub fn queue_repair_job(
        &mut self,
        topology_id: &str,
        cohort_id: &str,
        reason: RepairReason,
        missing_shards: u16,
        retry_count: u64,
        first_receipt_index: u64,
        receipt_count: u64,
    ) -> Result<String> {
        if self.repair_jobs.len() >= self.config.max_repair_jobs {
            return Err("repair job capacity exceeded".to_string());
        }
        if missing_shards == 0 || missing_shards > self.config.max_missing_shards {
            return Err("missing shard count outside repair mesh bounds".to_string());
        }
        if retry_count > self.config.max_retry_count {
            return Err("retry count exceeds low-fee repair mesh cap".to_string());
        }
        let topology = self
            .repair_topologies
            .get_mut(topology_id)
            .ok_or_else(|| "repair topology not found".to_string())?;
        if !topology.status.accepts_repairs() {
            return Err("repair topology does not accept jobs".to_string());
        }
        let cohort = self
            .shard_repair_cohorts
            .get(cohort_id)
            .ok_or_else(|| "confidential shard repair cohort not found".to_string())?;
        if !cohort.status.accepts_repairs() {
            return Err("confidential shard repair cohort does not accept repairs".to_string());
        }

        let scaled_base = self
            .config
            .base_retry_fee_micros
            .saturating_mul(retry_count.saturating_add(1))
            .saturating_mul(missing_shards as u64);
        let uncapped_fee_micros =
            scaled_base.saturating_mul(self.config.congestion_multiplier_bps) / MAX_BPS;
        let charged_fee_micros = uncapped_fee_micros.min(self.config.retry_fee_cap_micros);
        let receipt_commitment_root =
            receipt_commitment_root(cohort_id, first_receipt_index, receipt_count);
        let missing_shard_set_root = missing_shard_set_root(topology_id, cohort_id, missing_shards);
        let mesh_route_root = mesh_route_root(
            topology_id,
            cohort_id,
            topology.fanout_width,
            topology.quorum_threshold,
            &topology.topology_root,
        );
        let deterministic_repair_root = deterministic_repair_root(
            topology_id,
            cohort_id,
            self.current_slot,
            &receipt_commitment_root,
            &missing_shard_set_root,
            &mesh_route_root,
            &cohort.cohort_root,
        );
        let status = if uncapped_fee_micros > charged_fee_micros {
            RepairJobStatus::RetryCapped
        } else {
            RepairJobStatus::Queued
        };
        let mut job = RepairJob {
            job_id: format!(
                "repair-mesh-job-{topology_id}-{cohort_id}-{first_receipt_index}-{retry_count}"
            ),
            topology_id: topology_id.to_string(),
            cohort_id: cohort_id.to_string(),
            reason,
            status,
            missing_shards,
            retry_count,
            queued_slot: self.current_slot,
            routed_slot: self.current_slot.saturating_add(1),
            expires_at_slot: self
                .current_slot
                .saturating_add(self.config.repair_ttl_slots),
            uncapped_fee_micros,
            charged_fee_micros,
            fee_cap_micros: self.config.retry_fee_cap_micros,
            receipt_commitment_root,
            missing_shard_set_root,
            mesh_route_root,
            deterministic_repair_root,
            job_root: String::new(),
        };
        job.refresh_root();
        topology.routed_repairs = topology.routed_repairs.saturating_add(1);
        topology.refresh_root();
        let job_id = job.job_id.clone();
        self.repair_jobs.insert(job_id.clone(), job);
        self.counters.repair_jobs_queued = self.counters.repair_jobs_queued.saturating_add(1);
        self.counters.missing_shards_routed = self
            .counters
            .missing_shards_routed
            .saturating_add(missing_shards as u64);
        self.counters.retry_fees_micros = self
            .counters
            .retry_fees_micros
            .saturating_add(charged_fee_micros);
        self.counters.retry_fee_cap_savings_micros = self
            .counters
            .retry_fee_cap_savings_micros
            .saturating_add(uncapped_fee_micros.saturating_sub(charged_fee_micros));
        if status == RepairJobStatus::RetryCapped {
            self.counters.retry_caps_applied = self.counters.retry_caps_applied.saturating_add(1);
        }
        self.counters.deterministic_roots_emitted =
            self.counters.deterministic_roots_emitted.saturating_add(1);
        self.refresh_roots();
        Ok(job_id)
    }

    pub fn authenticate_repair_topology(
        &mut self,
        job_id: &str,
        authenticated_peers: u16,
    ) -> Result<()> {
        if self.pq_topology_attestations.len() >= self.config.max_attestations {
            return Err("PQ topology attestation capacity exceeded".to_string());
        }
        let job = self
            .repair_jobs
            .get_mut(job_id)
            .ok_or_else(|| "repair job not found".to_string())?;
        let topology = self
            .repair_topologies
            .get(&job.topology_id)
            .ok_or_else(|| "repair topology not found".to_string())?;
        let accepted = authenticated_peers >= topology.quorum_threshold;
        let mut attestation = PqTopologyAttestation {
            attestation_id: format!("pq-topology-attestation-{job_id}"),
            job_id: job_id.to_string(),
            topology_id: job.topology_id.clone(),
            status_accepted: accepted,
            fanout_width: topology.fanout_width,
            quorum_threshold: topology.quorum_threshold,
            authenticated_peers,
            pq_suite: PQ_REPAIR_TOPOLOGY_AUTH_SUITE.to_string(),
            security_bits: self.config.min_pq_security_bits,
            attested_topology_root: topology.topology_root.clone(),
            attested_job_root: job.job_root.clone(),
            aggregate_signature_root: dev_hash(
                "repair-topology-signature",
                authenticated_peers as u64,
            ),
            attestation_root: String::new(),
        };
        attestation.refresh_root();
        if attestation.accepted() {
            job.status = RepairJobStatus::TopologyAuthenticated;
            job.refresh_root();
            self.counters.pq_topology_attestations_verified = self
                .counters
                .pq_topology_attestations_verified
                .saturating_add(1);
            self.counters.authenticated_mesh_peers = self
                .counters
                .authenticated_mesh_peers
                .saturating_add(authenticated_peers as u64);
        }
        self.pq_topology_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh_roots();
        Ok(())
    }

    pub fn route_repair(&mut self, job_id: &str) -> Result<()> {
        let job = self
            .repair_jobs
            .get_mut(job_id)
            .ok_or_else(|| "repair job not found".to_string())?;
        if job.status != RepairJobStatus::TopologyAuthenticated {
            return Err("repair job is not PQ topology authenticated".to_string());
        }
        job.status = RepairJobStatus::Routed;
        job.refresh_root();
        self.counters.repair_jobs_routed = self.counters.repair_jobs_routed.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn mark_delivered(&mut self, job_id: &str) -> Result<()> {
        let job = self
            .repair_jobs
            .get_mut(job_id)
            .ok_or_else(|| "repair job not found".to_string())?;
        if !job.status.accepts_delivery() {
            return Err("repair job is not ready for delivery".to_string());
        }
        job.status = RepairJobStatus::Delivered;
        job.refresh_root();
        if let Some(topology) = self.repair_topologies.get_mut(&job.topology_id) {
            topology.delivered_repairs = topology.delivered_repairs.saturating_add(1);
            topology.refresh_root();
        }
        self.counters.repair_jobs_delivered = self.counters.repair_jobs_delivered.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "height": self.height,
            "epoch": self.epoch,
            "current_slot": self.current_slot,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "repair_topologies": self.repair_topologies.values().map(RepairTopology::public_record).collect::<Vec<_>>(),
            "shard_repair_cohorts": self.shard_repair_cohorts.values().map(ShardRepairCohort::public_record).collect::<Vec<_>>(),
            "repair_jobs": self.repair_jobs.values().map(RepairJob::public_record).collect::<Vec<_>>(),
            "pq_topology_attestations": self.pq_topology_attestations.values().map(PqTopologyAttestation::public_record).collect::<Vec<_>>(),
            "public_records": self.public_records.values().map(OperatorPublicRecord::public_record).collect::<Vec<_>>(),
            "operator_safe": true,
            "receipt_payloads_redacted": true,
            "pq_authenticated_repair_topology": true,
            "confidential_shard_repair_cohorts": true,
            "low_fee_retry_caps": true,
            "deterministic_roots": true
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(D_STATE, &self.public_record())
    }

    pub fn refresh_roots(&mut self) {
        let mut roots = Roots {
            config_root: self.config.root(),
            counters_root: self.counters.root(),
            repair_topologies_root: merkle_records(D_TOPOLOGIES, &self.repair_topologies),
            shard_repair_cohorts_root: merkle_records(D_COHORTS, &self.shard_repair_cohorts),
            repair_jobs_root: merkle_records(D_JOBS, &self.repair_jobs),
            pq_topology_attestations_root: merkle_records(
                D_ATTESTATIONS,
                &self.pq_topology_attestations,
            ),
            public_records_root: merkle_records(D_PUBLIC, &self.public_records),
            deterministic_state_root: String::new(),
            state_root: String::new(),
        };
        roots.deterministic_state_root = roots.root();
        roots.state_root = payload_root(D_ROOTS, &roots.public_record());
        self.roots = roots;
    }

    fn seed_devnet(&mut self) {
        let classes = [
            MeshClass::WalletFast,
            MeshClass::MerchantFast,
            MeshClass::BridgeExit,
            MeshClass::DefiSettlement,
            MeshClass::OperatorMirror,
            MeshClass::RecoveryArchive,
        ];
        for (index, class) in classes.into_iter().enumerate() {
            let topology_id = format!("repair-mesh-topology-devnet-{:02}", index + 1);
            let mut topology = RepairTopology::new(topology_id.clone(), class, &self.config);
            if matches!(class, MeshClass::BridgeExit | MeshClass::OperatorMirror) {
                topology.status = TopologyStatus::Hot;
                topology.refresh_root();
            } else if index % 2 == 1 {
                topology.status = TopologyStatus::FeeCapped;
                topology.refresh_root();
            }
            let _ = self.register_topology(topology);
            let cohort_id = self
                .open_shard_repair_cohort(
                    format!("confidential-repair-cohort-devnet-{:02}", index + 1),
                    class,
                    1_536 + index as u64 * 384,
                )
                .expect("devnet repair cohort capacity");
            let job_id = self
                .queue_repair_job(
                    &topology_id,
                    &cohort_id,
                    if index % 2 == 0 {
                        RepairReason::LowFeeRetryPreserve
                    } else {
                        RepairReason::MeshRebalance
                    },
                    2 + index as u16,
                    (index as u64 % self.config.max_retry_count).saturating_add(1),
                    980_000 + index as u64 * 30_000,
                    240 + index as u64 * 48,
                )
                .expect("devnet repair mesh job queues");
            let authenticated_peers = self
                .config
                .mesh_quorum
                .saturating_add((index as u16) % 9)
                .min(self.config.mesh_fanout_width);
            let _ = self.authenticate_repair_topology(&job_id, authenticated_peers);
            let _ = self.route_repair(&job_id);
            if index % 3 != 0 {
                let _ = self.mark_delivered(&job_id);
            }
        }
    }

    fn emit_public_record(&mut self) {
        if self.public_records.len() >= self.config.max_public_records {
            return;
        }
        let mut record = OperatorPublicRecord {
            record_id: "operator-public-record-devnet-erasurecast-receipt-repair-mesh".to_string(),
            height: self.height,
            epoch: self.epoch,
            repair_topology_count: self.repair_topologies.len(),
            shard_repair_cohort_count: self.shard_repair_cohorts.len(),
            repair_job_count: self.repair_jobs.len(),
            pq_attestation_count: self.pq_topology_attestations.len(),
            missing_shards_routed: self.counters.missing_shards_routed,
            roots: self.roots.clone(),
            record_root: String::new(),
        };
        record.record_root = record_root("OPERATOR-PUBLIC-RECORD", &record.public_record());
        self.public_records.insert(record.record_id.clone(), record);
        self.counters.public_records_emitted = self.public_records.len() as u64;
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

pub fn refresh_roots(state: &mut State) {
    state.refresh_roots();
}

pub fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-ERASURECAST-RECEIPT-REPAIR-MESH-{}",
            domain
        ),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn repair_topology_digest(record: &RepairTopology) -> String {
    payload_root(PQ_REPAIR_TOPOLOGY_AUTH_SUITE, &record.public_record())
}

pub fn shard_repair_cohort_digest(record: &ShardRepairCohort) -> String {
    payload_root(
        CONFIDENTIAL_SHARD_REPAIR_COHORT_SUITE,
        &record.public_record(),
    )
}

pub fn repair_job_digest(record: &RepairJob) -> String {
    payload_root(REPAIR_MESH_SUITE, &record.public_record())
}

pub fn pq_topology_attestation_digest(record: &PqTopologyAttestation) -> String {
    payload_root(PQ_REPAIR_TOPOLOGY_AUTH_SUITE, &record.public_record())
}

fn topology_commitment_root(topology_id: &str, fanout_width: u16, quorum_threshold: u16) -> String {
    domain_hash(
        PQ_REPAIR_TOPOLOGY_AUTH_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(topology_id),
            HashPart::U64(fanout_width as u64),
            HashPart::U64(quorum_threshold as u64),
            HashPart::Str("repair-topology-members-redacted"),
        ],
        32,
    )
}

fn cohort_key_root(cohort_id: &str, epoch: u64) -> String {
    domain_hash(
        CONFIDENTIAL_SHARD_REPAIR_COHORT_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(cohort_id),
            HashPart::U64(epoch),
        ],
        32,
    )
}

fn membership_root(cohort_id: &str, receipt_commitment_count: u64) -> String {
    domain_hash(
        CONFIDENTIAL_SHARD_REPAIR_COHORT_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(cohort_id),
            HashPart::U64(receipt_commitment_count),
        ],
        32,
    )
}

fn shard_custody_root(cohort_id: &str, receipt_commitment_count: u64) -> String {
    domain_hash(
        CONFIDENTIAL_SHARD_REPAIR_COHORT_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(cohort_id),
            HashPart::U64(receipt_commitment_count),
            HashPart::Str("confidential-shard-custody-map-redacted"),
        ],
        32,
    )
}

fn receipt_commitment_root(
    cohort_id: &str,
    first_receipt_index: u64,
    receipt_count: u64,
) -> String {
    domain_hash(
        REPAIR_MESH_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(cohort_id),
            HashPart::U64(first_receipt_index),
            HashPart::U64(receipt_count),
        ],
        32,
    )
}

fn missing_shard_set_root(topology_id: &str, cohort_id: &str, missing_shards: u16) -> String {
    domain_hash(
        REPAIR_MESH_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(topology_id),
            HashPart::Str(cohort_id),
            HashPart::U64(missing_shards as u64),
            HashPart::Str("missing-shard-index-set-redacted"),
        ],
        32,
    )
}

fn mesh_route_root(
    topology_id: &str,
    cohort_id: &str,
    fanout_width: u16,
    quorum_threshold: u16,
    topology_root: &str,
) -> String {
    domain_hash(
        REPAIR_MESH_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(topology_id),
            HashPart::Str(cohort_id),
            HashPart::U64(fanout_width as u64),
            HashPart::U64(quorum_threshold as u64),
            HashPart::Str(topology_root),
        ],
        32,
    )
}

fn deterministic_repair_root(
    topology_id: &str,
    cohort_id: &str,
    slot: u64,
    receipt_commitment_root: &str,
    missing_shard_set_root: &str,
    mesh_route_root: &str,
    cohort_root: &str,
) -> String {
    domain_hash(
        REPAIR_MESH_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(topology_id),
            HashPart::Str(cohort_id),
            HashPart::U64(slot),
            HashPart::Str(receipt_commitment_root),
            HashPart::Str(missing_shard_set_root),
            HashPart::Str(mesh_route_root),
            HashPart::Str(cohort_root),
        ],
        32,
    )
}

fn merkle_records<T: Serialize>(domain: &str, records: &BTreeMap<String, T>) -> String {
    let leaves = records
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn payload_root(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(value)],
        32,
    )
}

fn dev_hash(label: &str, index: u64) -> String {
    domain_hash(
        D_DEVNET,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(index),
        ],
        32,
    )
}
