use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialReceiptAvailabilityErasurecastRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_RECEIPT_AVAILABILITY_ERASURECAST_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-fast-pq-confidential-receipt-availability-erasurecast-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_RECEIPT_AVAILABILITY_ERASURECAST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "shake256-domain-separated-canonical-json-v1";
pub const ERASURECAST_SUITE: &str =
    "private-l2-fast-confidential-receipt-availability-erasurecast-v1";
pub const PQ_SHARD_AUTH_SUITE: &str = "ml-dsa-87+slh-dsa-shake-256f-shard-fanout-auth-v1";
pub const CONFIDENTIAL_RECEIPT_GROUP_SUITE: &str =
    "ml-kem-1024-confidential-receipt-availability-group-v1";
pub const RETRANSMIT_CAP_SUITE: &str = "private-l2-low-fee-receipt-retransmit-cap-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "operator-safe-confidential-receipt-availability-erasurecast-public-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_receipts_addresses_view_keys_group_members_or_shard_payload_bytes";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 5_340_000;
pub const DEVNET_EPOCH: u64 = 17_024;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_DATA_SHARDS: u16 = 12;
pub const DEFAULT_PARITY_SHARDS: u16 = 8;
pub const DEFAULT_FANOUT_WIDTH: u16 = 96;
pub const DEFAULT_FANOUT_QUORUM: u16 = 64;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MAX_GROUPS: usize = 65_536;
pub const DEFAULT_MAX_BATCHES: usize = 1_048_576;
pub const DEFAULT_MAX_SHARDS: usize = 16_777_216;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 1_048_576;
pub const DEFAULT_MAX_RETRANSMITS: usize = 1_048_576;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 65_536;
pub const DEFAULT_SHARD_TTL_SLOTS: u64 = 96;
pub const DEFAULT_TARGET_AVAILABILITY_MS: u64 = 40;
pub const DEFAULT_MAX_SHARD_BYTES: u64 = 512 * 1024;
pub const DEFAULT_BASE_RETRANSMIT_FEE_MICROS: u64 = 4;
pub const DEFAULT_RETRANSMIT_FEE_CAP_MICROS: u64 = 48;
pub const DEFAULT_CONGESTION_MULTIPLIER_BPS: u64 = 1_200;

const D_CONFIG: &str = "PL2-FAST-PQ-CONF-RECEIPT-AVAIL-ERASURECAST:CONFIG";
const D_COUNTERS: &str = "PL2-FAST-PQ-CONF-RECEIPT-AVAIL-ERASURECAST:COUNTERS";
const D_ROOTS: &str = "PL2-FAST-PQ-CONF-RECEIPT-AVAIL-ERASURECAST:ROOTS";
const D_STATE: &str = "PL2-FAST-PQ-CONF-RECEIPT-AVAIL-ERASURECAST:STATE";
const D_GROUPS: &str = "PL2-FAST-PQ-CONF-RECEIPT-AVAIL-ERASURECAST:GROUPS";
const D_BATCHES: &str = "PL2-FAST-PQ-CONF-RECEIPT-AVAIL-ERASURECAST:BATCHES";
const D_SHARDS: &str = "PL2-FAST-PQ-CONF-RECEIPT-AVAIL-ERASURECAST:SHARDS";
const D_ATTESTATIONS: &str = "PL2-FAST-PQ-CONF-RECEIPT-AVAIL-ERASURECAST:ATTESTATIONS";
const D_RETRANSMITS: &str = "PL2-FAST-PQ-CONF-RECEIPT-AVAIL-ERASURECAST:RETRANSMITS";
const D_PUBLIC: &str = "PL2-FAST-PQ-CONF-RECEIPT-AVAIL-ERASURECAST:PUBLIC";
const D_DEVNET: &str = "PL2-FAST-PQ-CONF-RECEIPT-AVAIL-ERASURECAST:DEVNET";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityClass {
    WalletFast,
    MerchantFast,
    BridgeExit,
    DefiSettlement,
    OperatorMirror,
    RecoveryArchive,
}

impl AvailabilityClass {
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
            Self::OperatorMirror => 9_700,
            Self::DefiSettlement => 9_100,
            Self::MerchantFast => 8_600,
            Self::WalletFast => 8_000,
            Self::RecoveryArchive => 5_400,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupStatus {
    Open,
    Sealing,
    RotatingKeys,
    Suspended,
    Retired,
}

impl GroupStatus {
    pub fn accepts_batches(self) -> bool {
        matches!(self, Self::Open | Self::Sealing)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Encoded,
    FanoutAuthenticated,
    Available,
    RetransmitQueued,
    Expired,
}

impl BatchStatus {
    pub fn accepts_retransmit(self) -> bool {
        matches!(self, Self::Available | Self::RetransmitQueued)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShardStatus {
    Encoded,
    PqAuthenticated,
    Erasurecast,
    Missing,
    Recovered,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetransmitReason {
    AvailabilityGap,
    FanoutTimeout,
    LowFeeCapPreserve,
    GroupKeyRotation,
    RecoveryReplay,
}

impl RetransmitReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AvailabilityGap => "availability_gap",
            Self::FanoutTimeout => "fanout_timeout",
            Self::LowFeeCapPreserve => "low_fee_cap_preserve",
            Self::GroupKeyRotation => "group_key_rotation",
            Self::RecoveryReplay => "recovery_replay",
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
    pub erasurecast_suite: String,
    pub pq_shard_auth_suite: String,
    pub confidential_receipt_group_suite: String,
    pub retransmit_cap_suite: String,
    pub public_record_scheme: String,
    pub privacy_boundary: String,
    pub data_shards: u16,
    pub parity_shards: u16,
    pub fanout_width: u16,
    pub fanout_quorum: u16,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub max_groups: usize,
    pub max_batches: usize,
    pub max_shards: usize,
    pub max_attestations: usize,
    pub max_retransmits: usize,
    pub max_public_records: usize,
    pub shard_ttl_slots: u64,
    pub target_availability_ms: u64,
    pub max_shard_bytes: u64,
    pub base_retransmit_fee_micros: u64,
    pub retransmit_fee_cap_micros: u64,
    pub congestion_multiplier_bps: u64,
    pub require_pq_authenticated_fanout: bool,
    pub require_confidential_receipt_groups: bool,
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
            erasurecast_suite: ERASURECAST_SUITE.to_string(),
            pq_shard_auth_suite: PQ_SHARD_AUTH_SUITE.to_string(),
            confidential_receipt_group_suite: CONFIDENTIAL_RECEIPT_GROUP_SUITE.to_string(),
            retransmit_cap_suite: RETRANSMIT_CAP_SUITE.to_string(),
            public_record_scheme: PUBLIC_RECORD_SCHEME.to_string(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            data_shards: DEFAULT_DATA_SHARDS,
            parity_shards: DEFAULT_PARITY_SHARDS,
            fanout_width: DEFAULT_FANOUT_WIDTH,
            fanout_quorum: DEFAULT_FANOUT_QUORUM,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_groups: DEFAULT_MAX_GROUPS,
            max_batches: DEFAULT_MAX_BATCHES,
            max_shards: DEFAULT_MAX_SHARDS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_retransmits: DEFAULT_MAX_RETRANSMITS,
            max_public_records: DEFAULT_MAX_PUBLIC_RECORDS,
            shard_ttl_slots: DEFAULT_SHARD_TTL_SLOTS,
            target_availability_ms: DEFAULT_TARGET_AVAILABILITY_MS,
            max_shard_bytes: DEFAULT_MAX_SHARD_BYTES,
            base_retransmit_fee_micros: DEFAULT_BASE_RETRANSMIT_FEE_MICROS,
            retransmit_fee_cap_micros: DEFAULT_RETRANSMIT_FEE_CAP_MICROS,
            congestion_multiplier_bps: DEFAULT_CONGESTION_MULTIPLIER_BPS,
            require_pq_authenticated_fanout: true,
            require_confidential_receipt_groups: true,
            require_deterministic_roots: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("protocol version mismatch".to_string());
        }
        if self.data_shards == 0 || self.parity_shards == 0 {
            return Err("erasurecast requires data and parity shards".to_string());
        }
        if self.fanout_quorum == 0 || self.fanout_quorum > self.fanout_width {
            return Err("fanout quorum must fit configured width".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("minimum PQ security below 192 bits".to_string());
        }
        if self.max_groups == 0 || self.max_batches == 0 || self.max_shards == 0 {
            return Err("availability capacities must be non-zero".to_string());
        }
        if self.max_shard_bytes == 0 {
            return Err("shard byte ceiling must be non-zero".to_string());
        }
        if self.base_retransmit_fee_micros > self.retransmit_fee_cap_micros {
            return Err("base retransmit fee exceeds cap".to_string());
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
    pub groups_opened: u64,
    pub batches_encoded: u64,
    pub shards_encoded: u64,
    pub shards_erasurecast: u64,
    pub shard_bytes_erasurecast: u64,
    pub pq_attestations_verified: u64,
    pub authenticated_fanout_peers: u64,
    pub availability_quorums_met: u64,
    pub retransmits_queued: u64,
    pub retransmits_delivered: u64,
    pub retransmit_fees_micros: u64,
    pub fee_cap_savings_micros: u64,
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
    pub receipt_groups_root: String,
    pub erasure_batches_root: String,
    pub availability_shards_root: String,
    pub pq_fanout_attestations_root: String,
    pub retransmits_root: String,
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
pub struct ConfidentialReceiptGroup {
    pub group_id: String,
    pub status: GroupStatus,
    pub class: AvailabilityClass,
    pub receipt_commitment_count: u64,
    pub privacy_set_size: u64,
    pub epoch: u64,
    pub encrypted_group_key_root: String,
    pub membership_commitment_root: String,
    pub group_root: String,
}

impl ConfidentialReceiptGroup {
    pub fn public_record(&self) -> Value {
        json!({
            "group_id": self.group_id,
            "status": self.status,
            "class": self.class.as_str(),
            "receipt_commitment_count": self.receipt_commitment_count,
            "privacy_set_size": self.privacy_set_size,
            "epoch": self.epoch,
            "encrypted_group_key_root": self.encrypted_group_key_root,
            "membership_commitment_root": self.membership_commitment_root,
            "group_root": self.group_root
        })
    }

    fn refresh_root(&mut self) {
        self.group_root = record_root("CONFIDENTIAL-RECEIPT-GROUP", &self.public_record());
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ErasureBatch {
    pub batch_id: String,
    pub group_id: String,
    pub class: AvailabilityClass,
    pub status: BatchStatus,
    pub first_receipt_index: u64,
    pub receipt_count: u64,
    pub data_shards: u16,
    pub parity_shards: u16,
    pub encoded_shard_count: u16,
    pub shard_bytes: u64,
    pub slot: u64,
    pub expires_at_slot: u64,
    pub receipt_commitment_root: String,
    pub erasure_matrix_root: String,
    pub group_root: String,
    pub deterministic_availability_root: String,
    pub batch_root: String,
}

impl ErasureBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "group_id": self.group_id,
            "class": self.class.as_str(),
            "status": self.status,
            "first_receipt_index": self.first_receipt_index,
            "receipt_count": self.receipt_count,
            "data_shards": self.data_shards,
            "parity_shards": self.parity_shards,
            "encoded_shard_count": self.encoded_shard_count,
            "shard_bytes": self.shard_bytes,
            "slot": self.slot,
            "expires_at_slot": self.expires_at_slot,
            "receipt_commitment_root": self.receipt_commitment_root,
            "erasure_matrix_root": self.erasure_matrix_root,
            "group_root": self.group_root,
            "deterministic_availability_root": self.deterministic_availability_root,
            "batch_root": self.batch_root
        })
    }

    fn refresh_root(&mut self) {
        self.batch_root = record_root("ERASURE-BATCH", &self.public_record());
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AvailabilityShard {
    pub shard_id: String,
    pub batch_id: String,
    pub group_id: String,
    pub shard_index: u16,
    pub status: ShardStatus,
    pub shard_bytes: u64,
    pub fanout_peer_count: u16,
    pub encrypted_payload_root: String,
    pub shard_commitment_root: String,
    pub pq_auth_root: String,
    pub shard_root: String,
}

impl AvailabilityShard {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    fn refresh_root(&mut self) {
        self.shard_root = record_root("AVAILABILITY-SHARD", &self.public_record());
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqFanoutAttestation {
    pub attestation_id: String,
    pub batch_id: String,
    pub group_id: String,
    pub status_accepted: bool,
    pub fanout_width: u16,
    pub quorum_threshold: u16,
    pub authenticated_peers: u16,
    pub pq_suite: String,
    pub security_bits: u16,
    pub attested_shard_root: String,
    pub aggregate_signature_root: String,
    pub attestation_root: String,
}

impl PqFanoutAttestation {
    pub fn accepted(&self) -> bool {
        self.status_accepted
            && self.security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS
            && self.authenticated_peers >= self.quorum_threshold
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    fn refresh_root(&mut self) {
        self.attestation_root = record_root("PQ-FANOUT-ATTESTATION", &self.public_record());
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRetransmit {
    pub retransmit_id: String,
    pub batch_id: String,
    pub reason: RetransmitReason,
    pub retry_count: u64,
    pub missing_shards: u16,
    pub scheduled_slot: u64,
    pub uncapped_fee_micros: u64,
    pub charged_fee_micros: u64,
    pub fee_cap_micros: u64,
    pub deterministic_root: String,
    pub retransmit_root: String,
}

impl LowFeeRetransmit {
    pub fn public_record(&self) -> Value {
        json!({
            "retransmit_id": self.retransmit_id,
            "batch_id": self.batch_id,
            "reason": self.reason.as_str(),
            "retry_count": self.retry_count,
            "missing_shards": self.missing_shards,
            "scheduled_slot": self.scheduled_slot,
            "uncapped_fee_micros": self.uncapped_fee_micros,
            "charged_fee_micros": self.charged_fee_micros,
            "fee_cap_micros": self.fee_cap_micros,
            "deterministic_root": self.deterministic_root,
            "retransmit_root": self.retransmit_root
        })
    }

    fn refresh_root(&mut self) {
        self.retransmit_root = record_root("LOW-FEE-RETRANSMIT", &self.public_record());
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorPublicRecord {
    pub record_id: String,
    pub height: u64,
    pub epoch: u64,
    pub receipt_group_count: usize,
    pub batch_count: usize,
    pub shard_count: usize,
    pub pq_attestation_count: usize,
    pub retransmit_count: usize,
    pub shard_bytes_erasurecast: u64,
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
    pub receipt_groups: BTreeMap<String, ConfidentialReceiptGroup>,
    pub erasure_batches: BTreeMap<String, ErasureBatch>,
    pub availability_shards: BTreeMap<String, AvailabilityShard>,
    pub pq_fanout_attestations: BTreeMap<String, PqFanoutAttestation>,
    pub retransmits: BTreeMap<String, LowFeeRetransmit>,
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
            receipt_groups: BTreeMap::new(),
            erasure_batches: BTreeMap::new(),
            availability_shards: BTreeMap::new(),
            pq_fanout_attestations: BTreeMap::new(),
            retransmits: BTreeMap::new(),
            public_records: BTreeMap::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).expect("devnet config is valid");
        state.current_slot = 88;
        state.seed_devnet();
        state.refresh_roots();
        state.emit_public_record();
        state.refresh_roots();
        state
    }

    pub fn demo() -> Self {
        Self::devnet()
    }

    pub fn open_receipt_group(
        &mut self,
        group_id: impl Into<String>,
        class: AvailabilityClass,
        receipt_commitment_count: u64,
    ) -> Result<String> {
        if self.receipt_groups.len() >= self.config.max_groups {
            return Err("receipt group capacity exceeded".to_string());
        }
        let group_id = group_id.into();
        let mut group = ConfidentialReceiptGroup {
            encrypted_group_key_root: group_key_root(&group_id, self.epoch),
            membership_commitment_root: membership_root(&group_id, receipt_commitment_count),
            group_id: group_id.clone(),
            status: GroupStatus::Open,
            class,
            receipt_commitment_count,
            privacy_set_size: self.config.min_privacy_set_size,
            epoch: self.epoch,
            group_root: String::new(),
        };
        group.refresh_root();
        self.receipt_groups.insert(group_id.clone(), group);
        self.counters.groups_opened = self.counters.groups_opened.saturating_add(1);
        self.refresh_roots();
        Ok(group_id)
    }

    pub fn encode_batch(
        &mut self,
        group_id: &str,
        first_receipt_index: u64,
        receipt_count: u64,
        shard_bytes: u64,
    ) -> Result<String> {
        if self.erasure_batches.len() >= self.config.max_batches {
            return Err("erasure batch capacity exceeded".to_string());
        }
        if shard_bytes > self.config.max_shard_bytes {
            return Err("availability shard exceeds byte ceiling".to_string());
        }
        let encoded_shard_count = self
            .config
            .data_shards
            .saturating_add(self.config.parity_shards);
        if self
            .availability_shards
            .len()
            .saturating_add(encoded_shard_count as usize)
            > self.config.max_shards
        {
            return Err("availability shard capacity exceeded".to_string());
        }
        let group = self
            .receipt_groups
            .get(group_id)
            .ok_or_else(|| "confidential receipt group not found".to_string())?;
        if !group.status.accepts_batches() {
            return Err("confidential receipt group does not accept batches".to_string());
        }
        let receipt_commitment_root =
            receipt_commitment_root(group_id, first_receipt_index, receipt_count);
        let erasure_matrix_root = erasure_matrix_root(
            group_id,
            self.config.data_shards,
            self.config.parity_shards,
            receipt_count,
        );
        let deterministic_availability_root = deterministic_availability_root(
            group_id,
            self.current_slot,
            &receipt_commitment_root,
            &erasure_matrix_root,
            &group.group_root,
        );
        let mut batch = ErasureBatch {
            batch_id: format!("erasure-batch-{group_id}-{first_receipt_index}"),
            group_id: group_id.to_string(),
            class: group.class,
            status: BatchStatus::Encoded,
            first_receipt_index,
            receipt_count,
            data_shards: self.config.data_shards,
            parity_shards: self.config.parity_shards,
            encoded_shard_count,
            shard_bytes,
            slot: self.current_slot,
            expires_at_slot: self
                .current_slot
                .saturating_add(self.config.shard_ttl_slots),
            receipt_commitment_root,
            erasure_matrix_root,
            group_root: group.group_root.clone(),
            deterministic_availability_root,
            batch_root: String::new(),
        };
        batch.refresh_root();
        let batch_id = batch.batch_id.clone();
        for shard_index in 0..encoded_shard_count {
            let mut shard = AvailabilityShard {
                shard_id: format!("availability-shard-{batch_id}-{shard_index:03}"),
                batch_id: batch_id.clone(),
                group_id: group_id.to_string(),
                shard_index,
                status: ShardStatus::Encoded,
                shard_bytes,
                fanout_peer_count: 0,
                encrypted_payload_root: encrypted_shard_payload_root(&batch_id, shard_index),
                shard_commitment_root: shard_commitment_root(&batch_id, shard_index, shard_bytes),
                pq_auth_root: String::new(),
                shard_root: String::new(),
            };
            shard.refresh_root();
            self.availability_shards
                .insert(shard.shard_id.clone(), shard);
        }
        self.erasure_batches.insert(batch_id.clone(), batch);
        self.counters.batches_encoded = self.counters.batches_encoded.saturating_add(1);
        self.counters.shards_encoded = self
            .counters
            .shards_encoded
            .saturating_add(encoded_shard_count as u64);
        self.counters.deterministic_roots_emitted =
            self.counters.deterministic_roots_emitted.saturating_add(1);
        self.refresh_roots();
        Ok(batch_id)
    }

    pub fn authenticate_fanout(&mut self, batch_id: &str, authenticated_peers: u16) -> Result<()> {
        if self.pq_fanout_attestations.len() >= self.config.max_attestations {
            return Err("PQ fanout attestation capacity exceeded".to_string());
        }
        let batch = self
            .erasure_batches
            .get_mut(batch_id)
            .ok_or_else(|| "erasure batch not found".to_string())?;
        let accepted = authenticated_peers >= self.config.fanout_quorum;
        let attested_shard_root = merkle_records(D_SHARDS, &self.availability_shards);
        let mut attestation = PqFanoutAttestation {
            attestation_id: format!("pq-fanout-attestation-{batch_id}"),
            batch_id: batch_id.to_string(),
            group_id: batch.group_id.clone(),
            status_accepted: accepted,
            fanout_width: self.config.fanout_width,
            quorum_threshold: self.config.fanout_quorum,
            authenticated_peers,
            pq_suite: PQ_SHARD_AUTH_SUITE.to_string(),
            security_bits: self.config.min_pq_security_bits,
            attested_shard_root,
            aggregate_signature_root: dev_hash("fanout-signature", authenticated_peers as u64),
            attestation_root: String::new(),
        };
        attestation.refresh_root();
        if attestation.accepted() {
            batch.status = BatchStatus::FanoutAuthenticated;
            batch.refresh_root();
            for shard in self
                .availability_shards
                .values_mut()
                .filter(|shard| shard.batch_id == batch_id)
            {
                shard.status = ShardStatus::PqAuthenticated;
                shard.fanout_peer_count = authenticated_peers;
                shard.pq_auth_root = attestation.attestation_root.clone();
                shard.refresh_root();
            }
            self.counters.pq_attestations_verified =
                self.counters.pq_attestations_verified.saturating_add(1);
            self.counters.authenticated_fanout_peers = self
                .counters
                .authenticated_fanout_peers
                .saturating_add(authenticated_peers as u64);
        }
        self.pq_fanout_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh_roots();
        Ok(())
    }

    pub fn mark_available(&mut self, batch_id: &str) -> Result<()> {
        let batch = self
            .erasure_batches
            .get_mut(batch_id)
            .ok_or_else(|| "erasure batch not found".to_string())?;
        if batch.status != BatchStatus::FanoutAuthenticated {
            return Err("erasure batch is not PQ authenticated".to_string());
        }
        batch.status = BatchStatus::Available;
        batch.refresh_root();
        let mut erasurecast_count = 0_u64;
        let mut erasurecast_bytes = 0_u64;
        for shard in self
            .availability_shards
            .values_mut()
            .filter(|shard| shard.batch_id == batch_id)
        {
            shard.status = ShardStatus::Erasurecast;
            shard.refresh_root();
            erasurecast_count = erasurecast_count.saturating_add(1);
            erasurecast_bytes = erasurecast_bytes.saturating_add(shard.shard_bytes);
        }
        self.counters.shards_erasurecast = self
            .counters
            .shards_erasurecast
            .saturating_add(erasurecast_count);
        self.counters.shard_bytes_erasurecast = self
            .counters
            .shard_bytes_erasurecast
            .saturating_add(erasurecast_bytes);
        self.counters.availability_quorums_met =
            self.counters.availability_quorums_met.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn queue_retransmit(
        &mut self,
        batch_id: &str,
        reason: RetransmitReason,
        retry_count: u64,
        missing_shards: u16,
    ) -> Result<String> {
        if self.retransmits.len() >= self.config.max_retransmits {
            return Err("retransmit capacity exceeded".to_string());
        }
        let batch = self
            .erasure_batches
            .get_mut(batch_id)
            .ok_or_else(|| "erasure batch not found".to_string())?;
        if !batch.status.accepts_retransmit() {
            return Err("erasure batch does not accept retransmits".to_string());
        }
        let scaled_base = self
            .config
            .base_retransmit_fee_micros
            .saturating_mul(retry_count.saturating_add(1))
            .saturating_mul(missing_shards.max(1) as u64);
        let uncapped_fee_micros =
            scaled_base.saturating_mul(self.config.congestion_multiplier_bps) / MAX_BPS;
        let charged_fee_micros = uncapped_fee_micros.min(self.config.retransmit_fee_cap_micros);
        let mut retransmit = LowFeeRetransmit {
            retransmit_id: format!("low-fee-retransmit-{batch_id}-{retry_count}"),
            batch_id: batch_id.to_string(),
            reason,
            retry_count,
            missing_shards,
            scheduled_slot: self.current_slot.saturating_add(1),
            uncapped_fee_micros,
            charged_fee_micros,
            fee_cap_micros: self.config.retransmit_fee_cap_micros,
            deterministic_root: batch.deterministic_availability_root.clone(),
            retransmit_root: String::new(),
        };
        retransmit.refresh_root();
        batch.status = BatchStatus::RetransmitQueued;
        batch.refresh_root();
        let retransmit_id = retransmit.retransmit_id.clone();
        self.retransmits.insert(retransmit_id.clone(), retransmit);
        self.counters.retransmits_queued = self.counters.retransmits_queued.saturating_add(1);
        self.counters.retransmit_fees_micros = self
            .counters
            .retransmit_fees_micros
            .saturating_add(charged_fee_micros);
        self.counters.fee_cap_savings_micros = self
            .counters
            .fee_cap_savings_micros
            .saturating_add(uncapped_fee_micros.saturating_sub(charged_fee_micros));
        self.refresh_roots();
        Ok(retransmit_id)
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
            "receipt_groups": self.receipt_groups.values().map(ConfidentialReceiptGroup::public_record).collect::<Vec<_>>(),
            "erasure_batches": self.erasure_batches.values().map(ErasureBatch::public_record).collect::<Vec<_>>(),
            "availability_shards": self.availability_shards.values().map(AvailabilityShard::public_record).collect::<Vec<_>>(),
            "pq_fanout_attestations": self.pq_fanout_attestations.values().map(PqFanoutAttestation::public_record).collect::<Vec<_>>(),
            "retransmits": self.retransmits.values().map(LowFeeRetransmit::public_record).collect::<Vec<_>>(),
            "public_records": self.public_records.values().map(OperatorPublicRecord::public_record).collect::<Vec<_>>(),
            "operator_safe": true,
            "receipt_payloads_redacted": true,
            "pq_authenticated_shard_fanout": true,
            "confidential_receipt_groups": true,
            "low_fee_retransmit_caps": true,
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
            receipt_groups_root: merkle_records(D_GROUPS, &self.receipt_groups),
            erasure_batches_root: merkle_records(D_BATCHES, &self.erasure_batches),
            availability_shards_root: merkle_records(D_SHARDS, &self.availability_shards),
            pq_fanout_attestations_root: merkle_records(
                D_ATTESTATIONS,
                &self.pq_fanout_attestations,
            ),
            retransmits_root: merkle_records(D_RETRANSMITS, &self.retransmits),
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
            AvailabilityClass::WalletFast,
            AvailabilityClass::MerchantFast,
            AvailabilityClass::BridgeExit,
            AvailabilityClass::DefiSettlement,
            AvailabilityClass::OperatorMirror,
            AvailabilityClass::RecoveryArchive,
        ];
        for (index, class) in classes.into_iter().enumerate() {
            let group_id = self
                .open_receipt_group(
                    format!("confidential-availability-group-devnet-{:02}", index + 1),
                    class,
                    1_536 + index as u64 * 384,
                )
                .expect("devnet group capacity");
            let receipt_count = 240 + index as u64 * 48;
            let shard_bytes = 64 * 1024 + index as u64 * 4_096;
            let batch_id = self
                .encode_batch(
                    &group_id,
                    900_000 + index as u64 * 30_000,
                    receipt_count,
                    shard_bytes,
                )
                .expect("devnet batch encodes");
            let authenticated_peers = self
                .config
                .fanout_quorum
                .saturating_add((index as u16) % 9)
                .min(self.config.fanout_width);
            let _ = self.authenticate_fanout(&batch_id, authenticated_peers);
            let _ = self.mark_available(&batch_id);
            if index % 2 == 0 {
                let _ = self.queue_retransmit(
                    &batch_id,
                    RetransmitReason::LowFeeCapPreserve,
                    index as u64 + 1,
                    2 + index as u16,
                );
            }
        }
    }

    fn emit_public_record(&mut self) {
        if self.public_records.len() >= self.config.max_public_records {
            return;
        }
        let mut record = OperatorPublicRecord {
            record_id: "operator-public-record-devnet-receipt-availability-erasurecast".to_string(),
            height: self.height,
            epoch: self.epoch,
            receipt_group_count: self.receipt_groups.len(),
            batch_count: self.erasure_batches.len(),
            shard_count: self.availability_shards.len(),
            pq_attestation_count: self.pq_fanout_attestations.len(),
            retransmit_count: self.retransmits.len(),
            shard_bytes_erasurecast: self.counters.shard_bytes_erasurecast,
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
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-RECEIPT-AVAILABILITY-ERASURECAST-{}",
            domain
        ),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn erasure_batch_digest(record: &ErasureBatch) -> String {
    payload_root(ERASURECAST_SUITE, &record.public_record())
}

pub fn availability_shard_digest(record: &AvailabilityShard) -> String {
    payload_root(ERASURECAST_SUITE, &record.public_record())
}

pub fn receipt_group_digest(record: &ConfidentialReceiptGroup) -> String {
    payload_root(CONFIDENTIAL_RECEIPT_GROUP_SUITE, &record.public_record())
}

pub fn pq_fanout_attestation_digest(record: &PqFanoutAttestation) -> String {
    payload_root(PQ_SHARD_AUTH_SUITE, &record.public_record())
}

pub fn retransmit_digest(record: &LowFeeRetransmit) -> String {
    payload_root(RETRANSMIT_CAP_SUITE, &record.public_record())
}

fn group_key_root(group_id: &str, epoch: u64) -> String {
    domain_hash(
        CONFIDENTIAL_RECEIPT_GROUP_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(group_id),
            HashPart::U64(epoch),
        ],
        32,
    )
}

fn membership_root(group_id: &str, receipt_commitment_count: u64) -> String {
    domain_hash(
        CONFIDENTIAL_RECEIPT_GROUP_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(group_id),
            HashPart::U64(receipt_commitment_count),
        ],
        32,
    )
}

fn receipt_commitment_root(group_id: &str, first_receipt_index: u64, receipt_count: u64) -> String {
    domain_hash(
        ERASURECAST_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(group_id),
            HashPart::U64(first_receipt_index),
            HashPart::U64(receipt_count),
        ],
        32,
    )
}

fn erasure_matrix_root(
    group_id: &str,
    data_shards: u16,
    parity_shards: u16,
    receipt_count: u64,
) -> String {
    domain_hash(
        ERASURECAST_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(group_id),
            HashPart::U64(data_shards as u64),
            HashPart::U64(parity_shards as u64),
            HashPart::U64(receipt_count),
        ],
        32,
    )
}

fn deterministic_availability_root(
    group_id: &str,
    slot: u64,
    receipt_commitment_root: &str,
    erasure_matrix_root: &str,
    group_root: &str,
) -> String {
    domain_hash(
        ERASURECAST_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(group_id),
            HashPart::U64(slot),
            HashPart::Str(receipt_commitment_root),
            HashPart::Str(erasure_matrix_root),
            HashPart::Str(group_root),
        ],
        32,
    )
}

fn encrypted_shard_payload_root(batch_id: &str, shard_index: u16) -> String {
    domain_hash(
        ERASURECAST_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(batch_id),
            HashPart::U64(shard_index as u64),
            HashPart::Str("encrypted-shard-payload-redacted"),
        ],
        32,
    )
}

fn shard_commitment_root(batch_id: &str, shard_index: u16, shard_bytes: u64) -> String {
    domain_hash(
        ERASURECAST_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(batch_id),
            HashPart::U64(shard_index as u64),
            HashPart::U64(shard_bytes),
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
