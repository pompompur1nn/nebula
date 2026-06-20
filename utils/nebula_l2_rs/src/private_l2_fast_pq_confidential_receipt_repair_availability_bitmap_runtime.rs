use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialReceiptRepairAvailabilityBitmapRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_RECEIPT_REPAIR_AVAILABILITY_BITMAP_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-fast-pq-confidential-receipt-repair-availability-bitmap-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_RECEIPT_REPAIR_AVAILABILITY_BITMAP_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "shake256-domain-separated-canonical-json-v1";
pub const AVAILABILITY_BITMAP_SUITE: &str =
    "private-l2-fast-confidential-receipt-repair-availability-bitmap-v1";
pub const PQ_REPAIR_COMMITMENT_AUTH_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-256f-repair-commitment-auth-v1";
pub const CONFIDENTIAL_SHARD_AVAILABILITY_COHORT_SUITE: &str =
    "ml-kem-1024-confidential-shard-availability-cohort-v1";
pub const LOW_FEE_RETRY_CAP_SUITE: &str =
    "private-l2-low-fee-repair-availability-bitmap-retry-cap-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "operator-safe-confidential-receipt-repair-availability-bitmap-public-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_receipts_addresses_view_keys_cohort_members_or_shard_payload_bytes";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 5_390_000;
pub const DEVNET_EPOCH: u64 = 17_184;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MAX_WINDOWS: usize = 131_072;
pub const DEFAULT_MAX_COHORTS: usize = 65_536;
pub const DEFAULT_MAX_REPAIR_COMMITMENTS: usize = 1_048_576;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 1_048_576;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 65_536;
pub const DEFAULT_BITMAP_WORDS: u16 = 64;
pub const DEFAULT_SHARDS_PER_WINDOW: u16 = 4_096;
pub const DEFAULT_AVAILABILITY_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_REPAIR_TTL_SLOTS: u64 = 48;
pub const DEFAULT_TARGET_REPAIR_MS: u64 = 16;
pub const DEFAULT_MAX_MISSING_SHARDS: u16 = 32;
pub const DEFAULT_MAX_RETRY_COUNT: u64 = 5;
pub const DEFAULT_BASE_RETRY_FEE_MICROS: u64 = 2;
pub const DEFAULT_RETRY_FEE_CAP_MICROS: u64 = 30;
pub const DEFAULT_CONGESTION_MULTIPLIER_BPS: u64 = 1_100;

const D_CONFIG: &str = "PL2-FAST-PQ-CONF-RECEIPT-REPAIR-AVAILABILITY-BITMAP:CONFIG";
const D_COUNTERS: &str = "PL2-FAST-PQ-CONF-RECEIPT-REPAIR-AVAILABILITY-BITMAP:COUNTERS";
const D_ROOTS: &str = "PL2-FAST-PQ-CONF-RECEIPT-REPAIR-AVAILABILITY-BITMAP:ROOTS";
const D_STATE: &str = "PL2-FAST-PQ-CONF-RECEIPT-REPAIR-AVAILABILITY-BITMAP:STATE";
const D_WINDOWS: &str = "PL2-FAST-PQ-CONF-RECEIPT-REPAIR-AVAILABILITY-BITMAP:WINDOWS";
const D_COHORTS: &str = "PL2-FAST-PQ-CONF-RECEIPT-REPAIR-AVAILABILITY-BITMAP:COHORTS";
const D_COMMITMENTS: &str = "PL2-FAST-PQ-CONF-RECEIPT-REPAIR-AVAILABILITY-BITMAP:COMMITMENTS";
const D_ATTESTATIONS: &str = "PL2-FAST-PQ-CONF-RECEIPT-REPAIR-AVAILABILITY-BITMAP:ATTESTATIONS";
const D_PUBLIC: &str = "PL2-FAST-PQ-CONF-RECEIPT-REPAIR-AVAILABILITY-BITMAP:PUBLIC";
const D_DEVNET: &str = "PL2-FAST-PQ-CONF-RECEIPT-REPAIR-AVAILABILITY-BITMAP:DEVNET";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BitmapClass {
    WalletFast,
    MerchantFast,
    BridgeExit,
    DefiSettlement,
    OperatorMirror,
    RecoveryArchive,
}

impl BitmapClass {
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
            Self::OperatorMirror => 9_850,
            Self::DefiSettlement => 9_250,
            Self::MerchantFast => 8_700,
            Self::WalletFast => 8_200,
            Self::RecoveryArchive => 5_700,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BitmapStatus {
    Open,
    Hot,
    Repairing,
    FeeCapped,
    Sealed,
    Retired,
}

impl BitmapStatus {
    pub fn accepts_repairs(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Hot | Self::Repairing | Self::FeeCapped
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
pub enum RepairCommitmentStatus {
    BitmapQueued,
    PqAuthenticated,
    Broadcast,
    Applied,
    RetryCapped,
    Expired,
}

impl RepairCommitmentStatus {
    pub fn accepts_apply(self) -> bool {
        matches!(self, Self::PqAuthenticated | Self::Broadcast)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairReason {
    AvailabilityGap,
    BitmapWordMissing,
    ShardDigestMismatch,
    CohortKeyRotation,
    LowFeeRetryPreserve,
    OperatorMirrorCatchup,
}

impl RepairReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AvailabilityGap => "availability_gap",
            Self::BitmapWordMissing => "bitmap_word_missing",
            Self::ShardDigestMismatch => "shard_digest_mismatch",
            Self::CohortKeyRotation => "cohort_key_rotation",
            Self::LowFeeRetryPreserve => "low_fee_retry_preserve",
            Self::OperatorMirrorCatchup => "operator_mirror_catchup",
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
    pub availability_bitmap_suite: String,
    pub pq_repair_commitment_auth_suite: String,
    pub confidential_shard_availability_cohort_suite: String,
    pub low_fee_retry_cap_suite: String,
    pub public_record_scheme: String,
    pub privacy_boundary: String,
    pub max_windows: usize,
    pub max_cohorts: usize,
    pub max_repair_commitments: usize,
    pub max_attestations: usize,
    pub max_public_records: usize,
    pub bitmap_words: u16,
    pub shards_per_window: u16,
    pub availability_quorum_bps: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub repair_ttl_slots: u64,
    pub target_repair_ms: u64,
    pub max_missing_shards: u16,
    pub max_retry_count: u64,
    pub base_retry_fee_micros: u64,
    pub retry_fee_cap_micros: u64,
    pub congestion_multiplier_bps: u64,
    pub require_fast_availability_bitmaps: bool,
    pub require_pq_authenticated_repair_commitments: bool,
    pub require_confidential_shard_availability_cohorts: bool,
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
            availability_bitmap_suite: AVAILABILITY_BITMAP_SUITE.to_string(),
            pq_repair_commitment_auth_suite: PQ_REPAIR_COMMITMENT_AUTH_SUITE.to_string(),
            confidential_shard_availability_cohort_suite:
                CONFIDENTIAL_SHARD_AVAILABILITY_COHORT_SUITE.to_string(),
            low_fee_retry_cap_suite: LOW_FEE_RETRY_CAP_SUITE.to_string(),
            public_record_scheme: PUBLIC_RECORD_SCHEME.to_string(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            max_windows: DEFAULT_MAX_WINDOWS,
            max_cohorts: DEFAULT_MAX_COHORTS,
            max_repair_commitments: DEFAULT_MAX_REPAIR_COMMITMENTS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_public_records: DEFAULT_MAX_PUBLIC_RECORDS,
            bitmap_words: DEFAULT_BITMAP_WORDS,
            shards_per_window: DEFAULT_SHARDS_PER_WINDOW,
            availability_quorum_bps: DEFAULT_AVAILABILITY_QUORUM_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            repair_ttl_slots: DEFAULT_REPAIR_TTL_SLOTS,
            target_repair_ms: DEFAULT_TARGET_REPAIR_MS,
            max_missing_shards: DEFAULT_MAX_MISSING_SHARDS,
            max_retry_count: DEFAULT_MAX_RETRY_COUNT,
            base_retry_fee_micros: DEFAULT_BASE_RETRY_FEE_MICROS,
            retry_fee_cap_micros: DEFAULT_RETRY_FEE_CAP_MICROS,
            congestion_multiplier_bps: DEFAULT_CONGESTION_MULTIPLIER_BPS,
            require_fast_availability_bitmaps: true,
            require_pq_authenticated_repair_commitments: true,
            require_confidential_shard_availability_cohorts: true,
            require_low_fee_retry_caps: true,
            require_deterministic_roots: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("protocol version mismatch".to_string());
        }
        if self.max_windows == 0 || self.max_cohorts == 0 || self.max_repair_commitments == 0 {
            return Err("availability bitmap capacities must be non-zero".to_string());
        }
        if self.bitmap_words == 0 || self.shards_per_window == 0 {
            return Err("availability bitmap dimensions must be non-zero".to_string());
        }
        if self.availability_quorum_bps == 0 || self.availability_quorum_bps > MAX_BPS {
            return Err("availability quorum must fit basis point ceiling".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("minimum PQ security below 192 bits".to_string());
        }
        if self.max_missing_shards == 0 || self.max_missing_shards > self.shards_per_window {
            return Err("missing shard ceiling outside bitmap window bounds".to_string());
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
    pub bitmap_windows_opened: u64,
    pub availability_cohorts_opened: u64,
    pub repair_commitments_queued: u64,
    pub repair_commitments_broadcast: u64,
    pub repair_commitments_applied: u64,
    pub missing_shards_committed: u64,
    pub pq_commitment_attestations_verified: u64,
    pub authenticated_repair_committers: u64,
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
    pub availability_windows_root: String,
    pub availability_cohorts_root: String,
    pub repair_commitments_root: String,
    pub pq_commitment_attestations_root: String,
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
pub struct AvailabilityWindow {
    pub window_id: String,
    pub class: BitmapClass,
    pub status: BitmapStatus,
    pub priority_weight: u64,
    pub first_receipt_index: u64,
    pub receipt_count: u64,
    pub bitmap_words: u16,
    pub shards_per_window: u16,
    pub available_shards: u16,
    pub missing_shards: u16,
    pub bitmap_commitment_root: String,
    pub availability_digest_root: String,
    pub window_root: String,
}

impl AvailabilityWindow {
    pub fn new(
        window_id: impl Into<String>,
        class: BitmapClass,
        first_receipt_index: u64,
        receipt_count: u64,
        available_shards: u16,
        config: &Config,
    ) -> Self {
        let window_id = window_id.into();
        let available_shards = available_shards.min(config.shards_per_window);
        let missing_shards = config.shards_per_window.saturating_sub(available_shards);
        let mut window = Self {
            bitmap_commitment_root: bitmap_commitment_root(
                &window_id,
                first_receipt_index,
                receipt_count,
                config.bitmap_words,
                available_shards,
            ),
            availability_digest_root: availability_digest_root(
                &window_id,
                available_shards,
                missing_shards,
            ),
            window_id,
            class,
            status: BitmapStatus::Open,
            priority_weight: class.priority_weight(),
            first_receipt_index,
            receipt_count,
            bitmap_words: config.bitmap_words,
            shards_per_window: config.shards_per_window,
            available_shards,
            missing_shards,
            window_root: String::new(),
        };
        window.refresh_root();
        window
    }

    pub fn availability_bps(&self) -> u64 {
        if self.shards_per_window == 0 {
            0
        } else {
            (self.available_shards as u64).saturating_mul(MAX_BPS) / self.shards_per_window as u64
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "class": self.class.as_str(),
            "status": self.status,
            "priority_weight": self.priority_weight,
            "first_receipt_index": self.first_receipt_index,
            "receipt_count": self.receipt_count,
            "bitmap_words": self.bitmap_words,
            "shards_per_window": self.shards_per_window,
            "available_shards": self.available_shards,
            "missing_shards": self.missing_shards,
            "availability_bps": self.availability_bps(),
            "bitmap_commitment_root": self.bitmap_commitment_root,
            "availability_digest_root": self.availability_digest_root,
            "window_root": self.window_root
        })
    }

    fn refresh_root(&mut self) {
        self.window_root = record_root("AVAILABILITY-WINDOW", &self.public_record());
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialAvailabilityCohort {
    pub cohort_id: String,
    pub status: CohortStatus,
    pub class: BitmapClass,
    pub receipt_commitment_count: u64,
    pub privacy_set_size: u64,
    pub epoch: u64,
    pub encrypted_cohort_key_root: String,
    pub membership_commitment_root: String,
    pub shard_availability_root: String,
    pub cohort_root: String,
}

impl ConfidentialAvailabilityCohort {
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
            "shard_availability_root": self.shard_availability_root,
            "cohort_root": self.cohort_root
        })
    }

    fn refresh_root(&mut self) {
        self.cohort_root = record_root("CONFIDENTIAL-AVAILABILITY-COHORT", &self.public_record());
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepairCommitment {
    pub commitment_id: String,
    pub window_id: String,
    pub cohort_id: String,
    pub reason: RepairReason,
    pub status: RepairCommitmentStatus,
    pub missing_shards: u16,
    pub retry_count: u64,
    pub queued_slot: u64,
    pub broadcast_slot: u64,
    pub expires_at_slot: u64,
    pub uncapped_fee_micros: u64,
    pub charged_fee_micros: u64,
    pub fee_cap_micros: u64,
    pub receipt_commitment_root: String,
    pub missing_shard_bitmap_root: String,
    pub pq_repair_commitment_root: String,
    pub deterministic_repair_root: String,
    pub commitment_root: String,
}

impl RepairCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "window_id": self.window_id,
            "cohort_id": self.cohort_id,
            "reason": self.reason.as_str(),
            "status": self.status,
            "missing_shards": self.missing_shards,
            "retry_count": self.retry_count,
            "queued_slot": self.queued_slot,
            "broadcast_slot": self.broadcast_slot,
            "expires_at_slot": self.expires_at_slot,
            "uncapped_fee_micros": self.uncapped_fee_micros,
            "charged_fee_micros": self.charged_fee_micros,
            "fee_cap_micros": self.fee_cap_micros,
            "receipt_commitment_root": self.receipt_commitment_root,
            "missing_shard_bitmap_root": self.missing_shard_bitmap_root,
            "pq_repair_commitment_root": self.pq_repair_commitment_root,
            "deterministic_repair_root": self.deterministic_repair_root,
            "commitment_root": self.commitment_root
        })
    }

    fn refresh_root(&mut self) {
        self.commitment_root = record_root("REPAIR-COMMITMENT", &self.public_record());
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqCommitmentAttestation {
    pub attestation_id: String,
    pub commitment_id: String,
    pub window_id: String,
    pub status_accepted: bool,
    pub quorum_bps: u64,
    pub observed_availability_bps: u64,
    pub authenticated_committers: u16,
    pub pq_suite: String,
    pub security_bits: u16,
    pub attested_window_root: String,
    pub attested_commitment_root: String,
    pub aggregate_signature_root: String,
    pub attestation_root: String,
}

impl PqCommitmentAttestation {
    pub fn accepted(&self) -> bool {
        self.status_accepted
            && self.security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS
            && self.observed_availability_bps < self.quorum_bps
            && self.authenticated_committers > 0
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    fn refresh_root(&mut self) {
        self.attestation_root = record_root("PQ-COMMITMENT-ATTESTATION", &self.public_record());
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorPublicRecord {
    pub record_id: String,
    pub height: u64,
    pub epoch: u64,
    pub availability_window_count: usize,
    pub availability_cohort_count: usize,
    pub repair_commitment_count: usize,
    pub pq_attestation_count: usize,
    pub missing_shards_committed: u64,
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
    pub availability_windows: BTreeMap<String, AvailabilityWindow>,
    pub availability_cohorts: BTreeMap<String, ConfidentialAvailabilityCohort>,
    pub repair_commitments: BTreeMap<String, RepairCommitment>,
    pub pq_commitment_attestations: BTreeMap<String, PqCommitmentAttestation>,
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
            availability_windows: BTreeMap::new(),
            availability_cohorts: BTreeMap::new(),
            repair_commitments: BTreeMap::new(),
            pq_commitment_attestations: BTreeMap::new(),
            public_records: BTreeMap::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).expect("devnet config is valid");
        state.current_slot = 102;
        state.seed_devnet();
        state.refresh_roots();
        state.emit_public_record();
        state.refresh_roots();
        state
    }

    pub fn demo() -> Self {
        Self::devnet()
    }

    pub fn register_availability_window(&mut self, window: AvailabilityWindow) -> Result<()> {
        if self.availability_windows.len() >= self.config.max_windows {
            return Err("availability bitmap window capacity exceeded".to_string());
        }
        self.availability_windows
            .insert(window.window_id.clone(), window);
        self.counters.bitmap_windows_opened = self.counters.bitmap_windows_opened.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn open_availability_cohort(
        &mut self,
        cohort_id: impl Into<String>,
        class: BitmapClass,
        receipt_commitment_count: u64,
    ) -> Result<String> {
        if self.availability_cohorts.len() >= self.config.max_cohorts {
            return Err("confidential availability cohort capacity exceeded".to_string());
        }
        let cohort_id = cohort_id.into();
        let mut cohort = ConfidentialAvailabilityCohort {
            encrypted_cohort_key_root: cohort_key_root(&cohort_id, self.epoch),
            membership_commitment_root: membership_root(&cohort_id, receipt_commitment_count),
            shard_availability_root: shard_availability_root(&cohort_id, receipt_commitment_count),
            cohort_id: cohort_id.clone(),
            status: CohortStatus::Open,
            class,
            receipt_commitment_count,
            privacy_set_size: self.config.min_privacy_set_size,
            epoch: self.epoch,
            cohort_root: String::new(),
        };
        cohort.refresh_root();
        self.availability_cohorts.insert(cohort_id.clone(), cohort);
        self.counters.availability_cohorts_opened =
            self.counters.availability_cohorts_opened.saturating_add(1);
        self.refresh_roots();
        Ok(cohort_id)
    }

    pub fn queue_repair_commitment(
        &mut self,
        window_id: &str,
        cohort_id: &str,
        reason: RepairReason,
        missing_shards: u16,
        retry_count: u64,
    ) -> Result<String> {
        if self.repair_commitments.len() >= self.config.max_repair_commitments {
            return Err("repair commitment capacity exceeded".to_string());
        }
        if missing_shards == 0 || missing_shards > self.config.max_missing_shards {
            return Err("missing shard count outside availability bitmap bounds".to_string());
        }
        if retry_count > self.config.max_retry_count {
            return Err("retry count exceeds low-fee availability bitmap cap".to_string());
        }
        let window = self
            .availability_windows
            .get_mut(window_id)
            .ok_or_else(|| "availability bitmap window not found".to_string())?;
        if !window.status.accepts_repairs() {
            return Err("availability bitmap window does not accept repairs".to_string());
        }
        if missing_shards > window.missing_shards {
            return Err("repair commitment exceeds observed missing shards".to_string());
        }
        let cohort = self
            .availability_cohorts
            .get(cohort_id)
            .ok_or_else(|| "confidential availability cohort not found".to_string())?;
        if !cohort.status.accepts_repairs() {
            return Err("confidential availability cohort does not accept repairs".to_string());
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
            receipt_commitment_root(cohort_id, window.first_receipt_index, window.receipt_count);
        let missing_shard_bitmap_root =
            missing_shard_bitmap_root(window_id, cohort_id, missing_shards, window.bitmap_words);
        let pq_repair_commitment_root = pq_repair_commitment_root(
            window_id,
            cohort_id,
            &window.bitmap_commitment_root,
            &missing_shard_bitmap_root,
        );
        let deterministic_repair_root = deterministic_repair_root(
            window_id,
            cohort_id,
            self.current_slot,
            &receipt_commitment_root,
            &missing_shard_bitmap_root,
            &pq_repair_commitment_root,
            &cohort.cohort_root,
        );
        let status = if uncapped_fee_micros > charged_fee_micros {
            RepairCommitmentStatus::RetryCapped
        } else {
            RepairCommitmentStatus::BitmapQueued
        };
        let mut commitment = RepairCommitment {
            commitment_id: format!(
                "availability-bitmap-repair-{window_id}-{cohort_id}-{}-{retry_count}",
                window.first_receipt_index
            ),
            window_id: window_id.to_string(),
            cohort_id: cohort_id.to_string(),
            reason,
            status,
            missing_shards,
            retry_count,
            queued_slot: self.current_slot,
            broadcast_slot: self.current_slot.saturating_add(1),
            expires_at_slot: self
                .current_slot
                .saturating_add(self.config.repair_ttl_slots),
            uncapped_fee_micros,
            charged_fee_micros,
            fee_cap_micros: self.config.retry_fee_cap_micros,
            receipt_commitment_root,
            missing_shard_bitmap_root,
            pq_repair_commitment_root,
            deterministic_repair_root,
            commitment_root: String::new(),
        };
        commitment.refresh_root();
        window.status = if status == RepairCommitmentStatus::RetryCapped {
            BitmapStatus::FeeCapped
        } else {
            BitmapStatus::Repairing
        };
        window.refresh_root();
        let commitment_id = commitment.commitment_id.clone();
        self.repair_commitments
            .insert(commitment_id.clone(), commitment);
        self.counters.repair_commitments_queued =
            self.counters.repair_commitments_queued.saturating_add(1);
        self.counters.missing_shards_committed = self
            .counters
            .missing_shards_committed
            .saturating_add(missing_shards as u64);
        self.counters.retry_fees_micros = self
            .counters
            .retry_fees_micros
            .saturating_add(charged_fee_micros);
        self.counters.retry_fee_cap_savings_micros = self
            .counters
            .retry_fee_cap_savings_micros
            .saturating_add(uncapped_fee_micros.saturating_sub(charged_fee_micros));
        if status == RepairCommitmentStatus::RetryCapped {
            self.counters.retry_caps_applied = self.counters.retry_caps_applied.saturating_add(1);
        }
        self.counters.deterministic_roots_emitted =
            self.counters.deterministic_roots_emitted.saturating_add(1);
        self.refresh_roots();
        Ok(commitment_id)
    }

    pub fn authenticate_repair_commitment(
        &mut self,
        commitment_id: &str,
        authenticated_committers: u16,
    ) -> Result<()> {
        if self.pq_commitment_attestations.len() >= self.config.max_attestations {
            return Err("PQ commitment attestation capacity exceeded".to_string());
        }
        let commitment = self
            .repair_commitments
            .get_mut(commitment_id)
            .ok_or_else(|| "repair commitment not found".to_string())?;
        let window = self
            .availability_windows
            .get(&commitment.window_id)
            .ok_or_else(|| "availability bitmap window not found".to_string())?;
        let observed_availability_bps = window.availability_bps();
        let accepted = observed_availability_bps < self.config.availability_quorum_bps
            && authenticated_committers > 0;
        let mut attestation = PqCommitmentAttestation {
            attestation_id: format!("pq-commitment-attestation-{commitment_id}"),
            commitment_id: commitment_id.to_string(),
            window_id: commitment.window_id.clone(),
            status_accepted: accepted,
            quorum_bps: self.config.availability_quorum_bps,
            observed_availability_bps,
            authenticated_committers,
            pq_suite: PQ_REPAIR_COMMITMENT_AUTH_SUITE.to_string(),
            security_bits: self.config.min_pq_security_bits,
            attested_window_root: window.window_root.clone(),
            attested_commitment_root: commitment.commitment_root.clone(),
            aggregate_signature_root: dev_hash(
                "repair-commitment-signature",
                authenticated_committers as u64,
            ),
            attestation_root: String::new(),
        };
        attestation.refresh_root();
        if attestation.accepted() {
            commitment.status = RepairCommitmentStatus::PqAuthenticated;
            commitment.refresh_root();
            self.counters.pq_commitment_attestations_verified = self
                .counters
                .pq_commitment_attestations_verified
                .saturating_add(1);
            self.counters.authenticated_repair_committers = self
                .counters
                .authenticated_repair_committers
                .saturating_add(authenticated_committers as u64);
        }
        self.pq_commitment_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh_roots();
        Ok(())
    }

    pub fn broadcast_repair_commitment(&mut self, commitment_id: &str) -> Result<()> {
        let commitment = self
            .repair_commitments
            .get_mut(commitment_id)
            .ok_or_else(|| "repair commitment not found".to_string())?;
        if commitment.status != RepairCommitmentStatus::PqAuthenticated {
            return Err("repair commitment is not PQ authenticated".to_string());
        }
        commitment.status = RepairCommitmentStatus::Broadcast;
        commitment.refresh_root();
        self.counters.repair_commitments_broadcast =
            self.counters.repair_commitments_broadcast.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn mark_applied(&mut self, commitment_id: &str) -> Result<()> {
        let commitment = self
            .repair_commitments
            .get_mut(commitment_id)
            .ok_or_else(|| "repair commitment not found".to_string())?;
        if !commitment.status.accepts_apply() {
            return Err("repair commitment is not ready to apply".to_string());
        }
        commitment.status = RepairCommitmentStatus::Applied;
        commitment.refresh_root();
        if let Some(window) = self.availability_windows.get_mut(&commitment.window_id) {
            let repaired = commitment.missing_shards.min(window.missing_shards);
            window.available_shards = window.available_shards.saturating_add(repaired);
            window.missing_shards = window.missing_shards.saturating_sub(repaired);
            window.availability_digest_root = availability_digest_root(
                &window.window_id,
                window.available_shards,
                window.missing_shards,
            );
            window.status = if window.missing_shards == 0 {
                BitmapStatus::Sealed
            } else {
                BitmapStatus::Hot
            };
            window.refresh_root();
        }
        self.counters.repair_commitments_applied =
            self.counters.repair_commitments_applied.saturating_add(1);
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
            "availability_windows": self.availability_windows.values().map(AvailabilityWindow::public_record).collect::<Vec<_>>(),
            "availability_cohorts": self.availability_cohorts.values().map(ConfidentialAvailabilityCohort::public_record).collect::<Vec<_>>(),
            "repair_commitments": self.repair_commitments.values().map(RepairCommitment::public_record).collect::<Vec<_>>(),
            "pq_commitment_attestations": self.pq_commitment_attestations.values().map(PqCommitmentAttestation::public_record).collect::<Vec<_>>(),
            "public_records": self.public_records.values().map(OperatorPublicRecord::public_record).collect::<Vec<_>>(),
            "operator_safe": true,
            "receipt_payloads_redacted": true,
            "fast_availability_bitmaps": true,
            "pq_authenticated_repair_commitments": true,
            "confidential_shard_availability_cohorts": true,
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
            availability_windows_root: merkle_records(D_WINDOWS, &self.availability_windows),
            availability_cohorts_root: merkle_records(D_COHORTS, &self.availability_cohorts),
            repair_commitments_root: merkle_records(D_COMMITMENTS, &self.repair_commitments),
            pq_commitment_attestations_root: merkle_records(
                D_ATTESTATIONS,
                &self.pq_commitment_attestations,
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
            BitmapClass::WalletFast,
            BitmapClass::MerchantFast,
            BitmapClass::BridgeExit,
            BitmapClass::DefiSettlement,
            BitmapClass::OperatorMirror,
            BitmapClass::RecoveryArchive,
        ];
        for (index, class) in classes.into_iter().enumerate() {
            let window_id = format!("availability-bitmap-window-devnet-{:02}", index + 1);
            let available_shards = self
                .config
                .shards_per_window
                .saturating_sub(3 + index as u16);
            let mut window = AvailabilityWindow::new(
                window_id.clone(),
                class,
                1_100_000 + index as u64 * 32_000,
                256 + index as u64 * 64,
                available_shards,
                &self.config,
            );
            if matches!(class, BitmapClass::BridgeExit | BitmapClass::OperatorMirror) {
                window.status = BitmapStatus::Hot;
                window.refresh_root();
            } else if index % 2 == 1 {
                window.status = BitmapStatus::FeeCapped;
                window.refresh_root();
            }
            let _ = self.register_availability_window(window);
            let cohort_id = self
                .open_availability_cohort(
                    format!("confidential-availability-cohort-devnet-{:02}", index + 1),
                    class,
                    1_536 + index as u64 * 384,
                )
                .expect("devnet availability cohort capacity");
            let commitment_id = self
                .queue_repair_commitment(
                    &window_id,
                    &cohort_id,
                    if index % 2 == 0 {
                        RepairReason::LowFeeRetryPreserve
                    } else {
                        RepairReason::AvailabilityGap
                    },
                    2 + index as u16,
                    (index as u64 % self.config.max_retry_count).saturating_add(1),
                )
                .expect("devnet repair commitment queues");
            let authenticated_committers = 48 + index as u16;
            let _ = self.authenticate_repair_commitment(&commitment_id, authenticated_committers);
            let _ = self.broadcast_repair_commitment(&commitment_id);
            if index % 3 != 0 {
                let _ = self.mark_applied(&commitment_id);
            }
        }
    }

    fn emit_public_record(&mut self) {
        if self.public_records.len() >= self.config.max_public_records {
            return;
        }
        let mut record = OperatorPublicRecord {
            record_id: "operator-public-record-devnet-receipt-repair-availability-bitmap"
                .to_string(),
            height: self.height,
            epoch: self.epoch,
            availability_window_count: self.availability_windows.len(),
            availability_cohort_count: self.availability_cohorts.len(),
            repair_commitment_count: self.repair_commitments.len(),
            pq_attestation_count: self.pq_commitment_attestations.len(),
            missing_shards_committed: self.counters.missing_shards_committed,
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
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-RECEIPT-REPAIR-AVAILABILITY-BITMAP-{}",
            domain
        ),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn availability_window_digest(record: &AvailabilityWindow) -> String {
    payload_root(AVAILABILITY_BITMAP_SUITE, &record.public_record())
}

pub fn availability_cohort_digest(record: &ConfidentialAvailabilityCohort) -> String {
    payload_root(
        CONFIDENTIAL_SHARD_AVAILABILITY_COHORT_SUITE,
        &record.public_record(),
    )
}

pub fn repair_commitment_digest(record: &RepairCommitment) -> String {
    payload_root(PQ_REPAIR_COMMITMENT_AUTH_SUITE, &record.public_record())
}

pub fn pq_commitment_attestation_digest(record: &PqCommitmentAttestation) -> String {
    payload_root(PQ_REPAIR_COMMITMENT_AUTH_SUITE, &record.public_record())
}

fn bitmap_commitment_root(
    window_id: &str,
    first_receipt_index: u64,
    receipt_count: u64,
    bitmap_words: u16,
    available_shards: u16,
) -> String {
    domain_hash(
        AVAILABILITY_BITMAP_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(window_id),
            HashPart::U64(first_receipt_index),
            HashPart::U64(receipt_count),
            HashPart::U64(bitmap_words as u64),
            HashPart::U64(available_shards as u64),
            HashPart::Str("availability-bitmap-words-redacted"),
        ],
        32,
    )
}

fn availability_digest_root(window_id: &str, available_shards: u16, missing_shards: u16) -> String {
    domain_hash(
        AVAILABILITY_BITMAP_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(window_id),
            HashPart::U64(available_shards as u64),
            HashPart::U64(missing_shards as u64),
        ],
        32,
    )
}

fn cohort_key_root(cohort_id: &str, epoch: u64) -> String {
    domain_hash(
        CONFIDENTIAL_SHARD_AVAILABILITY_COHORT_SUITE,
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
        CONFIDENTIAL_SHARD_AVAILABILITY_COHORT_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(cohort_id),
            HashPart::U64(receipt_commitment_count),
        ],
        32,
    )
}

fn shard_availability_root(cohort_id: &str, receipt_commitment_count: u64) -> String {
    domain_hash(
        CONFIDENTIAL_SHARD_AVAILABILITY_COHORT_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(cohort_id),
            HashPart::U64(receipt_commitment_count),
            HashPart::Str("confidential-shard-availability-map-redacted"),
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
        AVAILABILITY_BITMAP_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(cohort_id),
            HashPart::U64(first_receipt_index),
            HashPart::U64(receipt_count),
        ],
        32,
    )
}

fn missing_shard_bitmap_root(
    window_id: &str,
    cohort_id: &str,
    missing_shards: u16,
    bitmap_words: u16,
) -> String {
    domain_hash(
        AVAILABILITY_BITMAP_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(window_id),
            HashPart::Str(cohort_id),
            HashPart::U64(missing_shards as u64),
            HashPart::U64(bitmap_words as u64),
            HashPart::Str("missing-shard-bitmap-redacted"),
        ],
        32,
    )
}

fn pq_repair_commitment_root(
    window_id: &str,
    cohort_id: &str,
    bitmap_commitment_root: &str,
    missing_shard_bitmap_root: &str,
) -> String {
    domain_hash(
        PQ_REPAIR_COMMITMENT_AUTH_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(window_id),
            HashPart::Str(cohort_id),
            HashPart::Str(bitmap_commitment_root),
            HashPart::Str(missing_shard_bitmap_root),
        ],
        32,
    )
}

fn deterministic_repair_root(
    window_id: &str,
    cohort_id: &str,
    slot: u64,
    receipt_commitment_root: &str,
    missing_shard_bitmap_root: &str,
    pq_repair_commitment_root: &str,
    cohort_root: &str,
) -> String {
    domain_hash(
        AVAILABILITY_BITMAP_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(window_id),
            HashPart::Str(cohort_id),
            HashPart::U64(slot),
            HashPart::Str(receipt_commitment_root),
            HashPart::Str(missing_shard_bitmap_root),
            HashPart::Str(pq_repair_commitment_root),
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
