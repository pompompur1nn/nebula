use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialCrossContractStatePrefetchRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_CROSS_CONTRACT_STATE_PREFETCH_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-fast-pq-confidential-cross-contract-state-prefetch-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_CROSS_CONTRACT_STATE_PREFETCH_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-cross-contract-prefetch-attestation-v1";
pub const PQ_ENVELOPE_SUITE: &str =
    "ML-KEM-1024-threshold-confidential-cross-contract-state-prefetch-envelope-v1";
pub const WITNESS_PACK_SUITE: &str = "nova-pq-confidential-cross-contract-witness-pack-v1";
pub const CACHE_LEASE_SUITE: &str = "deterministic-confidential-state-cache-lease-v1";
pub const PRECONFIRMATION_RECEIPT_SUITE: &str =
    "confidential-cross-contract-prefetch-preconfirmation-receipt-v1";
pub const BACKPRESSURE_SUITE: &str = "latency-weighted-confidential-prefetch-backpressure-v1";
pub const LOW_FEE_REBATE_SUITE: &str = "low-fee-confidential-state-prefetch-cache-rebate-v1";
pub const PUBLIC_RECORD_SUITE: &str = "public-cross-contract-prefetch-record-root-v1";
pub const DEVNET_L2_HEIGHT: u64 = 2_940_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_590_000;
pub const DEVNET_EPOCH: u64 = 12_800;
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_PREFETCH_MS: u64 = 24;
pub const DEFAULT_MAX_PREFETCH_MS: u64 = 120;
pub const DEFAULT_DEPENDENCY_WINDOW_SLOTS: u64 = 16;
pub const DEFAULT_WITNESS_PACK_TTL_SLOTS: u64 = 48;
pub const DEFAULT_CACHE_LEASE_TTL_SLOTS: u64 = 64;
pub const DEFAULT_PRECONFIRMATION_TTL_SLOTS: u64 = 12;
pub const DEFAULT_BACKPRESSURE_HIGH_WATERMARK_BPS: u64 = 8_400;
pub const DEFAULT_BACKPRESSURE_RELEASE_BPS: u64 = 6_200;
pub const DEFAULT_QUORUM_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_SUPERMAJORITY_WEIGHT_BPS: u64 = 8_000;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 9;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 5;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 18;
pub const DEFAULT_MAX_DEPENDENCY_WINDOWS: usize = 524_288;
pub const DEFAULT_MAX_WITNESS_PACKS: usize = 1_048_576;
pub const DEFAULT_MAX_CACHE_LEASES: usize = 1_048_576;
pub const DEFAULT_MAX_PREFETCH_RECEIPTS: usize = 2_097_152;
pub const DEFAULT_MAX_BACKPRESSURE_SIGNALS: usize = 262_144;
pub const DEFAULT_MAX_PQ_ATTESTATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_LOW_FEE_REBATES: usize = 1_048_576;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 2_097_152;

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
pub enum ContractClass {
    MoneroBridge,
    ConfidentialToken,
    DefiVault,
    LendingPool,
    PerpetualMargin,
    OracleFeed,
    SmartAccount,
    EmergencyExit,
}

impl ContractClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroBridge => "monero_bridge",
            Self::ConfidentialToken => "confidential_token",
            Self::DefiVault => "defi_vault",
            Self::LendingPool => "lending_pool",
            Self::PerpetualMargin => "perpetual_margin",
            Self::OracleFeed => "oracle_feed",
            Self::SmartAccount => "smart_account",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyExit => 10_000,
            Self::MoneroBridge => 9_600,
            Self::PerpetualMargin => 9_300,
            Self::DefiVault => 9_100,
            Self::LendingPool => 8_800,
            Self::SmartAccount => 8_300,
            Self::ConfidentialToken => 8_000,
            Self::OracleFeed => 7_700,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowStatus {
    Open,
    Warmed,
    Receipted,
    Backpressured,
    Expired,
}

impl WindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Warmed => "warmed",
            Self::Receipted => "receipted",
            Self::Backpressured => "backpressured",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Open | Self::Warmed | Self::Backpressured)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseStatus {
    Offered,
    Active,
    Consumed,
    Released,
    Slashed,
    Expired,
}

impl LeaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Active => "active",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Include,
    Hold,
    Reject,
    Slash,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Include => "include",
            Self::Hold => "hold",
            Self::Reject => "reject",
            Self::Slash => "slash",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackpressureReason {
    CacheSaturation,
    WitnessLag,
    DependencyFanout,
    PqAttestationLag,
    ReceiptQueueDepth,
}

impl BackpressureReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CacheSaturation => "cache_saturation",
            Self::WitnessLag => "witness_lag",
            Self::DependencyFanout => "dependency_fanout",
            Self::PqAttestationLag => "pq_attestation_lag",
            Self::ReceiptQueueDepth => "receipt_queue_depth",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub mode: RuntimeMode,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_prefetch_ms: u64,
    pub max_prefetch_ms: u64,
    pub dependency_window_slots: u64,
    pub witness_pack_ttl_slots: u64,
    pub cache_lease_ttl_slots: u64,
    pub preconfirmation_ttl_slots: u64,
    pub backpressure_high_watermark_bps: u64,
    pub backpressure_release_bps: u64,
    pub quorum_weight_bps: u64,
    pub supermajority_weight_bps: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub max_dependency_windows: usize,
    pub max_witness_packs: usize,
    pub max_cache_leases: usize,
    pub max_prefetch_receipts: usize,
    pub max_backpressure_signals: usize,
    pub max_pq_attestations: usize,
    pub max_low_fee_rebates: usize,
    pub max_public_records: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: "nebula-devnet".to_string(),
            monero_network: "monero-devnet".to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            mode: RuntimeMode::Devnet,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_prefetch_ms: DEFAULT_TARGET_PREFETCH_MS,
            max_prefetch_ms: DEFAULT_MAX_PREFETCH_MS,
            dependency_window_slots: DEFAULT_DEPENDENCY_WINDOW_SLOTS,
            witness_pack_ttl_slots: DEFAULT_WITNESS_PACK_TTL_SLOTS,
            cache_lease_ttl_slots: DEFAULT_CACHE_LEASE_TTL_SLOTS,
            preconfirmation_ttl_slots: DEFAULT_PRECONFIRMATION_TTL_SLOTS,
            backpressure_high_watermark_bps: DEFAULT_BACKPRESSURE_HIGH_WATERMARK_BPS,
            backpressure_release_bps: DEFAULT_BACKPRESSURE_RELEASE_BPS,
            quorum_weight_bps: DEFAULT_QUORUM_WEIGHT_BPS,
            supermajority_weight_bps: DEFAULT_SUPERMAJORITY_WEIGHT_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
            max_dependency_windows: DEFAULT_MAX_DEPENDENCY_WINDOWS,
            max_witness_packs: DEFAULT_MAX_WITNESS_PACKS,
            max_cache_leases: DEFAULT_MAX_CACHE_LEASES,
            max_prefetch_receipts: DEFAULT_MAX_PREFETCH_RECEIPTS,
            max_backpressure_signals: DEFAULT_MAX_BACKPRESSURE_SIGNALS,
            max_pq_attestations: DEFAULT_MAX_PQ_ATTESTATIONS,
            max_low_fee_rebates: DEFAULT_MAX_LOW_FEE_REBATES,
            max_public_records: DEFAULT_MAX_PUBLIC_RECORDS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.chain_id.is_empty() || self.fee_asset_id.is_empty() {
            return Err("cross-contract prefetch config requires chain and fee asset ids".into());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("cross-contract prefetch requires 256-bit PQ security".into());
        }
        if self.min_privacy_set_size < DEFAULT_MIN_PRIVACY_SET_SIZE {
            return Err("cross-contract prefetch privacy set below devnet minimum".into());
        }
        if self.target_prefetch_ms == 0 || self.max_prefetch_ms < self.target_prefetch_ms {
            return Err("cross-contract prefetch latency bounds are invalid".into());
        }
        if self.backpressure_release_bps >= self.backpressure_high_watermark_bps {
            return Err("cross-contract prefetch backpressure watermarks are inverted".into());
        }
        if self.quorum_weight_bps > MAX_BPS
            || self.supermajority_weight_bps > MAX_BPS
            || self.quorum_weight_bps > self.supermajority_weight_bps
            || self.max_user_fee_bps > MAX_BPS
            || self.target_rebate_bps > self.max_rebate_bps
            || self.max_rebate_bps > MAX_BPS
        {
            return Err("cross-contract prefetch bps config is invalid".into());
        }
        Ok(())
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
            "hash_suite": HASH_SUITE,
            "pq_attestation_suite": PQ_ATTESTATION_SUITE,
            "pq_envelope_suite": PQ_ENVELOPE_SUITE,
            "witness_pack_suite": WITNESS_PACK_SUITE,
            "cache_lease_suite": CACHE_LEASE_SUITE,
            "preconfirmation_receipt_suite": PRECONFIRMATION_RECEIPT_SUITE,
            "backpressure_suite": BACKPRESSURE_SUITE,
            "low_fee_rebate_suite": LOW_FEE_REBATE_SUITE,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_prefetch_ms": self.target_prefetch_ms,
            "max_prefetch_ms": self.max_prefetch_ms,
            "dependency_window_slots": self.dependency_window_slots,
            "witness_pack_ttl_slots": self.witness_pack_ttl_slots,
            "cache_lease_ttl_slots": self.cache_lease_ttl_slots,
            "preconfirmation_ttl_slots": self.preconfirmation_ttl_slots,
            "backpressure_high_watermark_bps": self.backpressure_high_watermark_bps,
            "backpressure_release_bps": self.backpressure_release_bps,
            "quorum_weight_bps": self.quorum_weight_bps,
            "supermajority_weight_bps": self.supermajority_weight_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "max_rebate_bps": self.max_rebate_bps,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub dependency_windows_opened: u64,
    pub witness_packs_registered: u64,
    pub cache_leases_granted: u64,
    pub preconfirmation_receipts_issued: u64,
    pub backpressure_signals_emitted: u64,
    pub pq_attestations_accepted: u64,
    pub low_fee_rebates_accrued: u64,
    pub public_records_emitted: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "dependency_windows_opened": self.dependency_windows_opened,
            "witness_packs_registered": self.witness_packs_registered,
            "cache_leases_granted": self.cache_leases_granted,
            "preconfirmation_receipts_issued": self.preconfirmation_receipts_issued,
            "backpressure_signals_emitted": self.backpressure_signals_emitted,
            "pq_attestations_accepted": self.pq_attestations_accepted,
            "low_fee_rebates_accrued": self.low_fee_rebates_accrued,
            "public_records_emitted": self.public_records_emitted,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub dependency_window_root: String,
    pub witness_pack_root: String,
    pub cache_lease_root: String,
    pub preconfirmation_receipt_root: String,
    pub backpressure_root: String,
    pub pq_attestation_root: String,
    pub low_fee_rebate_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "dependency_window_root": self.dependency_window_root,
            "witness_pack_root": self.witness_pack_root,
            "cache_lease_root": self.cache_lease_root,
            "preconfirmation_receipt_root": self.preconfirmation_receipt_root,
            "backpressure_root": self.backpressure_root,
            "pq_attestation_root": self.pq_attestation_root,
            "low_fee_rebate_root": self.low_fee_rebate_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DependencyWindow {
    pub window_id: String,
    pub primary_contract_id: String,
    pub dependent_contract_ids: Vec<String>,
    pub contract_class: ContractClass,
    pub status: WindowStatus,
    pub read_set_root: String,
    pub write_intent_root: String,
    pub opens_at_slot: u64,
    pub expires_at_slot: u64,
    pub priority_weight: u64,
}

impl DependencyWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "dependency_window",
            "protocol_version": PROTOCOL_VERSION,
            "window_id": self.window_id,
            "primary_contract_id": self.primary_contract_id,
            "dependent_contract_ids": self.dependent_contract_ids,
            "contract_class": self.contract_class.as_str(),
            "status": self.status.as_str(),
            "read_set_root": self.read_set_root,
            "write_intent_root": self.write_intent_root,
            "opens_at_slot": self.opens_at_slot,
            "expires_at_slot": self.expires_at_slot,
            "priority_weight": self.priority_weight,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record("dependency-window", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WitnessPack {
    pub pack_id: String,
    pub window_id: String,
    pub witness_root: String,
    pub encrypted_pack_root: String,
    pub dependency_graph_root: String,
    pub privacy_set_size: u64,
    pub created_at_slot: u64,
    pub expires_at_slot: u64,
}

impl WitnessPack {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "witness_pack",
            "protocol_version": PROTOCOL_VERSION,
            "pack_id": self.pack_id,
            "window_id": self.window_id,
            "witness_root": self.witness_root,
            "encrypted_pack_root": self.encrypted_pack_root,
            "dependency_graph_root": self.dependency_graph_root,
            "privacy_set_size": self.privacy_set_size,
            "created_at_slot": self.created_at_slot,
            "expires_at_slot": self.expires_at_slot,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record("witness-pack", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CacheLease {
    pub lease_id: String,
    pub window_id: String,
    pub pack_id: String,
    pub cache_operator_id: String,
    pub status: LeaseStatus,
    pub cache_root: String,
    pub max_latency_ms: u64,
    pub granted_at_slot: u64,
    pub expires_at_slot: u64,
}

impl CacheLease {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "cache_lease",
            "protocol_version": PROTOCOL_VERSION,
            "lease_id": self.lease_id,
            "window_id": self.window_id,
            "pack_id": self.pack_id,
            "cache_operator_id": self.cache_operator_id,
            "status": self.status.as_str(),
            "cache_root": self.cache_root,
            "max_latency_ms": self.max_latency_ms,
            "granted_at_slot": self.granted_at_slot,
            "expires_at_slot": self.expires_at_slot,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record("cache-lease", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestation {
    pub attestation_id: String,
    pub lease_id: String,
    pub attester_id: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub attester_weight_bps: u64,
    pub verdict: AttestationVerdict,
    pub created_at_slot: u64,
}

impl PqAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_attestation",
            "protocol_version": PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "lease_id": self.lease_id,
            "attester_id": self.attester_id,
            "pq_public_key_root": self.pq_public_key_root,
            "pq_signature_root": self.pq_signature_root,
            "attester_weight_bps": self.attester_weight_bps,
            "verdict": self.verdict.as_str(),
            "created_at_slot": self.created_at_slot,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record("pq-attestation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreconfirmationReceipt {
    pub receipt_id: String,
    pub lease_id: String,
    pub deterministic_prefetch_root: String,
    pub preconfirmation_root: String,
    pub latency_ms: u64,
    pub issued_at_slot: u64,
    pub expires_at_slot: u64,
}

impl PreconfirmationReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "preconfirmation_receipt",
            "protocol_version": PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "lease_id": self.lease_id,
            "deterministic_prefetch_root": self.deterministic_prefetch_root,
            "preconfirmation_root": self.preconfirmation_root,
            "latency_ms": self.latency_ms,
            "issued_at_slot": self.issued_at_slot,
            "expires_at_slot": self.expires_at_slot,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record("preconfirmation-receipt", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackpressureSignal {
    pub signal_id: String,
    pub window_id: String,
    pub reason: BackpressureReason,
    pub pressure_bps: u64,
    pub queue_depth: u64,
    pub emitted_at_slot: u64,
}

impl BackpressureSignal {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "backpressure_signal",
            "protocol_version": PROTOCOL_VERSION,
            "signal_id": self.signal_id,
            "window_id": self.window_id,
            "reason": self.reason.as_str(),
            "pressure_bps": self.pressure_bps,
            "queue_depth": self.queue_depth,
            "emitted_at_slot": self.emitted_at_slot,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record("backpressure-signal", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeCacheRebate {
    pub rebate_id: String,
    pub lease_id: String,
    pub beneficiary_commitment: String,
    pub fee_asset_id: String,
    pub rebate_bps: u64,
    pub rebate_micro_units: u64,
    pub accrued_at_slot: u64,
}

impl LowFeeCacheRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_cache_rebate",
            "protocol_version": PROTOCOL_VERSION,
            "rebate_id": self.rebate_id,
            "lease_id": self.lease_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "fee_asset_id": self.fee_asset_id,
            "rebate_bps": self.rebate_bps,
            "rebate_micro_units": self.rebate_micro_units,
            "accrued_at_slot": self.accrued_at_slot,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record("low-fee-cache-rebate", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicRecord {
    pub record_id: String,
    pub kind: String,
    pub payload_root: String,
    pub emitted_at_height: u64,
    pub emitted_at_slot: u64,
}

impl PublicRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "public_record",
            "protocol_version": PROTOCOL_VERSION,
            "record_id": self.record_id,
            "record_kind": self.kind,
            "payload_root": self.payload_root,
            "emitted_at_height": self.emitted_at_height,
            "emitted_at_slot": self.emitted_at_slot,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record("public-record", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub current_height: u64,
    pub current_slot: u64,
    pub monero_anchor_height: u64,
    pub dependency_windows: BTreeMap<String, DependencyWindow>,
    pub witness_packs: BTreeMap<String, WitnessPack>,
    pub cache_leases: BTreeMap<String, CacheLease>,
    pub preconfirmation_receipts: BTreeMap<String, PreconfirmationReceipt>,
    pub backpressure_signals: BTreeMap<String, BackpressureSignal>,
    pub pq_attestations: BTreeMap<String, PqAttestation>,
    pub low_fee_rebates: BTreeMap<String, LowFeeCacheRebate>,
    pub public_records: BTreeMap<String, PublicRecord>,
    pub warmed_contracts: BTreeSet<String>,
}

impl State {
    pub fn new(
        config: Config,
        current_height: u64,
        current_slot: u64,
        monero_anchor_height: u64,
    ) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            current_height,
            current_slot,
            monero_anchor_height,
            dependency_windows: BTreeMap::new(),
            witness_packs: BTreeMap::new(),
            cache_leases: BTreeMap::new(),
            preconfirmation_receipts: BTreeMap::new(),
            backpressure_signals: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            public_records: BTreeMap::new(),
            warmed_contracts: BTreeSet::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Result<Self> {
        let mut state = Self::new(
            Config::devnet(),
            DEVNET_L2_HEIGHT,
            DEVNET_EPOCH,
            DEVNET_MONERO_HEIGHT,
        )?;
        let window_id = state.open_dependency_window(
            "devnet-confidential-vault",
            vec![
                "devnet-monero-bridge".to_string(),
                "devnet-oracle-feed".to_string(),
                "devnet-fee-rebate-vault".to_string(),
            ],
            ContractClass::DefiVault,
            root_from_parts("devnet-read-set", &["vault", "bridge", "oracle"]),
            root_from_parts("devnet-write-intent", &["vault-prefetch", "rebate"]),
        )?;
        let pack_id = state.register_witness_pack(
            &window_id,
            root_from_parts("devnet-witness", &["storage", "nullifier", "viewtag"]),
            root_from_parts("devnet-encrypted-pack", &["ml-kem", "threshold"]),
            root_from_parts("devnet-dependency-graph", &["bridge", "oracle", "vault"]),
            DEFAULT_MIN_PRIVACY_SET_SIZE,
        )?;
        let lease_id = state.grant_cache_lease(
            &window_id,
            &pack_id,
            "devnet-cross-contract-prefetch-cache-operator",
            root_from_parts("devnet-cache", &["hot", "lease", "state"]),
        )?;
        state.accept_pq_attestation(
            &lease_id,
            "devnet-pq-prefetch-attestor",
            root_from_parts("devnet-pq-key", &["ml-dsa", "slh-dsa"]),
            root_from_parts("devnet-pq-signature", &["lease", "pack", "window"]),
            DEFAULT_QUORUM_WEIGHT_BPS,
            AttestationVerdict::Include,
        )?;
        state.issue_preconfirmation_receipt(&lease_id, state.config.target_prefetch_ms)?;
        state.accrue_low_fee_rebate(
            &lease_id,
            "devnet-beneficiary-commitment",
            state.config.target_rebate_bps,
            1_250,
        )?;
        Ok(state)
    }

    pub fn open_dependency_window(
        &mut self,
        primary_contract_id: &str,
        dependent_contract_ids: Vec<String>,
        contract_class: ContractClass,
        read_set_root: String,
        write_intent_root: String,
    ) -> Result<String> {
        if self.dependency_windows.len() >= self.config.max_dependency_windows {
            return Err("cross-contract prefetch dependency window capacity reached".into());
        }
        require_nonempty("primary contract id", primary_contract_id)?;
        if dependent_contract_ids.is_empty() {
            return Err("cross-contract prefetch requires at least one dependency".into());
        }
        for contract_id in &dependent_contract_ids {
            require_nonempty("dependent contract id", contract_id)?;
        }
        let window_id = deterministic_id(
            "dependency-window-id",
            &[
                primary_contract_id,
                contract_class.as_str(),
                read_set_root.as_str(),
                write_intent_root.as_str(),
            ],
            self.counters.dependency_windows_opened,
        );
        let window = DependencyWindow {
            window_id: window_id.clone(),
            primary_contract_id: primary_contract_id.to_string(),
            dependent_contract_ids,
            contract_class,
            status: WindowStatus::Open,
            read_set_root,
            write_intent_root,
            opens_at_slot: self.current_slot,
            expires_at_slot: self.current_slot + self.config.dependency_window_slots,
            priority_weight: contract_class.priority_weight(),
        };
        self.dependency_windows.insert(window_id.clone(), window);
        self.counters.dependency_windows_opened += 1;
        self.emit_public_record(
            "dependency_window_opened",
            json!({ "window_id": window_id }),
        )?;
        self.refresh_roots();
        Ok(window_id)
    }

    pub fn register_witness_pack(
        &mut self,
        window_id: &str,
        witness_root: String,
        encrypted_pack_root: String,
        dependency_graph_root: String,
        privacy_set_size: u64,
    ) -> Result<String> {
        if self.witness_packs.len() >= self.config.max_witness_packs {
            return Err("cross-contract prefetch witness pack capacity reached".into());
        }
        let window = self
            .dependency_windows
            .get_mut(window_id)
            .ok_or_else(|| "cross-contract prefetch dependency window not found".to_string())?;
        if !window.status.live() {
            return Err("cross-contract prefetch dependency window is not live".into());
        }
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err("cross-contract prefetch witness privacy set is too small".into());
        }
        let pack_id = deterministic_id(
            "witness-pack-id",
            &[
                window_id,
                witness_root.as_str(),
                encrypted_pack_root.as_str(),
                dependency_graph_root.as_str(),
            ],
            self.counters.witness_packs_registered,
        );
        let pack = WitnessPack {
            pack_id: pack_id.clone(),
            window_id: window_id.to_string(),
            witness_root,
            encrypted_pack_root,
            dependency_graph_root,
            privacy_set_size,
            created_at_slot: self.current_slot,
            expires_at_slot: self.current_slot + self.config.witness_pack_ttl_slots,
        };
        window.status = WindowStatus::Warmed;
        self.witness_packs.insert(pack_id.clone(), pack);
        self.counters.witness_packs_registered += 1;
        self.emit_public_record(
            "witness_pack_registered",
            json!({ "window_id": window_id, "pack_id": pack_id }),
        )?;
        self.refresh_roots();
        Ok(pack_id)
    }

    pub fn grant_cache_lease(
        &mut self,
        window_id: &str,
        pack_id: &str,
        cache_operator_id: &str,
        cache_root: String,
    ) -> Result<String> {
        if self.cache_leases.len() >= self.config.max_cache_leases {
            return Err("cross-contract prefetch cache lease capacity reached".into());
        }
        require_nonempty("cache operator id", cache_operator_id)?;
        let pack = self
            .witness_packs
            .get(pack_id)
            .ok_or_else(|| "cross-contract prefetch witness pack not found".to_string())?;
        if pack.window_id != window_id {
            return Err("cross-contract prefetch lease window and pack mismatch".into());
        }
        let lease_id = deterministic_id(
            "cache-lease-id",
            &[window_id, pack_id, cache_operator_id, cache_root.as_str()],
            self.counters.cache_leases_granted,
        );
        let lease = CacheLease {
            lease_id: lease_id.clone(),
            window_id: window_id.to_string(),
            pack_id: pack_id.to_string(),
            cache_operator_id: cache_operator_id.to_string(),
            status: LeaseStatus::Active,
            cache_root,
            max_latency_ms: self.config.max_prefetch_ms,
            granted_at_slot: self.current_slot,
            expires_at_slot: self.current_slot + self.config.cache_lease_ttl_slots,
        };
        self.cache_leases.insert(lease_id.clone(), lease);
        self.counters.cache_leases_granted += 1;
        self.emit_public_record(
            "cache_lease_granted",
            json!({ "window_id": window_id, "pack_id": pack_id, "lease_id": lease_id }),
        )?;
        self.refresh_roots();
        Ok(lease_id)
    }

    pub fn accept_pq_attestation(
        &mut self,
        lease_id: &str,
        attester_id: &str,
        pq_public_key_root: String,
        pq_signature_root: String,
        attester_weight_bps: u64,
        verdict: AttestationVerdict,
    ) -> Result<String> {
        if self.pq_attestations.len() >= self.config.max_pq_attestations {
            return Err("cross-contract prefetch PQ attestation capacity reached".into());
        }
        require_nonempty("attester id", attester_id)?;
        if attester_weight_bps > MAX_BPS {
            return Err("cross-contract prefetch attester weight exceeds bps maximum".into());
        }
        let lease = self
            .cache_leases
            .get(lease_id)
            .ok_or_else(|| "cross-contract prefetch cache lease not found".to_string())?;
        if !matches!(lease.status, LeaseStatus::Active | LeaseStatus::Offered) {
            return Err("cross-contract prefetch lease is not attestable".into());
        }
        let attestation_id = deterministic_id(
            "pq-attestation-id",
            &[lease_id, attester_id, pq_public_key_root.as_str()],
            self.counters.pq_attestations_accepted,
        );
        let attestation = PqAttestation {
            attestation_id: attestation_id.clone(),
            lease_id: lease_id.to_string(),
            attester_id: attester_id.to_string(),
            pq_public_key_root,
            pq_signature_root,
            attester_weight_bps,
            verdict,
            created_at_slot: self.current_slot,
        };
        self.pq_attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.pq_attestations_accepted += 1;
        self.emit_public_record(
            "pq_attestation_accepted",
            json!({ "lease_id": lease_id, "attestation_id": attestation_id }),
        )?;
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn issue_preconfirmation_receipt(
        &mut self,
        lease_id: &str,
        latency_ms: u64,
    ) -> Result<String> {
        if self.preconfirmation_receipts.len() >= self.config.max_prefetch_receipts {
            return Err("cross-contract prefetch receipt capacity reached".into());
        }
        if latency_ms > self.config.max_prefetch_ms {
            return Err("cross-contract prefetch receipt latency exceeds maximum".into());
        }
        let lease = self
            .cache_leases
            .get_mut(lease_id)
            .ok_or_else(|| "cross-contract prefetch cache lease not found".to_string())?;
        if lease.status != LeaseStatus::Active {
            return Err("cross-contract prefetch lease is not active".into());
        }
        lease.status = LeaseStatus::Consumed;
        self.warmed_contracts.insert(lease.window_id.clone());
        let deterministic_prefetch_root = root_from_parts(
            "deterministic-prefetch",
            &[
                lease.window_id.as_str(),
                lease.pack_id.as_str(),
                lease.cache_root.as_str(),
            ],
        );
        let preconfirmation_root = root_from_parts(
            "preconfirmation",
            &[lease_id, deterministic_prefetch_root.as_str()],
        );
        let receipt_id = deterministic_id(
            "preconfirmation-receipt-id",
            &[lease_id, preconfirmation_root.as_str()],
            self.counters.preconfirmation_receipts_issued,
        );
        let receipt = PreconfirmationReceipt {
            receipt_id: receipt_id.clone(),
            lease_id: lease_id.to_string(),
            deterministic_prefetch_root,
            preconfirmation_root,
            latency_ms,
            issued_at_slot: self.current_slot,
            expires_at_slot: self.current_slot + self.config.preconfirmation_ttl_slots,
        };
        self.preconfirmation_receipts
            .insert(receipt_id.clone(), receipt);
        self.counters.preconfirmation_receipts_issued += 1;
        self.emit_public_record(
            "preconfirmation_receipt_issued",
            json!({ "lease_id": lease_id, "receipt_id": receipt_id }),
        )?;
        self.refresh_roots();
        Ok(receipt_id)
    }

    pub fn emit_backpressure(
        &mut self,
        window_id: &str,
        reason: BackpressureReason,
        pressure_bps: u64,
        queue_depth: u64,
    ) -> Result<String> {
        if self.backpressure_signals.len() >= self.config.max_backpressure_signals {
            return Err("cross-contract prefetch backpressure capacity reached".into());
        }
        if pressure_bps > MAX_BPS {
            return Err("cross-contract prefetch pressure exceeds bps maximum".into());
        }
        let window = self
            .dependency_windows
            .get_mut(window_id)
            .ok_or_else(|| "cross-contract prefetch dependency window not found".to_string())?;
        if pressure_bps >= self.config.backpressure_high_watermark_bps {
            window.status = WindowStatus::Backpressured;
        }
        let signal_id = deterministic_id(
            "backpressure-signal-id",
            &[window_id, reason.as_str()],
            self.counters.backpressure_signals_emitted,
        );
        let signal = BackpressureSignal {
            signal_id: signal_id.clone(),
            window_id: window_id.to_string(),
            reason,
            pressure_bps,
            queue_depth,
            emitted_at_slot: self.current_slot,
        };
        self.backpressure_signals.insert(signal_id.clone(), signal);
        self.counters.backpressure_signals_emitted += 1;
        self.emit_public_record(
            "backpressure_signal_emitted",
            json!({ "window_id": window_id, "signal_id": signal_id }),
        )?;
        self.refresh_roots();
        Ok(signal_id)
    }

    pub fn accrue_low_fee_rebate(
        &mut self,
        lease_id: &str,
        beneficiary_commitment: &str,
        rebate_bps: u64,
        rebate_micro_units: u64,
    ) -> Result<String> {
        if self.low_fee_rebates.len() >= self.config.max_low_fee_rebates {
            return Err("cross-contract prefetch low-fee rebate capacity reached".into());
        }
        require_nonempty("beneficiary commitment", beneficiary_commitment)?;
        if rebate_bps > self.config.max_rebate_bps {
            return Err("cross-contract prefetch rebate exceeds runtime maximum".into());
        }
        if !self.cache_leases.contains_key(lease_id) {
            return Err("cross-contract prefetch cache lease not found".into());
        }
        let rebate_id = deterministic_id(
            "low-fee-cache-rebate-id",
            &[lease_id, beneficiary_commitment],
            self.counters.low_fee_rebates_accrued,
        );
        let rebate = LowFeeCacheRebate {
            rebate_id: rebate_id.clone(),
            lease_id: lease_id.to_string(),
            beneficiary_commitment: beneficiary_commitment.to_string(),
            fee_asset_id: self.config.fee_asset_id.clone(),
            rebate_bps,
            rebate_micro_units,
            accrued_at_slot: self.current_slot,
        };
        self.low_fee_rebates.insert(rebate_id.clone(), rebate);
        self.counters.low_fee_rebates_accrued += 1;
        self.emit_public_record(
            "low_fee_cache_rebate_accrued",
            json!({ "lease_id": lease_id, "rebate_id": rebate_id }),
        )?;
        self.refresh_roots();
        Ok(rebate_id)
    }

    pub fn advance_clock(
        &mut self,
        height: u64,
        slot: u64,
        monero_anchor_height: u64,
    ) -> Result<()> {
        if height < self.current_height || slot < self.current_slot {
            return Err("cross-contract prefetch clock cannot move backwards".into());
        }
        self.current_height = height;
        self.current_slot = slot;
        self.monero_anchor_height = monero_anchor_height;
        self.expire_stale_items();
        self.refresh_roots();
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_fast_pq_confidential_cross_contract_state_prefetch_runtime",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": self.config.chain_id,
            "current_height": self.current_height,
            "current_slot": self.current_slot,
            "monero_anchor_height": self.monero_anchor_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn refresh_roots(&mut self) {
        let dependency_window_root = map_root(
            "dependency-windows",
            self.dependency_windows
                .values()
                .map(DependencyWindow::public_record),
        );
        let witness_pack_root = map_root(
            "witness-packs",
            self.witness_packs.values().map(WitnessPack::public_record),
        );
        let cache_lease_root = map_root(
            "cache-leases",
            self.cache_leases.values().map(CacheLease::public_record),
        );
        let preconfirmation_receipt_root = map_root(
            "preconfirmation-receipts",
            self.preconfirmation_receipts
                .values()
                .map(PreconfirmationReceipt::public_record),
        );
        let backpressure_root = map_root(
            "backpressure-signals",
            self.backpressure_signals
                .values()
                .map(BackpressureSignal::public_record),
        );
        let pq_attestation_root = map_root(
            "pq-attestations",
            self.pq_attestations
                .values()
                .map(PqAttestation::public_record),
        );
        let low_fee_rebate_root = map_root(
            "low-fee-rebates",
            self.low_fee_rebates
                .values()
                .map(LowFeeCacheRebate::public_record),
        );
        let public_record_root = map_root(
            "public-records",
            self.public_records
                .values()
                .map(PublicRecord::public_record),
        );
        let state_root = domain_hash(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-CROSS-CONTRACT-STATE-PREFETCH:STATE",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.chain_id),
                HashPart::U64(self.current_height),
                HashPart::U64(self.current_slot),
                HashPart::U64(self.monero_anchor_height),
                HashPart::Str(&dependency_window_root),
                HashPart::Str(&witness_pack_root),
                HashPart::Str(&cache_lease_root),
                HashPart::Str(&preconfirmation_receipt_root),
                HashPart::Str(&backpressure_root),
                HashPart::Str(&pq_attestation_root),
                HashPart::Str(&low_fee_rebate_root),
                HashPart::Str(&public_record_root),
                HashPart::Str(&self.counters.state_root()),
            ],
            32,
        );
        self.roots = Roots {
            dependency_window_root,
            witness_pack_root,
            cache_lease_root,
            preconfirmation_receipt_root,
            backpressure_root,
            pq_attestation_root,
            low_fee_rebate_root,
            public_record_root,
            state_root,
        };
    }

    fn emit_public_record(&mut self, kind: &str, payload: Value) -> Result<()> {
        if self.public_records.len() >= self.config.max_public_records {
            return Err("cross-contract prefetch public record capacity reached".into());
        }
        let payload_root = root_from_record(kind, &payload);
        let record_id = deterministic_id(
            "public-record-id",
            &[kind, payload_root.as_str()],
            self.counters.public_records_emitted,
        );
        let record = PublicRecord {
            record_id: record_id.clone(),
            kind: kind.to_string(),
            payload_root,
            emitted_at_height: self.current_height,
            emitted_at_slot: self.current_slot,
        };
        self.public_records.insert(record_id, record);
        self.counters.public_records_emitted += 1;
        Ok(())
    }

    fn expire_stale_items(&mut self) {
        for window in self.dependency_windows.values_mut() {
            if window.status.live() && window.expires_at_slot <= self.current_slot {
                window.status = WindowStatus::Expired;
            }
        }
        for lease in self.cache_leases.values_mut() {
            if matches!(lease.status, LeaseStatus::Offered | LeaseStatus::Active)
                && lease.expires_at_slot <= self.current_slot
            {
                lease.status = LeaseStatus::Expired;
            }
        }
    }
}

pub fn devnet() -> Result<State> {
    State::devnet()
}

pub fn demo() -> Value {
    match State::devnet() {
        Ok(state) => state.public_record(),
        Err(error) => json!({
            "kind": "private_l2_fast_pq_confidential_cross_contract_state_prefetch_runtime_demo_error",
            "protocol_version": PROTOCOL_VERSION,
            "error": error,
        }),
    }
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn require_nonempty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("cross-contract prefetch {label} is required"))
    } else {
        Ok(())
    }
}

fn map_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let leaves = records.into_iter().collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-L2-FAST-PQ-CONFIDENTIAL-CROSS-CONTRACT-PREFETCH:{domain}"),
        &leaves,
    )
}

fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-FAST-PQ-CONFIDENTIAL-CROSS-CONTRACT-PREFETCH:{domain}"),
        &[HashPart::Json(record)],
        32,
    )
}

fn root_from_parts(domain: &str, parts: &[&str]) -> String {
    let leaves = parts
        .iter()
        .map(|part| json!({ "part": part }))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-L2-FAST-PQ-CONFIDENTIAL-CROSS-CONTRACT-PREFETCH:{domain}"),
        &leaves,
    )
}

fn deterministic_id(domain: &str, parts: &[&str], sequence: u64) -> String {
    let mut hash_parts = Vec::with_capacity(parts.len() + 2);
    hash_parts.push(HashPart::Str(PROTOCOL_VERSION));
    for part in parts {
        hash_parts.push(HashPart::Str(part));
    }
    hash_parts.push(HashPart::U64(sequence));
    domain_hash(
        &format!("PRIVATE-L2-FAST-PQ-CONFIDENTIAL-CROSS-CONTRACT-PREFETCH:{domain}"),
        &hash_parts,
        20,
    )
}
