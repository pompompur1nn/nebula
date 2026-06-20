use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_CALL_COMPRESSION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-batch-call-compression-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_CALL_COMPRESSION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_SUITE: &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const CONFIDENTIAL_BATCH_CALL_COMPRESSION_SUITE: &str =
    "low-fee-pq-confidential-batch-call-compression-v1";
pub const ENCRYPTED_CALL_BUNDLE_SCHEME: &str =
    "pq-confidential-private-contract-call-bundle-ciphertext-v1";
pub const CALLDATA_DICTIONARY_SCHEME: &str =
    "deterministic-private-contract-calldata-dictionary-v1";
pub const WITNESS_DELTA_COMPRESSION_SCHEME: &str = "confidential-witness-delta-compression-root-v1";
pub const DA_VOUCHER_SCHEME: &str = "low-fee-confidential-da-voucher-v1";
pub const REBATE_CLAIM_SCHEME: &str = "confidential-batch-call-fee-rebate-claim-v1";
pub const ABI_FINGERPRINT_SCHEME: &str = "private-contract-abi-fingerprint-v1";
pub const PRIVACY_BUDGET_SCHEME: &str = "private-call-privacy-budget-accounting-v1";
pub const COMPRESSION_MARKET_SCHEME: &str = "private-batch-call-compression-market-v1";
pub const SOLVER_BID_SCHEME: &str = "defi-batch-route-compressor-solver-bid-v1";
pub const SLASHING_EVIDENCE_SCHEME: &str =
    "pq-compressor-withholding-or-miscompression-slashing-evidence-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_HEIGHT: u64 = 2_740_000;
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 8;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 6;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_000;
pub const DEFAULT_COMPRESSION_SHARE_BPS: u64 = 7_500;
pub const DEFAULT_DA_SAVINGS_SHARE_BPS: u64 = 8_250;
pub const DEFAULT_PRIVACY_BUDGET_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_QUOTE_TTL_BLOCKS: u64 = 8;
pub const DEFAULT_BUNDLE_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_DA_VOUCHER_TTL_BLOCKS: u64 = 128;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_EVIDENCE_WINDOW_BLOCKS: u64 = 192;
pub const DEFAULT_MAX_CALLS_PER_BUNDLE: usize = 4_096;
pub const DEFAULT_MAX_DICTIONARY_ENTRIES: usize = 262_144;
pub const DEFAULT_MAX_WITNESS_DELTAS: usize = 1_048_576;
pub const DEFAULT_MAX_MARKET_LANES: usize = 512;
pub const DEFAULT_MAX_COMPRESSORS: usize = 65_536;
pub const DEFAULT_MAX_SOLVER_BIDS: usize = 2_097_152;
pub const DEFAULT_MAX_EVENTS: usize = 16_777_216;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneKind {
    PrivateContractCall,
    ConfidentialSwap,
    ConfidentialLending,
    ConfidentialPerpMargin,
    StableSwapNetting,
    VaultRoute,
    OracleRefresh,
    BridgeMessage,
    MoneroFastExit,
    RecursiveWitness,
    EmergencyEscape,
}

impl LaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateContractCall => "private_contract_call",
            Self::ConfidentialSwap => "confidential_swap",
            Self::ConfidentialLending => "confidential_lending",
            Self::ConfidentialPerpMargin => "confidential_perp_margin",
            Self::StableSwapNetting => "stable_swap_netting",
            Self::VaultRoute => "vault_route",
            Self::OracleRefresh => "oracle_refresh",
            Self::BridgeMessage => "bridge_message",
            Self::MoneroFastExit => "monero_fast_exit",
            Self::RecursiveWitness => "recursive_witness",
            Self::EmergencyEscape => "emergency_escape",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyEscape => 10_000,
            Self::MoneroFastExit => 9_600,
            Self::ConfidentialPerpMargin => 9_250,
            Self::ConfidentialSwap => 9_100,
            Self::StableSwapNetting => 8_900,
            Self::VaultRoute => 8_700,
            Self::ConfidentialLending => 8_500,
            Self::PrivateContractCall => 8_200,
            Self::OracleRefresh => 7_600,
            Self::BridgeMessage => 7_400,
            Self::RecursiveWitness => 7_100,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Congested,
    Draining,
    Paused,
    Retired,
}

impl LaneStatus {
    pub fn accepts_bundles(self) -> bool {
        matches!(self, Self::Open | Self::Congested)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleStatus {
    Submitted,
    Compressed,
    VoucherAllocated,
    Sequenced,
    Settled,
    Rebated,
    Expired,
    Rejected,
    Challenged,
    Slashed,
}

impl BundleStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted
                | Self::Compressed
                | Self::VoucherAllocated
                | Self::Sequenced
                | Self::Challenged
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DictionaryStatus {
    Draft,
    Active,
    Saturated,
    Deprecated,
    Slashed,
}

impl DictionaryStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Saturated)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VoucherStatus {
    Available,
    Reserved,
    Consumed,
    Refunded,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Open,
    Settled,
    Rejected,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverBidStatus {
    Posted,
    Selected,
    Lost,
    Filled,
    Expired,
    Slashed,
}

impl SolverBidStatus {
    pub fn selectable(self) -> bool {
        matches!(self, Self::Posted | Self::Selected)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressorStatus {
    Active,
    Throttled,
    Probation,
    Paused,
    Slashed,
    Retired,
}

impl CompressorStatus {
    pub fn accepts_work(self) -> bool {
        matches!(self, Self::Active | Self::Throttled | Self::Probation)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionMode {
    DictionaryOnly,
    WitnessDeltaOnly,
    DictionaryAndDelta,
    RouteAwareDefi,
    RecursiveProofAware,
    EmergencyMinimal,
}

impl CompressionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DictionaryOnly => "dictionary_only",
            Self::WitnessDeltaOnly => "witness_delta_only",
            Self::DictionaryAndDelta => "dictionary_and_delta",
            Self::RouteAwareDefi => "route_aware_defi",
            Self::RecursiveProofAware => "recursive_proof_aware",
            Self::EmergencyMinimal => "emergency_minimal",
        }
    }

    pub fn complexity_weight(self) -> u64 {
        match self {
            Self::EmergencyMinimal => 600,
            Self::DictionaryOnly => 1_000,
            Self::WitnessDeltaOnly => 1_250,
            Self::DictionaryAndDelta => 1_500,
            Self::RouteAwareDefi => 1_900,
            Self::RecursiveProofAware => 2_200,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingKind {
    InvalidDictionaryRoot,
    InvalidWitnessDelta,
    CalldataDecompressionMismatch,
    DaVoucherDoubleSpend,
    RebateOverclaim,
    PrivacyBudgetOverspend,
    WithheldBundle,
    InvalidAbiFingerprint,
    SolverRouteMisquote,
}

impl SlashingKind {
    pub fn severity_weight(self) -> u64 {
        match self {
            Self::CalldataDecompressionMismatch => 10_000,
            Self::WithheldBundle => 9_500,
            Self::DaVoucherDoubleSpend => 9_200,
            Self::PrivacyBudgetOverspend => 8_900,
            Self::RebateOverclaim => 8_500,
            Self::InvalidWitnessDelta => 8_000,
            Self::InvalidDictionaryRoot => 7_700,
            Self::InvalidAbiFingerprint => 7_400,
            Self::SolverRouteMisquote => 7_100,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_suite: String,
    pub compression_suite: String,
    pub encrypted_call_bundle_scheme: String,
    pub calldata_dictionary_scheme: String,
    pub witness_delta_compression_scheme: String,
    pub da_voucher_scheme: String,
    pub rebate_claim_scheme: String,
    pub abi_fingerprint_scheme: String,
    pub privacy_budget_scheme: String,
    pub compression_market_scheme: String,
    pub solver_bid_scheme: String,
    pub slashing_evidence_scheme: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub compression_share_bps: u64,
    pub da_savings_share_bps: u64,
    pub privacy_budget_window_blocks: u64,
    pub quote_ttl_blocks: u64,
    pub bundle_ttl_blocks: u64,
    pub da_voucher_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub evidence_window_blocks: u64,
    pub max_calls_per_bundle: usize,
    pub max_dictionary_entries: usize,
    pub max_witness_deltas: usize,
    pub max_market_lanes: usize,
    pub max_compressors: usize,
    pub max_solver_bids: usize,
    pub max_events: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_suite: PQ_SUITE.to_string(),
            compression_suite: CONFIDENTIAL_BATCH_CALL_COMPRESSION_SUITE.to_string(),
            encrypted_call_bundle_scheme: ENCRYPTED_CALL_BUNDLE_SCHEME.to_string(),
            calldata_dictionary_scheme: CALLDATA_DICTIONARY_SCHEME.to_string(),
            witness_delta_compression_scheme: WITNESS_DELTA_COMPRESSION_SCHEME.to_string(),
            da_voucher_scheme: DA_VOUCHER_SCHEME.to_string(),
            rebate_claim_scheme: REBATE_CLAIM_SCHEME.to_string(),
            abi_fingerprint_scheme: ABI_FINGERPRINT_SCHEME.to_string(),
            privacy_budget_scheme: PRIVACY_BUDGET_SCHEME.to_string(),
            compression_market_scheme: COMPRESSION_MARKET_SCHEME.to_string(),
            solver_bid_scheme: SOLVER_BID_SCHEME.to_string(),
            slashing_evidence_scheme: SLASHING_EVIDENCE_SCHEME.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            compression_share_bps: DEFAULT_COMPRESSION_SHARE_BPS,
            da_savings_share_bps: DEFAULT_DA_SAVINGS_SHARE_BPS,
            privacy_budget_window_blocks: DEFAULT_PRIVACY_BUDGET_WINDOW_BLOCKS,
            quote_ttl_blocks: DEFAULT_QUOTE_TTL_BLOCKS,
            bundle_ttl_blocks: DEFAULT_BUNDLE_TTL_BLOCKS,
            da_voucher_ttl_blocks: DEFAULT_DA_VOUCHER_TTL_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            evidence_window_blocks: DEFAULT_EVIDENCE_WINDOW_BLOCKS,
            max_calls_per_bundle: DEFAULT_MAX_CALLS_PER_BUNDLE,
            max_dictionary_entries: DEFAULT_MAX_DICTIONARY_ENTRIES,
            max_witness_deltas: DEFAULT_MAX_WITNESS_DELTAS,
            max_market_lanes: DEFAULT_MAX_MARKET_LANES,
            max_compressors: DEFAULT_MAX_COMPRESSORS,
            max_solver_bids: DEFAULT_MAX_SOLVER_BIDS,
            max_events: DEFAULT_MAX_EVENTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "pq_suite": self.pq_suite,
            "compression_suite": self.compression_suite,
            "encrypted_call_bundle_scheme": self.encrypted_call_bundle_scheme,
            "calldata_dictionary_scheme": self.calldata_dictionary_scheme,
            "witness_delta_compression_scheme": self.witness_delta_compression_scheme,
            "da_voucher_scheme": self.da_voucher_scheme,
            "rebate_claim_scheme": self.rebate_claim_scheme,
            "abi_fingerprint_scheme": self.abi_fingerprint_scheme,
            "privacy_budget_scheme": self.privacy_budget_scheme,
            "compression_market_scheme": self.compression_market_scheme,
            "solver_bid_scheme": self.solver_bid_scheme,
            "slashing_evidence_scheme": self.slashing_evidence_scheme,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "compression_share_bps": self.compression_share_bps,
            "da_savings_share_bps": self.da_savings_share_bps,
            "privacy_budget_window_blocks": self.privacy_budget_window_blocks,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "bundle_ttl_blocks": self.bundle_ttl_blocks,
            "da_voucher_ttl_blocks": self.da_voucher_ttl_blocks,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "evidence_window_blocks": self.evidence_window_blocks,
            "max_calls_per_bundle": self.max_calls_per_bundle,
            "max_dictionary_entries": self.max_dictionary_entries,
            "max_witness_deltas": self.max_witness_deltas,
            "max_market_lanes": self.max_market_lanes,
            "max_compressors": self.max_compressors,
            "max_solver_bids": self.max_solver_bids,
            "max_events": self.max_events,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_lane_sequence: u64,
    pub next_compressor_sequence: u64,
    pub next_dictionary_sequence: u64,
    pub next_abi_sequence: u64,
    pub next_bundle_sequence: u64,
    pub next_witness_delta_sequence: u64,
    pub next_voucher_sequence: u64,
    pub next_rebate_sequence: u64,
    pub next_privacy_budget_sequence: u64,
    pub next_market_sequence: u64,
    pub next_solver_bid_sequence: u64,
    pub next_evidence_sequence: u64,
    pub next_event_sequence: u64,
}

impl Counters {
    pub fn devnet() -> Self {
        Self {
            next_lane_sequence: 1,
            next_compressor_sequence: 1,
            next_dictionary_sequence: 1,
            next_abi_sequence: 1,
            next_bundle_sequence: 1,
            next_witness_delta_sequence: 1,
            next_voucher_sequence: 1,
            next_rebate_sequence: 1,
            next_privacy_budget_sequence: 1,
            next_market_sequence: 1,
            next_solver_bid_sequence: 1,
            next_evidence_sequence: 1,
            next_event_sequence: 1,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "next_lane_sequence": self.next_lane_sequence,
            "next_compressor_sequence": self.next_compressor_sequence,
            "next_dictionary_sequence": self.next_dictionary_sequence,
            "next_abi_sequence": self.next_abi_sequence,
            "next_bundle_sequence": self.next_bundle_sequence,
            "next_witness_delta_sequence": self.next_witness_delta_sequence,
            "next_voucher_sequence": self.next_voucher_sequence,
            "next_rebate_sequence": self.next_rebate_sequence,
            "next_privacy_budget_sequence": self.next_privacy_budget_sequence,
            "next_market_sequence": self.next_market_sequence,
            "next_solver_bid_sequence": self.next_solver_bid_sequence,
            "next_evidence_sequence": self.next_evidence_sequence,
            "next_event_sequence": self.next_event_sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub lane_root: String,
    pub compressor_root: String,
    pub dictionary_root: String,
    pub abi_fingerprint_root: String,
    pub encrypted_bundle_root: String,
    pub compressed_bundle_root: String,
    pub witness_delta_root: String,
    pub da_voucher_root: String,
    pub rebate_claim_root: String,
    pub privacy_budget_root: String,
    pub compression_market_root: String,
    pub solver_bid_root: String,
    pub slashing_evidence_root: String,
    pub nullifier_root: String,
    pub event_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "lane_root": self.lane_root,
            "compressor_root": self.compressor_root,
            "dictionary_root": self.dictionary_root,
            "abi_fingerprint_root": self.abi_fingerprint_root,
            "encrypted_bundle_root": self.encrypted_bundle_root,
            "compressed_bundle_root": self.compressed_bundle_root,
            "witness_delta_root": self.witness_delta_root,
            "da_voucher_root": self.da_voucher_root,
            "rebate_claim_root": self.rebate_claim_root,
            "privacy_budget_root": self.privacy_budget_root,
            "compression_market_root": self.compression_market_root,
            "solver_bid_root": self.solver_bid_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "nullifier_root": self.nullifier_root,
            "event_root": self.event_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompressionLane {
    pub lane_id: String,
    pub kind: LaneKind,
    pub status: LaneStatus,
    pub fee_asset_id: String,
    pub base_fee_piconero: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub priority_weight: u64,
    pub latency_target_ms: u64,
    pub min_privacy_set_size: u64,
    pub accepted_abi_roots: BTreeSet<String>,
    pub created_at_height: u64,
    pub updated_at_height: u64,
}

impl CompressionLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "kind": self.kind,
            "status": self.status,
            "fee_asset_id": self.fee_asset_id,
            "base_fee_piconero": self.base_fee_piconero,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "priority_weight": self.priority_weight,
            "latency_target_ms": self.latency_target_ms,
            "min_privacy_set_size": self.min_privacy_set_size,
            "accepted_abi_roots": self.accepted_abi_roots,
            "created_at_height": self.created_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Compressor {
    pub compressor_id: String,
    pub operator_commitment: String,
    pub status: CompressorStatus,
    pub pq_attestation_root: String,
    pub supported_modes: BTreeSet<CompressionMode>,
    pub stake_commitment: String,
    pub reputation_score: u64,
    pub max_bundle_calls: usize,
    pub max_uncompressed_bytes: u64,
    pub min_savings_bps: u64,
    pub posted_at_height: u64,
    pub last_active_height: u64,
}

impl Compressor {
    pub fn public_record(&self) -> Value {
        json!({
            "compressor_id": self.compressor_id,
            "operator_commitment": self.operator_commitment,
            "status": self.status,
            "pq_attestation_root": self.pq_attestation_root,
            "supported_modes": self.supported_modes,
            "stake_commitment": self.stake_commitment,
            "reputation_score": self.reputation_score,
            "max_bundle_calls": self.max_bundle_calls,
            "max_uncompressed_bytes": self.max_uncompressed_bytes,
            "min_savings_bps": self.min_savings_bps,
            "posted_at_height": self.posted_at_height,
            "last_active_height": self.last_active_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CalldataDictionary {
    pub dictionary_id: String,
    pub owner_commitment: String,
    pub status: DictionaryStatus,
    pub abi_fingerprint_id: String,
    pub entry_root: String,
    pub selector_root: String,
    pub token_root: String,
    pub entry_count: usize,
    pub raw_bytes: u64,
    pub compressed_bytes: u64,
    pub savings_bps: u64,
    pub reuse_count: u64,
    pub created_at_height: u64,
    pub updated_at_height: u64,
}

impl CalldataDictionary {
    pub fn public_record(&self) -> Value {
        json!({
            "dictionary_id": self.dictionary_id,
            "owner_commitment": self.owner_commitment,
            "status": self.status,
            "abi_fingerprint_id": self.abi_fingerprint_id,
            "entry_root": self.entry_root,
            "selector_root": self.selector_root,
            "token_root": self.token_root,
            "entry_count": self.entry_count,
            "raw_bytes": self.raw_bytes,
            "compressed_bytes": self.compressed_bytes,
            "savings_bps": self.savings_bps,
            "reuse_count": self.reuse_count,
            "created_at_height": self.created_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AbiFingerprint {
    pub abi_fingerprint_id: String,
    pub contract_commitment: String,
    pub selector_root: String,
    pub event_root: String,
    pub storage_layout_root: String,
    pub bytecode_commitment: String,
    pub version_tag: String,
    pub method_count: usize,
    pub privacy_sensitive_methods: BTreeSet<String>,
    pub registered_at_height: u64,
}

impl AbiFingerprint {
    pub fn public_record(&self) -> Value {
        json!({
            "abi_fingerprint_id": self.abi_fingerprint_id,
            "contract_commitment": self.contract_commitment,
            "selector_root": self.selector_root,
            "event_root": self.event_root,
            "storage_layout_root": self.storage_layout_root,
            "bytecode_commitment": self.bytecode_commitment,
            "version_tag": self.version_tag,
            "method_count": self.method_count,
            "privacy_sensitive_methods": self.privacy_sensitive_methods,
            "registered_at_height": self.registered_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedCallBundle {
    pub bundle_id: String,
    pub lane_id: String,
    pub submitter_commitment: String,
    pub ciphertext_root: String,
    pub call_commitment_root: String,
    pub contract_root: String,
    pub abi_fingerprint_root: String,
    pub nullifier_root: String,
    pub call_count: usize,
    pub uncompressed_bytes: u64,
    pub max_fee_piconero: u64,
    pub privacy_set_size: u64,
    pub pq_ciphertext_root: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub status: BundleStatus,
}

impl EncryptedCallBundle {
    pub fn public_record(&self) -> Value {
        json!({
            "bundle_id": self.bundle_id,
            "lane_id": self.lane_id,
            "submitter_commitment": self.submitter_commitment,
            "ciphertext_root": self.ciphertext_root,
            "call_commitment_root": self.call_commitment_root,
            "contract_root": self.contract_root,
            "abi_fingerprint_root": self.abi_fingerprint_root,
            "nullifier_root": self.nullifier_root,
            "call_count": self.call_count,
            "uncompressed_bytes": self.uncompressed_bytes,
            "max_fee_piconero": self.max_fee_piconero,
            "privacy_set_size": self.privacy_set_size,
            "pq_ciphertext_root": self.pq_ciphertext_root,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WitnessDelta {
    pub witness_delta_id: String,
    pub bundle_id: String,
    pub compressor_id: String,
    pub base_witness_root: String,
    pub delta_root: String,
    pub patched_witness_root: String,
    pub lookup_root: String,
    pub old_bytes: u64,
    pub delta_bytes: u64,
    pub savings_bps: u64,
    pub created_at_height: u64,
}

impl WitnessDelta {
    pub fn public_record(&self) -> Value {
        json!({
            "witness_delta_id": self.witness_delta_id,
            "bundle_id": self.bundle_id,
            "compressor_id": self.compressor_id,
            "base_witness_root": self.base_witness_root,
            "delta_root": self.delta_root,
            "patched_witness_root": self.patched_witness_root,
            "lookup_root": self.lookup_root,
            "old_bytes": self.old_bytes,
            "delta_bytes": self.delta_bytes,
            "savings_bps": self.savings_bps,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompressedBundle {
    pub compressed_bundle_id: String,
    pub bundle_id: String,
    pub compressor_id: String,
    pub dictionary_ids: BTreeSet<String>,
    pub witness_delta_ids: BTreeSet<String>,
    pub mode: CompressionMode,
    pub compressed_call_root: String,
    pub compressed_witness_root: String,
    pub da_payload_root: String,
    pub route_plan_root: String,
    pub uncompressed_bytes: u64,
    pub compressed_bytes: u64,
    pub saved_bytes: u64,
    pub savings_bps: u64,
    pub estimated_da_fee_piconero: u64,
    pub user_fee_piconero: u64,
    pub compressed_at_height: u64,
}

impl CompressedBundle {
    pub fn public_record(&self) -> Value {
        json!({
            "compressed_bundle_id": self.compressed_bundle_id,
            "bundle_id": self.bundle_id,
            "compressor_id": self.compressor_id,
            "dictionary_ids": self.dictionary_ids,
            "witness_delta_ids": self.witness_delta_ids,
            "mode": self.mode,
            "compressed_call_root": self.compressed_call_root,
            "compressed_witness_root": self.compressed_witness_root,
            "da_payload_root": self.da_payload_root,
            "route_plan_root": self.route_plan_root,
            "uncompressed_bytes": self.uncompressed_bytes,
            "compressed_bytes": self.compressed_bytes,
            "saved_bytes": self.saved_bytes,
            "savings_bps": self.savings_bps,
            "estimated_da_fee_piconero": self.estimated_da_fee_piconero,
            "user_fee_piconero": self.user_fee_piconero,
            "compressed_at_height": self.compressed_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DaVoucher {
    pub voucher_id: String,
    pub sponsor_commitment: String,
    pub lane_id: String,
    pub bundle_id: String,
    pub compressed_bundle_id: String,
    pub status: VoucherStatus,
    pub covered_bytes: u64,
    pub face_value_piconero: u64,
    pub user_discount_piconero: u64,
    pub da_provider_commitment: String,
    pub availability_root: String,
    pub nullifier: String,
    pub allocated_at_height: u64,
    pub expires_at_height: u64,
}

impl DaVoucher {
    pub fn public_record(&self) -> Value {
        json!({
            "voucher_id": self.voucher_id,
            "sponsor_commitment": self.sponsor_commitment,
            "lane_id": self.lane_id,
            "bundle_id": self.bundle_id,
            "compressed_bundle_id": self.compressed_bundle_id,
            "status": self.status,
            "covered_bytes": self.covered_bytes,
            "face_value_piconero": self.face_value_piconero,
            "user_discount_piconero": self.user_discount_piconero,
            "da_provider_commitment": self.da_provider_commitment,
            "availability_root": self.availability_root,
            "nullifier": self.nullifier,
            "allocated_at_height": self.allocated_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateClaim {
    pub rebate_id: String,
    pub bundle_id: String,
    pub compressed_bundle_id: String,
    pub voucher_id: String,
    pub claimant_commitment: String,
    pub status: RebateStatus,
    pub gross_fee_piconero: u64,
    pub compressed_fee_piconero: u64,
    pub savings_piconero: u64,
    pub rebate_piconero: u64,
    pub proof_root: String,
    pub claimed_at_height: u64,
    pub settled_at_height: u64,
}

impl RebateClaim {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "bundle_id": self.bundle_id,
            "compressed_bundle_id": self.compressed_bundle_id,
            "voucher_id": self.voucher_id,
            "claimant_commitment": self.claimant_commitment,
            "status": self.status,
            "gross_fee_piconero": self.gross_fee_piconero,
            "compressed_fee_piconero": self.compressed_fee_piconero,
            "savings_piconero": self.savings_piconero,
            "rebate_piconero": self.rebate_piconero,
            "proof_root": self.proof_root,
            "claimed_at_height": self.claimed_at_height,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyBudgetAccount {
    pub budget_id: String,
    pub account_commitment: String,
    pub lane_id: String,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub starting_budget_units: u64,
    pub consumed_budget_units: u64,
    pub remaining_budget_units: u64,
    pub min_anonymity_set: u64,
    pub nullifier_root: String,
    pub last_update_height: u64,
}

impl PrivacyBudgetAccount {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "account_commitment": self.account_commitment,
            "lane_id": self.lane_id,
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "starting_budget_units": self.starting_budget_units,
            "consumed_budget_units": self.consumed_budget_units,
            "remaining_budget_units": self.remaining_budget_units,
            "min_anonymity_set": self.min_anonymity_set,
            "nullifier_root": self.nullifier_root,
            "last_update_height": self.last_update_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompressionMarket {
    pub market_id: String,
    pub lane_id: String,
    pub mode: CompressionMode,
    pub status: LaneStatus,
    pub min_savings_bps: u64,
    pub max_fee_piconero: u64,
    pub max_latency_ms: u64,
    pub accepted_compressor_root: String,
    pub settled_bundle_root: String,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
}

impl CompressionMarket {
    pub fn public_record(&self) -> Value {
        json!({
            "market_id": self.market_id,
            "lane_id": self.lane_id,
            "mode": self.mode,
            "status": self.status,
            "min_savings_bps": self.min_savings_bps,
            "max_fee_piconero": self.max_fee_piconero,
            "max_latency_ms": self.max_latency_ms,
            "accepted_compressor_root": self.accepted_compressor_root,
            "settled_bundle_root": self.settled_bundle_root,
            "opened_at_height": self.opened_at_height,
            "closes_at_height": self.closes_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SolverBid {
    pub bid_id: String,
    pub market_id: String,
    pub compressor_id: String,
    pub bundle_id: String,
    pub solver_commitment: String,
    pub status: SolverBidStatus,
    pub mode: CompressionMode,
    pub quoted_fee_piconero: u64,
    pub promised_savings_bps: u64,
    pub latency_ms: u64,
    pub route_plan_root: String,
    pub privacy_cost_units: u64,
    pub da_bytes: u64,
    pub score: u64,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
}

impl SolverBid {
    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "market_id": self.market_id,
            "compressor_id": self.compressor_id,
            "bundle_id": self.bundle_id,
            "solver_commitment": self.solver_commitment,
            "status": self.status,
            "mode": self.mode,
            "quoted_fee_piconero": self.quoted_fee_piconero,
            "promised_savings_bps": self.promised_savings_bps,
            "latency_ms": self.latency_ms,
            "route_plan_root": self.route_plan_root,
            "privacy_cost_units": self.privacy_cost_units,
            "da_bytes": self.da_bytes,
            "score": self.score,
            "posted_at_height": self.posted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub kind: SlashingKind,
    pub accused_commitment: String,
    pub bundle_id: String,
    pub compressed_bundle_id: String,
    pub evidence_root: String,
    pub expected_root: String,
    pub observed_root: String,
    pub slash_bps: u64,
    pub bond_penalty_piconero: u64,
    pub submitted_at_height: u64,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "kind": self.kind,
            "accused_commitment": self.accused_commitment,
            "bundle_id": self.bundle_id,
            "compressed_bundle_id": self.compressed_bundle_id,
            "evidence_root": self.evidence_root,
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "slash_bps": self.slash_bps,
            "bond_penalty_piconero": self.bond_penalty_piconero,
            "submitted_at_height": self.submitted_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub kind: String,
    pub object_id: String,
    pub height: u64,
    pub payload_root: String,
}

impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "kind": self.kind,
            "object_id": self.object_id,
            "height": self.height,
            "payload_root": self.payload_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub height: u64,
    pub lanes: BTreeMap<String, CompressionLane>,
    pub compressors: BTreeMap<String, Compressor>,
    pub dictionaries: BTreeMap<String, CalldataDictionary>,
    pub abi_fingerprints: BTreeMap<String, AbiFingerprint>,
    pub encrypted_bundles: BTreeMap<String, EncryptedCallBundle>,
    pub compressed_bundles: BTreeMap<String, CompressedBundle>,
    pub witness_deltas: BTreeMap<String, WitnessDelta>,
    pub da_vouchers: BTreeMap<String, DaVoucher>,
    pub rebate_claims: BTreeMap<String, RebateClaim>,
    pub privacy_budgets: BTreeMap<String, PrivacyBudgetAccount>,
    pub compression_markets: BTreeMap<String, CompressionMarket>,
    pub solver_bids: BTreeMap<String, SolverBid>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub spent_nullifiers: BTreeSet<String>,
    pub events: BTreeMap<String, RuntimeEvent>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::devnet(),
            height: DEVNET_HEIGHT,
            lanes: BTreeMap::new(),
            compressors: BTreeMap::new(),
            dictionaries: BTreeMap::new(),
            abi_fingerprints: BTreeMap::new(),
            encrypted_bundles: BTreeMap::new(),
            compressed_bundles: BTreeMap::new(),
            witness_deltas: BTreeMap::new(),
            da_vouchers: BTreeMap::new(),
            rebate_claims: BTreeMap::new(),
            privacy_budgets: BTreeMap::new(),
            compression_markets: BTreeMap::new(),
            solver_bids: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            events: BTreeMap::new(),
        };

        let lane_id = state
            .register_lane(
                LaneKind::ConfidentialSwap,
                DEFAULT_FEE_ASSET_ID,
                1_200,
                DEFAULT_MAX_USER_FEE_BPS,
                DEFAULT_TARGET_REBATE_BPS,
                650,
            )
            .unwrap_or_else(|message| deterministic_error_id("DEVNET-LANE-ERROR", &message));
        let compressor_id = state
            .register_compressor(
                "devnet-compressor-commitment",
                &root_from_parts("DEVNET-COMPRESSOR-PQ", &[HashPart::Str("pq-attestation")]),
                &root_from_parts("DEVNET-COMPRESSOR-STAKE", &[HashPart::Str("stake")]),
                [
                    CompressionMode::DictionaryAndDelta,
                    CompressionMode::RouteAwareDefi,
                ]
                .into_iter()
                .collect(),
                4_096,
                16_777_216,
                2_500,
            )
            .unwrap_or_else(|message| deterministic_error_id("DEVNET-COMPRESSOR-ERROR", &message));
        let abi_id = state
            .register_abi_fingerprint(
                "devnet-private-router-contract",
                &root_from_values("DEVNET-ABI-SELECTORS", &["swap", "lend", "repay"]),
                &root_from_values("DEVNET-ABI-EVENTS", &["filled", "rebated"]),
                &root_from_values("DEVNET-ABI-STORAGE", &["pool", "vault", "nonce"]),
                &root_from_parts("DEVNET-BYTECODE", &[HashPart::Str("private-router")]),
                "v1",
                ["swap", "lend"].into_iter().map(str::to_string).collect(),
            )
            .unwrap_or_else(|message| deterministic_error_id("DEVNET-ABI-ERROR", &message));
        let dictionary_id = state
            .register_dictionary(
                "devnet-dictionary-owner",
                &abi_id,
                &["swapExactPrivate", "lendPrivate", "repayPrivate"],
                &["0x12345678", "0xabcdef01"],
                &["asset_in", "asset_out", "amount_commitment", "route_hint"],
                18_432,
                5_120,
            )
            .unwrap_or_else(|message| deterministic_error_id("DEVNET-DICTIONARY-ERROR", &message));
        let budget_id = state
            .open_privacy_budget(
                "devnet-user-commitment",
                &lane_id,
                12_000,
                DEFAULT_MIN_PRIVACY_SET_SIZE,
                &root_from_parts("DEVNET-BUDGET-NULLIFIERS", &[HashPart::Str("budget")]),
            )
            .unwrap_or_else(|message| deterministic_error_id("DEVNET-BUDGET-ERROR", &message));
        let bundle_id = state
            .submit_encrypted_call_bundle(SubmitBundleRequest {
                lane_id: lane_id.clone(),
                submitter_commitment: "devnet-user-commitment".to_string(),
                ciphertext_root: root_from_parts(
                    "DEVNET-BUNDLE-CIPHERTEXT",
                    &[HashPart::Str("ciphertext")],
                ),
                call_commitment_root: root_from_values(
                    "DEVNET-BUNDLE-CALLS",
                    &["swap-call", "lend-call", "vault-call"],
                ),
                contract_root: root_from_values("DEVNET-BUNDLE-CONTRACTS", &["router", "vault"]),
                abi_fingerprint_root: root_from_values("DEVNET-BUNDLE-ABIS", &[abi_id.as_str()]),
                nullifiers: ["devnet-nullifier-0", "devnet-nullifier-1"]
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
                call_count: 3,
                uncompressed_bytes: 32_768,
                max_fee_piconero: 4_000,
                privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
                pq_ciphertext_root: root_from_parts(
                    "DEVNET-BUNDLE-PQ",
                    &[HashPart::Str("pq-ciphertext")],
                ),
            })
            .unwrap_or_else(|message| deterministic_error_id("DEVNET-BUNDLE-ERROR", &message));
        let witness_delta_id = state
            .record_witness_delta(
                &bundle_id,
                &compressor_id,
                &root_from_parts("DEVNET-WITNESS-BASE", &[HashPart::Str("base")]),
                &root_from_parts("DEVNET-WITNESS-DELTA", &[HashPart::Str("delta")]),
                &root_from_parts("DEVNET-WITNESS-PATCHED", &[HashPart::Str("patched")]),
                &root_from_values("DEVNET-WITNESS-LOOKUP", &["slot-a", "slot-b"]),
                24_576,
                4_096,
            )
            .unwrap_or_else(|message| deterministic_error_id("DEVNET-WITNESS-ERROR", &message));
        let compressed_bundle_id = state
            .compress_call_bundle(CompressBundleRequest {
                bundle_id: bundle_id.clone(),
                compressor_id: compressor_id.clone(),
                dictionary_ids: [dictionary_id.clone()].into_iter().collect(),
                witness_delta_ids: [witness_delta_id].into_iter().collect(),
                mode: CompressionMode::RouteAwareDefi,
                compressed_call_root: root_from_parts(
                    "DEVNET-COMPRESSED-CALL",
                    &[HashPart::Str("compressed-call")],
                ),
                compressed_witness_root: root_from_parts(
                    "DEVNET-COMPRESSED-WITNESS",
                    &[HashPart::Str("compressed-witness")],
                ),
                da_payload_root: root_from_parts(
                    "DEVNET-DA-PAYLOAD",
                    &[HashPart::Str("da-payload")],
                ),
                route_plan_root: root_from_values("DEVNET-ROUTE", &["pool-a", "pool-b"]),
                compressed_bytes: 7_936,
                estimated_da_fee_piconero: 1_250,
                user_fee_piconero: 950,
            })
            .unwrap_or_else(|message| deterministic_error_id("DEVNET-COMPRESS-ERROR", &message));
        let voucher_id = state
            .allocate_da_voucher(AllocateVoucherRequest {
                sponsor_commitment: "devnet-sponsor-commitment".to_string(),
                bundle_id: bundle_id.clone(),
                compressed_bundle_id: compressed_bundle_id.clone(),
                covered_bytes: 7_936,
                face_value_piconero: 1_200,
                da_provider_commitment: "devnet-da-provider".to_string(),
                availability_root: root_from_parts(
                    "DEVNET-AVAILABILITY",
                    &[HashPart::Str("available")],
                ),
                nullifier: "devnet-voucher-nullifier-0".to_string(),
            })
            .unwrap_or_else(|message| deterministic_error_id("DEVNET-VOUCHER-ERROR", &message));
        let market_id = state
            .open_compression_market(
                &lane_id,
                CompressionMode::RouteAwareDefi,
                5_000,
                1_500,
                650,
                &root_from_values("DEVNET-MARKET-COMPRESSORS", &[compressor_id.as_str()]),
            )
            .unwrap_or_else(|message| deterministic_error_id("DEVNET-MARKET-ERROR", &message));
        let _bid_id = state
            .post_solver_bid(PostSolverBidRequest {
                market_id,
                compressor_id,
                bundle_id: bundle_id.clone(),
                solver_commitment: "devnet-solver-commitment".to_string(),
                mode: CompressionMode::RouteAwareDefi,
                quoted_fee_piconero: 950,
                promised_savings_bps: 7_500,
                latency_ms: 390,
                route_plan_root: root_from_values("DEVNET-BID-ROUTE", &["stable", "vault"]),
                privacy_cost_units: 48,
                da_bytes: 7_936,
            })
            .unwrap_or_else(|message| deterministic_error_id("DEVNET-BID-ERROR", &message));
        let _rebate_ids = state
            .settle_rebate_batch(vec![RebateClaimInput {
                bundle_id,
                compressed_bundle_id,
                voucher_id,
                claimant_commitment: "devnet-user-commitment".to_string(),
                gross_fee_piconero: 4_000,
                compressed_fee_piconero: 950,
                proof_root: root_from_parts("DEVNET-REBATE-PROOF", &[HashPart::Str("proof")]),
            }])
            .unwrap_or_else(|_| Vec::new());
        let _ = state.consume_privacy_budget(&budget_id, 72);
        state
    }

    pub fn register_lane(
        &mut self,
        kind: LaneKind,
        fee_asset_id: &str,
        base_fee_piconero: u64,
        max_user_fee_bps: u64,
        target_rebate_bps: u64,
        latency_target_ms: u64,
    ) -> Result<String> {
        if self.lanes.len() >= self.config.max_market_lanes {
            return Err("market lane capacity exceeded".to_string());
        }
        ensure_bps(max_user_fee_bps, "max_user_fee_bps")?;
        ensure_bps(target_rebate_bps, "target_rebate_bps")?;
        let sequence = self.counters.next_lane_sequence;
        self.counters.next_lane_sequence = self.counters.next_lane_sequence.saturating_add(1);
        let lane_id = lane_id(sequence, kind, fee_asset_id);
        let lane = CompressionLane {
            lane_id: lane_id.clone(),
            kind,
            status: LaneStatus::Open,
            fee_asset_id: fee_asset_id.to_string(),
            base_fee_piconero,
            max_user_fee_bps,
            target_rebate_bps,
            priority_weight: kind.priority_weight(),
            latency_target_ms,
            min_privacy_set_size: self.config.min_privacy_set_size,
            accepted_abi_roots: BTreeSet::new(),
            created_at_height: self.height,
            updated_at_height: self.height,
        };
        self.lanes.insert(lane_id.clone(), lane);
        self.record_event("lane_registered", &lane_id, &json!({"kind": kind}))?;
        Ok(lane_id)
    }

    pub fn register_compressor(
        &mut self,
        operator_commitment: &str,
        pq_attestation_root: &str,
        stake_commitment: &str,
        supported_modes: BTreeSet<CompressionMode>,
        max_bundle_calls: usize,
        max_uncompressed_bytes: u64,
        min_savings_bps: u64,
    ) -> Result<String> {
        if self.compressors.len() >= self.config.max_compressors {
            return Err("compressor capacity exceeded".to_string());
        }
        ensure_non_empty(operator_commitment, "operator_commitment")?;
        ensure_non_empty(pq_attestation_root, "pq_attestation_root")?;
        ensure_non_empty(stake_commitment, "stake_commitment")?;
        ensure_bps(min_savings_bps, "min_savings_bps")?;
        if supported_modes.is_empty() {
            return Err("supported_modes must not be empty".to_string());
        }
        let sequence = self.counters.next_compressor_sequence;
        self.counters.next_compressor_sequence =
            self.counters.next_compressor_sequence.saturating_add(1);
        let compressor_id = compressor_id(sequence, operator_commitment, pq_attestation_root);
        let compressor = Compressor {
            compressor_id: compressor_id.clone(),
            operator_commitment: operator_commitment.to_string(),
            status: CompressorStatus::Active,
            pq_attestation_root: pq_attestation_root.to_string(),
            supported_modes,
            stake_commitment: stake_commitment.to_string(),
            reputation_score: 8_000,
            max_bundle_calls,
            max_uncompressed_bytes,
            min_savings_bps,
            posted_at_height: self.height,
            last_active_height: self.height,
        };
        self.compressors.insert(compressor_id.clone(), compressor);
        self.record_event(
            "compressor_registered",
            &compressor_id,
            &json!({"operator_commitment": operator_commitment}),
        )?;
        Ok(compressor_id)
    }

    pub fn register_abi_fingerprint(
        &mut self,
        contract_commitment: &str,
        selector_root: &str,
        event_root: &str,
        storage_layout_root: &str,
        bytecode_commitment: &str,
        version_tag: &str,
        privacy_sensitive_methods: BTreeSet<String>,
    ) -> Result<String> {
        ensure_non_empty(contract_commitment, "contract_commitment")?;
        ensure_non_empty(selector_root, "selector_root")?;
        ensure_non_empty(bytecode_commitment, "bytecode_commitment")?;
        let sequence = self.counters.next_abi_sequence;
        self.counters.next_abi_sequence = self.counters.next_abi_sequence.saturating_add(1);
        let abi_fingerprint_id =
            abi_fingerprint_id(sequence, contract_commitment, selector_root, version_tag);
        let method_count = privacy_sensitive_methods.len();
        let fingerprint = AbiFingerprint {
            abi_fingerprint_id: abi_fingerprint_id.clone(),
            contract_commitment: contract_commitment.to_string(),
            selector_root: selector_root.to_string(),
            event_root: event_root.to_string(),
            storage_layout_root: storage_layout_root.to_string(),
            bytecode_commitment: bytecode_commitment.to_string(),
            version_tag: version_tag.to_string(),
            method_count,
            privacy_sensitive_methods,
            registered_at_height: self.height,
        };
        self.abi_fingerprints
            .insert(abi_fingerprint_id.clone(), fingerprint);
        self.record_event(
            "abi_fingerprint_registered",
            &abi_fingerprint_id,
            &json!({"contract_commitment": contract_commitment}),
        )?;
        Ok(abi_fingerprint_id)
    }

    pub fn register_dictionary(
        &mut self,
        owner_commitment: &str,
        abi_fingerprint_id: &str,
        entries: &[&str],
        selectors: &[&str],
        tokens: &[&str],
        raw_bytes: u64,
        compressed_bytes: u64,
    ) -> Result<String> {
        if self.dictionaries.len() >= self.config.max_dictionary_entries {
            return Err("dictionary capacity exceeded".to_string());
        }
        ensure_non_empty(owner_commitment, "owner_commitment")?;
        if !self.abi_fingerprints.contains_key(abi_fingerprint_id) {
            return Err("unknown abi_fingerprint_id".to_string());
        }
        if entries.is_empty() {
            return Err("dictionary entries must not be empty".to_string());
        }
        let sequence = self.counters.next_dictionary_sequence;
        self.counters.next_dictionary_sequence =
            self.counters.next_dictionary_sequence.saturating_add(1);
        let entry_root = root_from_values("BATCH-CALL-DICTIONARY-ENTRIES", entries);
        let selector_root = root_from_values("BATCH-CALL-DICTIONARY-SELECTORS", selectors);
        let token_root = root_from_values("BATCH-CALL-DICTIONARY-TOKENS", tokens);
        let dictionary_id =
            dictionary_id(sequence, owner_commitment, abi_fingerprint_id, &entry_root);
        let dictionary = CalldataDictionary {
            dictionary_id: dictionary_id.clone(),
            owner_commitment: owner_commitment.to_string(),
            status: DictionaryStatus::Active,
            abi_fingerprint_id: abi_fingerprint_id.to_string(),
            entry_root,
            selector_root,
            token_root,
            entry_count: entries.len(),
            raw_bytes,
            compressed_bytes,
            savings_bps: savings_bps(raw_bytes, compressed_bytes),
            reuse_count: 0,
            created_at_height: self.height,
            updated_at_height: self.height,
        };
        self.dictionaries.insert(dictionary_id.clone(), dictionary);
        self.record_event(
            "dictionary_registered",
            &dictionary_id,
            &json!({"abi_fingerprint_id": abi_fingerprint_id}),
        )?;
        Ok(dictionary_id)
    }

    pub fn open_privacy_budget(
        &mut self,
        account_commitment: &str,
        lane_id: &str,
        starting_budget_units: u64,
        min_anonymity_set: u64,
        nullifier_root: &str,
    ) -> Result<String> {
        ensure_non_empty(account_commitment, "account_commitment")?;
        self.lane(lane_id)?;
        if min_anonymity_set < self.config.min_privacy_set_size {
            return Err("min_anonymity_set below runtime minimum".to_string());
        }
        let sequence = self.counters.next_privacy_budget_sequence;
        self.counters.next_privacy_budget_sequence =
            self.counters.next_privacy_budget_sequence.saturating_add(1);
        let window_start_height = self.height;
        let window_end_height = self
            .height
            .saturating_add(self.config.privacy_budget_window_blocks);
        let budget_id = privacy_budget_id(sequence, account_commitment, lane_id);
        let account = PrivacyBudgetAccount {
            budget_id: budget_id.clone(),
            account_commitment: account_commitment.to_string(),
            lane_id: lane_id.to_string(),
            window_start_height,
            window_end_height,
            starting_budget_units,
            consumed_budget_units: 0,
            remaining_budget_units: starting_budget_units,
            min_anonymity_set,
            nullifier_root: nullifier_root.to_string(),
            last_update_height: self.height,
        };
        self.privacy_budgets.insert(budget_id.clone(), account);
        self.record_event(
            "privacy_budget_opened",
            &budget_id,
            &json!({"lane_id": lane_id}),
        )?;
        Ok(budget_id)
    }

    pub fn consume_privacy_budget(&mut self, budget_id: &str, units: u64) -> Result<()> {
        let account = self
            .privacy_budgets
            .get_mut(budget_id)
            .ok_or_else(|| "unknown privacy budget".to_string())?;
        if account.remaining_budget_units < units {
            return Err("privacy budget exhausted".to_string());
        }
        account.remaining_budget_units = account.remaining_budget_units.saturating_sub(units);
        account.consumed_budget_units = account.consumed_budget_units.saturating_add(units);
        account.last_update_height = self.height;
        self.record_event(
            "privacy_budget_consumed",
            budget_id,
            &json!({"units": units}),
        )
    }

    pub fn submit_encrypted_call_bundle(&mut self, request: SubmitBundleRequest) -> Result<String> {
        let lane = self.lane(&request.lane_id)?;
        if !lane.status.accepts_bundles() {
            return Err("lane does not accept bundles".to_string());
        }
        if request.call_count == 0 || request.call_count > self.config.max_calls_per_bundle {
            return Err("call_count outside configured bundle limits".to_string());
        }
        if request.privacy_set_size < lane.min_privacy_set_size {
            return Err("privacy_set_size below lane minimum".to_string());
        }
        for nullifier in &request.nullifiers {
            if self.spent_nullifiers.contains(nullifier) {
                return Err("bundle contains a spent nullifier".to_string());
            }
        }
        let sequence = self.counters.next_bundle_sequence;
        self.counters.next_bundle_sequence = self.counters.next_bundle_sequence.saturating_add(1);
        let nullifier_root =
            root_from_string_set("BATCH-CALL-BUNDLE-NULLIFIERS", &request.nullifiers);
        let bundle_id = bundle_id(sequence, &request.lane_id, &request.ciphertext_root);
        let bundle = EncryptedCallBundle {
            bundle_id: bundle_id.clone(),
            lane_id: request.lane_id,
            submitter_commitment: request.submitter_commitment,
            ciphertext_root: request.ciphertext_root,
            call_commitment_root: request.call_commitment_root,
            contract_root: request.contract_root,
            abi_fingerprint_root: request.abi_fingerprint_root,
            nullifier_root,
            call_count: request.call_count,
            uncompressed_bytes: request.uncompressed_bytes,
            max_fee_piconero: request.max_fee_piconero,
            privacy_set_size: request.privacy_set_size,
            pq_ciphertext_root: request.pq_ciphertext_root,
            submitted_at_height: self.height,
            expires_at_height: self.height.saturating_add(self.config.bundle_ttl_blocks),
            status: BundleStatus::Submitted,
        };
        for nullifier in request.nullifiers {
            self.spent_nullifiers.insert(nullifier);
        }
        self.encrypted_bundles.insert(bundle_id.clone(), bundle);
        self.record_event(
            "encrypted_bundle_submitted",
            &bundle_id,
            &json!({"call_count": request.call_count}),
        )?;
        Ok(bundle_id)
    }

    pub fn record_witness_delta(
        &mut self,
        bundle_id: &str,
        compressor_id: &str,
        base_witness_root: &str,
        delta_root: &str,
        patched_witness_root: &str,
        lookup_root: &str,
        old_bytes: u64,
        delta_bytes: u64,
    ) -> Result<String> {
        if self.witness_deltas.len() >= self.config.max_witness_deltas {
            return Err("witness delta capacity exceeded".to_string());
        }
        self.bundle(bundle_id)?;
        self.compressor(compressor_id)?;
        let sequence = self.counters.next_witness_delta_sequence;
        self.counters.next_witness_delta_sequence =
            self.counters.next_witness_delta_sequence.saturating_add(1);
        let witness_delta_id = witness_delta_id(sequence, bundle_id, compressor_id, delta_root);
        let delta = WitnessDelta {
            witness_delta_id: witness_delta_id.clone(),
            bundle_id: bundle_id.to_string(),
            compressor_id: compressor_id.to_string(),
            base_witness_root: base_witness_root.to_string(),
            delta_root: delta_root.to_string(),
            patched_witness_root: patched_witness_root.to_string(),
            lookup_root: lookup_root.to_string(),
            old_bytes,
            delta_bytes,
            savings_bps: savings_bps(old_bytes, delta_bytes),
            created_at_height: self.height,
        };
        self.witness_deltas.insert(witness_delta_id.clone(), delta);
        self.record_event(
            "witness_delta_recorded",
            &witness_delta_id,
            &json!({"bundle_id": bundle_id}),
        )?;
        Ok(witness_delta_id)
    }

    pub fn compress_call_bundle(&mut self, request: CompressBundleRequest) -> Result<String> {
        let bundle = self.bundle(&request.bundle_id)?.clone();
        let compressor = self.compressor(&request.compressor_id)?.clone();
        if !compressor.status.accepts_work() {
            return Err("compressor does not accept work".to_string());
        }
        if !compressor.supported_modes.contains(&request.mode) {
            return Err("compressor does not support requested mode".to_string());
        }
        if bundle.call_count > compressor.max_bundle_calls {
            return Err("bundle exceeds compressor call capacity".to_string());
        }
        if bundle.uncompressed_bytes > compressor.max_uncompressed_bytes {
            return Err("bundle exceeds compressor byte capacity".to_string());
        }
        if request.compressed_bytes >= bundle.uncompressed_bytes {
            return Err("compressed_bytes must be below uncompressed bytes".to_string());
        }
        for dictionary_id in &request.dictionary_ids {
            let dictionary = self
                .dictionaries
                .get(dictionary_id)
                .ok_or_else(|| "unknown dictionary_id".to_string())?;
            if !dictionary.status.usable() {
                return Err("dictionary is not usable".to_string());
            }
        }
        for witness_delta_id in &request.witness_delta_ids {
            if !self.witness_deltas.contains_key(witness_delta_id) {
                return Err("unknown witness_delta_id".to_string());
            }
        }
        let bundle_savings_bps = savings_bps(bundle.uncompressed_bytes, request.compressed_bytes);
        if bundle_savings_bps < compressor.min_savings_bps {
            return Err("compression savings below compressor minimum".to_string());
        }
        let sequence = self.counters.next_bundle_sequence;
        self.counters.next_bundle_sequence = self.counters.next_bundle_sequence.saturating_add(1);
        let compressed_bundle_id =
            compressed_bundle_id(sequence, &request.bundle_id, &request.compressed_call_root);
        let compressed = CompressedBundle {
            compressed_bundle_id: compressed_bundle_id.clone(),
            bundle_id: request.bundle_id.clone(),
            compressor_id: request.compressor_id.clone(),
            dictionary_ids: request.dictionary_ids.clone(),
            witness_delta_ids: request.witness_delta_ids,
            mode: request.mode,
            compressed_call_root: request.compressed_call_root,
            compressed_witness_root: request.compressed_witness_root,
            da_payload_root: request.da_payload_root,
            route_plan_root: request.route_plan_root,
            uncompressed_bytes: bundle.uncompressed_bytes,
            compressed_bytes: request.compressed_bytes,
            saved_bytes: bundle
                .uncompressed_bytes
                .saturating_sub(request.compressed_bytes),
            savings_bps: bundle_savings_bps,
            estimated_da_fee_piconero: request.estimated_da_fee_piconero,
            user_fee_piconero: request.user_fee_piconero,
            compressed_at_height: self.height,
        };
        for dictionary_id in &request.dictionary_ids {
            if let Some(dictionary) = self.dictionaries.get_mut(dictionary_id) {
                dictionary.reuse_count = dictionary.reuse_count.saturating_add(1);
                dictionary.updated_at_height = self.height;
            }
        }
        if let Some(bundle) = self.encrypted_bundles.get_mut(&request.bundle_id) {
            bundle.status = BundleStatus::Compressed;
        }
        if let Some(compressor) = self.compressors.get_mut(&request.compressor_id) {
            compressor.last_active_height = self.height;
            compressor.reputation_score = compressor
                .reputation_score
                .saturating_add(bundle_savings_bps / 100);
        }
        self.compressed_bundles
            .insert(compressed_bundle_id.clone(), compressed);
        self.record_event(
            "bundle_compressed",
            &compressed_bundle_id,
            &json!({"bundle_id": request.bundle_id, "savings_bps": bundle_savings_bps}),
        )?;
        Ok(compressed_bundle_id)
    }

    pub fn allocate_da_voucher(&mut self, request: AllocateVoucherRequest) -> Result<String> {
        let bundle = self.bundle(&request.bundle_id)?.clone();
        let compressed = self
            .compressed_bundle(&request.compressed_bundle_id)?
            .clone();
        if compressed.bundle_id != bundle.bundle_id {
            return Err("compressed bundle does not belong to bundle".to_string());
        }
        if self.spent_nullifiers.contains(&request.nullifier) {
            return Err("voucher nullifier already spent".to_string());
        }
        let sequence = self.counters.next_voucher_sequence;
        self.counters.next_voucher_sequence = self.counters.next_voucher_sequence.saturating_add(1);
        let voucher_id = da_voucher_id(sequence, &request.bundle_id, &request.nullifier);
        let user_discount_piconero = mul_bps(
            request.face_value_piconero,
            self.config.sponsor_cover_bps.min(MAX_BPS),
        );
        let voucher = DaVoucher {
            voucher_id: voucher_id.clone(),
            sponsor_commitment: request.sponsor_commitment,
            lane_id: bundle.lane_id.clone(),
            bundle_id: request.bundle_id.clone(),
            compressed_bundle_id: request.compressed_bundle_id,
            status: VoucherStatus::Reserved,
            covered_bytes: request.covered_bytes,
            face_value_piconero: request.face_value_piconero,
            user_discount_piconero,
            da_provider_commitment: request.da_provider_commitment,
            availability_root: request.availability_root,
            nullifier: request.nullifier.clone(),
            allocated_at_height: self.height,
            expires_at_height: self
                .height
                .saturating_add(self.config.da_voucher_ttl_blocks),
        };
        self.spent_nullifiers.insert(request.nullifier);
        if let Some(bundle) = self.encrypted_bundles.get_mut(&request.bundle_id) {
            bundle.status = BundleStatus::VoucherAllocated;
        }
        self.da_vouchers.insert(voucher_id.clone(), voucher);
        self.record_event(
            "da_voucher_allocated",
            &voucher_id,
            &json!({"bundle_id": request.bundle_id, "discount": user_discount_piconero}),
        )?;
        Ok(voucher_id)
    }

    pub fn settle_rebate_batch(&mut self, claims: Vec<RebateClaimInput>) -> Result<Vec<String>> {
        let mut rebate_ids = Vec::with_capacity(claims.len());
        for claim in claims {
            let compressed = self.compressed_bundle(&claim.compressed_bundle_id)?.clone();
            if compressed.bundle_id != claim.bundle_id {
                return Err("rebate compressed bundle mismatch".to_string());
            }
            let voucher = self
                .da_vouchers
                .get(&claim.voucher_id)
                .ok_or_else(|| "unknown voucher_id".to_string())?
                .clone();
            if voucher.bundle_id != claim.bundle_id {
                return Err("rebate voucher bundle mismatch".to_string());
            }
            let savings = claim
                .gross_fee_piconero
                .saturating_sub(claim.compressed_fee_piconero);
            let rebate_piconero = mul_bps(savings, self.config.target_rebate_bps);
            let sequence = self.counters.next_rebate_sequence;
            self.counters.next_rebate_sequence =
                self.counters.next_rebate_sequence.saturating_add(1);
            let rebate_id = rebate_id(sequence, &claim.bundle_id, &claim.proof_root);
            let record = RebateClaim {
                rebate_id: rebate_id.clone(),
                bundle_id: claim.bundle_id.clone(),
                compressed_bundle_id: claim.compressed_bundle_id.clone(),
                voucher_id: claim.voucher_id.clone(),
                claimant_commitment: claim.claimant_commitment,
                status: RebateStatus::Settled,
                gross_fee_piconero: claim.gross_fee_piconero,
                compressed_fee_piconero: claim.compressed_fee_piconero,
                savings_piconero: savings,
                rebate_piconero,
                proof_root: claim.proof_root,
                claimed_at_height: self.height,
                settled_at_height: self.height,
            };
            if let Some(voucher) = self.da_vouchers.get_mut(&claim.voucher_id) {
                voucher.status = VoucherStatus::Consumed;
            }
            if let Some(bundle) = self.encrypted_bundles.get_mut(&claim.bundle_id) {
                bundle.status = BundleStatus::Rebated;
            }
            self.rebate_claims.insert(rebate_id.clone(), record);
            self.record_event(
                "rebate_settled",
                &rebate_id,
                &json!({"bundle_id": claim.bundle_id, "rebate_piconero": rebate_piconero}),
            )?;
            rebate_ids.push(rebate_id);
        }
        Ok(rebate_ids)
    }

    pub fn open_compression_market(
        &mut self,
        lane_id: &str,
        mode: CompressionMode,
        min_savings_bps: u64,
        max_fee_piconero: u64,
        max_latency_ms: u64,
        accepted_compressor_root: &str,
    ) -> Result<String> {
        self.lane(lane_id)?;
        ensure_bps(min_savings_bps, "min_savings_bps")?;
        let sequence = self.counters.next_market_sequence;
        self.counters.next_market_sequence = self.counters.next_market_sequence.saturating_add(1);
        let market_id = market_id(sequence, lane_id, mode);
        let market = CompressionMarket {
            market_id: market_id.clone(),
            lane_id: lane_id.to_string(),
            mode,
            status: LaneStatus::Open,
            min_savings_bps,
            max_fee_piconero,
            max_latency_ms,
            accepted_compressor_root: accepted_compressor_root.to_string(),
            settled_bundle_root: root_from_values("BATCH-CALL-MARKET-SETTLED-EMPTY", &[]),
            opened_at_height: self.height,
            closes_at_height: self.height.saturating_add(self.config.quote_ttl_blocks),
        };
        self.compression_markets.insert(market_id.clone(), market);
        self.record_event(
            "compression_market_opened",
            &market_id,
            &json!({"lane_id": lane_id, "mode": mode}),
        )?;
        Ok(market_id)
    }

    pub fn post_solver_bid(&mut self, request: PostSolverBidRequest) -> Result<String> {
        if self.solver_bids.len() >= self.config.max_solver_bids {
            return Err("solver bid capacity exceeded".to_string());
        }
        let market = self
            .compression_markets
            .get(&request.market_id)
            .ok_or_else(|| "unknown market_id".to_string())?
            .clone();
        if !market.status.accepts_bundles() {
            return Err("market is not open for bids".to_string());
        }
        self.compressor(&request.compressor_id)?;
        self.bundle(&request.bundle_id)?;
        if request.quoted_fee_piconero > market.max_fee_piconero {
            return Err("quoted fee exceeds market maximum".to_string());
        }
        if request.latency_ms > market.max_latency_ms {
            return Err("latency exceeds market maximum".to_string());
        }
        if request.promised_savings_bps < market.min_savings_bps {
            return Err("promised savings below market minimum".to_string());
        }
        let score = self.score_compressor_bid_fields(
            &request.compressor_id,
            request.quoted_fee_piconero,
            request.promised_savings_bps,
            request.latency_ms,
            request.privacy_cost_units,
            request.da_bytes,
        )?;
        let sequence = self.counters.next_solver_bid_sequence;
        self.counters.next_solver_bid_sequence =
            self.counters.next_solver_bid_sequence.saturating_add(1);
        let bid_id = solver_bid_id(
            sequence,
            &request.market_id,
            &request.compressor_id,
            &request.bundle_id,
        );
        let bid = SolverBid {
            bid_id: bid_id.clone(),
            market_id: request.market_id,
            compressor_id: request.compressor_id,
            bundle_id: request.bundle_id,
            solver_commitment: request.solver_commitment,
            status: SolverBidStatus::Posted,
            mode: request.mode,
            quoted_fee_piconero: request.quoted_fee_piconero,
            promised_savings_bps: request.promised_savings_bps,
            latency_ms: request.latency_ms,
            route_plan_root: request.route_plan_root,
            privacy_cost_units: request.privacy_cost_units,
            da_bytes: request.da_bytes,
            score,
            posted_at_height: self.height,
            expires_at_height: self.height.saturating_add(self.config.quote_ttl_blocks),
        };
        self.solver_bids.insert(bid_id.clone(), bid);
        self.record_event("solver_bid_posted", &bid_id, &json!({"score": score}))?;
        Ok(bid_id)
    }

    pub fn score_compressor_bid(&self, bid_id: &str) -> Result<u64> {
        let bid = self
            .solver_bids
            .get(bid_id)
            .ok_or_else(|| "unknown bid_id".to_string())?;
        self.score_compressor_bid_fields(
            &bid.compressor_id,
            bid.quoted_fee_piconero,
            bid.promised_savings_bps,
            bid.latency_ms,
            bid.privacy_cost_units,
            bid.da_bytes,
        )
    }

    pub fn score_compressor_bid_fields(
        &self,
        compressor_id: &str,
        quoted_fee_piconero: u64,
        promised_savings_bps: u64,
        latency_ms: u64,
        privacy_cost_units: u64,
        da_bytes: u64,
    ) -> Result<u64> {
        let compressor = self.compressor(compressor_id)?;
        let fee_penalty = quoted_fee_piconero / 8;
        let latency_penalty = latency_ms.saturating_mul(3);
        let privacy_penalty = privacy_cost_units.saturating_mul(11);
        let da_penalty = da_bytes / 64;
        let savings_score = promised_savings_bps.saturating_mul(7);
        let reputation_score = compressor.reputation_score.saturating_mul(2);
        Ok(savings_score
            .saturating_add(reputation_score)
            .saturating_sub(fee_penalty)
            .saturating_sub(latency_penalty)
            .saturating_sub(privacy_penalty)
            .saturating_sub(da_penalty))
    }

    pub fn submit_slashing_evidence(
        &mut self,
        kind: SlashingKind,
        accused_commitment: &str,
        bundle_id: &str,
        compressed_bundle_id: &str,
        expected_root: &str,
        observed_root: &str,
    ) -> Result<String> {
        self.bundle(bundle_id)?;
        self.compressed_bundle(compressed_bundle_id)?;
        ensure_non_empty(accused_commitment, "accused_commitment")?;
        let evidence_root = root_from_parts(
            "BATCH-CALL-SLASHING-EVIDENCE-ROOT",
            &[
                HashPart::Str(kind.as_ref()),
                HashPart::Str(accused_commitment),
                HashPart::Str(bundle_id),
                HashPart::Str(compressed_bundle_id),
                HashPart::Str(expected_root),
                HashPart::Str(observed_root),
            ],
        );
        let sequence = self.counters.next_evidence_sequence;
        self.counters.next_evidence_sequence =
            self.counters.next_evidence_sequence.saturating_add(1);
        let evidence_id = slashing_evidence_id(sequence, accused_commitment, &evidence_root);
        let slash_bps = kind.severity_weight().min(MAX_BPS);
        let evidence = SlashingEvidence {
            evidence_id: evidence_id.clone(),
            kind,
            accused_commitment: accused_commitment.to_string(),
            bundle_id: bundle_id.to_string(),
            compressed_bundle_id: compressed_bundle_id.to_string(),
            evidence_root,
            expected_root: expected_root.to_string(),
            observed_root: observed_root.to_string(),
            slash_bps,
            bond_penalty_piconero: mul_bps(1_000_000, slash_bps),
            submitted_at_height: self.height,
        };
        self.slashing_evidence.insert(evidence_id.clone(), evidence);
        self.record_event(
            "slashing_evidence_submitted",
            &evidence_id,
            &json!({"kind": kind, "slash_bps": slash_bps}),
        )?;
        Ok(evidence_id)
    }

    pub fn roots(&self) -> Roots {
        let config_root = root_json("BATCH-CALL-CONFIG", &self.config.public_record());
        let counters_root = root_json("BATCH-CALL-COUNTERS", &self.counters.public_record());
        let lane_root = map_root(
            "BATCH-CALL-LANES",
            self.lanes.values().map(CompressionLane::public_record),
        );
        let compressor_root = map_root(
            "BATCH-CALL-COMPRESSORS",
            self.compressors.values().map(Compressor::public_record),
        );
        let dictionary_root = map_root(
            "BATCH-CALL-DICTIONARIES",
            self.dictionaries
                .values()
                .map(CalldataDictionary::public_record),
        );
        let abi_fingerprint_root = map_root(
            "BATCH-CALL-ABI-FINGERPRINTS",
            self.abi_fingerprints
                .values()
                .map(AbiFingerprint::public_record),
        );
        let encrypted_bundle_root = map_root(
            "BATCH-CALL-ENCRYPTED-BUNDLES",
            self.encrypted_bundles
                .values()
                .map(EncryptedCallBundle::public_record),
        );
        let compressed_bundle_root = map_root(
            "BATCH-CALL-COMPRESSED-BUNDLES",
            self.compressed_bundles
                .values()
                .map(CompressedBundle::public_record),
        );
        let witness_delta_root = map_root(
            "BATCH-CALL-WITNESS-DELTAS",
            self.witness_deltas
                .values()
                .map(WitnessDelta::public_record),
        );
        let da_voucher_root = map_root(
            "BATCH-CALL-DA-VOUCHERS",
            self.da_vouchers.values().map(DaVoucher::public_record),
        );
        let rebate_claim_root = map_root(
            "BATCH-CALL-REBATE-CLAIMS",
            self.rebate_claims.values().map(RebateClaim::public_record),
        );
        let privacy_budget_root = map_root(
            "BATCH-CALL-PRIVACY-BUDGETS",
            self.privacy_budgets
                .values()
                .map(PrivacyBudgetAccount::public_record),
        );
        let compression_market_root = map_root(
            "BATCH-CALL-COMPRESSION-MARKETS",
            self.compression_markets
                .values()
                .map(CompressionMarket::public_record),
        );
        let solver_bid_root = map_root(
            "BATCH-CALL-SOLVER-BIDS",
            self.solver_bids.values().map(SolverBid::public_record),
        );
        let slashing_evidence_root = map_root(
            "BATCH-CALL-SLASHING-EVIDENCE",
            self.slashing_evidence
                .values()
                .map(SlashingEvidence::public_record),
        );
        let nullifier_root =
            root_from_string_set("BATCH-CALL-SPENT-NULLIFIERS", &self.spent_nullifiers);
        let event_root = map_root(
            "BATCH-CALL-EVENTS",
            self.events.values().map(RuntimeEvent::public_record),
        );
        let public_record = self.public_record_without_roots();
        let public_record_root = root_json("BATCH-CALL-PUBLIC-RECORD", &public_record);
        let state_root = domain_hash(
            "BATCH-CALL-STATE-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(self.height),
                HashPart::Str(&config_root),
                HashPart::Str(&counters_root),
                HashPart::Str(&lane_root),
                HashPart::Str(&compressor_root),
                HashPart::Str(&dictionary_root),
                HashPart::Str(&abi_fingerprint_root),
                HashPart::Str(&encrypted_bundle_root),
                HashPart::Str(&compressed_bundle_root),
                HashPart::Str(&witness_delta_root),
                HashPart::Str(&da_voucher_root),
                HashPart::Str(&rebate_claim_root),
                HashPart::Str(&privacy_budget_root),
                HashPart::Str(&compression_market_root),
                HashPart::Str(&solver_bid_root),
                HashPart::Str(&slashing_evidence_root),
                HashPart::Str(&nullifier_root),
                HashPart::Str(&event_root),
                HashPart::Str(&public_record_root),
            ],
            32,
        );
        Roots {
            config_root,
            counters_root,
            lane_root,
            compressor_root,
            dictionary_root,
            abi_fingerprint_root,
            encrypted_bundle_root,
            compressed_bundle_root,
            witness_delta_root,
            da_voucher_root,
            rebate_claim_root,
            privacy_budget_root,
            compression_market_root,
            solver_bid_root,
            slashing_evidence_root,
            nullifier_root,
            event_root,
            public_record_root,
            state_root,
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let mut record = self.public_record_without_roots();
        if let Value::Object(ref mut object) = record {
            object.insert("roots".to_string(), roots.public_record());
        }
        record
    }

    fn public_record_without_roots(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "lanes": records(self.lanes.values().map(CompressionLane::public_record)),
            "compressors": records(self.compressors.values().map(Compressor::public_record)),
            "dictionaries": records(self.dictionaries.values().map(CalldataDictionary::public_record)),
            "abi_fingerprints": records(self.abi_fingerprints.values().map(AbiFingerprint::public_record)),
            "encrypted_bundles": records(self.encrypted_bundles.values().map(EncryptedCallBundle::public_record)),
            "compressed_bundles": records(self.compressed_bundles.values().map(CompressedBundle::public_record)),
            "witness_deltas": records(self.witness_deltas.values().map(WitnessDelta::public_record)),
            "da_vouchers": records(self.da_vouchers.values().map(DaVoucher::public_record)),
            "rebate_claims": records(self.rebate_claims.values().map(RebateClaim::public_record)),
            "privacy_budgets": records(self.privacy_budgets.values().map(PrivacyBudgetAccount::public_record)),
            "compression_markets": records(self.compression_markets.values().map(CompressionMarket::public_record)),
            "solver_bids": records(self.solver_bids.values().map(SolverBid::public_record)),
            "slashing_evidence": records(self.slashing_evidence.values().map(SlashingEvidence::public_record)),
            "spent_nullifiers": self.spent_nullifiers,
            "events": records(self.events.values().map(RuntimeEvent::public_record)),
        })
    }

    fn lane(&self, lane_id: &str) -> Result<&CompressionLane> {
        self.lanes
            .get(lane_id)
            .ok_or_else(|| "unknown lane_id".to_string())
    }

    fn compressor(&self, compressor_id: &str) -> Result<&Compressor> {
        self.compressors
            .get(compressor_id)
            .ok_or_else(|| "unknown compressor_id".to_string())
    }

    fn bundle(&self, bundle_id: &str) -> Result<&EncryptedCallBundle> {
        self.encrypted_bundles
            .get(bundle_id)
            .ok_or_else(|| "unknown bundle_id".to_string())
    }

    fn compressed_bundle(&self, compressed_bundle_id: &str) -> Result<&CompressedBundle> {
        self.compressed_bundles
            .get(compressed_bundle_id)
            .ok_or_else(|| "unknown compressed_bundle_id".to_string())
    }

    fn record_event(&mut self, kind: &str, object_id: &str, payload: &Value) -> Result<()> {
        if self.events.len() >= self.config.max_events {
            return Err("event capacity exceeded".to_string());
        }
        let sequence = self.counters.next_event_sequence;
        self.counters.next_event_sequence = self.counters.next_event_sequence.saturating_add(1);
        let payload_root = root_json("BATCH-CALL-EVENT-PAYLOAD", payload);
        let event_id = event_id(sequence, kind, object_id, &payload_root);
        let event = RuntimeEvent {
            event_id: event_id.clone(),
            kind: kind.to_string(),
            object_id: object_id.to_string(),
            height: self.height,
            payload_root,
        };
        self.events.insert(event_id, event);
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitBundleRequest {
    pub lane_id: String,
    pub submitter_commitment: String,
    pub ciphertext_root: String,
    pub call_commitment_root: String,
    pub contract_root: String,
    pub abi_fingerprint_root: String,
    pub nullifiers: BTreeSet<String>,
    pub call_count: usize,
    pub uncompressed_bytes: u64,
    pub max_fee_piconero: u64,
    pub privacy_set_size: u64,
    pub pq_ciphertext_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompressBundleRequest {
    pub bundle_id: String,
    pub compressor_id: String,
    pub dictionary_ids: BTreeSet<String>,
    pub witness_delta_ids: BTreeSet<String>,
    pub mode: CompressionMode,
    pub compressed_call_root: String,
    pub compressed_witness_root: String,
    pub da_payload_root: String,
    pub route_plan_root: String,
    pub compressed_bytes: u64,
    pub estimated_da_fee_piconero: u64,
    pub user_fee_piconero: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AllocateVoucherRequest {
    pub sponsor_commitment: String,
    pub bundle_id: String,
    pub compressed_bundle_id: String,
    pub covered_bytes: u64,
    pub face_value_piconero: u64,
    pub da_provider_commitment: String,
    pub availability_root: String,
    pub nullifier: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateClaimInput {
    pub bundle_id: String,
    pub compressed_bundle_id: String,
    pub voucher_id: String,
    pub claimant_commitment: String,
    pub gross_fee_piconero: u64,
    pub compressed_fee_piconero: u64,
    pub proof_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PostSolverBidRequest {
    pub market_id: String,
    pub compressor_id: String,
    pub bundle_id: String,
    pub solver_commitment: String,
    pub mode: CompressionMode,
    pub quoted_fee_piconero: u64,
    pub promised_savings_bps: u64,
    pub latency_ms: u64,
    pub route_plan_root: String,
    pub privacy_cost_units: u64,
    pub da_bytes: u64,
}

impl AsRef<str> for SlashingKind {
    fn as_ref(&self) -> &str {
        match self {
            Self::InvalidDictionaryRoot => "invalid_dictionary_root",
            Self::InvalidWitnessDelta => "invalid_witness_delta",
            Self::CalldataDecompressionMismatch => "calldata_decompression_mismatch",
            Self::DaVoucherDoubleSpend => "da_voucher_double_spend",
            Self::RebateOverclaim => "rebate_overclaim",
            Self::PrivacyBudgetOverspend => "privacy_budget_overspend",
            Self::WithheldBundle => "withheld_bundle",
            Self::InvalidAbiFingerprint => "invalid_abi_fingerprint",
            Self::SolverRouteMisquote => "solver_route_misquote",
        }
    }
}

pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}

pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}

pub fn state_root_from_public_record(record: &Value) -> String {
    domain_hash(
        "BATCH-CALL-STATE-ROOT-FROM-PUBLIC-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn lane_id(sequence: u64, kind: LaneKind, fee_asset_id: &str) -> String {
    domain_hash(
        "BATCH-CALL-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(sequence),
            HashPart::Str(kind.as_str()),
            HashPart::Str(fee_asset_id),
        ],
        20,
    )
}

pub fn compressor_id(
    sequence: u64,
    operator_commitment: &str,
    pq_attestation_root: &str,
) -> String {
    domain_hash(
        "BATCH-CALL-COMPRESSOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(sequence),
            HashPart::Str(operator_commitment),
            HashPart::Str(pq_attestation_root),
        ],
        20,
    )
}

pub fn dictionary_id(
    sequence: u64,
    owner_commitment: &str,
    abi_fingerprint_id: &str,
    entry_root: &str,
) -> String {
    domain_hash(
        "BATCH-CALL-DICTIONARY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(sequence),
            HashPart::Str(owner_commitment),
            HashPart::Str(abi_fingerprint_id),
            HashPart::Str(entry_root),
        ],
        20,
    )
}

pub fn abi_fingerprint_id(
    sequence: u64,
    contract_commitment: &str,
    selector_root: &str,
    version_tag: &str,
) -> String {
    domain_hash(
        "BATCH-CALL-ABI-FINGERPRINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(sequence),
            HashPart::Str(contract_commitment),
            HashPart::Str(selector_root),
            HashPart::Str(version_tag),
        ],
        20,
    )
}

pub fn bundle_id(sequence: u64, lane_id: &str, ciphertext_root: &str) -> String {
    domain_hash(
        "BATCH-CALL-BUNDLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(sequence),
            HashPart::Str(lane_id),
            HashPart::Str(ciphertext_root),
        ],
        20,
    )
}

pub fn witness_delta_id(
    sequence: u64,
    bundle_id: &str,
    compressor_id: &str,
    delta_root: &str,
) -> String {
    domain_hash(
        "BATCH-CALL-WITNESS-DELTA-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(sequence),
            HashPart::Str(bundle_id),
            HashPart::Str(compressor_id),
            HashPart::Str(delta_root),
        ],
        20,
    )
}

pub fn compressed_bundle_id(sequence: u64, bundle_id: &str, compressed_call_root: &str) -> String {
    domain_hash(
        "BATCH-CALL-COMPRESSED-BUNDLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(sequence),
            HashPart::Str(bundle_id),
            HashPart::Str(compressed_call_root),
        ],
        20,
    )
}

pub fn da_voucher_id(sequence: u64, bundle_id: &str, nullifier: &str) -> String {
    domain_hash(
        "BATCH-CALL-DA-VOUCHER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(sequence),
            HashPart::Str(bundle_id),
            HashPart::Str(nullifier),
        ],
        20,
    )
}

pub fn rebate_id(sequence: u64, bundle_id: &str, proof_root: &str) -> String {
    domain_hash(
        "BATCH-CALL-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(sequence),
            HashPart::Str(bundle_id),
            HashPart::Str(proof_root),
        ],
        20,
    )
}

pub fn privacy_budget_id(sequence: u64, account_commitment: &str, lane_id: &str) -> String {
    domain_hash(
        "BATCH-CALL-PRIVACY-BUDGET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(sequence),
            HashPart::Str(account_commitment),
            HashPart::Str(lane_id),
        ],
        20,
    )
}

pub fn market_id(sequence: u64, lane_id: &str, mode: CompressionMode) -> String {
    domain_hash(
        "BATCH-CALL-COMPRESSION-MARKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(sequence),
            HashPart::Str(lane_id),
            HashPart::Str(mode.as_str()),
        ],
        20,
    )
}

pub fn solver_bid_id(
    sequence: u64,
    market_id: &str,
    compressor_id: &str,
    bundle_id: &str,
) -> String {
    domain_hash(
        "BATCH-CALL-SOLVER-BID-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(sequence),
            HashPart::Str(market_id),
            HashPart::Str(compressor_id),
            HashPart::Str(bundle_id),
        ],
        20,
    )
}

pub fn slashing_evidence_id(
    sequence: u64,
    accused_commitment: &str,
    evidence_root: &str,
) -> String {
    domain_hash(
        "BATCH-CALL-SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(sequence),
            HashPart::Str(accused_commitment),
            HashPart::Str(evidence_root),
        ],
        20,
    )
}

pub fn event_id(sequence: u64, kind: &str, object_id: &str, payload_root: &str) -> String {
    domain_hash(
        "BATCH-CALL-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(sequence),
            HashPart::Str(kind),
            HashPart::Str(object_id),
            HashPart::Str(payload_root),
        ],
        20,
    )
}

pub fn root_from_parts(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

pub fn root_json(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

pub fn root_from_values(domain: &str, values: &[&str]) -> String {
    let leaves = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn root_from_string_set(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn map_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let leaves = records.into_iter().collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn records<I>(records: I) -> Vec<Value>
where
    I: IntoIterator<Item = Value>,
{
    records.into_iter().collect()
}

pub fn savings_bps(uncompressed_bytes: u64, compressed_bytes: u64) -> u64 {
    if uncompressed_bytes == 0 || compressed_bytes >= uncompressed_bytes {
        return 0;
    }
    uncompressed_bytes
        .saturating_sub(compressed_bytes)
        .saturating_mul(MAX_BPS)
        / uncompressed_bytes
}

pub fn mul_bps(value: u64, bps: u64) -> u64 {
    value.saturating_mul(bps.min(MAX_BPS)) / MAX_BPS
}

pub fn deterministic_error_id(domain: &str, message: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(message),
        ],
        20,
    )
}

fn ensure_bps(value: u64, label: &str) -> Result<()> {
    if value > MAX_BPS {
        return Err(format!("{label} exceeds MAX_BPS"));
    }
    Ok(())
}

fn ensure_non_empty(value: &str, label: &str) -> Result<()> {
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(())
}
