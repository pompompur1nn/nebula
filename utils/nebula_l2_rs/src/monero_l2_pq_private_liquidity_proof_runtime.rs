use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2PqPrivateLiquidityProofRuntimeResult<T> = Result<T, String>;

pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-liquidity-proof-runtime-v1";
pub const PROTOCOL_VERSION: &str = MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_PROTOCOL_VERSION;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEVNET_HEIGHT: u64 = 544_000;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEVNET_MONERO_NETWORK: &str =
    "monero-devnet";
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEVNET_FEE_ASSET_ID: &str =
    "piconero-devnet";
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEVNET_WATCHER_SET_ID: &str =
    "monero-l2-pq-private-liquidity-proof-devnet-watchers";
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_WINDOW_SCHEME: &str =
    "roots-only-private-liquidity-proof-window-v1";
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_SAMPLE_SCHEME: &str =
    "ml-kem-1024-sealed-monero-reserve-sample-root-v1";
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_WATCHER_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-192f-private-liquidity-watcher-attestation-v1";
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_RESERVATION_SCHEME: &str =
    "low-fee-private-liquidity-proof-reservation-root-v1";
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_BATCH_SCHEME: &str =
    "fast-private-liquidity-proof-batch-root-v1";
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_RECEIPT_SCHEME: &str =
    "bridge-defi-private-liquidity-proof-receipt-root-v1";
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_REBATE_SCHEME: &str =
    "low-fee-private-liquidity-proof-rebate-root-v1";
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_NULLIFIER_SCHEME: &str =
    "monero-l2-pq-private-liquidity-proof-nullifier-root-v1";
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_REPLAY_DOMAIN: &str =
    "monero-l2-pq-private-liquidity-proof-devnet";
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_MAX_BPS: u64 = 10_000;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_WINDOW_TTL_BLOCKS: u64 = 48;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_SAMPLE_TTL_BLOCKS: u64 = 24;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 18;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 6;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_RECEIPT_FINALITY_BLOCKS: u64 = 4;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_REBATE_TTL_BLOCKS: u64 = 144;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 =
    10_500;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_TARGET_RESERVE_COVERAGE_BPS: u64 =
    12_500;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_MIN_WATCHER_COUNT: u64 = 2;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_MIN_WATCHER_WEIGHT: u64 = 3;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_WATCHER_QUORUM_BPS: u64 = 6_700;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_STRONG_QUORUM_BPS: u64 = 8_000;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_LOW_FEE_BPS: u64 = 4;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 20;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_REBATE_BPS: u64 = 10;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_SPONSOR_COVER_BPS: u64 = 8_500;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_MAX_BATCH_ITEMS: usize = 512;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_MAX_WINDOWS: usize = 262_144;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_MAX_SAMPLES: usize = 524_288;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_MAX_ATTESTATIONS: usize = 1_048_576;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_MAX_RESERVATIONS: usize = 524_288;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_MAX_BATCHES: usize = 262_144;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_MAX_RECEIPTS: usize = 524_288;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_MAX_REBATES: usize = 524_288;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_MAX_PUBLIC_RECORDS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofLane {
    LowFee,
    FastBridge,
    Defi,
    Rebalance,
    ReserveAudit,
    Emergency,
}

impl ProofLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::FastBridge => "fast_bridge",
            Self::Defi => "defi",
            Self::Rebalance => "rebalance",
            Self::ReserveAudit => "reserve_audit",
            Self::Emergency => "emergency",
        }
    }

    pub fn fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::LowFee | Self::ReserveAudit => config.low_fee_bps,
            Self::Defi | Self::Rebalance => config.max_user_fee_bps.saturating_mul(2) / 3,
            Self::FastBridge | Self::Emergency => config.max_user_fee_bps,
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Emergency => 1_000,
            Self::FastBridge => 920,
            Self::LowFee => 860,
            Self::Defi => 760,
            Self::Rebalance => 700,
            Self::ReserveAudit => 640,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofDirection {
    PrivateEntry,
    PrivateExit,
    DefiMint,
    DefiRedeem,
    RebalanceIn,
    RebalanceOut,
}

impl ProofDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateEntry => "private_entry",
            Self::PrivateExit => "private_exit",
            Self::DefiMint => "defi_mint",
            Self::DefiRedeem => "defi_redeem",
            Self::RebalanceIn => "rebalance_in",
            Self::RebalanceOut => "rebalance_out",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowStatus {
    Open,
    Sampling,
    Attesting,
    QuorumAttested,
    Batched,
    Settled,
    Disputed,
    Expired,
}

impl WindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sampling => "sampling",
            Self::Attesting => "attesting",
            Self::QuorumAttested => "quorum_attested",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Sampling | Self::Attesting | Self::QuorumAttested
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SampleStatus {
    Submitted,
    Accepted,
    Attested,
    Batched,
    Rejected,
    Expired,
}

impl SampleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Attested => "attested",
            Self::Batched => "batched",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    WeakQuorum,
    StrongQuorum,
    Superseded,
    Rejected,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::WeakQuorum => "weak_quorum",
            Self::StrongQuorum => "strong_quorum",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Matched,
    Batched,
    ReceiptIssued,
    Released,
    Expired,
    Cancelled,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Matched => "matched",
            Self::Batched => "batched",
            Self::ReceiptIssued => "receipt_issued",
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Reserved | Self::Matched | Self::Batched)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Sealed,
    ReceiptReady,
    Settled,
    Disputed,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::ReceiptReady => "receipt_ready",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Published,
    Finalized,
    Rebalanced,
    Failed,
    Disputed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Rebalanced => "rebalanced",
            Self::Failed => "failed",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accrued,
    Claimable,
    Claimed,
    Expired,
    Cancelled,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accrued => "accrued",
            Self::Claimable => "claimable",
            Self::Claimed => "claimed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub monero_network: String,
    pub l2_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub watcher_set_id: String,
    pub hash_suite: String,
    pub window_scheme: String,
    pub sample_scheme: String,
    pub watcher_attestation_scheme: String,
    pub reservation_scheme: String,
    pub batch_scheme: String,
    pub receipt_scheme: String,
    pub rebate_scheme: String,
    pub nullifier_scheme: String,
    pub replay_domain: String,
    pub genesis_height: u64,
    pub window_ttl_blocks: u64,
    pub sample_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub batch_window_blocks: u64,
    pub receipt_finality_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_reserve_coverage_bps: u64,
    pub target_reserve_coverage_bps: u64,
    pub min_watcher_count: u64,
    pub min_watcher_weight: u64,
    pub watcher_quorum_bps: u64,
    pub strong_quorum_bps: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub low_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub max_batch_items: usize,
    pub max_windows: usize,
    pub max_samples: usize,
    pub max_attestations: usize,
    pub max_reservations: usize,
    pub max_batches: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub max_public_records: usize,
    pub roots_only: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_SCHEMA_VERSION,
            monero_network: MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEVNET_MONERO_NETWORK
                .to_string(),
            l2_network: MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEVNET_L2_NETWORK.to_string(),
            asset_id: MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEVNET_FEE_ASSET_ID
                .to_string(),
            watcher_set_id: MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEVNET_WATCHER_SET_ID
                .to_string(),
            hash_suite: MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_HASH_SUITE.to_string(),
            window_scheme: MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_WINDOW_SCHEME.to_string(),
            sample_scheme: MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_SAMPLE_SCHEME.to_string(),
            watcher_attestation_scheme:
                MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_WATCHER_ATTESTATION_SCHEME.to_string(),
            reservation_scheme: MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_RESERVATION_SCHEME
                .to_string(),
            batch_scheme: MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_BATCH_SCHEME.to_string(),
            receipt_scheme: MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_RECEIPT_SCHEME.to_string(),
            rebate_scheme: MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_REBATE_SCHEME.to_string(),
            nullifier_scheme: MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_NULLIFIER_SCHEME
                .to_string(),
            replay_domain: MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_REPLAY_DOMAIN.to_string(),
            genesis_height: MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEVNET_HEIGHT,
            window_ttl_blocks:
                MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_WINDOW_TTL_BLOCKS,
            sample_ttl_blocks:
                MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_SAMPLE_TTL_BLOCKS,
            reservation_ttl_blocks:
                MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
            batch_window_blocks:
                MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_BATCH_WINDOW_BLOCKS,
            receipt_finality_blocks:
                MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_RECEIPT_FINALITY_BLOCKS,
            rebate_ttl_blocks:
                MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_REBATE_TTL_BLOCKS,
            min_privacy_set_size:
                MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_reserve_coverage_bps:
                MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            target_reserve_coverage_bps:
                MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_TARGET_RESERVE_COVERAGE_BPS,
            min_watcher_count:
                MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_MIN_WATCHER_COUNT,
            min_watcher_weight:
                MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_MIN_WATCHER_WEIGHT,
            watcher_quorum_bps:
                MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_WATCHER_QUORUM_BPS,
            strong_quorum_bps:
                MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_STRONG_QUORUM_BPS,
            min_pq_security_bits:
                MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits:
                MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_TARGET_PQ_SECURITY_BITS,
            low_fee_bps: MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_LOW_FEE_BPS,
            max_user_fee_bps: MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            rebate_bps: MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_REBATE_BPS,
            sponsor_cover_bps:
                MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_SPONSOR_COVER_BPS,
            max_batch_items: MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEFAULT_MAX_BATCH_ITEMS,
            max_windows: MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_MAX_WINDOWS,
            max_samples: MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_MAX_SAMPLES,
            max_attestations: MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_MAX_ATTESTATIONS,
            max_reservations: MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_MAX_RESERVATIONS,
            max_batches: MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_MAX_BATCHES,
            max_receipts: MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_MAX_RECEIPTS,
            max_rebates: MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_MAX_REBATES,
            max_public_records: MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_MAX_PUBLIC_RECORDS,
            roots_only: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "MONERO-L2-PQ-PRIVATE-LIQUIDITY-PROOF-CONFIG",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub window_counter: u64,
    pub sample_counter: u64,
    pub attestation_counter: u64,
    pub reservation_counter: u64,
    pub batch_counter: u64,
    pub receipt_counter: u64,
    pub rebate_counter: u64,
    pub proof_windows: u64,
    pub encrypted_samples: u64,
    pub watcher_attestations: u64,
    pub low_fee_reservations: u64,
    pub liquidity_batches: u64,
    pub bridge_receipts: u64,
    pub rebates: u64,
    pub nullifiers: u64,
    pub public_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub proof_window_root: String,
    pub encrypted_sample_root: String,
    pub watcher_attestation_root: String,
    pub low_fee_reservation_root: String,
    pub liquidity_batch_root: String,
    pub bridge_receipt_root: String,
    pub rebate_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateLiquidityProofWindowRequest {
    pub operator_id: String,
    pub lane: ProofLane,
    pub direction: ProofDirection,
    pub window_nonce: String,
    pub monero_start_height: u64,
    pub monero_end_height: u64,
    pub l2_start_height: u64,
    pub l2_end_height: u64,
    pub reserve_commitment_root: String,
    pub liability_commitment_root: String,
    pub privacy_set_root: String,
    pub min_liquidity_piconero: u64,
    pub target_liquidity_piconero: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl PrivateLiquidityProofWindowRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateLiquidityProofWindow {
    pub window_id: String,
    pub sequence: u64,
    pub operator_id: String,
    pub lane: ProofLane,
    pub direction: ProofDirection,
    pub window_nonce: String,
    pub monero_start_height: u64,
    pub monero_end_height: u64,
    pub l2_start_height: u64,
    pub l2_end_height: u64,
    pub reserve_commitment_root: String,
    pub liability_commitment_root: String,
    pub privacy_set_root: String,
    pub min_liquidity_piconero: u64,
    pub target_liquidity_piconero: u64,
    pub fee_bps: u64,
    pub priority_weight: u64,
    pub privacy_set_size: u64,
    pub reserve_coverage_bps: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: WindowStatus,
    pub window_root: String,
}

impl PrivateLiquidityProofWindow {
    pub fn new(
        request: &PrivateLiquidityProofWindowRequest,
        config: &Config,
        sequence: u64,
        height: u64,
    ) -> Self {
        let seed = json!({
            "operator_id": request.operator_id,
            "lane": request.lane.as_str(),
            "direction": request.direction.as_str(),
            "sequence": sequence,
            "window_nonce": request.window_nonce,
            "monero_start_height": request.monero_start_height,
            "monero_end_height": request.monero_end_height,
            "reserve_commitment_root": request.reserve_commitment_root,
            "liability_commitment_root": request.liability_commitment_root,
        });
        let window_id = id_from_record("WINDOW-ID", &seed);
        let reserve_coverage_bps = coverage_bps(
            request.target_liquidity_piconero,
            request.min_liquidity_piconero,
            config.target_reserve_coverage_bps,
        );
        let window_root = payload_root(
            "WINDOW-ROOT",
            &json!({
                "window_id": window_id,
                "reserve_commitment_root": request.reserve_commitment_root,
                "liability_commitment_root": request.liability_commitment_root,
                "privacy_set_root": request.privacy_set_root,
                "privacy_set_size": request.privacy_set_size,
                "pq_security_bits": request.pq_security_bits,
            }),
        );
        Self {
            window_id,
            sequence,
            operator_id: request.operator_id.clone(),
            lane: request.lane,
            direction: request.direction,
            window_nonce: request.window_nonce.clone(),
            monero_start_height: request.monero_start_height,
            monero_end_height: request.monero_end_height,
            l2_start_height: request.l2_start_height,
            l2_end_height: request.l2_end_height,
            reserve_commitment_root: request.reserve_commitment_root.clone(),
            liability_commitment_root: request.liability_commitment_root.clone(),
            privacy_set_root: request.privacy_set_root.clone(),
            min_liquidity_piconero: request.min_liquidity_piconero,
            target_liquidity_piconero: request.target_liquidity_piconero,
            fee_bps: request.lane.fee_bps(config),
            priority_weight: request.lane.priority_weight(),
            privacy_set_size: request.privacy_set_size,
            reserve_coverage_bps,
            pq_security_bits: request.pq_security_bits,
            opened_at_height: height,
            expires_at_height: height.saturating_add(config.window_ttl_blocks),
            status: WindowStatus::Open,
            window_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "sequence": self.sequence,
            "operator_id": self.operator_id,
            "lane": self.lane.as_str(),
            "direction": self.direction.as_str(),
            "monero_start_height": self.monero_start_height,
            "monero_end_height": self.monero_end_height,
            "l2_start_height": self.l2_start_height,
            "l2_end_height": self.l2_end_height,
            "reserve_commitment_root": self.reserve_commitment_root,
            "liability_commitment_root": self.liability_commitment_root,
            "privacy_set_root": self.privacy_set_root,
            "min_liquidity_piconero": self.min_liquidity_piconero,
            "target_liquidity_piconero": self.target_liquidity_piconero,
            "fee_bps": self.fee_bps,
            "priority_weight": self.priority_weight,
            "privacy_set_size": self.privacy_set_size,
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "pq_security_bits": self.pq_security_bits,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "window_root": self.window_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedReserveSampleRequest {
    pub window_id: String,
    pub reporter_id: String,
    pub sample_nonce: String,
    pub encrypted_sample_root: String,
    pub reserve_bucket_root: String,
    pub liability_bucket_root: String,
    pub amount_commitment_root: String,
    pub decoy_set_root: String,
    pub range_proof_root: String,
    pub nullifier: String,
    pub sample_count: u64,
    pub revealed_bucket_count: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl EncryptedReserveSampleRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedReserveSample {
    pub sample_id: String,
    pub sequence: u64,
    pub window_id: String,
    pub reporter_id: String,
    pub sample_nonce: String,
    pub encrypted_sample_root: String,
    pub reserve_bucket_root: String,
    pub liability_bucket_root: String,
    pub amount_commitment_root: String,
    pub decoy_set_root: String,
    pub range_proof_root: String,
    pub nullifier: String,
    pub sample_count: u64,
    pub revealed_bucket_count: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub status: SampleStatus,
    pub sample_root: String,
}

impl EncryptedReserveSample {
    pub fn new(
        request: &EncryptedReserveSampleRequest,
        sequence: u64,
        height: u64,
        config: &Config,
    ) -> Self {
        let sample_id = id_from_record(
            "SAMPLE-ID",
            &json!({
                "sequence": sequence,
                "window_id": request.window_id,
                "reporter_id": request.reporter_id,
                "encrypted_sample_root": request.encrypted_sample_root,
                "nullifier": request.nullifier,
            }),
        );
        let sample_root = payload_root(
            "ENCRYPTED-RESERVE-SAMPLE",
            &json!({
                "sample_id": sample_id,
                "encrypted_sample_root": request.encrypted_sample_root,
                "reserve_bucket_root": request.reserve_bucket_root,
                "liability_bucket_root": request.liability_bucket_root,
                "amount_commitment_root": request.amount_commitment_root,
                "decoy_set_root": request.decoy_set_root,
                "range_proof_root": request.range_proof_root,
            }),
        );
        Self {
            sample_id,
            sequence,
            window_id: request.window_id.clone(),
            reporter_id: request.reporter_id.clone(),
            sample_nonce: request.sample_nonce.clone(),
            encrypted_sample_root: request.encrypted_sample_root.clone(),
            reserve_bucket_root: request.reserve_bucket_root.clone(),
            liability_bucket_root: request.liability_bucket_root.clone(),
            amount_commitment_root: request.amount_commitment_root.clone(),
            decoy_set_root: request.decoy_set_root.clone(),
            range_proof_root: request.range_proof_root.clone(),
            nullifier: request.nullifier.clone(),
            sample_count: request.sample_count,
            revealed_bucket_count: request.revealed_bucket_count,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            submitted_at_height: height,
            expires_at_height: height.saturating_add(config.sample_ttl_blocks),
            status: SampleStatus::Submitted,
            sample_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sample_id": self.sample_id,
            "sequence": self.sequence,
            "window_id": self.window_id,
            "reporter_id": self.reporter_id,
            "encrypted_sample_root": self.encrypted_sample_root,
            "reserve_bucket_root": self.reserve_bucket_root,
            "liability_bucket_root": self.liability_bucket_root,
            "amount_commitment_root": self.amount_commitment_root,
            "decoy_set_root": self.decoy_set_root,
            "range_proof_root": self.range_proof_root,
            "sample_count": self.sample_count,
            "revealed_bucket_count": self.revealed_bucket_count,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "sample_root": self.sample_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqWatcherAttestationRequest {
    pub window_id: String,
    pub sample_id: String,
    pub watcher_id: String,
    pub watcher_set_root: String,
    pub aggregate_pq_signature_root: String,
    pub reserve_sample_root: String,
    pub liquidity_claim_root: String,
    pub coverage_bps: u64,
    pub watcher_weight: u64,
    pub watcher_count: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl PqWatcherAttestationRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqWatcherAttestation {
    pub attestation_id: String,
    pub sequence: u64,
    pub window_id: String,
    pub sample_id: String,
    pub watcher_id: String,
    pub watcher_set_root: String,
    pub aggregate_pq_signature_root: String,
    pub reserve_sample_root: String,
    pub liquidity_claim_root: String,
    pub coverage_bps: u64,
    pub watcher_weight: u64,
    pub watcher_count: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub attested_at_height: u64,
    pub status: AttestationStatus,
    pub attestation_root: String,
}

impl PqWatcherAttestation {
    pub fn new(
        request: &PqWatcherAttestationRequest,
        sequence: u64,
        height: u64,
        config: &Config,
    ) -> Self {
        let status = if request.coverage_bps >= config.target_reserve_coverage_bps
            && quorum_bps(request.watcher_weight, request.watcher_count) >= config.strong_quorum_bps
        {
            AttestationStatus::StrongQuorum
        } else if request.coverage_bps >= config.min_reserve_coverage_bps
            && quorum_bps(request.watcher_weight, request.watcher_count)
                >= config.watcher_quorum_bps
        {
            AttestationStatus::WeakQuorum
        } else {
            AttestationStatus::Accepted
        };
        let attestation_id = id_from_record(
            "WATCHER-ATTESTATION-ID",
            &json!({
                "sequence": sequence,
                "window_id": request.window_id,
                "sample_id": request.sample_id,
                "watcher_id": request.watcher_id,
                "aggregate_pq_signature_root": request.aggregate_pq_signature_root,
            }),
        );
        let attestation_root = payload_root(
            "WATCHER-ATTESTATION",
            &json!({
                "attestation_id": attestation_id,
                "watcher_set_root": request.watcher_set_root,
                "aggregate_pq_signature_root": request.aggregate_pq_signature_root,
                "reserve_sample_root": request.reserve_sample_root,
                "liquidity_claim_root": request.liquidity_claim_root,
                "coverage_bps": request.coverage_bps,
                "watcher_weight": request.watcher_weight,
                "watcher_count": request.watcher_count,
            }),
        );
        Self {
            attestation_id,
            sequence,
            window_id: request.window_id.clone(),
            sample_id: request.sample_id.clone(),
            watcher_id: request.watcher_id.clone(),
            watcher_set_root: request.watcher_set_root.clone(),
            aggregate_pq_signature_root: request.aggregate_pq_signature_root.clone(),
            reserve_sample_root: request.reserve_sample_root.clone(),
            liquidity_claim_root: request.liquidity_claim_root.clone(),
            coverage_bps: request.coverage_bps,
            watcher_weight: request.watcher_weight,
            watcher_count: request.watcher_count,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            attested_at_height: height,
            status,
            attestation_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "sequence": self.sequence,
            "window_id": self.window_id,
            "sample_id": self.sample_id,
            "watcher_id": self.watcher_id,
            "watcher_set_root": self.watcher_set_root,
            "aggregate_pq_signature_root": self.aggregate_pq_signature_root,
            "reserve_sample_root": self.reserve_sample_root,
            "liquidity_claim_root": self.liquidity_claim_root,
            "coverage_bps": self.coverage_bps,
            "watcher_weight": self.watcher_weight,
            "watcher_count": self.watcher_count,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "attested_at_height": self.attested_at_height,
            "status": self.status.as_str(),
            "attestation_root": self.attestation_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeProofReservationRequest {
    pub window_id: String,
    pub reserver_id: String,
    pub lane: ProofLane,
    pub direction: ProofDirection,
    pub amount_piconero: u64,
    pub max_fee_bps: u64,
    pub sponsor_commitment_root: String,
    pub private_route_commitment: String,
    pub defi_call_commitment: Option<String>,
    pub reservation_nonce: String,
    pub nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl LowFeeProofReservationRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeProofReservation {
    pub reservation_id: String,
    pub sequence: u64,
    pub window_id: String,
    pub reserver_id: String,
    pub lane: ProofLane,
    pub direction: ProofDirection,
    pub amount_piconero: u64,
    pub fee_bps: u64,
    pub fee_piconero: u64,
    pub rebate_bps: u64,
    pub rebate_piconero: u64,
    pub sponsor_cover_bps: u64,
    pub sponsor_commitment_root: String,
    pub private_route_commitment: String,
    pub defi_call_commitment: Option<String>,
    pub reservation_nonce: String,
    pub nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
    pub status: ReservationStatus,
    pub reservation_root: String,
}

impl LowFeeProofReservation {
    pub fn new(
        request: &LowFeeProofReservationRequest,
        config: &Config,
        sequence: u64,
        height: u64,
    ) -> Self {
        let fee_bps = request.lane.fee_bps(config).min(request.max_fee_bps);
        let fee_piconero = bps_amount(request.amount_piconero, fee_bps);
        let rebate_piconero = bps_amount(request.amount_piconero, config.rebate_bps);
        let reservation_id = id_from_record(
            "LOW-FEE-RESERVATION-ID",
            &json!({
                "sequence": sequence,
                "window_id": request.window_id,
                "reserver_id": request.reserver_id,
                "amount_piconero": request.amount_piconero,
                "reservation_nonce": request.reservation_nonce,
                "nullifier": request.nullifier,
            }),
        );
        let reservation_root = payload_root(
            "LOW-FEE-RESERVATION",
            &json!({
                "reservation_id": reservation_id,
                "window_id": request.window_id,
                "amount_piconero": request.amount_piconero,
                "fee_bps": fee_bps,
                "rebate_bps": config.rebate_bps,
                "sponsor_commitment_root": request.sponsor_commitment_root,
                "private_route_commitment": request.private_route_commitment,
                "defi_call_commitment": request.defi_call_commitment,
            }),
        );
        Self {
            reservation_id,
            sequence,
            window_id: request.window_id.clone(),
            reserver_id: request.reserver_id.clone(),
            lane: request.lane,
            direction: request.direction,
            amount_piconero: request.amount_piconero,
            fee_bps,
            fee_piconero,
            rebate_bps: config.rebate_bps,
            rebate_piconero,
            sponsor_cover_bps: config.sponsor_cover_bps,
            sponsor_commitment_root: request.sponsor_commitment_root.clone(),
            private_route_commitment: request.private_route_commitment.clone(),
            defi_call_commitment: request.defi_call_commitment.clone(),
            reservation_nonce: request.reservation_nonce.clone(),
            nullifier: request.nullifier.clone(),
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            reserved_at_height: height,
            expires_at_height: height.saturating_add(config.reservation_ttl_blocks),
            status: ReservationStatus::Reserved,
            reservation_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "sequence": self.sequence,
            "window_id": self.window_id,
            "reserver_id": self.reserver_id,
            "lane": self.lane.as_str(),
            "direction": self.direction.as_str(),
            "amount_piconero": self.amount_piconero,
            "fee_bps": self.fee_bps,
            "fee_piconero": self.fee_piconero,
            "rebate_bps": self.rebate_bps,
            "rebate_piconero": self.rebate_piconero,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "sponsor_commitment_root": self.sponsor_commitment_root,
            "private_route_commitment": self.private_route_commitment,
            "defi_call_commitment": self.defi_call_commitment,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "reservation_root": self.reservation_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityProofBatchRequest {
    pub batcher_id: String,
    pub lane: ProofLane,
    pub window_ids: Vec<String>,
    pub sample_ids: Vec<String>,
    pub attestation_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub batch_nonce: String,
    pub aggregate_proof_root: String,
    pub aggregate_signature_root: String,
    pub settlement_manifest_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl LiquidityProofBatchRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityProofBatch {
    pub batch_id: String,
    pub sequence: u64,
    pub batcher_id: String,
    pub lane: ProofLane,
    pub window_ids: Vec<String>,
    pub sample_ids: Vec<String>,
    pub attestation_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub batch_nonce: String,
    pub aggregate_proof_root: String,
    pub aggregate_signature_root: String,
    pub settlement_manifest_root: String,
    pub item_count: usize,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
    pub status: BatchStatus,
    pub batch_root: String,
}

impl LiquidityProofBatch {
    pub fn new(
        request: &LiquidityProofBatchRequest,
        config: &Config,
        sequence: u64,
        height: u64,
    ) -> Self {
        let item_count = request.window_ids.len()
            + request.sample_ids.len()
            + request.attestation_ids.len()
            + request.reservation_ids.len();
        let batch_id = id_from_record(
            "LIQUIDITY-PROOF-BATCH-ID",
            &json!({
                "sequence": sequence,
                "batcher_id": request.batcher_id,
                "lane": request.lane.as_str(),
                "batch_nonce": request.batch_nonce,
                "aggregate_proof_root": request.aggregate_proof_root,
            }),
        );
        let batch_root = payload_root(
            "LIQUIDITY-PROOF-BATCH",
            &json!({
                "batch_id": batch_id,
                "window_ids_root": id_list_root("WINDOWS", &request.window_ids),
                "sample_ids_root": id_list_root("SAMPLES", &request.sample_ids),
                "attestation_ids_root": id_list_root("ATTESTATIONS", &request.attestation_ids),
                "reservation_ids_root": id_list_root("RESERVATIONS", &request.reservation_ids),
                "aggregate_proof_root": request.aggregate_proof_root,
                "aggregate_signature_root": request.aggregate_signature_root,
                "settlement_manifest_root": request.settlement_manifest_root,
            }),
        );
        Self {
            batch_id,
            sequence,
            batcher_id: request.batcher_id.clone(),
            lane: request.lane,
            window_ids: request.window_ids.clone(),
            sample_ids: request.sample_ids.clone(),
            attestation_ids: request.attestation_ids.clone(),
            reservation_ids: request.reservation_ids.clone(),
            batch_nonce: request.batch_nonce.clone(),
            aggregate_proof_root: request.aggregate_proof_root.clone(),
            aggregate_signature_root: request.aggregate_signature_root.clone(),
            settlement_manifest_root: request.settlement_manifest_root.clone(),
            item_count,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            opened_at_height: height,
            closes_at_height: height.saturating_add(config.batch_window_blocks),
            status: BatchStatus::Open,
            batch_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "sequence": self.sequence,
            "batcher_id": self.batcher_id,
            "lane": self.lane.as_str(),
            "window_ids_root": id_list_root("WINDOWS", &self.window_ids),
            "sample_ids_root": id_list_root("SAMPLES", &self.sample_ids),
            "attestation_ids_root": id_list_root("ATTESTATIONS", &self.attestation_ids),
            "reservation_ids_root": id_list_root("RESERVATIONS", &self.reservation_ids),
            "item_count": self.item_count,
            "aggregate_proof_root": self.aggregate_proof_root,
            "aggregate_signature_root": self.aggregate_signature_root,
            "settlement_manifest_root": self.settlement_manifest_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "opened_at_height": self.opened_at_height,
            "closes_at_height": self.closes_at_height,
            "status": self.status.as_str(),
            "batch_root": self.batch_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeRebalanceReceiptRequest {
    pub batch_id: String,
    pub publisher_id: String,
    pub lane: ProofLane,
    pub receipt_nonce: String,
    pub bridge_manifest_root: String,
    pub rebalance_manifest_root: String,
    pub settlement_tx_root: String,
    pub reserve_delta_root: String,
    pub amount_piconero: u64,
    pub fee_piconero: u64,
    pub rebate_piconero: u64,
    pub finalized_l2_height: u64,
}

impl BridgeRebalanceReceiptRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeRebalanceReceipt {
    pub receipt_id: String,
    pub sequence: u64,
    pub batch_id: String,
    pub publisher_id: String,
    pub lane: ProofLane,
    pub receipt_nonce: String,
    pub bridge_manifest_root: String,
    pub rebalance_manifest_root: String,
    pub settlement_tx_root: String,
    pub reserve_delta_root: String,
    pub amount_piconero: u64,
    pub fee_piconero: u64,
    pub rebate_piconero: u64,
    pub published_at_height: u64,
    pub finalizes_at_height: u64,
    pub finalized_l2_height: u64,
    pub status: ReceiptStatus,
    pub receipt_root: String,
}

impl BridgeRebalanceReceipt {
    pub fn new(
        request: &BridgeRebalanceReceiptRequest,
        config: &Config,
        sequence: u64,
        height: u64,
    ) -> Self {
        let receipt_id = id_from_record(
            "BRIDGE-REBALANCE-RECEIPT-ID",
            &json!({
                "sequence": sequence,
                "batch_id": request.batch_id,
                "publisher_id": request.publisher_id,
                "receipt_nonce": request.receipt_nonce,
                "settlement_tx_root": request.settlement_tx_root,
            }),
        );
        let receipt_root = payload_root(
            "BRIDGE-REBALANCE-RECEIPT",
            &json!({
                "receipt_id": receipt_id,
                "batch_id": request.batch_id,
                "bridge_manifest_root": request.bridge_manifest_root,
                "rebalance_manifest_root": request.rebalance_manifest_root,
                "settlement_tx_root": request.settlement_tx_root,
                "reserve_delta_root": request.reserve_delta_root,
                "amount_piconero": request.amount_piconero,
                "fee_piconero": request.fee_piconero,
                "rebate_piconero": request.rebate_piconero,
            }),
        );
        Self {
            receipt_id,
            sequence,
            batch_id: request.batch_id.clone(),
            publisher_id: request.publisher_id.clone(),
            lane: request.lane,
            receipt_nonce: request.receipt_nonce.clone(),
            bridge_manifest_root: request.bridge_manifest_root.clone(),
            rebalance_manifest_root: request.rebalance_manifest_root.clone(),
            settlement_tx_root: request.settlement_tx_root.clone(),
            reserve_delta_root: request.reserve_delta_root.clone(),
            amount_piconero: request.amount_piconero,
            fee_piconero: request.fee_piconero,
            rebate_piconero: request.rebate_piconero,
            published_at_height: height,
            finalizes_at_height: height.saturating_add(config.receipt_finality_blocks),
            finalized_l2_height: request.finalized_l2_height,
            status: ReceiptStatus::Published,
            receipt_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "sequence": self.sequence,
            "batch_id": self.batch_id,
            "publisher_id": self.publisher_id,
            "lane": self.lane.as_str(),
            "bridge_manifest_root": self.bridge_manifest_root,
            "rebalance_manifest_root": self.rebalance_manifest_root,
            "settlement_tx_root": self.settlement_tx_root,
            "reserve_delta_root": self.reserve_delta_root,
            "amount_piconero": self.amount_piconero,
            "fee_piconero": self.fee_piconero,
            "rebate_piconero": self.rebate_piconero,
            "published_at_height": self.published_at_height,
            "finalizes_at_height": self.finalizes_at_height,
            "finalized_l2_height": self.finalized_l2_height,
            "status": self.status.as_str(),
            "receipt_root": self.receipt_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeRebateRequest {
    pub receipt_id: String,
    pub reservation_id: String,
    pub beneficiary_commitment: String,
    pub sponsor_commitment_root: String,
    pub rebate_note_root: String,
    pub claim_nullifier: String,
    pub amount_piconero: u64,
    pub rebate_nonce: String,
}

impl LowFeeRebateRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub sequence: u64,
    pub receipt_id: String,
    pub reservation_id: String,
    pub beneficiary_commitment: String,
    pub sponsor_commitment_root: String,
    pub rebate_note_root: String,
    pub claim_nullifier: String,
    pub amount_piconero: u64,
    pub rebate_nonce: String,
    pub accrued_at_height: u64,
    pub expires_at_height: u64,
    pub status: RebateStatus,
    pub rebate_root: String,
}

impl LowFeeRebate {
    pub fn new(request: &LowFeeRebateRequest, config: &Config, sequence: u64, height: u64) -> Self {
        let rebate_id = id_from_record(
            "LOW-FEE-REBATE-ID",
            &json!({
                "sequence": sequence,
                "receipt_id": request.receipt_id,
                "reservation_id": request.reservation_id,
                "claim_nullifier": request.claim_nullifier,
                "rebate_nonce": request.rebate_nonce,
            }),
        );
        let rebate_root = payload_root(
            "LOW-FEE-REBATE",
            &json!({
                "rebate_id": rebate_id,
                "receipt_id": request.receipt_id,
                "reservation_id": request.reservation_id,
                "beneficiary_commitment": request.beneficiary_commitment,
                "sponsor_commitment_root": request.sponsor_commitment_root,
                "rebate_note_root": request.rebate_note_root,
                "amount_piconero": request.amount_piconero,
            }),
        );
        Self {
            rebate_id,
            sequence,
            receipt_id: request.receipt_id.clone(),
            reservation_id: request.reservation_id.clone(),
            beneficiary_commitment: request.beneficiary_commitment.clone(),
            sponsor_commitment_root: request.sponsor_commitment_root.clone(),
            rebate_note_root: request.rebate_note_root.clone(),
            claim_nullifier: request.claim_nullifier.clone(),
            amount_piconero: request.amount_piconero,
            rebate_nonce: request.rebate_nonce.clone(),
            accrued_at_height: height,
            expires_at_height: height.saturating_add(config.rebate_ttl_blocks),
            status: RebateStatus::Accrued,
            rebate_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "sequence": self.sequence,
            "receipt_id": self.receipt_id,
            "reservation_id": self.reservation_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "sponsor_commitment_root": self.sponsor_commitment_root,
            "rebate_note_root": self.rebate_note_root,
            "amount_piconero": self.amount_piconero,
            "accrued_at_height": self.accrued_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "rebate_root": self.rebate_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootsOnlyPublicRecord {
    pub record_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub disclosed: Value,
    pub recorded_at_height: u64,
}

impl RootsOnlyPublicRecord {
    pub fn new(subject_kind: &str, subject_id: &str, subject_record: &Value, height: u64) -> Self {
        let subject_root = root_from_record("ROOTS-ONLY-SUBJECT", subject_record);
        let disclosed = project_privacy_fields(subject_record);
        let record_id = id_from_record(
            "ROOTS-ONLY-PUBLIC-RECORD-ID",
            &json!({
                "subject_kind": subject_kind,
                "subject_id": subject_id,
                "subject_root": subject_root,
                "recorded_at_height": height,
            }),
        );
        Self {
            record_id,
            subject_kind: subject_kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root,
            disclosed,
            recorded_at_height: height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub counters: Counters,
    pub proof_windows: BTreeMap<String, PrivateLiquidityProofWindow>,
    pub encrypted_samples: BTreeMap<String, EncryptedReserveSample>,
    pub watcher_attestations: BTreeMap<String, PqWatcherAttestation>,
    pub low_fee_reservations: BTreeMap<String, LowFeeProofReservation>,
    pub liquidity_batches: BTreeMap<String, LiquidityProofBatch>,
    pub bridge_receipts: BTreeMap<String, BridgeRebalanceReceipt>,
    pub rebates: BTreeMap<String, LowFeeRebate>,
    pub nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, RootsOnlyPublicRecord>,
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

impl State {
    pub fn devnet() -> Self {
        Self::new(
            Config::devnet(),
            MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_DEVNET_HEIGHT,
        )
    }

    pub fn new(config: Config, height: u64) -> Self {
        Self {
            config,
            height,
            counters: Counters::default(),
            proof_windows: BTreeMap::new(),
            encrypted_samples: BTreeMap::new(),
            watcher_attestations: BTreeMap::new(),
            low_fee_reservations: BTreeMap::new(),
            liquidity_batches: BTreeMap::new(),
            bridge_receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn open_private_liquidity_proof_window(
        &mut self,
        request: PrivateLiquidityProofWindowRequest,
    ) -> MoneroL2PqPrivateLiquidityProofRuntimeResult<PrivateLiquidityProofWindow> {
        self.validate_window_request(&request)?;
        ensure_capacity(
            self.proof_windows.len(),
            self.config.max_windows,
            "proof windows",
        )?;
        self.counters.window_counter = self.counters.window_counter.saturating_add(1);
        let record = PrivateLiquidityProofWindow::new(
            &request,
            &self.config,
            self.counters.window_counter,
            self.height,
        );
        insert_unique(
            &mut self.proof_windows,
            record.window_id.clone(),
            record.clone(),
            "proof window",
        )?;
        self.counters.proof_windows = self.proof_windows.len() as u64;
        self.refresh_public_records();
        Ok(record)
    }

    pub fn submit_encrypted_reserve_sample(
        &mut self,
        request: EncryptedReserveSampleRequest,
    ) -> MoneroL2PqPrivateLiquidityProofRuntimeResult<EncryptedReserveSample> {
        self.validate_sample_request(&request)?;
        ensure_capacity(
            self.encrypted_samples.len(),
            self.config.max_samples,
            "encrypted reserve samples",
        )?;
        self.counters.sample_counter = self.counters.sample_counter.saturating_add(1);
        let record = EncryptedReserveSample::new(
            &request,
            self.counters.sample_counter,
            self.height,
            &self.config,
        );
        insert_unique(
            &mut self.encrypted_samples,
            record.sample_id.clone(),
            record.clone(),
            "encrypted reserve sample",
        )?;
        self.nullifiers.insert(record.nullifier.clone());
        if let Some(window) = self.proof_windows.get_mut(&record.window_id) {
            if window.status == WindowStatus::Open {
                window.status = WindowStatus::Sampling;
            }
        }
        self.counters.encrypted_samples = self.encrypted_samples.len() as u64;
        self.counters.nullifiers = self.nullifiers.len() as u64;
        self.refresh_public_records();
        Ok(record)
    }

    pub fn submit_pq_watcher_attestation(
        &mut self,
        request: PqWatcherAttestationRequest,
    ) -> MoneroL2PqPrivateLiquidityProofRuntimeResult<PqWatcherAttestation> {
        self.validate_attestation_request(&request)?;
        ensure_capacity(
            self.watcher_attestations.len(),
            self.config.max_attestations,
            "watcher attestations",
        )?;
        self.counters.attestation_counter = self.counters.attestation_counter.saturating_add(1);
        let record = PqWatcherAttestation::new(
            &request,
            self.counters.attestation_counter,
            self.height,
            &self.config,
        );
        insert_unique(
            &mut self.watcher_attestations,
            record.attestation_id.clone(),
            record.clone(),
            "watcher attestation",
        )?;
        if let Some(sample) = self.encrypted_samples.get_mut(&record.sample_id) {
            sample.status = SampleStatus::Attested;
        }
        if let Some(window) = self.proof_windows.get_mut(&record.window_id) {
            window.status = if record.status == AttestationStatus::StrongQuorum
                || record.status == AttestationStatus::WeakQuorum
            {
                WindowStatus::QuorumAttested
            } else {
                WindowStatus::Attesting
            };
        }
        self.counters.watcher_attestations = self.watcher_attestations.len() as u64;
        self.refresh_public_records();
        Ok(record)
    }

    pub fn reserve_low_fee_proof(
        &mut self,
        request: LowFeeProofReservationRequest,
    ) -> MoneroL2PqPrivateLiquidityProofRuntimeResult<LowFeeProofReservation> {
        self.validate_reservation_request(&request)?;
        ensure_capacity(
            self.low_fee_reservations.len(),
            self.config.max_reservations,
            "low fee reservations",
        )?;
        self.counters.reservation_counter = self.counters.reservation_counter.saturating_add(1);
        let record = LowFeeProofReservation::new(
            &request,
            &self.config,
            self.counters.reservation_counter,
            self.height,
        );
        insert_unique(
            &mut self.low_fee_reservations,
            record.reservation_id.clone(),
            record.clone(),
            "low fee reservation",
        )?;
        self.nullifiers.insert(record.nullifier.clone());
        self.counters.low_fee_reservations = self.low_fee_reservations.len() as u64;
        self.counters.nullifiers = self.nullifiers.len() as u64;
        self.refresh_public_records();
        Ok(record)
    }

    pub fn build_liquidity_proof_batch(
        &mut self,
        request: LiquidityProofBatchRequest,
    ) -> MoneroL2PqPrivateLiquidityProofRuntimeResult<LiquidityProofBatch> {
        self.validate_batch_request(&request)?;
        ensure_capacity(
            self.liquidity_batches.len(),
            self.config.max_batches,
            "liquidity proof batches",
        )?;
        self.counters.batch_counter = self.counters.batch_counter.saturating_add(1);
        let record = LiquidityProofBatch::new(
            &request,
            &self.config,
            self.counters.batch_counter,
            self.height,
        );
        insert_unique(
            &mut self.liquidity_batches,
            record.batch_id.clone(),
            record.clone(),
            "liquidity proof batch",
        )?;
        for id in &record.window_ids {
            if let Some(window) = self.proof_windows.get_mut(id) {
                window.status = WindowStatus::Batched;
            }
        }
        for id in &record.sample_ids {
            if let Some(sample) = self.encrypted_samples.get_mut(id) {
                sample.status = SampleStatus::Batched;
            }
        }
        for id in &record.reservation_ids {
            if let Some(reservation) = self.low_fee_reservations.get_mut(id) {
                reservation.status = ReservationStatus::Batched;
            }
        }
        self.counters.liquidity_batches = self.liquidity_batches.len() as u64;
        self.refresh_public_records();
        Ok(record)
    }

    pub fn publish_bridge_rebalance_receipt(
        &mut self,
        request: BridgeRebalanceReceiptRequest,
    ) -> MoneroL2PqPrivateLiquidityProofRuntimeResult<BridgeRebalanceReceipt> {
        self.validate_receipt_request(&request)?;
        ensure_capacity(
            self.bridge_receipts.len(),
            self.config.max_receipts,
            "bridge rebalance receipts",
        )?;
        self.counters.receipt_counter = self.counters.receipt_counter.saturating_add(1);
        let record = BridgeRebalanceReceipt::new(
            &request,
            &self.config,
            self.counters.receipt_counter,
            self.height,
        );
        insert_unique(
            &mut self.bridge_receipts,
            record.receipt_id.clone(),
            record.clone(),
            "bridge rebalance receipt",
        )?;
        if let Some(batch) = self.liquidity_batches.get_mut(&record.batch_id) {
            batch.status = BatchStatus::ReceiptReady;
        }
        self.counters.bridge_receipts = self.bridge_receipts.len() as u64;
        self.refresh_public_records();
        Ok(record)
    }

    pub fn accrue_low_fee_rebate(
        &mut self,
        request: LowFeeRebateRequest,
    ) -> MoneroL2PqPrivateLiquidityProofRuntimeResult<LowFeeRebate> {
        self.validate_rebate_request(&request)?;
        ensure_capacity(
            self.rebates.len(),
            self.config.max_rebates,
            "low fee rebates",
        )?;
        self.counters.rebate_counter = self.counters.rebate_counter.saturating_add(1);
        let record = LowFeeRebate::new(
            &request,
            &self.config,
            self.counters.rebate_counter,
            self.height,
        );
        insert_unique(
            &mut self.rebates,
            record.rebate_id.clone(),
            record.clone(),
            "low fee rebate",
        )?;
        self.nullifiers.insert(record.claim_nullifier.clone());
        if let Some(reservation) = self.low_fee_reservations.get_mut(&record.reservation_id) {
            reservation.status = ReservationStatus::ReceiptIssued;
        }
        self.counters.rebates = self.rebates.len() as u64;
        self.counters.nullifiers = self.nullifiers.len() as u64;
        self.refresh_public_records();
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.state_root(),
            proof_window_root: map_root(
                "MONERO-L2-PQ-PRIVATE-LIQUIDITY-PROOF-WINDOWS",
                &self.proof_windows,
                PrivateLiquidityProofWindow::public_record,
            ),
            encrypted_sample_root: map_root(
                "MONERO-L2-PQ-PRIVATE-LIQUIDITY-PROOF-ENCRYPTED-SAMPLES",
                &self.encrypted_samples,
                EncryptedReserveSample::public_record,
            ),
            watcher_attestation_root: map_root(
                "MONERO-L2-PQ-PRIVATE-LIQUIDITY-PROOF-WATCHER-ATTESTATIONS",
                &self.watcher_attestations,
                PqWatcherAttestation::public_record,
            ),
            low_fee_reservation_root: map_root(
                "MONERO-L2-PQ-PRIVATE-LIQUIDITY-PROOF-LOW-FEE-RESERVATIONS",
                &self.low_fee_reservations,
                LowFeeProofReservation::public_record,
            ),
            liquidity_batch_root: map_root(
                "MONERO-L2-PQ-PRIVATE-LIQUIDITY-PROOF-BATCHES",
                &self.liquidity_batches,
                LiquidityProofBatch::public_record,
            ),
            bridge_receipt_root: map_root(
                "MONERO-L2-PQ-PRIVATE-LIQUIDITY-PROOF-BRIDGE-REBALANCE-RECEIPTS",
                &self.bridge_receipts,
                BridgeRebalanceReceipt::public_record,
            ),
            rebate_root: map_root(
                "MONERO-L2-PQ-PRIVATE-LIQUIDITY-PROOF-REBATES",
                &self.rebates,
                LowFeeRebate::public_record,
            ),
            nullifier_root: set_root(
                "MONERO-L2-PQ-PRIVATE-LIQUIDITY-PROOF-NULLIFIERS",
                &self.nullifiers,
            ),
            public_record_root: map_root(
                "MONERO-L2-PQ-PRIVATE-LIQUIDITY-PROOF-PUBLIC-RECORDS",
                &self.public_records,
                RootsOnlyPublicRecord::public_record,
            ),
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        set_json_field(&mut record, "state_root", json!(self.state_root()));
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_root())
    }

    fn validate_window_request(
        &self,
        request: &PrivateLiquidityProofWindowRequest,
    ) -> MoneroL2PqPrivateLiquidityProofRuntimeResult<()> {
        required("operator_id", &request.operator_id)?;
        required("window_nonce", &request.window_nonce)?;
        validate_root("reserve_commitment_root", &request.reserve_commitment_root)?;
        validate_root(
            "liability_commitment_root",
            &request.liability_commitment_root,
        )?;
        validate_root("privacy_set_root", &request.privacy_set_root)?;
        require(
            request.monero_start_height <= request.monero_end_height,
            "monero window heights are invalid",
        )?;
        require(
            request.l2_start_height <= request.l2_end_height,
            "l2 window heights are invalid",
        )?;
        require(
            request.min_liquidity_piconero > 0,
            "minimum liquidity is required",
        )?;
        require(
            request.target_liquidity_piconero >= request.min_liquidity_piconero,
            "target liquidity must cover minimum liquidity",
        )?;
        ensure_privacy(&self.config, request.privacy_set_size)?;
        ensure_pq(&self.config, request.pq_security_bits)
    }

    fn validate_sample_request(
        &self,
        request: &EncryptedReserveSampleRequest,
    ) -> MoneroL2PqPrivateLiquidityProofRuntimeResult<()> {
        required("window_id", &request.window_id)?;
        required("reporter_id", &request.reporter_id)?;
        required("sample_nonce", &request.sample_nonce)?;
        validate_root("encrypted_sample_root", &request.encrypted_sample_root)?;
        validate_root("reserve_bucket_root", &request.reserve_bucket_root)?;
        validate_root("liability_bucket_root", &request.liability_bucket_root)?;
        validate_root("amount_commitment_root", &request.amount_commitment_root)?;
        validate_root("decoy_set_root", &request.decoy_set_root)?;
        validate_root("range_proof_root", &request.range_proof_root)?;
        required("nullifier", &request.nullifier)?;
        require(
            self.proof_windows.contains_key(&request.window_id),
            "sample references unknown proof window",
        )?;
        require(
            !self.nullifiers.contains(&request.nullifier),
            "sample nullifier already used",
        )?;
        require(request.sample_count > 0, "sample count is required")?;
        require(
            request.revealed_bucket_count <= request.sample_count,
            "revealed bucket count exceeds sample count",
        )?;
        ensure_privacy(&self.config, request.privacy_set_size)?;
        ensure_pq(&self.config, request.pq_security_bits)
    }

    fn validate_attestation_request(
        &self,
        request: &PqWatcherAttestationRequest,
    ) -> MoneroL2PqPrivateLiquidityProofRuntimeResult<()> {
        required("window_id", &request.window_id)?;
        required("sample_id", &request.sample_id)?;
        required("watcher_id", &request.watcher_id)?;
        validate_root("watcher_set_root", &request.watcher_set_root)?;
        validate_root(
            "aggregate_pq_signature_root",
            &request.aggregate_pq_signature_root,
        )?;
        validate_root("reserve_sample_root", &request.reserve_sample_root)?;
        validate_root("liquidity_claim_root", &request.liquidity_claim_root)?;
        require(
            self.proof_windows.contains_key(&request.window_id),
            "attestation references unknown proof window",
        )?;
        require(
            self.encrypted_samples.contains_key(&request.sample_id),
            "attestation references unknown reserve sample",
        )?;
        require(
            request.coverage_bps >= self.config.min_reserve_coverage_bps,
            "reserve coverage below minimum",
        )?;
        require(
            request.watcher_count >= self.config.min_watcher_count,
            "watcher count below minimum",
        )?;
        require(
            request.watcher_weight >= self.config.min_watcher_weight,
            "watcher weight below minimum",
        )?;
        ensure_privacy(&self.config, request.privacy_set_size)?;
        ensure_pq(&self.config, request.pq_security_bits)
    }

    fn validate_reservation_request(
        &self,
        request: &LowFeeProofReservationRequest,
    ) -> MoneroL2PqPrivateLiquidityProofRuntimeResult<()> {
        required("window_id", &request.window_id)?;
        required("reserver_id", &request.reserver_id)?;
        validate_root("sponsor_commitment_root", &request.sponsor_commitment_root)?;
        required(
            "private_route_commitment",
            &request.private_route_commitment,
        )?;
        required("reservation_nonce", &request.reservation_nonce)?;
        required("nullifier", &request.nullifier)?;
        require(
            self.proof_windows.contains_key(&request.window_id),
            "reservation references unknown proof window",
        )?;
        require(
            !self.nullifiers.contains(&request.nullifier),
            "reservation nullifier already used",
        )?;
        require(
            request.amount_piconero > 0,
            "reservation amount is required",
        )?;
        require(
            request.max_fee_bps <= self.config.max_user_fee_bps,
            "max fee exceeds runtime cap",
        )?;
        ensure_privacy(&self.config, request.privacy_set_size)?;
        ensure_pq(&self.config, request.pq_security_bits)
    }

    fn validate_batch_request(
        &self,
        request: &LiquidityProofBatchRequest,
    ) -> MoneroL2PqPrivateLiquidityProofRuntimeResult<()> {
        required("batcher_id", &request.batcher_id)?;
        required("batch_nonce", &request.batch_nonce)?;
        validate_root("aggregate_proof_root", &request.aggregate_proof_root)?;
        validate_root(
            "aggregate_signature_root",
            &request.aggregate_signature_root,
        )?;
        validate_root(
            "settlement_manifest_root",
            &request.settlement_manifest_root,
        )?;
        let item_count = request.window_ids.len()
            + request.sample_ids.len()
            + request.attestation_ids.len()
            + request.reservation_ids.len();
        require(item_count > 0, "batch must include at least one item")?;
        require(
            item_count <= self.config.max_batch_items,
            "batch item count exceeds runtime cap",
        )?;
        for id in &request.window_ids {
            require(
                self.proof_windows.contains_key(id),
                "batch references unknown proof window",
            )?;
        }
        for id in &request.sample_ids {
            require(
                self.encrypted_samples.contains_key(id),
                "batch references unknown encrypted sample",
            )?;
        }
        for id in &request.attestation_ids {
            require(
                self.watcher_attestations.contains_key(id),
                "batch references unknown watcher attestation",
            )?;
        }
        for id in &request.reservation_ids {
            require(
                self.low_fee_reservations.contains_key(id),
                "batch references unknown low fee reservation",
            )?;
        }
        ensure_privacy(&self.config, request.privacy_set_size)?;
        ensure_pq(&self.config, request.pq_security_bits)
    }

    fn validate_receipt_request(
        &self,
        request: &BridgeRebalanceReceiptRequest,
    ) -> MoneroL2PqPrivateLiquidityProofRuntimeResult<()> {
        required("batch_id", &request.batch_id)?;
        required("publisher_id", &request.publisher_id)?;
        required("receipt_nonce", &request.receipt_nonce)?;
        validate_root("bridge_manifest_root", &request.bridge_manifest_root)?;
        validate_root("rebalance_manifest_root", &request.rebalance_manifest_root)?;
        validate_root("settlement_tx_root", &request.settlement_tx_root)?;
        validate_root("reserve_delta_root", &request.reserve_delta_root)?;
        require(
            self.liquidity_batches.contains_key(&request.batch_id),
            "receipt references unknown liquidity proof batch",
        )?;
        require(request.amount_piconero > 0, "receipt amount is required")
    }

    fn validate_rebate_request(
        &self,
        request: &LowFeeRebateRequest,
    ) -> MoneroL2PqPrivateLiquidityProofRuntimeResult<()> {
        required("receipt_id", &request.receipt_id)?;
        required("reservation_id", &request.reservation_id)?;
        required("beneficiary_commitment", &request.beneficiary_commitment)?;
        validate_root("sponsor_commitment_root", &request.sponsor_commitment_root)?;
        validate_root("rebate_note_root", &request.rebate_note_root)?;
        required("claim_nullifier", &request.claim_nullifier)?;
        required("rebate_nonce", &request.rebate_nonce)?;
        require(
            self.bridge_receipts.contains_key(&request.receipt_id),
            "rebate references unknown receipt",
        )?;
        require(
            self.low_fee_reservations
                .contains_key(&request.reservation_id),
            "rebate references unknown reservation",
        )?;
        require(
            !self.nullifiers.contains(&request.claim_nullifier),
            "rebate claim nullifier already used",
        )?;
        require(request.amount_piconero > 0, "rebate amount is required")
    }

    fn refresh_public_records(&mut self) {
        self.public_records.clear();
        let mut records = Vec::new();
        for record in self.proof_windows.values() {
            records.push((
                "proof_window",
                record.window_id.clone(),
                record.public_record(),
            ));
        }
        for record in self.encrypted_samples.values() {
            records.push((
                "encrypted_reserve_sample",
                record.sample_id.clone(),
                record.public_record(),
            ));
        }
        for record in self.watcher_attestations.values() {
            records.push((
                "pq_watcher_attestation",
                record.attestation_id.clone(),
                record.public_record(),
            ));
        }
        for record in self.low_fee_reservations.values() {
            records.push((
                "low_fee_proof_reservation",
                record.reservation_id.clone(),
                record.public_record(),
            ));
        }
        for record in self.liquidity_batches.values() {
            records.push((
                "liquidity_proof_batch",
                record.batch_id.clone(),
                record.public_record(),
            ));
        }
        for record in self.bridge_receipts.values() {
            records.push((
                "bridge_rebalance_receipt",
                record.receipt_id.clone(),
                record.public_record(),
            ));
        }
        for record in self.rebates.values() {
            records.push((
                "low_fee_rebate",
                record.rebate_id.clone(),
                record.public_record(),
            ));
        }
        for (kind, id, record) in records {
            if self.public_records.len() >= self.config.max_public_records {
                break;
            }
            let public_record = RootsOnlyPublicRecord::new(kind, &id, &record, self.height);
            self.public_records
                .insert(public_record.record_id.clone(), public_record);
        }
        self.counters.public_records = self.public_records.len() as u64;
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn monero_l2_pq_private_liquidity_proof_runtime_devnet() -> State {
    State::devnet()
}

pub fn monero_l2_pq_private_liquidity_proof_runtime_state_root(state: &State) -> String {
    state.state_root()
}

pub fn monero_l2_pq_private_liquidity_proof_runtime_public_record(state: &State) -> Value {
    state.public_record()
}

pub fn private_liquidity_proof_window_id(
    request: &PrivateLiquidityProofWindowRequest,
    config: &Config,
    sequence: u64,
    height: u64,
) -> String {
    PrivateLiquidityProofWindow::new(request, config, sequence, height).window_id
}

pub fn encrypted_reserve_sample_id(
    request: &EncryptedReserveSampleRequest,
    config: &Config,
    sequence: u64,
    height: u64,
) -> String {
    EncryptedReserveSample::new(request, sequence, height, config).sample_id
}

pub fn pq_watcher_attestation_id(
    request: &PqWatcherAttestationRequest,
    config: &Config,
    sequence: u64,
    height: u64,
) -> String {
    PqWatcherAttestation::new(request, sequence, height, config).attestation_id
}

pub fn low_fee_proof_reservation_id(
    request: &LowFeeProofReservationRequest,
    config: &Config,
    sequence: u64,
    height: u64,
) -> String {
    LowFeeProofReservation::new(request, config, sequence, height).reservation_id
}

pub fn liquidity_proof_batch_id(
    request: &LiquidityProofBatchRequest,
    config: &Config,
    sequence: u64,
    height: u64,
) -> String {
    LiquidityProofBatch::new(request, config, sequence, height).batch_id
}

pub fn bridge_rebalance_receipt_id(
    request: &BridgeRebalanceReceiptRequest,
    config: &Config,
    sequence: u64,
    height: u64,
) -> String {
    BridgeRebalanceReceipt::new(request, config, sequence, height).receipt_id
}

pub fn low_fee_rebate_id(
    request: &LowFeeRebateRequest,
    config: &Config,
    sequence: u64,
    height: u64,
) -> String {
    LowFeeRebate::new(request, config, sequence, height).rebate_id
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    let mut sorted = records.to_vec();
    sorted.sort_by_key(crate::hash::canonical_json_string);
    merkle_root(domain, &sorted)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("MONERO-L2-PQ-PRIVATE-LIQUIDITY-PROOF-STATE", record)
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("MONERO-L2-PQ-PRIVATE-LIQUIDITY-PROOF:{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, record: &Value) -> String {
    root_from_record(domain, record)
}

fn id_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("MONERO-L2-PQ-PRIVATE-LIQUIDITY-PROOF:{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        20,
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let records = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": public_record(value) }))
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let records = set.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &records)
}

fn id_list_root(label: &str, ids: &[String]) -> String {
    let records = ids.iter().map(|id| json!({ "id": id })).collect::<Vec<_>>();
    merkle_root(
        &format!("MONERO-L2-PQ-PRIVATE-LIQUIDITY-PROOF-{label}-ID-LIST"),
        &records,
    )
}

fn project_privacy_fields(record: &Value) -> Value {
    let fields = [
        "window_id",
        "sample_id",
        "attestation_id",
        "reservation_id",
        "batch_id",
        "receipt_id",
        "rebate_id",
        "sequence",
        "lane",
        "direction",
        "status",
        "privacy_set_size",
        "pq_security_bits",
        "reserve_coverage_bps",
        "fee_bps",
        "rebate_bps",
        "opened_at_height",
        "submitted_at_height",
        "attested_at_height",
        "reserved_at_height",
        "published_at_height",
        "accrued_at_height",
        "expires_at_height",
    ];
    let mut projected = serde_json::Map::new();
    if let Some(object) = record.as_object() {
        for field in fields {
            if let Some(value) = object.get(field) {
                projected.insert(field.to_string(), value.clone());
            }
        }
    }
    Value::Object(projected)
}

fn bps_amount(amount: u64, bps: u64) -> u64 {
    amount.saturating_mul(bps) / MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_MAX_BPS
}

fn coverage_bps(numerator: u64, denominator: u64, fallback: u64) -> u64 {
    if denominator == 0 {
        fallback
    } else {
        numerator.saturating_mul(MONERO_L2_PQ_PRIVATE_LIQUIDITY_PROOF_RUNTIME_MAX_BPS) / denominator
    }
}

fn quorum_bps(weight: u64, count: u64) -> u64 {
    coverage_bps(weight, count, 0)
}

fn ensure_capacity(
    current: usize,
    max: usize,
    label: &str,
) -> MoneroL2PqPrivateLiquidityProofRuntimeResult<()> {
    require(current < max, &format!("{label} capacity exceeded"))
}

fn validate_root(field: &str, value: &str) -> MoneroL2PqPrivateLiquidityProofRuntimeResult<()> {
    required(field, value)
}

fn required(field: &str, value: &str) -> MoneroL2PqPrivateLiquidityProofRuntimeResult<()> {
    require(!value.trim().is_empty(), &format!("{field} is required"))
}

fn ensure_privacy(
    config: &Config,
    privacy_set_size: u64,
) -> MoneroL2PqPrivateLiquidityProofRuntimeResult<()> {
    require(
        privacy_set_size >= config.min_privacy_set_size,
        &format!(
            "privacy set {} below minimum {}",
            privacy_set_size, config.min_privacy_set_size
        ),
    )
}

fn ensure_pq(
    config: &Config,
    pq_security_bits: u16,
) -> MoneroL2PqPrivateLiquidityProofRuntimeResult<()> {
    require(
        pq_security_bits >= config.min_pq_security_bits,
        &format!(
            "pq security {} below minimum {}",
            pq_security_bits, config.min_pq_security_bits
        ),
    )
}

fn insert_unique<T>(
    map: &mut BTreeMap<String, T>,
    key: String,
    value: T,
    label: &str,
) -> MoneroL2PqPrivateLiquidityProofRuntimeResult<()> {
    require(!key.is_empty(), &format!("{label} key is empty"))?;
    require(!map.contains_key(&key), &format!("{label} already exists"))?;
    map.insert(key, value);
    Ok(())
}

fn require(condition: bool, message: &str) -> MoneroL2PqPrivateLiquidityProofRuntimeResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn set_json_field(record: &mut Value, key: &str, value: Value) {
    if let Value::Object(fields) = record {
        fields.insert(key.to_string(), value);
    }
}
