use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_STATE_DIFF_SPONSOR_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-state-diff-sponsor-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_STATE_DIFF_SPONSOR_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-state-diff-sponsor-auth-v1";
pub const PQ_SEALING_SUITE: &str = "ML-KEM-1024+XWing-sealed-confidential-state-diff-envelope-v1";
pub const STATE_DIFF_COMPRESSION_SUITE: &str =
    "recursive-zstd-fec-confidential-state-diff-bundle-v1";
pub const SPONSOR_VAULT_SCHEME: &str = "anonymous-low-fee-state-diff-sponsor-vault-root-v1";
pub const REBATE_COUPON_SCHEME: &str = "confidential-state-diff-rebate-coupon-root-v1";
pub const PROVER_RESERVATION_SCHEME: &str = "pq-confidential-state-diff-prover-reservation-v1";
pub const ENCRYPTED_CALLDATA_DEDUP_SCHEME: &str =
    "encrypted-calldata-dedup-anchor-state-diff-root-v1";
pub const FEE_FUTURE_SCHEME: &str = "private-low-fee-state-diff-fee-future-root-v1";
pub const DA_VOUCHER_SCHEME: &str = "confidential-state-diff-da-voucher-root-v1";
pub const SETTLEMENT_RECEIPT_SCHEME: &str = "state-diff-sponsor-settlement-receipt-root-v1";
pub const PRIVACY_FENCE_SCHEME: &str = "state-diff-sponsor-nullifier-fence-root-v1";
pub const SLASHING_EVIDENCE_SCHEME: &str = "state-diff-sponsor-slashing-evidence-root-v1";
pub const DEVNET_HEIGHT: u64 = 3_120_960;
pub const DEVNET_EPOCH: u64 = 4_334;
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_QUOTE_ASSET_ID: &str = "dusd-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_BUNDLE_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_VAULT_TTL_BLOCKS: u64 = 43_200;
pub const DEFAULT_COUPON_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_PROVER_RESERVATION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_DEDUP_ANCHOR_TTL_BLOCKS: u64 = 4_320;
pub const DEFAULT_FEE_FUTURE_TTL_BLOCKS: u64 = 21_600;
pub const DEFAULT_DA_VOUCHER_TTL_BLOCKS: u64 = 7_200;
pub const DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 14_400;
pub const DEFAULT_FENCE_TTL_BLOCKS: u64 = 21_600;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_NULLIFIER_SET_SIZE: u64 = 8_192;
pub const DEFAULT_MIN_DEDUP_SET_SIZE: u64 = 4_096;
pub const DEFAULT_BASE_STATE_DIFF_MICRO_FEE: u64 = 7;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 8;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 8_900;
pub const DEFAULT_SPONSOR_RESERVE_BPS: u64 = 1_500;
pub const DEFAULT_REBATE_BPS: u64 = 6;
pub const DEFAULT_PROVER_FEE_BPS: u64 = 2;
pub const DEFAULT_DA_FEE_BPS: u64 = 2;
pub const DEFAULT_SETTLEMENT_FEE_BPS: u64 = 1;
pub const DEFAULT_SLASH_BPS: u64 = 2_500;
pub const DEFAULT_COMPRESSION_MIN_SAVINGS_BPS: u64 = 3_000;
pub const DEFAULT_MAX_BUNDLES: usize = 8_388_608;
pub const DEFAULT_MAX_SPONSOR_VAULTS: usize = 1_048_576;
pub const DEFAULT_MAX_REBATE_COUPONS: usize = 8_388_608;
pub const DEFAULT_MAX_PROVER_RESERVATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_DEDUP_ANCHORS: usize = 8_388_608;
pub const DEFAULT_MAX_FEE_FUTURES: usize = 2_097_152;
pub const DEFAULT_MAX_DA_VOUCHERS: usize = 4_194_304;
pub const DEFAULT_MAX_SETTLEMENT_RECEIPTS: usize = 8_388_608;
pub const DEFAULT_MAX_PRIVACY_FENCES: usize = 4_194_304;
pub const DEFAULT_MAX_SLASHING_EVIDENCE: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StateDiffLaneKind {
    PrivateContractStorage,
    ConfidentialTokenAccounting,
    DefiBatchNetting,
    MoneroBridgeExit,
    CrossRollupMessage,
    RecursiveWitness,
    OracleStateUpdate,
    EmergencyEscape,
}

impl StateDiffLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateContractStorage => "private_contract_storage",
            Self::ConfidentialTokenAccounting => "confidential_token_accounting",
            Self::DefiBatchNetting => "defi_batch_netting",
            Self::MoneroBridgeExit => "monero_bridge_exit",
            Self::CrossRollupMessage => "cross_rollup_message",
            Self::RecursiveWitness => "recursive_witness",
            Self::OracleStateUpdate => "oracle_state_update",
            Self::EmergencyEscape => "emergency_escape",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyEscape => 10_000,
            Self::MoneroBridgeExit => 9_600,
            Self::DefiBatchNetting => 9_000,
            Self::ConfidentialTokenAccounting => 8_600,
            Self::PrivateContractStorage => 8_200,
            Self::CrossRollupMessage => 7_900,
            Self::OracleStateUpdate => 7_400,
            Self::RecursiveWitness => 7_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionCodec {
    ZstdFec,
    BrotliFec,
    PoseidonDeltaTree,
    SparseMerklePatch,
    RecursiveWitnessDelta,
    CiphertextChunkDictionary,
}

impl CompressionCodec {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ZstdFec => "zstd_fec",
            Self::BrotliFec => "brotli_fec",
            Self::PoseidonDeltaTree => "poseidon_delta_tree",
            Self::SparseMerklePatch => "sparse_merkle_patch",
            Self::RecursiveWitnessDelta => "recursive_witness_delta",
            Self::CiphertextChunkDictionary => "ciphertext_chunk_dictionary",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleStatus {
    Draft,
    Submitted,
    Sponsored,
    ProverReserved,
    DaVoucherIssued,
    Settling,
    Settled,
    Rebated,
    Expired,
    Rejected,
    Slashed,
}

impl BundleStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted
                | Self::Sponsored
                | Self::ProverReserved
                | Self::DaVoucherIssued
                | Self::Settling
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Active,
    Draining,
    Paused,
    Locked,
    Slashed,
    Retired,
}

impl VaultStatus {
    pub fn can_sponsor(self) -> bool {
        matches!(self, Self::Active | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Issued,
    Locked,
    Redeemed,
    Expired,
    Revoked,
    Challenged,
}

impl CouponStatus {
    pub fn spendable(self) -> bool {
        matches!(self, Self::Issued | Self::Locked)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Requested,
    Accepted,
    WitnessLocked,
    Proving,
    Proved,
    Settled,
    Expired,
    Cancelled,
    Slashed,
}

impl ReservationStatus {
    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Requested | Self::Accepted | Self::WitnessLocked | Self::Proving
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorStatus {
    Proposed,
    Accepted,
    Deduped,
    Saturated,
    Expired,
    Slashed,
}

impl AnchorStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Accepted | Self::Deduped | Self::Saturated)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FutureSide {
    LongCompressionCost,
    ShortCompressionCost,
    SponsorCovered,
    DaCostHedge,
    ProverCostHedge,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FutureStatus {
    Open,
    Hedged,
    Exercised,
    Settled,
    Expired,
    Challenged,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VoucherStatus {
    Issued,
    Reserved,
    Posted,
    Settled,
    Expired,
    Revoked,
    Slashed,
}

impl VoucherStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Issued | Self::Reserved | Self::Posted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Finalized,
    Rebated,
    Challenged,
    Reversed,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceStatus {
    Proposed,
    Active,
    Sealed,
    Expired,
    Slashed,
}

impl FenceStatus {
    pub fn open(self) -> bool {
        matches!(self, Self::Proposed | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingReason {
    InvalidStateDiff,
    InvalidCompressionProof,
    WithheldDataAvailability,
    DoubleSponsoredBundle,
    CouponReplay,
    ProverReservationDefault,
    DedupAnchorEquivocation,
    FeeFutureManipulation,
    NullifierFenceViolation,
    InvalidPqSignature,
}

impl SlashingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidStateDiff => "invalid_state_diff",
            Self::InvalidCompressionProof => "invalid_compression_proof",
            Self::WithheldDataAvailability => "withheld_data_availability",
            Self::DoubleSponsoredBundle => "double_sponsored_bundle",
            Self::CouponReplay => "coupon_replay",
            Self::ProverReservationDefault => "prover_reservation_default",
            Self::DedupAnchorEquivocation => "dedup_anchor_equivocation",
            Self::FeeFutureManipulation => "fee_future_manipulation",
            Self::NullifierFenceViolation => "nullifier_fence_violation",
            Self::InvalidPqSignature => "invalid_pq_signature",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub pq_sealing_suite: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub quote_asset_id: String,
    pub epoch_blocks: u64,
    pub bundle_ttl_blocks: u64,
    pub vault_ttl_blocks: u64,
    pub coupon_ttl_blocks: u64,
    pub prover_reservation_ttl_blocks: u64,
    pub dedup_anchor_ttl_blocks: u64,
    pub fee_future_ttl_blocks: u64,
    pub da_voucher_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub fence_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_nullifier_set_size: u64,
    pub min_dedup_set_size: u64,
    pub base_state_diff_micro_fee: u64,
    pub max_user_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub sponsor_reserve_bps: u64,
    pub rebate_bps: u64,
    pub prover_fee_bps: u64,
    pub da_fee_bps: u64,
    pub settlement_fee_bps: u64,
    pub slash_bps: u64,
    pub compression_min_savings_bps: u64,
    pub max_bundles: usize,
    pub max_sponsor_vaults: usize,
    pub max_rebate_coupons: usize,
    pub max_prover_reservations: usize,
    pub max_dedup_anchors: usize,
    pub max_fee_futures: usize,
    pub max_da_vouchers: usize,
    pub max_settlement_receipts: usize,
    pub max_privacy_fences: usize,
    pub max_slashing_evidence: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_auth_suite: PQ_AUTH_SUITE.to_string(),
            pq_sealing_suite: PQ_SEALING_SUITE.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            quote_asset_id: DEVNET_QUOTE_ASSET_ID.to_string(),
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            bundle_ttl_blocks: DEFAULT_BUNDLE_TTL_BLOCKS,
            vault_ttl_blocks: DEFAULT_VAULT_TTL_BLOCKS,
            coupon_ttl_blocks: DEFAULT_COUPON_TTL_BLOCKS,
            prover_reservation_ttl_blocks: DEFAULT_PROVER_RESERVATION_TTL_BLOCKS,
            dedup_anchor_ttl_blocks: DEFAULT_DEDUP_ANCHOR_TTL_BLOCKS,
            fee_future_ttl_blocks: DEFAULT_FEE_FUTURE_TTL_BLOCKS,
            da_voucher_ttl_blocks: DEFAULT_DA_VOUCHER_TTL_BLOCKS,
            receipt_ttl_blocks: DEFAULT_RECEIPT_TTL_BLOCKS,
            fence_ttl_blocks: DEFAULT_FENCE_TTL_BLOCKS,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_nullifier_set_size: DEFAULT_MIN_NULLIFIER_SET_SIZE,
            min_dedup_set_size: DEFAULT_MIN_DEDUP_SET_SIZE,
            base_state_diff_micro_fee: DEFAULT_BASE_STATE_DIFF_MICRO_FEE,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            sponsor_reserve_bps: DEFAULT_SPONSOR_RESERVE_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            prover_fee_bps: DEFAULT_PROVER_FEE_BPS,
            da_fee_bps: DEFAULT_DA_FEE_BPS,
            settlement_fee_bps: DEFAULT_SETTLEMENT_FEE_BPS,
            slash_bps: DEFAULT_SLASH_BPS,
            compression_min_savings_bps: DEFAULT_COMPRESSION_MIN_SAVINGS_BPS,
            max_bundles: DEFAULT_MAX_BUNDLES,
            max_sponsor_vaults: DEFAULT_MAX_SPONSOR_VAULTS,
            max_rebate_coupons: DEFAULT_MAX_REBATE_COUPONS,
            max_prover_reservations: DEFAULT_MAX_PROVER_RESERVATIONS,
            max_dedup_anchors: DEFAULT_MAX_DEDUP_ANCHORS,
            max_fee_futures: DEFAULT_MAX_FEE_FUTURES,
            max_da_vouchers: DEFAULT_MAX_DA_VOUCHERS,
            max_settlement_receipts: DEFAULT_MAX_SETTLEMENT_RECEIPTS,
            max_privacy_fences: DEFAULT_MAX_PRIVACY_FENCES,
            max_slashing_evidence: DEFAULT_MAX_SLASHING_EVIDENCE,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(self.chain_id == CHAIN_ID, "unexpected chain id");
        ensure!(
            self.protocol_version == PROTOCOL_VERSION,
            "unexpected protocol"
        );
        ensure!(self.schema_version == SCHEMA_VERSION, "unexpected schema");
        ensure!(self.min_pq_security_bits >= 192, "pq security too low");
        ensure!(
            self.target_privacy_set_size >= self.min_privacy_set_size,
            "target privacy set below minimum"
        );
        ensure!(
            self.min_privacy_set_size >= self.min_nullifier_set_size,
            "privacy set below nullifier floor"
        );
        ensure!(
            self.min_dedup_set_size > 0,
            "dedup set size must be positive"
        );
        ensure!(
            self.max_user_fee_bps <= 100,
            "max low-fee user bps too high"
        );
        ensure!(
            self.sponsor_cover_bps <= MAX_BPS
                && self.sponsor_reserve_bps <= MAX_BPS
                && self.rebate_bps <= MAX_BPS
                && self.prover_fee_bps <= MAX_BPS
                && self.da_fee_bps <= MAX_BPS
                && self.settlement_fee_bps <= MAX_BPS
                && self.slash_bps <= MAX_BPS
                && self.compression_min_savings_bps <= MAX_BPS,
            "basis points out of range"
        );
        ensure!(
            self.base_state_diff_micro_fee > 0,
            "base fee must be positive"
        );
        ensure!(self.bundle_ttl_blocks > 0, "bundle ttl must be positive");
        ensure!(
            self.prover_reservation_ttl_blocks > 0,
            "prover reservation ttl must be positive"
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "pq_auth_suite": self.pq_auth_suite,
            "pq_sealing_suite": self.pq_sealing_suite,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "epoch_blocks": self.epoch_blocks,
            "bundle_ttl_blocks": self.bundle_ttl_blocks,
            "vault_ttl_blocks": self.vault_ttl_blocks,
            "coupon_ttl_blocks": self.coupon_ttl_blocks,
            "prover_reservation_ttl_blocks": self.prover_reservation_ttl_blocks,
            "dedup_anchor_ttl_blocks": self.dedup_anchor_ttl_blocks,
            "fee_future_ttl_blocks": self.fee_future_ttl_blocks,
            "da_voucher_ttl_blocks": self.da_voucher_ttl_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "fence_ttl_blocks": self.fence_ttl_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_nullifier_set_size": self.min_nullifier_set_size,
            "min_dedup_set_size": self.min_dedup_set_size,
            "base_state_diff_micro_fee": self.base_state_diff_micro_fee,
            "max_user_fee_bps": self.max_user_fee_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "sponsor_reserve_bps": self.sponsor_reserve_bps,
            "rebate_bps": self.rebate_bps,
            "prover_fee_bps": self.prover_fee_bps,
            "da_fee_bps": self.da_fee_bps,
            "settlement_fee_bps": self.settlement_fee_bps,
            "slash_bps": self.slash_bps,
            "compression_min_savings_bps": self.compression_min_savings_bps,
            "max_bundles": self.max_bundles,
            "max_sponsor_vaults": self.max_sponsor_vaults,
            "max_rebate_coupons": self.max_rebate_coupons,
            "max_prover_reservations": self.max_prover_reservations,
            "max_dedup_anchors": self.max_dedup_anchors,
            "max_fee_futures": self.max_fee_futures,
            "max_da_vouchers": self.max_da_vouchers,
            "max_settlement_receipts": self.max_settlement_receipts,
            "max_privacy_fences": self.max_privacy_fences,
            "max_slashing_evidence": self.max_slashing_evidence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub bundles: u64,
    pub sponsor_vaults: u64,
    pub rebate_coupons: u64,
    pub prover_reservations: u64,
    pub dedup_anchors: u64,
    pub fee_futures: u64,
    pub da_vouchers: u64,
    pub settlement_receipts: u64,
    pub privacy_fences: u64,
    pub slashing_evidence: u64,
    pub live_bundles: u64,
    pub active_reservations: u64,
    pub open_fee_futures: u64,
    pub total_original_bytes: u128,
    pub total_compressed_bytes: u128,
    pub total_sponsored_micro_fee: u128,
    pub total_rebated_micro_fee: u128,
    pub total_reserved_prover_micro_fee: u128,
    pub total_da_micro_fee: u128,
    pub total_slashed_micro_fee: u128,
}

impl Counters {
    pub fn empty() -> Self {
        Self {
            bundles: 0,
            sponsor_vaults: 0,
            rebate_coupons: 0,
            prover_reservations: 0,
            dedup_anchors: 0,
            fee_futures: 0,
            da_vouchers: 0,
            settlement_receipts: 0,
            privacy_fences: 0,
            slashing_evidence: 0,
            live_bundles: 0,
            active_reservations: 0,
            open_fee_futures: 0,
            total_original_bytes: 0,
            total_compressed_bytes: 0,
            total_sponsored_micro_fee: 0,
            total_rebated_micro_fee: 0,
            total_reserved_prover_micro_fee: 0,
            total_da_micro_fee: 0,
            total_slashed_micro_fee: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bundles": self.bundles,
            "sponsor_vaults": self.sponsor_vaults,
            "rebate_coupons": self.rebate_coupons,
            "prover_reservations": self.prover_reservations,
            "dedup_anchors": self.dedup_anchors,
            "fee_futures": self.fee_futures,
            "da_vouchers": self.da_vouchers,
            "settlement_receipts": self.settlement_receipts,
            "privacy_fences": self.privacy_fences,
            "slashing_evidence": self.slashing_evidence,
            "live_bundles": self.live_bundles,
            "active_reservations": self.active_reservations,
            "open_fee_futures": self.open_fee_futures,
            "total_original_bytes": self.total_original_bytes,
            "total_compressed_bytes": self.total_compressed_bytes,
            "total_sponsored_micro_fee": self.total_sponsored_micro_fee,
            "total_rebated_micro_fee": self.total_rebated_micro_fee,
            "total_reserved_prover_micro_fee": self.total_reserved_prover_micro_fee,
            "total_da_micro_fee": self.total_da_micro_fee,
            "total_slashed_micro_fee": self.total_slashed_micro_fee,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub bundle_root: String,
    pub sponsor_vault_root: String,
    pub rebate_coupon_root: String,
    pub prover_reservation_root: String,
    pub dedup_anchor_root: String,
    pub fee_future_root: String,
    pub da_voucher_root: String,
    pub settlement_receipt_root: String,
    pub privacy_fence_root: String,
    pub slashing_evidence_root: String,
    pub nullifier_index_root: String,
    pub cross_index_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "bundle_root": self.bundle_root,
            "sponsor_vault_root": self.sponsor_vault_root,
            "rebate_coupon_root": self.rebate_coupon_root,
            "prover_reservation_root": self.prover_reservation_root,
            "dedup_anchor_root": self.dedup_anchor_root,
            "fee_future_root": self.fee_future_root,
            "da_voucher_root": self.da_voucher_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "privacy_fence_root": self.privacy_fence_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "nullifier_index_root": self.nullifier_index_root,
            "cross_index_root": self.cross_index_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompressedStateDiffBundle {
    pub bundle_id: String,
    pub lane: StateDiffLaneKind,
    pub codec: CompressionCodec,
    pub submitter_commitment: String,
    pub previous_state_root: String,
    pub post_state_root: String,
    pub state_diff_commitment_root: String,
    pub compressed_payload_root: String,
    pub encrypted_calldata_root: String,
    pub witness_commitment_root: String,
    pub compression_proof_root: String,
    pub original_bytes: u64,
    pub compressed_bytes: u64,
    pub max_user_micro_fee: u128,
    pub sponsor_vault_id: Option<String>,
    pub dedup_anchor_id: Option<String>,
    pub prover_reservation_id: Option<String>,
    pub da_voucher_id: Option<String>,
    pub privacy_fence_id: Option<String>,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: BundleStatus,
}

impl CompressedStateDiffBundle {
    pub fn compression_savings_bps(&self) -> u64 {
        if self.original_bytes == 0 || self.compressed_bytes >= self.original_bytes {
            return 0;
        }
        let saved = self.original_bytes.saturating_sub(self.compressed_bytes) as u128;
        ((saved.saturating_mul(MAX_BPS as u128)) / self.original_bytes as u128) as u64
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bundle_id": self.bundle_id,
            "lane": self.lane,
            "lane_label": self.lane.as_str(),
            "lane_priority_weight": self.lane.priority_weight(),
            "codec": self.codec,
            "codec_label": self.codec.as_str(),
            "submitter_commitment": self.submitter_commitment,
            "previous_state_root": self.previous_state_root,
            "post_state_root": self.post_state_root,
            "state_diff_commitment_root": self.state_diff_commitment_root,
            "compressed_payload_root": self.compressed_payload_root,
            "encrypted_calldata_root": self.encrypted_calldata_root,
            "witness_commitment_root": self.witness_commitment_root,
            "compression_proof_root": self.compression_proof_root,
            "original_bytes": self.original_bytes,
            "compressed_bytes": self.compressed_bytes,
            "compression_savings_bps": self.compression_savings_bps(),
            "max_user_micro_fee": self.max_user_micro_fee,
            "sponsor_vault_id": self.sponsor_vault_id,
            "dedup_anchor_id": self.dedup_anchor_id,
            "prover_reservation_id": self.prover_reservation_id,
            "da_voucher_id": self.da_voucher_id,
            "privacy_fence_id": self.privacy_fence_id,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn root(&self) -> String {
        payload_root("STATE-DIFF-BUNDLE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorVault {
    pub vault_id: String,
    pub sponsor_commitment: String,
    pub asset_id: String,
    pub balance_commitment: String,
    pub available_micro_fee: u128,
    pub reserved_micro_fee: u128,
    pub covered_bundle_root: String,
    pub nullifier_root: String,
    pub min_privacy_set_size: u64,
    pub max_state_diff_bytes: u64,
    pub cover_bps: u64,
    pub reserve_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: VaultStatus,
}

impl SponsorVault {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "sponsor_commitment": self.sponsor_commitment,
            "asset_id": self.asset_id,
            "balance_commitment": self.balance_commitment,
            "available_micro_fee": self.available_micro_fee,
            "reserved_micro_fee": self.reserved_micro_fee,
            "covered_bundle_root": self.covered_bundle_root,
            "nullifier_root": self.nullifier_root,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_state_diff_bytes": self.max_state_diff_bytes,
            "cover_bps": self.cover_bps,
            "reserve_bps": self.reserve_bps,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn root(&self) -> String {
        payload_root("SPONSOR-VAULT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateCoupon {
    pub coupon_id: String,
    pub bundle_id: String,
    pub sponsor_vault_id: String,
    pub recipient_commitment: String,
    pub coupon_nullifier: String,
    pub rebate_micro_fee: u128,
    pub eligibility_root: String,
    pub pq_signature_root: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub status: CouponStatus,
}

impl RebateCoupon {
    pub fn public_record(&self) -> Value {
        json!({
            "coupon_id": self.coupon_id,
            "bundle_id": self.bundle_id,
            "sponsor_vault_id": self.sponsor_vault_id,
            "recipient_commitment": self.recipient_commitment,
            "coupon_nullifier": self.coupon_nullifier,
            "rebate_micro_fee": self.rebate_micro_fee,
            "eligibility_root": self.eligibility_root,
            "pq_signature_root": self.pq_signature_root,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn root(&self) -> String {
        payload_root("REBATE-COUPON", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProverReservation {
    pub reservation_id: String,
    pub bundle_id: String,
    pub prover_commitment: String,
    pub prover_pool_root: String,
    pub witness_root: String,
    pub proving_system_root: String,
    pub reserved_compute_units: u64,
    pub reserved_micro_fee: u128,
    pub security_bits: u16,
    pub accepted_at_height: u64,
    pub expires_at_height: u64,
    pub status: ReservationStatus,
}

impl ProverReservation {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "bundle_id": self.bundle_id,
            "prover_commitment": self.prover_commitment,
            "prover_pool_root": self.prover_pool_root,
            "witness_root": self.witness_root,
            "proving_system_root": self.proving_system_root,
            "reserved_compute_units": self.reserved_compute_units,
            "reserved_micro_fee": self.reserved_micro_fee,
            "security_bits": self.security_bits,
            "accepted_at_height": self.accepted_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn root(&self) -> String {
        payload_root("PROVER-RESERVATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedCalldataDedupAnchor {
    pub anchor_id: String,
    pub lane: StateDiffLaneKind,
    pub encrypted_calldata_root: String,
    pub dictionary_root: String,
    pub duplicate_set_root: String,
    pub ciphertext_sample_root: String,
    pub membership_proof_root: String,
    pub min_dedup_set_size: u64,
    pub referenced_bundle_count: u64,
    pub saved_bytes: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: AnchorStatus,
}

impl EncryptedCalldataDedupAnchor {
    pub fn public_record(&self) -> Value {
        json!({
            "anchor_id": self.anchor_id,
            "lane": self.lane,
            "lane_label": self.lane.as_str(),
            "encrypted_calldata_root": self.encrypted_calldata_root,
            "dictionary_root": self.dictionary_root,
            "duplicate_set_root": self.duplicate_set_root,
            "ciphertext_sample_root": self.ciphertext_sample_root,
            "membership_proof_root": self.membership_proof_root,
            "min_dedup_set_size": self.min_dedup_set_size,
            "referenced_bundle_count": self.referenced_bundle_count,
            "saved_bytes": self.saved_bytes,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn root(&self) -> String {
        payload_root("DEDUP-ANCHOR", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeFuture {
    pub future_id: String,
    pub bundle_id: String,
    pub side: FutureSide,
    pub owner_commitment: String,
    pub quote_asset_id: String,
    pub notional_micro_fee: u128,
    pub strike_micro_fee_per_byte: u64,
    pub margin_commitment: String,
    pub oracle_rate_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: FutureStatus,
}

impl FeeFuture {
    pub fn public_record(&self) -> Value {
        json!({
            "future_id": self.future_id,
            "bundle_id": self.bundle_id,
            "side": self.side,
            "owner_commitment": self.owner_commitment,
            "quote_asset_id": self.quote_asset_id,
            "notional_micro_fee": self.notional_micro_fee,
            "strike_micro_fee_per_byte": self.strike_micro_fee_per_byte,
            "margin_commitment": self.margin_commitment,
            "oracle_rate_root": self.oracle_rate_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn root(&self) -> String {
        payload_root("FEE-FUTURE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DaVoucher {
    pub voucher_id: String,
    pub bundle_id: String,
    pub da_committee_root: String,
    pub erasure_commitment_root: String,
    pub sampling_receipt_root: String,
    pub byte_limit: u64,
    pub prepaid_micro_fee: u128,
    pub finality_height: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub status: VoucherStatus,
}

impl DaVoucher {
    pub fn public_record(&self) -> Value {
        json!({
            "voucher_id": self.voucher_id,
            "bundle_id": self.bundle_id,
            "da_committee_root": self.da_committee_root,
            "erasure_commitment_root": self.erasure_commitment_root,
            "sampling_receipt_root": self.sampling_receipt_root,
            "byte_limit": self.byte_limit,
            "prepaid_micro_fee": self.prepaid_micro_fee,
            "finality_height": self.finality_height,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn root(&self) -> String {
        payload_root("DA-VOUCHER", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub bundle_id: String,
    pub sponsor_vault_id: Option<String>,
    pub prover_reservation_id: Option<String>,
    pub da_voucher_id: Option<String>,
    pub final_state_root: String,
    pub settlement_proof_root: String,
    pub settlement_fee_micro: u128,
    pub sponsor_paid_micro: u128,
    pub user_paid_micro: u128,
    pub settled_at_height: u64,
    pub challenge_expires_at_height: u64,
    pub status: ReceiptStatus,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "bundle_id": self.bundle_id,
            "sponsor_vault_id": self.sponsor_vault_id,
            "prover_reservation_id": self.prover_reservation_id,
            "da_voucher_id": self.da_voucher_id,
            "final_state_root": self.final_state_root,
            "settlement_proof_root": self.settlement_proof_root,
            "settlement_fee_micro": self.settlement_fee_micro,
            "sponsor_paid_micro": self.sponsor_paid_micro,
            "user_paid_micro": self.user_paid_micro,
            "settled_at_height": self.settled_at_height,
            "challenge_expires_at_height": self.challenge_expires_at_height,
            "status": self.status,
        })
    }

    pub fn root(&self) -> String {
        payload_root("SETTLEMENT-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub account_commitment: String,
    pub nullifier_root: String,
    pub membership_root: String,
    pub decoy_set_root: String,
    pub bundle_scope_root: String,
    pub min_anonymity_set_size: u64,
    pub spent_nullifiers: BTreeSet<String>,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: FenceStatus,
}

impl PrivacyFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "account_commitment": self.account_commitment,
            "nullifier_root": self.nullifier_root,
            "membership_root": self.membership_root,
            "decoy_set_root": self.decoy_set_root,
            "bundle_scope_root": self.bundle_scope_root,
            "min_anonymity_set_size": self.min_anonymity_set_size,
            "spent_nullifiers": self.spent_nullifiers.iter().cloned().collect::<Vec<_>>(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn root(&self) -> String {
        payload_root("PRIVACY-FENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub reason: SlashingReason,
    pub accused_commitment: String,
    pub bundle_id: Option<String>,
    pub sponsor_vault_id: Option<String>,
    pub prover_reservation_id: Option<String>,
    pub da_voucher_id: Option<String>,
    pub transcript_root: String,
    pub conflicting_root: String,
    pub pq_signature_root: String,
    pub slash_micro_fee: u128,
    pub reported_at_height: u64,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "reason": self.reason,
            "reason_label": self.reason.as_str(),
            "accused_commitment": self.accused_commitment,
            "bundle_id": self.bundle_id,
            "sponsor_vault_id": self.sponsor_vault_id,
            "prover_reservation_id": self.prover_reservation_id,
            "da_voucher_id": self.da_voucher_id,
            "transcript_root": self.transcript_root,
            "conflicting_root": self.conflicting_root,
            "pq_signature_root": self.pq_signature_root,
            "slash_micro_fee": self.slash_micro_fee,
            "reported_at_height": self.reported_at_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("SLASHING-EVIDENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub current_height: u64,
    pub current_epoch: u64,
    pub counters: Counters,
    pub bundles: BTreeMap<String, CompressedStateDiffBundle>,
    pub sponsor_vaults: BTreeMap<String, SponsorVault>,
    pub rebate_coupons: BTreeMap<String, RebateCoupon>,
    pub prover_reservations: BTreeMap<String, ProverReservation>,
    pub dedup_anchors: BTreeMap<String, EncryptedCalldataDedupAnchor>,
    pub fee_futures: BTreeMap<String, FeeFuture>,
    pub da_vouchers: BTreeMap<String, DaVoucher>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub bundle_nullifiers: BTreeSet<String>,
    pub coupon_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config, current_height: u64, current_epoch: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            current_height,
            current_epoch,
            counters: Counters::empty(),
            bundles: BTreeMap::new(),
            sponsor_vaults: BTreeMap::new(),
            rebate_coupons: BTreeMap::new(),
            prover_reservations: BTreeMap::new(),
            dedup_anchors: BTreeMap::new(),
            fee_futures: BTreeMap::new(),
            da_vouchers: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            bundle_nullifiers: BTreeSet::new(),
            coupon_nullifiers: BTreeSet::new(),
        })
    }

    pub fn devnet() -> Self {
        let mut state = match Self::new(Config::devnet(), DEVNET_HEIGHT, DEVNET_EPOCH) {
            Ok(state) => state,
            Err(_) => Self {
                config: Config::devnet(),
                current_height: DEVNET_HEIGHT,
                current_epoch: DEVNET_EPOCH,
                counters: Counters::empty(),
                bundles: BTreeMap::new(),
                sponsor_vaults: BTreeMap::new(),
                rebate_coupons: BTreeMap::new(),
                prover_reservations: BTreeMap::new(),
                dedup_anchors: BTreeMap::new(),
                fee_futures: BTreeMap::new(),
                da_vouchers: BTreeMap::new(),
                settlement_receipts: BTreeMap::new(),
                privacy_fences: BTreeMap::new(),
                slashing_evidence: BTreeMap::new(),
                bundle_nullifiers: BTreeSet::new(),
                coupon_nullifiers: BTreeSet::new(),
            },
        };
        let _ = state.seed_devnet();
        state
    }

    fn seed_devnet(&mut self) -> Result<()> {
        let fence = PrivacyFence {
            fence_id: privacy_fence_id("devnet-account", "devnet-nullifier-root", DEVNET_HEIGHT),
            account_commitment: "devnet-account".to_string(),
            nullifier_root: "devnet-nullifier-root".to_string(),
            membership_root: deterministic_root("devnet-membership", &[HashPart::Str(CHAIN_ID)]),
            decoy_set_root: deterministic_root("devnet-decoy-set", &[HashPart::Str("decoys")]),
            bundle_scope_root: deterministic_root(
                "devnet-bundle-scope",
                &[HashPart::Str("state-diff")],
            ),
            min_anonymity_set_size: self.config.target_privacy_set_size,
            spent_nullifiers: BTreeSet::new(),
            opened_at_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT + self.config.fence_ttl_blocks,
            status: FenceStatus::Active,
        };
        let fence_id = fence.fence_id.clone();
        self.upsert_privacy_fence(fence)?;

        let anchor = EncryptedCalldataDedupAnchor {
            anchor_id: dedup_anchor_id(
                StateDiffLaneKind::PrivateContractStorage,
                "devnet-encrypted-calldata",
                DEVNET_HEIGHT,
            ),
            lane: StateDiffLaneKind::PrivateContractStorage,
            encrypted_calldata_root: "devnet-encrypted-calldata".to_string(),
            dictionary_root: deterministic_root("devnet-dictionary", &[HashPart::Str("chunks")]),
            duplicate_set_root: deterministic_root(
                "devnet-duplicate-set",
                &[HashPart::Str("dedup")],
            ),
            ciphertext_sample_root: deterministic_root(
                "devnet-ciphertext-sample",
                &[HashPart::Str("sample")],
            ),
            membership_proof_root: deterministic_root(
                "devnet-dedup-membership",
                &[HashPart::Str("membership")],
            ),
            min_dedup_set_size: self.config.min_dedup_set_size,
            referenced_bundle_count: 1,
            saved_bytes: 24_576,
            opened_at_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT + self.config.dedup_anchor_ttl_blocks,
            status: AnchorStatus::Accepted,
        };
        let anchor_id = anchor.anchor_id.clone();
        self.upsert_dedup_anchor(anchor)?;

        let vault = SponsorVault {
            vault_id: sponsor_vault_id("devnet-sponsor", DEVNET_FEE_ASSET_ID, DEVNET_HEIGHT),
            sponsor_commitment: "devnet-sponsor".to_string(),
            asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            balance_commitment: "devnet-sponsor-balance".to_string(),
            available_micro_fee: 48_000_000,
            reserved_micro_fee: 3_200_000,
            covered_bundle_root: deterministic_root(
                "devnet-covered-bundles",
                &[HashPart::Str("bundle")],
            ),
            nullifier_root: deterministic_root(
                "devnet-vault-nullifier",
                &[HashPart::Str(CHAIN_ID)],
            ),
            min_privacy_set_size: self.config.min_privacy_set_size,
            max_state_diff_bytes: 1_048_576,
            cover_bps: self.config.sponsor_cover_bps,
            reserve_bps: self.config.sponsor_reserve_bps,
            opened_at_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT + self.config.vault_ttl_blocks,
            status: VaultStatus::Active,
        };
        let vault_id = vault.vault_id.clone();
        self.upsert_sponsor_vault(vault)?;

        let bundle = CompressedStateDiffBundle {
            bundle_id: state_diff_bundle_id(
                StateDiffLaneKind::PrivateContractStorage,
                "devnet-submitter",
                "devnet-prev-state",
                "devnet-post-state",
                DEVNET_HEIGHT,
            ),
            lane: StateDiffLaneKind::PrivateContractStorage,
            codec: CompressionCodec::ZstdFec,
            submitter_commitment: "devnet-submitter".to_string(),
            previous_state_root: "devnet-prev-state".to_string(),
            post_state_root: "devnet-post-state".to_string(),
            state_diff_commitment_root: deterministic_root(
                "devnet-state-diff",
                &[HashPart::Str("delta")],
            ),
            compressed_payload_root: deterministic_root(
                "devnet-compressed-payload",
                &[HashPart::Str("payload")],
            ),
            encrypted_calldata_root: "devnet-encrypted-calldata".to_string(),
            witness_commitment_root: deterministic_root(
                "devnet-witness",
                &[HashPart::Str("witness")],
            ),
            compression_proof_root: deterministic_root(
                "devnet-compression-proof",
                &[HashPart::Str("proof")],
            ),
            original_bytes: 131_072,
            compressed_bytes: 73_728,
            max_user_micro_fee: 900_000,
            sponsor_vault_id: Some(vault_id.clone()),
            dedup_anchor_id: Some(anchor_id.clone()),
            prover_reservation_id: None,
            da_voucher_id: None,
            privacy_fence_id: Some(fence_id.clone()),
            opened_at_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT + self.config.bundle_ttl_blocks,
            status: BundleStatus::Sponsored,
        };
        let bundle_id = bundle.bundle_id.clone();
        self.upsert_bundle(bundle)?;

        let reservation = ProverReservation {
            reservation_id: prover_reservation_id(&bundle_id, "devnet-prover", DEVNET_HEIGHT),
            bundle_id: bundle_id.clone(),
            prover_commitment: "devnet-prover".to_string(),
            prover_pool_root: deterministic_root("devnet-prover-pool", &[HashPart::Str("pool")]),
            witness_root: deterministic_root("devnet-prover-witness", &[HashPart::Str("witness")]),
            proving_system_root: deterministic_root(
                "devnet-proving-system",
                &[HashPart::Str("stark")],
            ),
            reserved_compute_units: 96_000,
            reserved_micro_fee: 480_000,
            security_bits: self.config.min_pq_security_bits,
            accepted_at_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT + self.config.prover_reservation_ttl_blocks,
            status: ReservationStatus::Accepted,
        };
        let reservation_id = reservation.reservation_id.clone();
        self.upsert_prover_reservation(reservation)?;

        let voucher = DaVoucher {
            voucher_id: da_voucher_id(&bundle_id, "devnet-da-committee", DEVNET_HEIGHT),
            bundle_id: bundle_id.clone(),
            da_committee_root: "devnet-da-committee".to_string(),
            erasure_commitment_root: deterministic_root("devnet-erasure", &[HashPart::Str("fec")]),
            sampling_receipt_root: deterministic_root(
                "devnet-sampling",
                &[HashPart::Str("samples")],
            ),
            byte_limit: 96_000,
            prepaid_micro_fee: 336_000,
            finality_height: DEVNET_HEIGHT + 8,
            issued_at_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT + self.config.da_voucher_ttl_blocks,
            status: VoucherStatus::Issued,
        };
        let voucher_id = voucher.voucher_id.clone();
        self.upsert_da_voucher(voucher)?;

        let future = FeeFuture {
            future_id: fee_future_id(&bundle_id, FutureSide::SponsorCovered, "devnet-sponsor"),
            bundle_id: bundle_id.clone(),
            side: FutureSide::SponsorCovered,
            owner_commitment: "devnet-sponsor".to_string(),
            quote_asset_id: DEVNET_QUOTE_ASSET_ID.to_string(),
            notional_micro_fee: 1_200_000,
            strike_micro_fee_per_byte: self.config.base_state_diff_micro_fee,
            margin_commitment: "devnet-margin".to_string(),
            oracle_rate_root: deterministic_root(
                "devnet-fee-oracle",
                &[HashPart::Str("state-diff-fee")],
            ),
            opened_at_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT + self.config.fee_future_ttl_blocks,
            status: FutureStatus::Hedged,
        };
        self.upsert_fee_future(future)?;

        let receipt = SettlementReceipt {
            receipt_id: settlement_receipt_id(&bundle_id, "devnet-settlement", DEVNET_HEIGHT + 8),
            bundle_id: bundle_id.clone(),
            sponsor_vault_id: Some(vault_id.clone()),
            prover_reservation_id: Some(reservation_id.clone()),
            da_voucher_id: Some(voucher_id.clone()),
            final_state_root: "devnet-post-state".to_string(),
            settlement_proof_root: deterministic_root(
                "devnet-settlement-proof",
                &[HashPart::Str("settled")],
            ),
            settlement_fee_micro: 1_080_000,
            sponsor_paid_micro: 972_000,
            user_paid_micro: 108_000,
            settled_at_height: DEVNET_HEIGHT + 8,
            challenge_expires_at_height: DEVNET_HEIGHT + 8 + self.config.challenge_window_blocks,
            status: ReceiptStatus::Finalized,
        };
        self.upsert_settlement_receipt(receipt)?;

        let coupon = RebateCoupon {
            coupon_id: rebate_coupon_id(
                &bundle_id,
                &vault_id,
                "devnet-recipient",
                DEVNET_HEIGHT + 9,
            ),
            bundle_id,
            sponsor_vault_id: vault_id,
            recipient_commitment: "devnet-recipient".to_string(),
            coupon_nullifier: deterministic_root(
                "devnet-coupon-nullifier",
                &[HashPart::Str("coupon")],
            ),
            rebate_micro_fee: 64_800,
            eligibility_root: deterministic_root(
                "devnet-eligibility",
                &[HashPart::Str("eligible")],
            ),
            pq_signature_root: deterministic_root(
                "devnet-coupon-sig",
                &[HashPart::Str(PQ_AUTH_SUITE)],
            ),
            issued_at_height: DEVNET_HEIGHT + 9,
            expires_at_height: DEVNET_HEIGHT + 9 + self.config.coupon_ttl_blocks,
            status: CouponStatus::Issued,
        };
        self.upsert_rebate_coupon(coupon)?;
        Ok(())
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: payload_root("STATE-DIFF-CONFIG", &self.config.public_record()),
            bundle_root: map_root(
                "STATE-DIFF-BUNDLES",
                &self.bundles,
                CompressedStateDiffBundle::public_record,
            ),
            sponsor_vault_root: map_root(
                "STATE-DIFF-SPONSOR-VAULTS",
                &self.sponsor_vaults,
                SponsorVault::public_record,
            ),
            rebate_coupon_root: map_root(
                "STATE-DIFF-REBATE-COUPONS",
                &self.rebate_coupons,
                RebateCoupon::public_record,
            ),
            prover_reservation_root: map_root(
                "STATE-DIFF-PROVER-RESERVATIONS",
                &self.prover_reservations,
                ProverReservation::public_record,
            ),
            dedup_anchor_root: map_root(
                "STATE-DIFF-DEDUP-ANCHORS",
                &self.dedup_anchors,
                EncryptedCalldataDedupAnchor::public_record,
            ),
            fee_future_root: map_root(
                "STATE-DIFF-FEE-FUTURES",
                &self.fee_futures,
                FeeFuture::public_record,
            ),
            da_voucher_root: map_root(
                "STATE-DIFF-DA-VOUCHERS",
                &self.da_vouchers,
                DaVoucher::public_record,
            ),
            settlement_receipt_root: map_root(
                "STATE-DIFF-SETTLEMENT-RECEIPTS",
                &self.settlement_receipts,
                SettlementReceipt::public_record,
            ),
            privacy_fence_root: map_root(
                "STATE-DIFF-PRIVACY-FENCES",
                &self.privacy_fences,
                PrivacyFence::public_record,
            ),
            slashing_evidence_root: map_root(
                "STATE-DIFF-SLASHING-EVIDENCE",
                &self.slashing_evidence,
                SlashingEvidence::public_record,
            ),
            nullifier_index_root: self.nullifier_index_root(),
            cross_index_root: self.cross_index_root(),
        }
    }

    pub fn counters(&self) -> Counters {
        let mut counters = self.counters.clone();
        counters.bundles = self.bundles.len() as u64;
        counters.sponsor_vaults = self.sponsor_vaults.len() as u64;
        counters.rebate_coupons = self.rebate_coupons.len() as u64;
        counters.prover_reservations = self.prover_reservations.len() as u64;
        counters.dedup_anchors = self.dedup_anchors.len() as u64;
        counters.fee_futures = self.fee_futures.len() as u64;
        counters.da_vouchers = self.da_vouchers.len() as u64;
        counters.settlement_receipts = self.settlement_receipts.len() as u64;
        counters.privacy_fences = self.privacy_fences.len() as u64;
        counters.slashing_evidence = self.slashing_evidence.len() as u64;
        counters.live_bundles = self
            .bundles
            .values()
            .filter(|bundle| bundle.status.live())
            .count() as u64;
        counters.active_reservations = self
            .prover_reservations
            .values()
            .filter(|reservation| reservation.status.active())
            .count() as u64;
        counters.open_fee_futures = self
            .fee_futures
            .values()
            .filter(|future| matches!(future.status, FutureStatus::Open | FutureStatus::Hedged))
            .count() as u64;
        counters.total_original_bytes = self
            .bundles
            .values()
            .map(|bundle| bundle.original_bytes as u128)
            .sum();
        counters.total_compressed_bytes = self
            .bundles
            .values()
            .map(|bundle| bundle.compressed_bytes as u128)
            .sum();
        counters.total_sponsored_micro_fee = self
            .sponsor_vaults
            .values()
            .map(|vault| vault.reserved_micro_fee)
            .sum();
        counters.total_rebated_micro_fee = self
            .rebate_coupons
            .values()
            .filter(|coupon| coupon.status.spendable())
            .map(|coupon| coupon.rebate_micro_fee)
            .sum();
        counters.total_reserved_prover_micro_fee = self
            .prover_reservations
            .values()
            .map(|reservation| reservation.reserved_micro_fee)
            .sum();
        counters.total_da_micro_fee = self
            .da_vouchers
            .values()
            .map(|voucher| voucher.prepaid_micro_fee)
            .sum();
        counters.total_slashed_micro_fee = self
            .slashing_evidence
            .values()
            .map(|evidence| evidence.slash_micro_fee)
            .sum();
        counters
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_auth_suite": PQ_AUTH_SUITE,
            "pq_sealing_suite": PQ_SEALING_SUITE,
            "state_diff_compression_suite": STATE_DIFF_COMPRESSION_SUITE,
            "current_height": self.current_height,
            "current_epoch": self.current_epoch,
            "config": self.config.public_record(),
            "counters": counters.public_record(),
            "roots": roots.public_record(),
        })
    }

    pub fn upsert_bundle(&mut self, bundle: CompressedStateDiffBundle) -> Result<()> {
        ensure!(
            self.bundles.len() < self.config.max_bundles
                || self.bundles.contains_key(&bundle.bundle_id),
            "bundle capacity exceeded"
        );
        ensure!(bundle.original_bytes > 0, "original bytes must be positive");
        ensure!(
            bundle.compressed_bytes > 0 && bundle.compressed_bytes <= bundle.original_bytes,
            "compressed bytes invalid"
        );
        ensure!(
            bundle.compression_savings_bps() >= self.config.compression_min_savings_bps,
            "compression savings below policy"
        );
        ensure!(
            bundle.expires_at_height > bundle.opened_at_height,
            "bundle expiry must be after opening"
        );
        if let Some(vault_id) = &bundle.sponsor_vault_id {
            ensure!(
                self.sponsor_vaults
                    .get(vault_id)
                    .map(|vault| vault.status.can_sponsor())
                    .unwrap_or(false),
                "sponsor vault unavailable"
            );
        }
        if let Some(anchor_id) = &bundle.dedup_anchor_id {
            ensure!(
                self.dedup_anchors
                    .get(anchor_id)
                    .map(|anchor| anchor.status.usable())
                    .unwrap_or(false),
                "dedup anchor unavailable"
            );
        }
        if let Some(fence_id) = &bundle.privacy_fence_id {
            ensure!(
                self.privacy_fences
                    .get(fence_id)
                    .map(|fence| fence.status.open())
                    .unwrap_or(false),
                "privacy fence unavailable"
            );
        }
        self.bundle_nullifiers
            .insert(bundle.state_diff_commitment_root.clone());
        self.current_height = self.current_height.max(bundle.opened_at_height);
        self.bundles.insert(bundle.bundle_id.clone(), bundle);
        Ok(())
    }

    pub fn upsert_sponsor_vault(&mut self, vault: SponsorVault) -> Result<()> {
        ensure!(
            self.sponsor_vaults.len() < self.config.max_sponsor_vaults
                || self.sponsor_vaults.contains_key(&vault.vault_id),
            "sponsor vault capacity exceeded"
        );
        ensure!(
            vault.asset_id == self.config.fee_asset_id,
            "unexpected fee asset"
        );
        ensure!(
            vault.available_micro_fee >= vault.reserved_micro_fee,
            "sponsor vault over reserved"
        );
        ensure!(vault.cover_bps <= MAX_BPS, "sponsor cover bps out of range");
        ensure!(
            vault.reserve_bps <= MAX_BPS,
            "sponsor reserve bps out of range"
        );
        ensure!(
            vault.min_privacy_set_size >= self.config.min_privacy_set_size,
            "sponsor privacy set too small"
        );
        ensure!(
            vault.expires_at_height > vault.opened_at_height,
            "sponsor vault expiry must be after opening"
        );
        self.current_height = self.current_height.max(vault.opened_at_height);
        self.sponsor_vaults.insert(vault.vault_id.clone(), vault);
        Ok(())
    }

    pub fn upsert_rebate_coupon(&mut self, coupon: RebateCoupon) -> Result<()> {
        ensure!(
            self.rebate_coupons.len() < self.config.max_rebate_coupons
                || self.rebate_coupons.contains_key(&coupon.coupon_id),
            "rebate coupon capacity exceeded"
        );
        ensure!(
            self.bundles.contains_key(&coupon.bundle_id),
            "rebate coupon bundle missing"
        );
        ensure!(
            self.sponsor_vaults.contains_key(&coupon.sponsor_vault_id),
            "rebate coupon sponsor missing"
        );
        ensure!(
            coupon.expires_at_height > coupon.issued_at_height,
            "rebate coupon expiry must be after issue"
        );
        ensure!(
            !self.coupon_nullifiers.contains(&coupon.coupon_nullifier)
                || self.rebate_coupons.contains_key(&coupon.coupon_id),
            "rebate coupon nullifier already used"
        );
        self.coupon_nullifiers
            .insert(coupon.coupon_nullifier.clone());
        self.current_height = self.current_height.max(coupon.issued_at_height);
        self.rebate_coupons.insert(coupon.coupon_id.clone(), coupon);
        Ok(())
    }

    pub fn upsert_prover_reservation(&mut self, reservation: ProverReservation) -> Result<()> {
        ensure!(
            self.prover_reservations.len() < self.config.max_prover_reservations
                || self
                    .prover_reservations
                    .contains_key(&reservation.reservation_id),
            "prover reservation capacity exceeded"
        );
        ensure!(
            self.bundles.contains_key(&reservation.bundle_id),
            "prover reservation bundle missing"
        );
        ensure!(
            reservation.security_bits >= self.config.min_pq_security_bits,
            "prover reservation pq security too low"
        );
        ensure!(
            reservation.reserved_compute_units > 0,
            "prover compute units must be positive"
        );
        ensure!(
            reservation.expires_at_height > reservation.accepted_at_height,
            "prover reservation expiry must be after acceptance"
        );
        self.current_height = self.current_height.max(reservation.accepted_at_height);
        self.prover_reservations
            .insert(reservation.reservation_id.clone(), reservation);
        Ok(())
    }

    pub fn upsert_dedup_anchor(&mut self, anchor: EncryptedCalldataDedupAnchor) -> Result<()> {
        ensure!(
            self.dedup_anchors.len() < self.config.max_dedup_anchors
                || self.dedup_anchors.contains_key(&anchor.anchor_id),
            "dedup anchor capacity exceeded"
        );
        ensure!(
            anchor.min_dedup_set_size >= self.config.min_dedup_set_size,
            "dedup anchor set too small"
        );
        ensure!(
            anchor.expires_at_height > anchor.opened_at_height,
            "dedup anchor expiry must be after opening"
        );
        self.current_height = self.current_height.max(anchor.opened_at_height);
        self.dedup_anchors.insert(anchor.anchor_id.clone(), anchor);
        Ok(())
    }

    pub fn upsert_fee_future(&mut self, future: FeeFuture) -> Result<()> {
        ensure!(
            self.fee_futures.len() < self.config.max_fee_futures
                || self.fee_futures.contains_key(&future.future_id),
            "fee future capacity exceeded"
        );
        ensure!(
            self.bundles.contains_key(&future.bundle_id),
            "fee future bundle missing"
        );
        ensure!(
            future.quote_asset_id == self.config.quote_asset_id,
            "fee future quote asset mismatch"
        );
        ensure!(
            future.notional_micro_fee > 0,
            "future notional must be positive"
        );
        ensure!(
            future.expires_at_height > future.opened_at_height,
            "fee future expiry must be after opening"
        );
        self.current_height = self.current_height.max(future.opened_at_height);
        self.fee_futures.insert(future.future_id.clone(), future);
        Ok(())
    }

    pub fn upsert_da_voucher(&mut self, voucher: DaVoucher) -> Result<()> {
        ensure!(
            self.da_vouchers.len() < self.config.max_da_vouchers
                || self.da_vouchers.contains_key(&voucher.voucher_id),
            "da voucher capacity exceeded"
        );
        ensure!(
            self.bundles.contains_key(&voucher.bundle_id),
            "da voucher bundle missing"
        );
        ensure!(
            voucher.byte_limit > 0,
            "da voucher byte limit must be positive"
        );
        ensure!(
            voucher.expires_at_height > voucher.issued_at_height,
            "da voucher expiry must be after issue"
        );
        ensure!(
            voucher.finality_height >= voucher.issued_at_height,
            "da voucher finality before issue"
        );
        self.current_height = self.current_height.max(voucher.issued_at_height);
        self.da_vouchers.insert(voucher.voucher_id.clone(), voucher);
        Ok(())
    }

    pub fn upsert_settlement_receipt(&mut self, receipt: SettlementReceipt) -> Result<()> {
        ensure!(
            self.settlement_receipts.len() < self.config.max_settlement_receipts
                || self.settlement_receipts.contains_key(&receipt.receipt_id),
            "settlement receipt capacity exceeded"
        );
        ensure!(
            self.bundles.contains_key(&receipt.bundle_id),
            "settlement receipt bundle missing"
        );
        if let Some(vault_id) = &receipt.sponsor_vault_id {
            ensure!(
                self.sponsor_vaults.contains_key(vault_id),
                "settlement sponsor vault missing"
            );
        }
        if let Some(reservation_id) = &receipt.prover_reservation_id {
            ensure!(
                self.prover_reservations.contains_key(reservation_id),
                "settlement prover reservation missing"
            );
        }
        if let Some(voucher_id) = &receipt.da_voucher_id {
            ensure!(
                self.da_vouchers
                    .get(voucher_id)
                    .map(|voucher| voucher.status.usable())
                    .unwrap_or(false),
                "settlement da voucher unavailable"
            );
        }
        ensure!(
            receipt.challenge_expires_at_height > receipt.settled_at_height,
            "settlement challenge window invalid"
        );
        self.current_height = self.current_height.max(receipt.settled_at_height);
        self.settlement_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        Ok(())
    }

    pub fn upsert_privacy_fence(&mut self, fence: PrivacyFence) -> Result<()> {
        ensure!(
            self.privacy_fences.len() < self.config.max_privacy_fences
                || self.privacy_fences.contains_key(&fence.fence_id),
            "privacy fence capacity exceeded"
        );
        ensure!(
            fence.min_anonymity_set_size >= self.config.min_nullifier_set_size,
            "privacy fence anonymity set too small"
        );
        ensure!(
            fence.expires_at_height > fence.opened_at_height,
            "privacy fence expiry must be after opening"
        );
        self.current_height = self.current_height.max(fence.opened_at_height);
        self.privacy_fences.insert(fence.fence_id.clone(), fence);
        Ok(())
    }

    pub fn upsert_slashing_evidence(&mut self, evidence: SlashingEvidence) -> Result<()> {
        ensure!(
            self.slashing_evidence.len() < self.config.max_slashing_evidence
                || self.slashing_evidence.contains_key(&evidence.evidence_id),
            "slashing evidence capacity exceeded"
        );
        ensure!(
            evidence.slash_micro_fee > 0,
            "slash amount must be positive"
        );
        if let Some(bundle_id) = &evidence.bundle_id {
            ensure!(
                self.bundles.contains_key(bundle_id),
                "slashing bundle missing"
            );
        }
        self.current_height = self.current_height.max(evidence.reported_at_height);
        self.slashing_evidence
            .insert(evidence.evidence_id.clone(), evidence);
        Ok(())
    }

    fn nullifier_index_root(&self) -> String {
        let record = json!({
            "bundle_nullifiers": self.bundle_nullifiers.iter().cloned().collect::<Vec<_>>(),
            "coupon_nullifiers": self.coupon_nullifiers.iter().cloned().collect::<Vec<_>>(),
            "privacy_fence_ids": self.privacy_fences.keys().cloned().collect::<Vec<_>>(),
        });
        payload_root("STATE-DIFF-NULLIFIER-INDEX", &record)
    }

    fn cross_index_root(&self) -> String {
        let record = json!({
            "bundle_ids": self.bundles.keys().cloned().collect::<Vec<_>>(),
            "sponsor_vault_ids": self.sponsor_vaults.keys().cloned().collect::<Vec<_>>(),
            "rebate_coupon_ids": self.rebate_coupons.keys().cloned().collect::<Vec<_>>(),
            "prover_reservation_ids": self.prover_reservations.keys().cloned().collect::<Vec<_>>(),
            "dedup_anchor_ids": self.dedup_anchors.keys().cloned().collect::<Vec<_>>(),
            "fee_future_ids": self.fee_futures.keys().cloned().collect::<Vec<_>>(),
            "da_voucher_ids": self.da_vouchers.keys().cloned().collect::<Vec<_>>(),
            "settlement_receipt_ids": self.settlement_receipts.keys().cloned().collect::<Vec<_>>(),
            "slashing_evidence_ids": self.slashing_evidence.keys().cloned().collect::<Vec<_>>(),
        });
        payload_root("STATE-DIFF-CROSS-INDEX", &record)
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
        "STATE-DIFF-SPONSOR-RUNTIME-STATE-ROOT",
        &[HashPart::Json(record)],
        32,
    )
}

fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

fn deterministic_root(label: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(label, parts, 32)
}

fn map_root<T, F>(domain: &str, values: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let records = values.values().map(public_record).collect::<Vec<_>>();
    merkle_root(domain, &records)
}

pub fn state_diff_bundle_id(
    lane: StateDiffLaneKind,
    submitter_commitment: &str,
    previous_state_root: &str,
    post_state_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "STATE-DIFF-BUNDLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str(submitter_commitment),
            HashPart::Str(previous_state_root),
            HashPart::Str(post_state_root),
            HashPart::U64(opened_at_height),
        ],
        32,
    )
}

pub fn sponsor_vault_id(sponsor_commitment: &str, asset_id: &str, opened_at_height: u64) -> String {
    domain_hash(
        "STATE-DIFF-SPONSOR-VAULT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(SPONSOR_VAULT_SCHEME),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(asset_id),
            HashPart::U64(opened_at_height),
        ],
        32,
    )
}

pub fn rebate_coupon_id(
    bundle_id: &str,
    sponsor_vault_id: &str,
    recipient_commitment: &str,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "STATE-DIFF-REBATE-COUPON-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(REBATE_COUPON_SCHEME),
            HashPart::Str(bundle_id),
            HashPart::Str(sponsor_vault_id),
            HashPart::Str(recipient_commitment),
            HashPart::U64(issued_at_height),
        ],
        32,
    )
}

pub fn prover_reservation_id(
    bundle_id: &str,
    prover_commitment: &str,
    accepted_at_height: u64,
) -> String {
    domain_hash(
        "STATE-DIFF-PROVER-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROVER_RESERVATION_SCHEME),
            HashPart::Str(bundle_id),
            HashPart::Str(prover_commitment),
            HashPart::U64(accepted_at_height),
        ],
        32,
    )
}

pub fn dedup_anchor_id(
    lane: StateDiffLaneKind,
    encrypted_calldata_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "STATE-DIFF-DEDUP-ANCHOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(ENCRYPTED_CALLDATA_DEDUP_SCHEME),
            HashPart::Str(lane.as_str()),
            HashPart::Str(encrypted_calldata_root),
            HashPart::U64(opened_at_height),
        ],
        32,
    )
}

pub fn fee_future_id(bundle_id: &str, side: FutureSide, owner_commitment: &str) -> String {
    domain_hash(
        "STATE-DIFF-FEE-FUTURE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(FEE_FUTURE_SCHEME),
            HashPart::Str(bundle_id),
            HashPart::Str(&format!("{side:?}")),
            HashPart::Str(owner_commitment),
        ],
        32,
    )
}

pub fn da_voucher_id(bundle_id: &str, da_committee_root: &str, issued_at_height: u64) -> String {
    domain_hash(
        "STATE-DIFF-DA-VOUCHER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(DA_VOUCHER_SCHEME),
            HashPart::Str(bundle_id),
            HashPart::Str(da_committee_root),
            HashPart::U64(issued_at_height),
        ],
        32,
    )
}

pub fn settlement_receipt_id(
    bundle_id: &str,
    settlement_proof_root: &str,
    settled_at_height: u64,
) -> String {
    domain_hash(
        "STATE-DIFF-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(SETTLEMENT_RECEIPT_SCHEME),
            HashPart::Str(bundle_id),
            HashPart::Str(settlement_proof_root),
            HashPart::U64(settled_at_height),
        ],
        32,
    )
}

pub fn privacy_fence_id(
    account_commitment: &str,
    nullifier_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "STATE-DIFF-PRIVACY-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVACY_FENCE_SCHEME),
            HashPart::Str(account_commitment),
            HashPart::Str(nullifier_root),
            HashPart::U64(opened_at_height),
        ],
        32,
    )
}

pub fn slashing_evidence_id(
    reason: SlashingReason,
    accused_commitment: &str,
    transcript_root: &str,
    reported_at_height: u64,
) -> String {
    domain_hash(
        "STATE-DIFF-SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(SLASHING_EVIDENCE_SCHEME),
            HashPart::Str(reason.as_str()),
            HashPart::Str(accused_commitment),
            HashPart::Str(transcript_root),
            HashPart::U64(reported_at_height),
        ],
        32,
    )
}
