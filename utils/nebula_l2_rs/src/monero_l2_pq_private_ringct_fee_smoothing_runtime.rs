use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2PqPrivateRingctFeeSmoothingRuntimeResult<T> = Result<T, String>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const MONERO_L2_PQ_PRIVATE_RINGCT_FEE_SMOOTHING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-ringct-fee-smoothing-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_RINGCT_FEE_SMOOTHING_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_REBATE_ASSET_ID: &str = "wxmr-fee-rebate-devnet";
pub const DEVNET_HEIGHT: u64 = 2_241_360;
pub const DEVNET_EPOCH: u64 = 4_669;
pub const SHIELDED_FEE_BUCKET_SCHEME: &str = "ringct-shielded-fee-bucket-root-v1";
pub const DECOY_AWARE_FEE_LANE_SCHEME: &str = "monero-decoy-aware-fee-lane-root-v1";
pub const PQ_OPERATOR_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256f-ringct-fee-smoothing-operator-attestation-v1";
pub const FEE_SMOOTHING_WINDOW_SCHEME: &str = "ringct-private-fee-smoothing-window-root-v1";
pub const LOW_FEE_REBATE_SCHEME: &str = "ringct-low-fee-rebate-commitment-root-v1";
pub const LINKABILITY_GUARD_COUNTER_SCHEME: &str = "ringct-fee-linkability-guard-counter-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str = "operator-safe-ringct-fee-smoothing-public-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_addresses_amounts_key_images_view_keys_or_recipient_graphs";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_WINDOW_BLOCKS: u64 = 96;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_BUCKET_TTL_BLOCKS: u64 = 5_760;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_MIN_RING_SIZE: u16 = 16;
pub const DEFAULT_MIN_DECOY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_DECOY_AGE_BUCKETS: u16 = 8;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_TARGET_FEE_BPS: u64 = 6;
pub const DEFAULT_MAX_FEE_SPIKE_BPS: u64 = 550;
pub const DEFAULT_REBATE_SHARE_BPS: u64 = 6_250;
pub const DEFAULT_OPERATOR_MARGIN_BPS: u64 = 80;
pub const DEFAULT_LINKABILITY_WARN_BPS: u16 = 125;
pub const DEFAULT_LINKABILITY_HALT_BPS: u16 = 275;
pub const DEFAULT_MAX_DECOY_AGE_SKEW_BPS: u16 = 450;
pub const DEFAULT_MIN_GUARD_SAMPLE_RATE_BPS: u16 = 200;
pub const DEFAULT_MIN_BUCKET_LIQUIDITY_PICONERO: u64 = 2_000_000_000;
pub const DEFAULT_LOW_FEE_CAP_PICONERO: u64 = 50_000;
pub const DEFAULT_SMOOTHING_RESERVE_TARGET_BPS: u64 = 1_600;
pub const MAX_SHIELDED_BUCKETS: usize = 1_048_576;
pub const MAX_DECOY_LANES: usize = 262_144;
pub const MAX_OPERATOR_ATTESTATIONS: usize = 1_048_576;
pub const MAX_SMOOTHING_WINDOWS: usize = 524_288;
pub const MAX_LOW_FEE_REBATES: usize = 2_097_152;
pub const MAX_LINKABILITY_COUNTERS: usize = 1_048_576;
pub const MAX_PUBLIC_SNAPSHOTS: usize = 524_288;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeLane {
    WalletTransfer,
    MerchantCheckout,
    BridgeDeposit,
    BridgeWithdrawal,
    DefiSettlement,
    ContractReceipt,
    TokenMintBurn,
    RecursiveProof,
    FastPreconfirmation,
    EmergencyEscape,
}

impl FeeLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletTransfer => "wallet_transfer",
            Self::MerchantCheckout => "merchant_checkout",
            Self::BridgeDeposit => "bridge_deposit",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::DefiSettlement => "defi_settlement",
            Self::ContractReceipt => "contract_receipt",
            Self::TokenMintBurn => "token_mint_burn",
            Self::RecursiveProof => "recursive_proof",
            Self::FastPreconfirmation => "fast_preconfirmation",
            Self::EmergencyEscape => "emergency_escape",
        }
    }

    pub fn decoy_weight(self) -> u64 {
        match self {
            Self::WalletTransfer => 10,
            Self::MerchantCheckout => 9,
            Self::BridgeDeposit => 8,
            Self::BridgeWithdrawal => 11,
            Self::DefiSettlement => 12,
            Self::ContractReceipt => 7,
            Self::TokenMintBurn => 6,
            Self::RecursiveProof => 5,
            Self::FastPreconfirmation => 8,
            Self::EmergencyEscape => 13,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketStatus {
    Proposed,
    Active,
    Filling,
    Smoothing,
    RebateOnly,
    Guarded,
    Frozen,
    Drained,
    Retired,
}

impl BucketStatus {
    pub fn usable(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Filling | Self::Smoothing | Self::RebateOnly | Self::Guarded
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Active => "active",
            Self::Filling => "filling",
            Self::Smoothing => "smoothing",
            Self::RebateOnly => "rebate_only",
            Self::Guarded => "guarded",
            Self::Frozen => "frozen",
            Self::Drained => "drained",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Proposed,
    Open,
    DecoyBalanced,
    Congested,
    Subsidized,
    GuardLimited,
    Paused,
    Retired,
}

impl LaneStatus {
    pub fn usable(self) -> bool {
        matches!(
            self,
            Self::Open | Self::DecoyBalanced | Self::Congested | Self::Subsidized
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowStatus {
    Scheduled,
    Open,
    Smoothing,
    Settling,
    RebateFinalized,
    GuardHalted,
    Expired,
    Cancelled,
}

impl WindowStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Scheduled | Self::Open | Self::Smoothing | Self::Settling
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Quoted,
    Reserved,
    Batched,
    Claimable,
    Claimed,
    Expired,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Quorum,
    StrongQuorum,
    Expired,
    Revoked,
    Rejected,
}

impl AttestationStatus {
    pub fn accepted(self) -> bool {
        matches!(self, Self::Quorum | Self::StrongQuorum)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardSeverity {
    Clear,
    Watch,
    Elevated,
    Halt,
}

impl GuardSeverity {
    pub fn from_score(score_bps: u16, warn_bps: u16, halt_bps: u16) -> Self {
        if score_bps >= halt_bps {
            Self::Halt
        } else if score_bps >= warn_bps.saturating_mul(2) {
            Self::Elevated
        } else if score_bps >= warn_bps {
            Self::Watch
        } else {
            Self::Clear
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub epoch_blocks: u64,
    pub window_blocks: u64,
    pub bucket_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub min_ring_size: u16,
    pub min_decoy_set_size: u64,
    pub min_decoy_age_buckets: u16,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub target_fee_bps: u64,
    pub max_fee_spike_bps: u64,
    pub rebate_share_bps: u64,
    pub operator_margin_bps: u64,
    pub smoothing_reserve_target_bps: u64,
    pub low_fee_cap_piconero: u64,
    pub min_bucket_liquidity_piconero: u64,
    pub linkability_warn_bps: u16,
    pub linkability_halt_bps: u16,
    pub max_decoy_age_skew_bps: u16,
    pub min_guard_sample_rate_bps: u16,
    pub privacy_boundary: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEVNET_REBATE_ASSET_ID.to_string(),
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            window_blocks: DEFAULT_WINDOW_BLOCKS,
            bucket_ttl_blocks: DEFAULT_BUCKET_TTL_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            min_ring_size: DEFAULT_MIN_RING_SIZE,
            min_decoy_set_size: DEFAULT_MIN_DECOY_SET_SIZE,
            min_decoy_age_buckets: DEFAULT_MIN_DECOY_AGE_BUCKETS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            target_fee_bps: DEFAULT_TARGET_FEE_BPS,
            max_fee_spike_bps: DEFAULT_MAX_FEE_SPIKE_BPS,
            rebate_share_bps: DEFAULT_REBATE_SHARE_BPS,
            operator_margin_bps: DEFAULT_OPERATOR_MARGIN_BPS,
            smoothing_reserve_target_bps: DEFAULT_SMOOTHING_RESERVE_TARGET_BPS,
            low_fee_cap_piconero: DEFAULT_LOW_FEE_CAP_PICONERO,
            min_bucket_liquidity_piconero: DEFAULT_MIN_BUCKET_LIQUIDITY_PICONERO,
            linkability_warn_bps: DEFAULT_LINKABILITY_WARN_BPS,
            linkability_halt_bps: DEFAULT_LINKABILITY_HALT_BPS,
            max_decoy_age_skew_bps: DEFAULT_MAX_DECOY_AGE_SKEW_BPS,
            min_guard_sample_rate_bps: DEFAULT_MIN_GUARD_SAMPLE_RATE_BPS,
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "epoch_blocks": self.epoch_blocks,
            "window_blocks": self.window_blocks,
            "bucket_ttl_blocks": self.bucket_ttl_blocks,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "min_ring_size": self.min_ring_size,
            "min_decoy_set_size": self.min_decoy_set_size,
            "min_decoy_age_buckets": self.min_decoy_age_buckets,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "target_fee_bps": self.target_fee_bps,
            "max_fee_spike_bps": self.max_fee_spike_bps,
            "rebate_share_bps": self.rebate_share_bps,
            "operator_margin_bps": self.operator_margin_bps,
            "smoothing_reserve_target_bps": self.smoothing_reserve_target_bps,
            "low_fee_cap_piconero": self.low_fee_cap_piconero,
            "min_bucket_liquidity_piconero": self.min_bucket_liquidity_piconero,
            "linkability_warn_bps": self.linkability_warn_bps,
            "linkability_halt_bps": self.linkability_halt_bps,
            "max_decoy_age_skew_bps": self.max_decoy_age_skew_bps,
            "min_guard_sample_rate_bps": self.min_guard_sample_rate_bps,
            "privacy_boundary": self.privacy_boundary,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub buckets_created: u64,
    pub lanes_registered: u64,
    pub attestations_recorded: u64,
    pub smoothing_windows_opened: u64,
    pub rebates_reserved: u64,
    pub rebates_claimed: u64,
    pub guard_counters_recorded: u64,
    pub public_snapshots_published: u64,
    pub gross_fee_piconero: u64,
    pub smoothed_fee_piconero: u64,
    pub rebate_piconero: u64,
    pub reserve_drawn_piconero: u64,
    pub guard_halts: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "buckets_created": self.buckets_created,
            "lanes_registered": self.lanes_registered,
            "attestations_recorded": self.attestations_recorded,
            "smoothing_windows_opened": self.smoothing_windows_opened,
            "rebates_reserved": self.rebates_reserved,
            "rebates_claimed": self.rebates_claimed,
            "guard_counters_recorded": self.guard_counters_recorded,
            "public_snapshots_published": self.public_snapshots_published,
            "gross_fee_piconero": self.gross_fee_piconero,
            "smoothed_fee_piconero": self.smoothed_fee_piconero,
            "rebate_piconero": self.rebate_piconero,
            "reserve_drawn_piconero": self.reserve_drawn_piconero,
            "guard_halts": self.guard_halts,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub bucket_root: String,
    pub lane_root: String,
    pub attestation_root: String,
    pub window_root: String,
    pub rebate_root: String,
    pub guard_counter_root: String,
    pub public_snapshot_root: String,
    pub counters_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "bucket_root": self.bucket_root,
            "lane_root": self.lane_root,
            "attestation_root": self.attestation_root,
            "window_root": self.window_root,
            "rebate_root": self.rebate_root,
            "guard_counter_root": self.guard_counter_root,
            "public_snapshot_root": self.public_snapshot_root,
            "counters_root": self.counters_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShieldedFeeBucket {
    pub bucket_id: String,
    pub status: BucketStatus,
    pub lane: FeeLane,
    pub epoch: u64,
    pub shielded_balance_commitment: String,
    pub available_piconero: u64,
    pub smoothing_reserve_piconero: u64,
    pub rebate_reserve_piconero: u64,
    pub decoy_set_root: String,
    pub ringct_output_root: String,
    pub fee_commitment_root: String,
    pub nullifier_root: String,
    pub guard_counter_id: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl ShieldedFeeBucket {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "status": self.status,
            "status_label": self.status.as_str(),
            "usable": self.status.usable(),
            "lane": self.lane,
            "lane_label": self.lane.as_str(),
            "epoch": self.epoch,
            "shielded_balance_commitment": self.shielded_balance_commitment,
            "available_piconero": self.available_piconero,
            "smoothing_reserve_piconero": self.smoothing_reserve_piconero,
            "rebate_reserve_piconero": self.rebate_reserve_piconero,
            "decoy_set_root": self.decoy_set_root,
            "ringct_output_root": self.ringct_output_root,
            "fee_commitment_root": self.fee_commitment_root,
            "nullifier_root": self.nullifier_root,
            "guard_counter_id": self.guard_counter_id,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DecoyAwareFeeLane {
    pub lane_id: String,
    pub lane: FeeLane,
    pub status: LaneStatus,
    pub min_ring_size: u16,
    pub min_decoy_set_size: u64,
    pub decoy_age_bucket_count: u16,
    pub fee_floor_piconero: u64,
    pub low_fee_cap_piconero: u64,
    pub target_fee_bps: u64,
    pub spike_limit_bps: u64,
    pub decoy_distribution_root: String,
    pub output_age_histogram_root: String,
    pub lane_policy_root: String,
    pub operator_set_root: String,
}

impl DecoyAwareFeeLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "lane": self.lane,
            "lane_label": self.lane.as_str(),
            "status": self.status,
            "usable": self.status.usable(),
            "min_ring_size": self.min_ring_size,
            "min_decoy_set_size": self.min_decoy_set_size,
            "decoy_age_bucket_count": self.decoy_age_bucket_count,
            "fee_floor_piconero": self.fee_floor_piconero,
            "low_fee_cap_piconero": self.low_fee_cap_piconero,
            "target_fee_bps": self.target_fee_bps,
            "spike_limit_bps": self.spike_limit_bps,
            "decoy_weight": self.lane.decoy_weight(),
            "decoy_distribution_root": self.decoy_distribution_root,
            "output_age_histogram_root": self.output_age_histogram_root,
            "lane_policy_root": self.lane_policy_root,
            "operator_set_root": self.operator_set_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqOperatorAttestation {
    pub attestation_id: String,
    pub operator_id: String,
    pub status: AttestationStatus,
    pub lane_id: String,
    pub bucket_root: String,
    pub window_root: String,
    pub guard_counter_root: String,
    pub min_security_bits: u16,
    pub pq_signature_root: String,
    pub transcript_hash: String,
    pub produced_at_height: u64,
    pub expires_at_height: u64,
}

impl PqOperatorAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "operator_id": self.operator_id,
            "status": self.status,
            "accepted": self.status.accepted(),
            "lane_id": self.lane_id,
            "bucket_root": self.bucket_root,
            "window_root": self.window_root,
            "guard_counter_root": self.guard_counter_root,
            "min_security_bits": self.min_security_bits,
            "pq_signature_root": self.pq_signature_root,
            "transcript_hash": self.transcript_hash,
            "produced_at_height": self.produced_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeSmoothingWindow {
    pub window_id: String,
    pub status: WindowStatus,
    pub lane_id: String,
    pub bucket_id: String,
    pub epoch: u64,
    pub opening_fee_index_bps: u64,
    pub target_fee_bps: u64,
    pub observed_fee_piconero: u64,
    pub smoothed_fee_piconero: u64,
    pub reserve_draw_piconero: u64,
    pub rebate_pool_piconero: u64,
    pub decoy_pressure_bps: u16,
    pub guard_counter_id: String,
    pub quote_root: String,
    pub receipt_root: String,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
}

impl FeeSmoothingWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "status": self.status,
            "live": self.status.live(),
            "lane_id": self.lane_id,
            "bucket_id": self.bucket_id,
            "epoch": self.epoch,
            "opening_fee_index_bps": self.opening_fee_index_bps,
            "target_fee_bps": self.target_fee_bps,
            "observed_fee_piconero": self.observed_fee_piconero,
            "smoothed_fee_piconero": self.smoothed_fee_piconero,
            "reserve_draw_piconero": self.reserve_draw_piconero,
            "rebate_pool_piconero": self.rebate_pool_piconero,
            "decoy_pressure_bps": self.decoy_pressure_bps,
            "guard_counter_id": self.guard_counter_id,
            "quote_root": self.quote_root,
            "receipt_root": self.receipt_root,
            "opened_at_height": self.opened_at_height,
            "closes_at_height": self.closes_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub status: RebateStatus,
    pub lane_id: String,
    pub window_id: String,
    pub bucket_id: String,
    pub wallet_commitment: String,
    pub fee_commitment: String,
    pub rebate_commitment: String,
    pub rebate_piconero: u64,
    pub capped_fee_piconero: u64,
    pub nullifier_hash: String,
    pub claim_root: String,
    pub produced_at_height: u64,
    pub expires_at_height: u64,
}

impl LowFeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "status": self.status,
            "lane_id": self.lane_id,
            "window_id": self.window_id,
            "bucket_id": self.bucket_id,
            "wallet_commitment": self.wallet_commitment,
            "fee_commitment": self.fee_commitment,
            "rebate_commitment": self.rebate_commitment,
            "rebate_piconero": self.rebate_piconero,
            "capped_fee_piconero": self.capped_fee_piconero,
            "nullifier_hash": self.nullifier_hash,
            "claim_root": self.claim_root,
            "produced_at_height": self.produced_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LinkabilityGuardCounter {
    pub counter_id: String,
    pub lane_id: String,
    pub window_id: String,
    pub severity: GuardSeverity,
    pub ring_intersection_count: u64,
    pub decoy_reuse_count: u64,
    pub view_tag_cluster_count: u64,
    pub amount_timing_bucket_count: u64,
    pub sampled_output_count: u64,
    pub max_linkability_score_bps: u16,
    pub decoy_age_skew_bps: u16,
    pub guard_sample_rate_bps: u16,
    pub halt: bool,
    pub counter_root: String,
    pub produced_at_height: u64,
}

impl LinkabilityGuardCounter {
    pub fn public_record(&self) -> Value {
        json!({
            "counter_id": self.counter_id,
            "lane_id": self.lane_id,
            "window_id": self.window_id,
            "severity": self.severity,
            "ring_intersection_count": self.ring_intersection_count,
            "decoy_reuse_count": self.decoy_reuse_count,
            "view_tag_cluster_count": self.view_tag_cluster_count,
            "amount_timing_bucket_count": self.amount_timing_bucket_count,
            "sampled_output_count": self.sampled_output_count,
            "max_linkability_score_bps": self.max_linkability_score_bps,
            "decoy_age_skew_bps": self.decoy_age_skew_bps,
            "guard_sample_rate_bps": self.guard_sample_rate_bps,
            "halt": self.halt,
            "counter_root": self.counter_root,
            "produced_at_height": self.produced_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeterministicPublicSnapshot {
    pub snapshot_id: String,
    pub epoch: u64,
    pub height: u64,
    pub active_bucket_count: u64,
    pub live_lane_count: u64,
    pub live_window_count: u64,
    pub accepted_attestation_count: u64,
    pub claimable_rebate_count: u64,
    pub guard_halt_count: u64,
    pub total_available_piconero: u64,
    pub total_rebate_piconero: u64,
    pub bucket_root: String,
    pub lane_root: String,
    pub window_root: String,
    pub rebate_root: String,
    pub guard_counter_root: String,
    pub operator_message_root: String,
}

impl DeterministicPublicSnapshot {
    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "epoch": self.epoch,
            "height": self.height,
            "active_bucket_count": self.active_bucket_count,
            "live_lane_count": self.live_lane_count,
            "live_window_count": self.live_window_count,
            "accepted_attestation_count": self.accepted_attestation_count,
            "claimable_rebate_count": self.claimable_rebate_count,
            "guard_halt_count": self.guard_halt_count,
            "total_available_piconero": self.total_available_piconero,
            "total_rebate_piconero": self.total_rebate_piconero,
            "bucket_root": self.bucket_root,
            "lane_root": self.lane_root,
            "window_root": self.window_root,
            "rebate_root": self.rebate_root,
            "guard_counter_root": self.guard_counter_root,
            "operator_message_root": self.operator_message_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateRequest {
    pub wallet_commitment: String,
    pub lane_id: String,
    pub window_id: String,
    pub bucket_id: String,
    pub observed_fee_piconero: u64,
    pub capped_fee_piconero: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub height: u64,
    pub epoch: u64,
    pub shielded_buckets: BTreeMap<String, ShieldedFeeBucket>,
    pub decoy_lanes: BTreeMap<String, DecoyAwareFeeLane>,
    pub operator_attestations: BTreeMap<String, PqOperatorAttestation>,
    pub smoothing_windows: BTreeMap<String, FeeSmoothingWindow>,
    pub low_fee_rebates: BTreeMap<String, LowFeeRebate>,
    pub linkability_counters: BTreeMap<String, LinkabilityGuardCounter>,
    pub public_snapshots: BTreeMap<String, DeterministicPublicSnapshot>,
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            height,
            epoch,
            shielded_buckets: BTreeMap::new(),
            decoy_lanes: BTreeMap::new(),
            operator_attestations: BTreeMap::new(),
            smoothing_windows: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            linkability_counters: BTreeMap::new(),
            public_snapshots: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn register_lane(
        &mut self,
        lane: DecoyAwareFeeLane,
    ) -> MoneroL2PqPrivateRingctFeeSmoothingRuntimeResult<()> {
        ensure!(
            self.decoy_lanes.len() < MAX_DECOY_LANES,
            "decoy lane capacity exceeded"
        );
        ensure!(!lane.lane_id.is_empty(), "lane id is required");
        ensure!(
            lane.min_ring_size >= self.config.min_ring_size,
            "lane ring size below runtime floor"
        );
        ensure!(
            lane.min_decoy_set_size >= self.config.min_decoy_set_size,
            "lane decoy set below runtime floor"
        );
        ensure!(
            lane.decoy_age_bucket_count >= self.config.min_decoy_age_buckets,
            "lane decoy age buckets below runtime floor"
        );
        ensure!(
            lane.target_fee_bps <= MAX_BPS && lane.spike_limit_bps <= MAX_BPS,
            "lane fee bps exceeds max"
        );
        let fresh = self
            .decoy_lanes
            .insert(lane.lane_id.clone(), lane)
            .is_none();
        if fresh {
            self.counters.lanes_registered = self.counters.lanes_registered.saturating_add(1);
        }
        self.refresh_roots();
        Ok(())
    }

    pub fn create_bucket(
        &mut self,
        bucket: ShieldedFeeBucket,
    ) -> MoneroL2PqPrivateRingctFeeSmoothingRuntimeResult<()> {
        ensure!(
            self.shielded_buckets.len() < MAX_SHIELDED_BUCKETS,
            "shielded bucket capacity exceeded"
        );
        ensure!(!bucket.bucket_id.is_empty(), "bucket id is required");
        ensure!(
            self.decoy_lanes
                .values()
                .any(|lane| lane.lane == bucket.lane && lane.status.usable()),
            "bucket lane is not open"
        );
        ensure!(
            bucket.available_piconero >= self.config.min_bucket_liquidity_piconero,
            "bucket liquidity below runtime floor"
        );
        ensure!(
            bucket.expires_at_height > bucket.opened_at_height,
            "bucket expiry must follow open height"
        );
        let fresh = self
            .shielded_buckets
            .insert(bucket.bucket_id.clone(), bucket)
            .is_none();
        if fresh {
            self.counters.buckets_created = self.counters.buckets_created.saturating_add(1);
        }
        self.refresh_roots();
        Ok(())
    }

    pub fn record_guard_counter(
        &mut self,
        mut counter: LinkabilityGuardCounter,
    ) -> MoneroL2PqPrivateRingctFeeSmoothingRuntimeResult<()> {
        ensure!(
            self.linkability_counters.len() < MAX_LINKABILITY_COUNTERS,
            "linkability counter capacity exceeded"
        );
        ensure!(!counter.counter_id.is_empty(), "counter id is required");
        ensure!(
            self.decoy_lanes.contains_key(&counter.lane_id),
            "guard lane is unknown"
        );
        ensure!(
            counter.guard_sample_rate_bps >= self.config.min_guard_sample_rate_bps,
            "guard sample rate below runtime floor"
        );
        ensure!(
            counter.decoy_age_skew_bps <= self.config.max_decoy_age_skew_bps,
            "decoy age skew exceeds runtime floor"
        );
        counter.severity = GuardSeverity::from_score(
            counter.max_linkability_score_bps,
            self.config.linkability_warn_bps,
            self.config.linkability_halt_bps,
        );
        counter.halt = matches!(counter.severity, GuardSeverity::Halt);
        let fresh = self
            .linkability_counters
            .insert(counter.counter_id.clone(), counter.clone())
            .is_none();
        if fresh {
            self.counters.guard_counters_recorded =
                self.counters.guard_counters_recorded.saturating_add(1);
        }
        if counter.halt {
            self.counters.guard_halts = self.counters.guard_halts.saturating_add(1);
        }
        self.refresh_roots();
        Ok(())
    }

    pub fn open_window(
        &mut self,
        window: FeeSmoothingWindow,
    ) -> MoneroL2PqPrivateRingctFeeSmoothingRuntimeResult<()> {
        ensure!(
            self.smoothing_windows.len() < MAX_SMOOTHING_WINDOWS,
            "smoothing window capacity exceeded"
        );
        ensure!(!window.window_id.is_empty(), "window id is required");
        ensure!(
            self.decoy_lanes.contains_key(&window.lane_id),
            "window lane is unknown"
        );
        ensure!(
            self.shielded_buckets.contains_key(&window.bucket_id),
            "window bucket is unknown"
        );
        ensure!(
            self.linkability_counters
                .contains_key(&window.guard_counter_id),
            "window guard counter is unknown"
        );
        ensure!(
            window.target_fee_bps <= MAX_BPS && window.opening_fee_index_bps <= MAX_BPS,
            "window fee bps exceeds max"
        );
        ensure!(
            window.closes_at_height > window.opened_at_height,
            "window close height must follow open height"
        );
        let fresh = self
            .smoothing_windows
            .insert(window.window_id.clone(), window.clone())
            .is_none();
        if fresh {
            self.counters.smoothing_windows_opened =
                self.counters.smoothing_windows_opened.saturating_add(1);
        }
        self.counters.gross_fee_piconero = self
            .counters
            .gross_fee_piconero
            .saturating_add(window.observed_fee_piconero);
        self.counters.smoothed_fee_piconero = self
            .counters
            .smoothed_fee_piconero
            .saturating_add(window.smoothed_fee_piconero);
        self.counters.reserve_drawn_piconero = self
            .counters
            .reserve_drawn_piconero
            .saturating_add(window.reserve_draw_piconero);
        self.refresh_roots();
        Ok(())
    }

    pub fn reserve_rebate(
        &mut self,
        request: RebateRequest,
    ) -> MoneroL2PqPrivateRingctFeeSmoothingRuntimeResult<LowFeeRebate> {
        ensure!(
            self.low_fee_rebates.len() < MAX_LOW_FEE_REBATES,
            "low fee rebate capacity exceeded"
        );
        ensure!(
            self.decoy_lanes.contains_key(&request.lane_id),
            "rebate lane is unknown"
        );
        ensure!(
            self.smoothing_windows.contains_key(&request.window_id),
            "rebate window is unknown"
        );
        ensure!(
            self.shielded_buckets.contains_key(&request.bucket_id),
            "rebate bucket is unknown"
        );
        ensure!(
            request.capped_fee_piconero <= self.config.low_fee_cap_piconero,
            "rebate capped fee exceeds runtime low fee cap"
        );
        let excess = request
            .observed_fee_piconero
            .saturating_sub(request.capped_fee_piconero);
        let rebate_piconero = mul_div(excess, self.config.rebate_share_bps, MAX_BPS);
        let seed = domain_hash(
            "MONERO-L2-PQ-RINGCT-FEE-SMOOTHING-REBATE-SEED",
            &[
                HashPart::Str(&request.wallet_commitment),
                HashPart::Str(&request.window_id),
                HashPart::U64(request.observed_fee_piconero),
                HashPart::U64(request.capped_fee_piconero),
            ],
            32,
        );
        let rebate = LowFeeRebate {
            rebate_id: deterministic_id("rebate", &seed),
            status: RebateStatus::Reserved,
            lane_id: request.lane_id,
            window_id: request.window_id,
            bucket_id: request.bucket_id,
            wallet_commitment: request.wallet_commitment.clone(),
            fee_commitment: deterministic_id("fee-commitment", &seed),
            rebate_commitment: deterministic_id("rebate-commitment", &seed),
            rebate_piconero,
            capped_fee_piconero: request.capped_fee_piconero,
            nullifier_hash: deterministic_id("rebate-nullifier", &seed),
            claim_root: deterministic_id("rebate-claim", &seed),
            produced_at_height: self.height,
            expires_at_height: self.height.saturating_add(self.config.rebate_ttl_blocks),
        };
        let fresh = self
            .low_fee_rebates
            .insert(rebate.rebate_id.clone(), rebate.clone())
            .is_none();
        if fresh {
            self.counters.rebates_reserved = self.counters.rebates_reserved.saturating_add(1);
        }
        self.counters.rebate_piconero = self
            .counters
            .rebate_piconero
            .saturating_add(rebate_piconero);
        self.refresh_roots();
        Ok(rebate)
    }

    pub fn claim_rebate(
        &mut self,
        rebate_id: &str,
    ) -> MoneroL2PqPrivateRingctFeeSmoothingRuntimeResult<()> {
        let rebate = self
            .low_fee_rebates
            .get_mut(rebate_id)
            .ok_or_else(|| format!("unknown rebate {rebate_id}"))?;
        ensure!(
            matches!(
                rebate.status,
                RebateStatus::Reserved | RebateStatus::Claimable
            ),
            "rebate is not claimable"
        );
        rebate.status = RebateStatus::Claimed;
        self.counters.rebates_claimed = self.counters.rebates_claimed.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn record_attestation(
        &mut self,
        attestation: PqOperatorAttestation,
    ) -> MoneroL2PqPrivateRingctFeeSmoothingRuntimeResult<()> {
        ensure!(
            self.operator_attestations.len() < MAX_OPERATOR_ATTESTATIONS,
            "operator attestation capacity exceeded"
        );
        ensure!(
            !attestation.attestation_id.is_empty(),
            "attestation id is required"
        );
        ensure!(
            self.decoy_lanes.contains_key(&attestation.lane_id),
            "attestation lane is unknown"
        );
        ensure!(
            attestation.min_security_bits >= self.config.min_pq_security_bits,
            "attestation security below runtime floor"
        );
        ensure!(
            attestation.expires_at_height > attestation.produced_at_height,
            "attestation expiry must follow production height"
        );
        let fresh = self
            .operator_attestations
            .insert(attestation.attestation_id.clone(), attestation)
            .is_none();
        if fresh {
            self.counters.attestations_recorded =
                self.counters.attestations_recorded.saturating_add(1);
        }
        self.refresh_roots();
        Ok(())
    }

    pub fn publish_snapshot(&mut self, snapshot: DeterministicPublicSnapshot) {
        let fresh = self
            .public_snapshots
            .insert(snapshot.snapshot_id.clone(), snapshot)
            .is_none();
        if fresh {
            self.counters.public_snapshots_published =
                self.counters.public_snapshots_published.saturating_add(1);
        }
        self.refresh_roots();
    }

    pub fn deterministic_snapshot(&self, label: &str) -> DeterministicPublicSnapshot {
        DeterministicPublicSnapshot {
            snapshot_id: deterministic_id("snapshot", label),
            epoch: self.epoch,
            height: self.height,
            active_bucket_count: self
                .shielded_buckets
                .values()
                .filter(|bucket| bucket.status.usable())
                .count() as u64,
            live_lane_count: self
                .decoy_lanes
                .values()
                .filter(|lane| lane.status.usable())
                .count() as u64,
            live_window_count: self
                .smoothing_windows
                .values()
                .filter(|window| window.status.live())
                .count() as u64,
            accepted_attestation_count: self
                .operator_attestations
                .values()
                .filter(|attestation| attestation.status.accepted())
                .count() as u64,
            claimable_rebate_count: self
                .low_fee_rebates
                .values()
                .filter(|rebate| {
                    matches!(
                        rebate.status,
                        RebateStatus::Reserved | RebateStatus::Claimable
                    )
                })
                .count() as u64,
            guard_halt_count: self
                .linkability_counters
                .values()
                .filter(|counter| counter.halt)
                .count() as u64,
            total_available_piconero: self
                .shielded_buckets
                .values()
                .map(|bucket| bucket.available_piconero)
                .sum(),
            total_rebate_piconero: self
                .low_fee_rebates
                .values()
                .map(|rebate| rebate.rebate_piconero)
                .sum(),
            bucket_root: self.roots.bucket_root.clone(),
            lane_root: self.roots.lane_root.clone(),
            window_root: self.roots.window_root.clone(),
            rebate_root: self.roots.rebate_root.clone(),
            guard_counter_root: self.roots.guard_counter_root.clone(),
            operator_message_root: deterministic_id("operator-message", label),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "epoch": self.epoch,
            "hash_suite": HASH_SUITE,
            "schemes": {
                "shielded_fee_bucket": SHIELDED_FEE_BUCKET_SCHEME,
                "decoy_aware_fee_lane": DECOY_AWARE_FEE_LANE_SCHEME,
                "pq_operator_attestation": PQ_OPERATOR_ATTESTATION_SCHEME,
                "fee_smoothing_window": FEE_SMOOTHING_WINDOW_SCHEME,
                "low_fee_rebate": LOW_FEE_REBATE_SCHEME,
                "linkability_guard_counter": LINKABILITY_GUARD_COUNTER_SCHEME,
                "public_record": PUBLIC_RECORD_SCHEME,
            },
            "privacy_boundary": self.config.privacy_boundary,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "counts": {
                "shielded_buckets": self.shielded_buckets.len(),
                "decoy_lanes": self.decoy_lanes.len(),
                "operator_attestations": self.operator_attestations.len(),
                "smoothing_windows": self.smoothing_windows.len(),
                "low_fee_rebates": self.low_fee_rebates.len(),
                "linkability_counters": self.linkability_counters.len(),
                "public_snapshots": self.public_snapshots.len(),
            },
            "shielded_buckets": self
                .shielded_buckets
                .values()
                .map(ShieldedFeeBucket::public_record)
                .collect::<Vec<_>>(),
            "decoy_lanes": self
                .decoy_lanes
                .values()
                .map(DecoyAwareFeeLane::public_record)
                .collect::<Vec<_>>(),
            "operator_attestations": self
                .operator_attestations
                .values()
                .map(PqOperatorAttestation::public_record)
                .collect::<Vec<_>>(),
            "smoothing_windows": self
                .smoothing_windows
                .values()
                .map(FeeSmoothingWindow::public_record)
                .collect::<Vec<_>>(),
            "low_fee_rebates": self
                .low_fee_rebates
                .values()
                .map(LowFeeRebate::public_record)
                .collect::<Vec<_>>(),
            "linkability_counters": self
                .linkability_counters
                .values()
                .map(LinkabilityGuardCounter::public_record)
                .collect::<Vec<_>>(),
            "public_snapshots": self
                .public_snapshots
                .values()
                .map(DeterministicPublicSnapshot::public_record)
                .collect::<Vec<_>>(),
        })
    }

    pub fn refresh_roots(&mut self) {
        self.roots.config_root = merkle_root(
            "RINGCT-FEE-SMOOTHING-CONFIG",
            &[self.config.public_record()],
        );
        self.roots.bucket_root = merkle_root(
            SHIELDED_FEE_BUCKET_SCHEME,
            &self
                .shielded_buckets
                .values()
                .map(ShieldedFeeBucket::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.lane_root = merkle_root(
            DECOY_AWARE_FEE_LANE_SCHEME,
            &self
                .decoy_lanes
                .values()
                .map(DecoyAwareFeeLane::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.attestation_root = merkle_root(
            PQ_OPERATOR_ATTESTATION_SCHEME,
            &self
                .operator_attestations
                .values()
                .map(PqOperatorAttestation::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.window_root = merkle_root(
            FEE_SMOOTHING_WINDOW_SCHEME,
            &self
                .smoothing_windows
                .values()
                .map(FeeSmoothingWindow::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.rebate_root = merkle_root(
            LOW_FEE_REBATE_SCHEME,
            &self
                .low_fee_rebates
                .values()
                .map(LowFeeRebate::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.guard_counter_root = merkle_root(
            LINKABILITY_GUARD_COUNTER_SCHEME,
            &self
                .linkability_counters
                .values()
                .map(LinkabilityGuardCounter::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.public_snapshot_root = merkle_root(
            PUBLIC_RECORD_SCHEME,
            &self
                .public_snapshots
                .values()
                .map(DeterministicPublicSnapshot::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.counters_root = merkle_root(
            "RINGCT-FEE-SMOOTHING-COUNTERS",
            &[self.counters.public_record()],
        );
        self.roots.public_record_root = domain_hash(
            "RINGCT-FEE-SMOOTHING-PUBLIC-RECORD-ROOT",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(self.height),
                HashPart::U64(self.epoch),
                HashPart::Str(&self.roots.config_root),
                HashPart::Str(&self.roots.bucket_root),
                HashPart::Str(&self.roots.lane_root),
                HashPart::Str(&self.roots.attestation_root),
                HashPart::Str(&self.roots.window_root),
                HashPart::Str(&self.roots.rebate_root),
                HashPart::Str(&self.roots.guard_counter_root),
                HashPart::Str(&self.roots.public_snapshot_root),
                HashPart::Str(&self.roots.counters_root),
            ],
            32,
        );
        self.roots.state_root = domain_hash(
            "RINGCT-FEE-SMOOTHING-STATE-ROOT",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(CHAIN_ID),
                HashPart::U64(SCHEMA_VERSION),
                HashPart::U64(self.height),
                HashPart::U64(self.epoch),
                HashPart::Str(&self.roots.public_record_root),
            ],
            32,
        );
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }
}

pub fn devnet() -> State {
    let mut state = State::new(Config::default(), DEVNET_HEIGHT, DEVNET_EPOCH);
    let wallet_lane_id = deterministic_id("lane", FeeLane::WalletTransfer.as_str());
    let bridge_lane_id = deterministic_id("lane", FeeLane::BridgeWithdrawal.as_str());
    let emergency_lane_id = deterministic_id("lane", FeeLane::EmergencyEscape.as_str());

    for (lane_id, lane, status, fee_floor, cap) in [
        (
            wallet_lane_id.clone(),
            FeeLane::WalletTransfer,
            LaneStatus::DecoyBalanced,
            8_000,
            DEFAULT_LOW_FEE_CAP_PICONERO,
        ),
        (
            bridge_lane_id.clone(),
            FeeLane::BridgeWithdrawal,
            LaneStatus::Subsidized,
            32_000,
            90_000,
        ),
        (
            emergency_lane_id.clone(),
            FeeLane::EmergencyEscape,
            LaneStatus::GuardLimited,
            120_000,
            180_000,
        ),
    ] {
        state
            .register_lane(DecoyAwareFeeLane {
                lane_id: lane_id.clone(),
                lane,
                status,
                min_ring_size: DEFAULT_MIN_RING_SIZE,
                min_decoy_set_size: DEFAULT_MIN_DECOY_SET_SIZE,
                decoy_age_bucket_count: DEFAULT_MIN_DECOY_AGE_BUCKETS + 2,
                fee_floor_piconero: fee_floor,
                low_fee_cap_piconero: cap,
                target_fee_bps: DEFAULT_TARGET_FEE_BPS,
                spike_limit_bps: DEFAULT_MAX_FEE_SPIKE_BPS,
                decoy_distribution_root: deterministic_id("decoy-distribution", &lane_id),
                output_age_histogram_root: deterministic_id("output-age-histogram", &lane_id),
                lane_policy_root: deterministic_id("lane-policy", &lane_id),
                operator_set_root: deterministic_id("operator-set", &lane_id),
            })
            .expect("devnet lane");
    }

    let wallet_counter_id = deterministic_id("guard-counter", "wallet-devnet");
    state
        .record_guard_counter(LinkabilityGuardCounter {
            counter_id: wallet_counter_id.clone(),
            lane_id: wallet_lane_id.clone(),
            window_id: deterministic_id("pending-window", "wallet-devnet"),
            severity: GuardSeverity::Clear,
            ring_intersection_count: 2,
            decoy_reuse_count: 7,
            view_tag_cluster_count: 3,
            amount_timing_bucket_count: 11,
            sampled_output_count: 98_304,
            max_linkability_score_bps: 72,
            decoy_age_skew_bps: 180,
            guard_sample_rate_bps: 275,
            halt: false,
            counter_root: deterministic_id("counter-root", "wallet-devnet"),
            produced_at_height: DEVNET_HEIGHT - 4,
        })
        .expect("devnet wallet counter");

    let bridge_counter_id = deterministic_id("guard-counter", "bridge-devnet");
    state
        .record_guard_counter(LinkabilityGuardCounter {
            counter_id: bridge_counter_id.clone(),
            lane_id: bridge_lane_id.clone(),
            window_id: deterministic_id("pending-window", "bridge-devnet"),
            severity: GuardSeverity::Watch,
            ring_intersection_count: 4,
            decoy_reuse_count: 15,
            view_tag_cluster_count: 8,
            amount_timing_bucket_count: 19,
            sampled_output_count: 131_072,
            max_linkability_score_bps: 138,
            decoy_age_skew_bps: 260,
            guard_sample_rate_bps: 325,
            halt: false,
            counter_root: deterministic_id("counter-root", "bridge-devnet"),
            produced_at_height: DEVNET_HEIGHT - 3,
        })
        .expect("devnet bridge counter");

    let wallet_bucket_id = deterministic_id("bucket", "wallet-devnet");
    state
        .create_bucket(ShieldedFeeBucket {
            bucket_id: wallet_bucket_id.clone(),
            status: BucketStatus::Smoothing,
            lane: FeeLane::WalletTransfer,
            epoch: DEVNET_EPOCH,
            shielded_balance_commitment: deterministic_id("shielded-balance", &wallet_bucket_id),
            available_piconero: 9_600_000_000,
            smoothing_reserve_piconero: 1_920_000_000,
            rebate_reserve_piconero: 840_000_000,
            decoy_set_root: deterministic_id("bucket-decoys", &wallet_bucket_id),
            ringct_output_root: deterministic_id("bucket-ringct-outputs", &wallet_bucket_id),
            fee_commitment_root: deterministic_id("bucket-fees", &wallet_bucket_id),
            nullifier_root: deterministic_id("bucket-nullifiers", &wallet_bucket_id),
            guard_counter_id: wallet_counter_id.clone(),
            opened_at_height: DEVNET_HEIGHT - 48,
            expires_at_height: DEVNET_HEIGHT + DEFAULT_BUCKET_TTL_BLOCKS,
        })
        .expect("devnet wallet bucket");

    let bridge_bucket_id = deterministic_id("bucket", "bridge-devnet");
    state
        .create_bucket(ShieldedFeeBucket {
            bucket_id: bridge_bucket_id.clone(),
            status: BucketStatus::Guarded,
            lane: FeeLane::BridgeWithdrawal,
            epoch: DEVNET_EPOCH,
            shielded_balance_commitment: deterministic_id("shielded-balance", &bridge_bucket_id),
            available_piconero: 18_400_000_000,
            smoothing_reserve_piconero: 4_100_000_000,
            rebate_reserve_piconero: 1_250_000_000,
            decoy_set_root: deterministic_id("bucket-decoys", &bridge_bucket_id),
            ringct_output_root: deterministic_id("bucket-ringct-outputs", &bridge_bucket_id),
            fee_commitment_root: deterministic_id("bucket-fees", &bridge_bucket_id),
            nullifier_root: deterministic_id("bucket-nullifiers", &bridge_bucket_id),
            guard_counter_id: bridge_counter_id.clone(),
            opened_at_height: DEVNET_HEIGHT - 96,
            expires_at_height: DEVNET_HEIGHT + DEFAULT_BUCKET_TTL_BLOCKS,
        })
        .expect("devnet bridge bucket");

    let wallet_window_id = deterministic_id("window", "wallet-devnet");
    state
        .open_window(FeeSmoothingWindow {
            window_id: wallet_window_id.clone(),
            status: WindowStatus::Smoothing,
            lane_id: wallet_lane_id.clone(),
            bucket_id: wallet_bucket_id.clone(),
            epoch: DEVNET_EPOCH,
            opening_fee_index_bps: 326,
            target_fee_bps: DEFAULT_TARGET_FEE_BPS,
            observed_fee_piconero: 118_000,
            smoothed_fee_piconero: 48_000,
            reserve_draw_piconero: 70_000,
            rebate_pool_piconero: 43_750,
            decoy_pressure_bps: 180,
            guard_counter_id: wallet_counter_id.clone(),
            quote_root: deterministic_id("window-quotes", &wallet_window_id),
            receipt_root: deterministic_id("window-receipts", &wallet_window_id),
            opened_at_height: DEVNET_HEIGHT - 8,
            closes_at_height: DEVNET_HEIGHT + DEFAULT_WINDOW_BLOCKS,
        })
        .expect("devnet wallet window");

    let bridge_window_id = deterministic_id("window", "bridge-devnet");
    state
        .open_window(FeeSmoothingWindow {
            window_id: bridge_window_id.clone(),
            status: WindowStatus::Settling,
            lane_id: bridge_lane_id.clone(),
            bucket_id: bridge_bucket_id.clone(),
            epoch: DEVNET_EPOCH,
            opening_fee_index_bps: 488,
            target_fee_bps: DEFAULT_TARGET_FEE_BPS,
            observed_fee_piconero: 240_000,
            smoothed_fee_piconero: 86_000,
            reserve_draw_piconero: 154_000,
            rebate_pool_piconero: 96_250,
            decoy_pressure_bps: 260,
            guard_counter_id: bridge_counter_id.clone(),
            quote_root: deterministic_id("window-quotes", &bridge_window_id),
            receipt_root: deterministic_id("window-receipts", &bridge_window_id),
            opened_at_height: DEVNET_HEIGHT - 12,
            closes_at_height: DEVNET_HEIGHT + DEFAULT_WINDOW_BLOCKS,
        })
        .expect("devnet bridge window");

    let wallet_rebate = state
        .reserve_rebate(RebateRequest {
            wallet_commitment: deterministic_id("wallet", "devnet-001"),
            lane_id: wallet_lane_id.clone(),
            window_id: wallet_window_id.clone(),
            bucket_id: wallet_bucket_id.clone(),
            observed_fee_piconero: 118_000,
            capped_fee_piconero: 38_000,
        })
        .expect("devnet wallet rebate");
    state
        .reserve_rebate(RebateRequest {
            wallet_commitment: deterministic_id("wallet", "devnet-bridge-001"),
            lane_id: bridge_lane_id.clone(),
            window_id: bridge_window_id.clone(),
            bucket_id: bridge_bucket_id.clone(),
            observed_fee_piconero: 240_000,
            capped_fee_piconero: 72_000,
        })
        .expect("devnet bridge rebate");
    state
        .claim_rebate(&wallet_rebate.rebate_id)
        .expect("devnet claimed rebate");

    let lane_set = BTreeSet::from([wallet_lane_id.clone(), bridge_lane_id.clone()]);
    let lane_set_root = merkle_root(
        "RINGCT-FEE-SMOOTHING-DEVNET-LANE-SET",
        &lane_set
            .iter()
            .map(|lane_id| json!({ "lane_id": lane_id }))
            .collect::<Vec<_>>(),
    );
    state
        .record_attestation(PqOperatorAttestation {
            attestation_id: deterministic_id("attestation", "devnet-primary"),
            operator_id: "ringct-fee-smoothing-operator-devnet-0".to_string(),
            status: AttestationStatus::StrongQuorum,
            lane_id: wallet_lane_id,
            bucket_root: state.roots.bucket_root.clone(),
            window_root: state.roots.window_root.clone(),
            guard_counter_root: state.roots.guard_counter_root.clone(),
            min_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            pq_signature_root: deterministic_id("pq-signature", &lane_set_root),
            transcript_hash: deterministic_id("attestation-transcript", &lane_set_root),
            produced_at_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT + DEFAULT_ATTESTATION_TTL_BLOCKS,
        })
        .expect("devnet attestation");

    let snapshot = state.deterministic_snapshot("devnet-public");
    state.publish_snapshot(snapshot);
    state.refresh_roots();
    state
}

pub fn demo() -> State {
    devnet()
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

fn mul_div(value: u64, numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    ((value as u128)
        .saturating_mul(numerator as u128)
        .saturating_div(denominator as u128)) as u64
}

fn deterministic_id(domain: &str, seed: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-RINGCT-FEE-SMOOTHING-DETERMINISTIC-ID",
        &[HashPart::Str(domain), HashPart::Str(seed)],
        32,
    )
}
