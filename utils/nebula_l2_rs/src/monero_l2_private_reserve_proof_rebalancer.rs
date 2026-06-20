use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2PrivateReserveProofRebalancerResult<T> = Result<T, String>;

pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-private-reserve-proof-rebalancer-v1";
pub const PROTOCOL_VERSION: &str = MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_PROTOCOL_VERSION;
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_SCHEMA_VERSION: u64 = 1;
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEVNET_HEIGHT: u64 = 192_000;
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_RESERVE_PROOF_SCHEME: &str =
    "roots-only-monero-private-reserve-proof-v1";
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_WATCHER_QUORUM_SCHEME: &str =
    "pq-watcher-quorum-attestation-root-v1";
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_REBALANCE_COMMITMENT_SCHEME: &str =
    "private-rebalance-intent-commitment-root-v1";
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_LP_MOVE_SCHEME: &str =
    "lp-reserve-move-commitment-root-v1";
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_SETTLEMENT_RECEIPT_SCHEME: &str =
    "private-reserve-rebalance-settlement-receipt-root-v1";
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_LOW_FEE_SPONSOR_SCHEME: &str =
    "low-fee-private-reserve-rebalance-sponsor-root-v1";
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_NULLIFIER_SCHEME: &str =
    "reserve-proof-rebalance-nullifier-root-v1";
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 8_192;
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEFAULT_MIN_WATCHER_WEIGHT: u64 = 5;
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEFAULT_MIN_WATCHER_COUNT: u64 = 3;
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEFAULT_MIN_RESERVE_FLOOR_BPS: u64 = 10_500;
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEFAULT_TARGET_RESERVE_BPS: u64 = 12_000;
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEFAULT_EMERGENCY_FLOOR_BPS: u64 = 10_100;
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEFAULT_MAX_LANE_EXPOSURE_BPS: u64 = 2_500;
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEFAULT_MAX_PROVIDER_EXPOSURE_BPS: u64 = 1_500;
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEFAULT_STANDARD_FEE_BPS: u64 = 35;
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEFAULT_LOW_FEE_BPS: u64 = 8;
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEFAULT_SPONSOR_COVER_BPS: u64 = 8_000;
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEFAULT_OBSERVATION_TTL_BLOCKS: u64 = 96;
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEFAULT_REBALANCE_TTL_BLOCKS: u64 = 48;
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 192;
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEFAULT_REPLAY_FENCE_TTL_BLOCKS: u64 = 512;
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_MAX_BPS: u64 = 10_000;
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_MAX_OBSERVATIONS: usize = 262_144;
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_MAX_QUORUMS: usize = 262_144;
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_MAX_COMMITMENTS: usize = 262_144;
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_MAX_MOVES: usize = 262_144;
pub const MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_MAX_RECEIPTS: usize = 262_144;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveProofKind {
    ViewKeyReserve,
    DecoySetSolvency,
    ThresholdVault,
    FastExitLiquidity,
    EmergencyReserve,
}

impl ReserveProofKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ViewKeyReserve => "view_key_reserve",
            Self::DecoySetSolvency => "decoy_set_solvency",
            Self::ThresholdVault => "threshold_vault",
            Self::FastExitLiquidity => "fast_exit_liquidity",
            Self::EmergencyReserve => "emergency_reserve",
        }
    }

    pub fn requires_emergency_floor(self) -> bool {
        matches!(self, Self::EmergencyReserve | Self::FastExitLiquidity)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebalanceAction {
    TopUpFastExitLane,
    DrainHotReserve,
    RotateReserveSubaddress,
    MoveToLpVault,
    MoveFromLpVault,
    SponsorLowFeeExits,
    PauseLane,
}

impl RebalanceAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TopUpFastExitLane => "top_up_fast_exit_lane",
            Self::DrainHotReserve => "drain_hot_reserve",
            Self::RotateReserveSubaddress => "rotate_reserve_subaddress",
            Self::MoveToLpVault => "move_to_lp_vault",
            Self::MoveFromLpVault => "move_from_lp_vault",
            Self::SponsorLowFeeExits => "sponsor_low_fee_exits",
            Self::PauseLane => "pause_lane",
        }
    }

    pub fn requires_sponsor(self) -> bool {
        matches!(self, Self::SponsorLowFeeExits)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuorumStatus {
    Pending,
    Accepted,
    Rejected,
    Expired,
}

impl QuorumStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Scheduled,
    Settled,
    Failed,
    Expired,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Settled => "settled",
            Self::Failed => "failed",
            Self::Expired => "expired",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Failed | Self::Expired)
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
    pub hash_suite: String,
    pub reserve_proof_scheme: String,
    pub watcher_quorum_scheme: String,
    pub rebalance_commitment_scheme: String,
    pub lp_move_scheme: String,
    pub settlement_receipt_scheme: String,
    pub low_fee_sponsor_scheme: String,
    pub nullifier_scheme: String,
    pub genesis_height: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub min_watcher_weight: u64,
    pub min_watcher_count: u64,
    pub min_reserve_floor_bps: u64,
    pub target_reserve_bps: u64,
    pub emergency_floor_bps: u64,
    pub max_lane_exposure_bps: u64,
    pub max_provider_exposure_bps: u64,
    pub standard_fee_bps: u64,
    pub low_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub observation_ttl_blocks: u64,
    pub rebalance_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub replay_fence_ttl_blocks: u64,
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
            schema_version: MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_SCHEMA_VERSION,
            monero_network: MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEVNET_MONERO_NETWORK
                .to_string(),
            l2_network: MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEVNET_L2_NETWORK.to_string(),
            asset_id: MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEVNET_FEE_ASSET_ID
                .to_string(),
            hash_suite: MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_HASH_SUITE.to_string(),
            reserve_proof_scheme: MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_RESERVE_PROOF_SCHEME
                .to_string(),
            watcher_quorum_scheme: MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_WATCHER_QUORUM_SCHEME
                .to_string(),
            rebalance_commitment_scheme:
                MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_REBALANCE_COMMITMENT_SCHEME.to_string(),
            lp_move_scheme: MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_LP_MOVE_SCHEME.to_string(),
            settlement_receipt_scheme:
                MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_SETTLEMENT_RECEIPT_SCHEME.to_string(),
            low_fee_sponsor_scheme:
                MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_LOW_FEE_SPONSOR_SCHEME.to_string(),
            nullifier_scheme: MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_NULLIFIER_SCHEME
                .to_string(),
            genesis_height: MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEVNET_HEIGHT,
            min_privacy_set_size:
                MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits:
                MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEFAULT_TARGET_PQ_SECURITY_BITS,
            min_watcher_weight:
                MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEFAULT_MIN_WATCHER_WEIGHT,
            min_watcher_count: MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEFAULT_MIN_WATCHER_COUNT,
            min_reserve_floor_bps:
                MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEFAULT_MIN_RESERVE_FLOOR_BPS,
            target_reserve_bps:
                MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEFAULT_TARGET_RESERVE_BPS,
            emergency_floor_bps:
                MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEFAULT_EMERGENCY_FLOOR_BPS,
            max_lane_exposure_bps:
                MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEFAULT_MAX_LANE_EXPOSURE_BPS,
            max_provider_exposure_bps:
                MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEFAULT_MAX_PROVIDER_EXPOSURE_BPS,
            standard_fee_bps: MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEFAULT_STANDARD_FEE_BPS,
            low_fee_bps: MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEFAULT_LOW_FEE_BPS,
            sponsor_cover_bps: MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEFAULT_SPONSOR_COVER_BPS,
            observation_ttl_blocks:
                MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEFAULT_OBSERVATION_TTL_BLOCKS,
            rebalance_ttl_blocks:
                MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEFAULT_REBALANCE_TTL_BLOCKS,
            settlement_ttl_blocks:
                MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            replay_fence_ttl_blocks:
                MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEFAULT_REPLAY_FENCE_TTL_BLOCKS,
            roots_only: true,
        }
    }

    pub fn validate(&self) -> MoneroL2PrivateReserveProofRebalancerResult<()> {
        if self.chain_id != CHAIN_ID {
            return Err("config chain id does not match runtime chain id".to_string());
        }
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(
                "unsupported private reserve proof rebalancer protocol version".to_string(),
            );
        }
        if !self.roots_only {
            return Err("private reserve proof rebalancer requires roots-only privacy".to_string());
        }
        if self.min_privacy_set_size == 0 {
            return Err("privacy set size floor must be positive".to_string());
        }
        if self.min_pq_security_bits < 128 {
            return Err("post-quantum security floor is too low".to_string());
        }
        if self.target_pq_security_bits < self.min_pq_security_bits {
            return Err("target post-quantum security cannot be below the floor".to_string());
        }
        if self.min_watcher_weight == 0 || self.min_watcher_count == 0 {
            return Err("watcher quorum floors must be positive".to_string());
        }
        if self.emergency_floor_bps < MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_MAX_BPS {
            return Err("emergency reserve floor must cover at least 100%".to_string());
        }
        if self.min_reserve_floor_bps < self.emergency_floor_bps {
            return Err("reserve floor cannot be below emergency floor".to_string());
        }
        if self.target_reserve_bps < self.min_reserve_floor_bps {
            return Err("target reserve cannot be below reserve floor".to_string());
        }
        if self.max_lane_exposure_bps > MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_MAX_BPS
            || self.max_provider_exposure_bps > MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_MAX_BPS
        {
            return Err("exposure caps cannot exceed 100%".to_string());
        }
        if self.low_fee_bps > self.standard_fee_bps {
            return Err("low fee bps cannot exceed standard fee bps".to_string());
        }
        if self.standard_fee_bps > MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_MAX_BPS
            || self.sponsor_cover_bps > MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_MAX_BPS
        {
            return Err("fee and sponsor bps values cannot exceed 100%".to_string());
        }
        if self.observation_ttl_blocks == 0
            || self.rebalance_ttl_blocks == 0
            || self.settlement_ttl_blocks == 0
            || self.replay_fence_ttl_blocks == 0
        {
            return Err("ttl windows must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_private_reserve_proof_rebalancer_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "reserve_proof_scheme": self.reserve_proof_scheme,
            "watcher_quorum_scheme": self.watcher_quorum_scheme,
            "rebalance_commitment_scheme": self.rebalance_commitment_scheme,
            "lp_move_scheme": self.lp_move_scheme,
            "settlement_receipt_scheme": self.settlement_receipt_scheme,
            "low_fee_sponsor_scheme": self.low_fee_sponsor_scheme,
            "nullifier_scheme": self.nullifier_scheme,
            "genesis_height": self.genesis_height,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "min_watcher_weight": self.min_watcher_weight,
            "min_watcher_count": self.min_watcher_count,
            "min_reserve_floor_bps": self.min_reserve_floor_bps,
            "target_reserve_bps": self.target_reserve_bps,
            "emergency_floor_bps": self.emergency_floor_bps,
            "max_lane_exposure_bps": self.max_lane_exposure_bps,
            "max_provider_exposure_bps": self.max_provider_exposure_bps,
            "standard_fee_bps": self.standard_fee_bps,
            "low_fee_bps": self.low_fee_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "observation_ttl_blocks": self.observation_ttl_blocks,
            "rebalance_ttl_blocks": self.rebalance_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "replay_fence_ttl_blocks": self.replay_fence_ttl_blocks,
            "privacy": "roots_only",
            "roots_only": self.roots_only,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub reserve_observations: u64,
    pub accepted_quorums: u64,
    pub rejected_quorums: u64,
    pub scheduled_rebalances: u64,
    pub settled_rebalances: u64,
    pub failed_rebalances: u64,
    pub lp_moves: u64,
    pub low_fee_sponsored_moves: u64,
    pub replay_rejections: u64,
    pub reserve_floor_rejections: u64,
    pub quorum_rejections: u64,
    pub pq_rejections: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_private_reserve_proof_rebalancer_counters",
            "reserve_observations": self.reserve_observations,
            "accepted_quorums": self.accepted_quorums,
            "rejected_quorums": self.rejected_quorums,
            "scheduled_rebalances": self.scheduled_rebalances,
            "settled_rebalances": self.settled_rebalances,
            "failed_rebalances": self.failed_rebalances,
            "lp_moves": self.lp_moves,
            "low_fee_sponsored_moves": self.low_fee_sponsored_moves,
            "replay_rejections": self.replay_rejections,
            "reserve_floor_rejections": self.reserve_floor_rejections,
            "quorum_rejections": self.quorum_rejections,
            "pq_rejections": self.pq_rejections,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitReserveObservationRequest {
    pub proof_kind: ReserveProofKind,
    pub reserve_epoch: u64,
    pub observed_height: u64,
    pub reserve_commitment_root: String,
    pub liability_commitment_root: String,
    pub decoy_set_root: String,
    pub view_tag_set_root: String,
    pub reserve_amount_upper_bound: u64,
    pub liability_amount_upper_bound: u64,
    pub locked_fast_exit_upper_bound: u64,
    pub lane_exposure_upper_bound: u64,
    pub provider_exposure_upper_bound: u64,
    pub privacy_set_size: u64,
    pub pq_proof_root: String,
    pub pq_signature_root: String,
    pub pq_security_bits: u16,
    pub watcher_hint_root: String,
    pub nullifier: String,
    pub replay_fence: String,
    pub submitted_at_height: u64,
    pub request_nonce: String,
}

impl SubmitReserveObservationRequest {
    pub fn validate(&self, config: &Config) -> MoneroL2PrivateReserveProofRebalancerResult<()> {
        require_root("reserve commitment root", &self.reserve_commitment_root)?;
        require_root("liability commitment root", &self.liability_commitment_root)?;
        require_root("decoy set root", &self.decoy_set_root)?;
        require_root("view tag set root", &self.view_tag_set_root)?;
        require_root("pq proof root", &self.pq_proof_root)?;
        require_root("pq signature root", &self.pq_signature_root)?;
        require_root("watcher hint root", &self.watcher_hint_root)?;
        require_secret_root("nullifier", &self.nullifier)?;
        require_secret_root("replay fence", &self.replay_fence)?;
        if self.reserve_epoch == 0 {
            return Err("reserve epoch must be positive".to_string());
        }
        if self.reserve_amount_upper_bound == 0 {
            return Err("reserve amount upper bound must be positive".to_string());
        }
        if self.liability_amount_upper_bound == 0 {
            return Err("liability amount upper bound must be positive".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("reserve observation privacy set is below configured floor".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err(
                "reserve observation pq security bits are below configured floor".to_string(),
            );
        }
        if self.request_nonce.is_empty() {
            return Err("reserve observation request nonce cannot be empty".to_string());
        }
        let floor = if self.proof_kind.requires_emergency_floor() {
            config.emergency_floor_bps
        } else {
            config.min_reserve_floor_bps
        };
        ensure_reserve_floor(
            self.reserve_amount_upper_bound,
            self.liability_amount_upper_bound
                .saturating_add(self.locked_fast_exit_upper_bound),
            floor,
        )?;
        ensure_exposure_cap(
            self.lane_exposure_upper_bound,
            self.reserve_amount_upper_bound,
            config.max_lane_exposure_bps,
            "lane exposure",
        )?;
        ensure_exposure_cap(
            self.provider_exposure_upper_bound,
            self.reserve_amount_upper_bound,
            config.max_provider_exposure_bps,
            "provider exposure",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestQuorumRequest {
    pub observation_id: String,
    pub watcher_set_root: String,
    pub attestation_root: String,
    pub pq_signature_batch_root: String,
    pub watcher_weight: u64,
    pub watcher_count: u64,
    pub pq_security_bits: u16,
    pub status: QuorumStatus,
    pub attested_height: u64,
    pub attestation_nonce: String,
}

impl AttestQuorumRequest {
    pub fn validate(&self, config: &Config) -> MoneroL2PrivateReserveProofRebalancerResult<()> {
        if self.observation_id.is_empty() {
            return Err("quorum observation id cannot be empty".to_string());
        }
        require_root("watcher set root", &self.watcher_set_root)?;
        require_root("attestation root", &self.attestation_root)?;
        require_root("pq signature batch root", &self.pq_signature_batch_root)?;
        if self.watcher_weight < config.min_watcher_weight {
            return Err("watcher quorum weight below configured floor".to_string());
        }
        if self.watcher_count < config.min_watcher_count {
            return Err("watcher quorum count below configured floor".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("watcher quorum pq security bits below configured floor".to_string());
        }
        if self.attestation_nonce.is_empty() {
            return Err("quorum attestation nonce cannot be empty".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleRebalanceRequest {
    pub observation_id: String,
    pub quorum_id: String,
    pub action: RebalanceAction,
    pub lane_id: String,
    pub provider_id: String,
    pub rebalance_commitment_root: String,
    pub private_route_root: String,
    pub amount_bucket_upper_bound: u64,
    pub post_move_reserve_upper_bound: u64,
    pub post_move_liability_upper_bound: u64,
    pub fee_commitment_root: String,
    pub max_fee_bps: u64,
    pub low_fee_sponsor_root: Option<String>,
    pub sponsor_budget_upper_bound: u64,
    pub pq_authorization_root: String,
    pub pq_signature_root: String,
    pub pq_security_bits: u16,
    pub nullifier: String,
    pub replay_fence: String,
    pub scheduled_at_height: u64,
    pub request_nonce: String,
}

impl ScheduleRebalanceRequest {
    pub fn validate(&self, config: &Config) -> MoneroL2PrivateReserveProofRebalancerResult<()> {
        if self.observation_id.is_empty() || self.quorum_id.is_empty() {
            return Err("rebalance schedule requires observation and quorum ids".to_string());
        }
        if self.lane_id.is_empty() || self.provider_id.is_empty() {
            return Err("rebalance schedule requires lane and provider ids".to_string());
        }
        require_root("rebalance commitment root", &self.rebalance_commitment_root)?;
        require_root("private route root", &self.private_route_root)?;
        require_root("fee commitment root", &self.fee_commitment_root)?;
        require_root("pq authorization root", &self.pq_authorization_root)?;
        require_root("pq signature root", &self.pq_signature_root)?;
        require_secret_root("nullifier", &self.nullifier)?;
        require_secret_root("replay fence", &self.replay_fence)?;
        if self.amount_bucket_upper_bound == 0 {
            return Err("rebalance amount upper bound must be positive".to_string());
        }
        if self.max_fee_bps > config.standard_fee_bps {
            return Err("rebalance max fee exceeds configured standard fee cap".to_string());
        }
        if self.action.requires_sponsor() {
            let sponsor_root = self
                .low_fee_sponsor_root
                .as_ref()
                .ok_or_else(|| "low fee rebalance requires sponsor root".to_string())?;
            require_root("low fee sponsor root", sponsor_root)?;
            if self.max_fee_bps > config.low_fee_bps {
                return Err("low fee sponsored rebalance exceeds low fee cap".to_string());
            }
            if self
                .sponsor_budget_upper_bound
                .saturating_mul(MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_MAX_BPS)
                < self
                    .amount_bucket_upper_bound
                    .saturating_mul(config.sponsor_cover_bps)
            {
                return Err("low fee sponsor budget below configured cover floor".to_string());
            }
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("rebalance pq security bits below configured floor".to_string());
        }
        if self.request_nonce.is_empty() {
            return Err("rebalance request nonce cannot be empty".to_string());
        }
        ensure_reserve_floor(
            self.post_move_reserve_upper_bound,
            self.post_move_liability_upper_bound,
            config.emergency_floor_bps,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleRebalanceRequest {
    pub commitment_id: String,
    pub lp_move_root: String,
    pub settlement_receipt_root: String,
    pub settlement_tx_root: String,
    pub reserve_release_root: String,
    pub fee_sponsor_receipt_root: Option<String>,
    pub pq_receipt_root: String,
    pub pq_security_bits: u16,
    pub settled_height: u64,
    pub receipt_status: ReceiptStatus,
    pub settlement_nonce: String,
}

impl SettleRebalanceRequest {
    pub fn validate(&self, config: &Config) -> MoneroL2PrivateReserveProofRebalancerResult<()> {
        if self.commitment_id.is_empty() {
            return Err("settlement commitment id cannot be empty".to_string());
        }
        require_root("lp move root", &self.lp_move_root)?;
        require_root("settlement receipt root", &self.settlement_receipt_root)?;
        require_root("settlement tx root", &self.settlement_tx_root)?;
        require_root("reserve release root", &self.reserve_release_root)?;
        require_root("pq receipt root", &self.pq_receipt_root)?;
        if let Some(root) = self.fee_sponsor_receipt_root.as_ref() {
            require_root("fee sponsor receipt root", root)?;
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("settlement receipt pq security bits below configured floor".to_string());
        }
        if self.settlement_nonce.is_empty() {
            return Err("settlement nonce cannot be empty".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveObservationRecord {
    pub observation_id: String,
    pub proof_kind: ReserveProofKind,
    pub reserve_epoch: u64,
    pub observed_height: u64,
    pub reserve_commitment_root: String,
    pub liability_commitment_root: String,
    pub decoy_set_root: String,
    pub view_tag_set_root: String,
    pub reserve_amount_upper_bound: u64,
    pub liability_amount_upper_bound: u64,
    pub locked_fast_exit_upper_bound: u64,
    pub reserve_floor_bps: u64,
    pub privacy_set_size: u64,
    pub pq_proof_root: String,
    pub pq_signature_root: String,
    pub pq_security_bits: u16,
    pub watcher_hint_root: String,
    pub nullifier_root: String,
    pub replay_fence_root: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl ReserveObservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_private_reserve_observation",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "observation_id": self.observation_id,
            "proof_kind": self.proof_kind.as_str(),
            "reserve_epoch": self.reserve_epoch,
            "observed_height": self.observed_height,
            "reserve_commitment_root": self.reserve_commitment_root,
            "liability_commitment_root": self.liability_commitment_root,
            "decoy_set_root": self.decoy_set_root,
            "view_tag_set_root": self.view_tag_set_root,
            "reserve_amount_upper_bound": self.reserve_amount_upper_bound,
            "liability_amount_upper_bound": self.liability_amount_upper_bound,
            "locked_fast_exit_upper_bound": self.locked_fast_exit_upper_bound,
            "reserve_floor_bps": self.reserve_floor_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_proof_root": self.pq_proof_root,
            "pq_signature_root": self.pq_signature_root,
            "pq_security_bits": self.pq_security_bits,
            "watcher_hint_root": self.watcher_hint_root,
            "nullifier_root": self.nullifier_root,
            "replay_fence_root": self.replay_fence_root,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "privacy": "roots_only",
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "MONERO-L2-PRIVATE-RESERVE-OBSERVATION",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqWatcherQuorumAttestation {
    pub quorum_id: String,
    pub observation_id: String,
    pub watcher_set_root: String,
    pub attestation_root: String,
    pub pq_signature_batch_root: String,
    pub watcher_weight: u64,
    pub watcher_count: u64,
    pub pq_security_bits: u16,
    pub status: QuorumStatus,
    pub attested_height: u64,
}

impl PqWatcherQuorumAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_private_reserve_pq_watcher_quorum",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "quorum_id": self.quorum_id,
            "observation_id": self.observation_id,
            "watcher_set_root": self.watcher_set_root,
            "attestation_root": self.attestation_root,
            "pq_signature_batch_root": self.pq_signature_batch_root,
            "watcher_weight": self.watcher_weight,
            "watcher_count": self.watcher_count,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status.as_str(),
            "attested_height": self.attested_height,
            "privacy": "roots_only",
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "MONERO-L2-PRIVATE-RESERVE-WATCHER-QUORUM",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateRebalanceCommitment {
    pub commitment_id: String,
    pub observation_id: String,
    pub quorum_id: String,
    pub action: RebalanceAction,
    pub lane_id: String,
    pub provider_id: String,
    pub rebalance_commitment_root: String,
    pub private_route_root: String,
    pub amount_bucket_upper_bound: u64,
    pub post_move_reserve_upper_bound: u64,
    pub post_move_liability_upper_bound: u64,
    pub fee_commitment_root: String,
    pub max_fee_bps: u64,
    pub low_fee_sponsor_root: Option<String>,
    pub sponsor_budget_upper_bound: u64,
    pub pq_authorization_root: String,
    pub pq_signature_root: String,
    pub pq_security_bits: u16,
    pub nullifier_root: String,
    pub replay_fence_root: String,
    pub status: ReceiptStatus,
    pub scheduled_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivateRebalanceCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_private_rebalance_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "commitment_id": self.commitment_id,
            "observation_id": self.observation_id,
            "quorum_id": self.quorum_id,
            "action": self.action.as_str(),
            "lane_id": self.lane_id,
            "provider_id": self.provider_id,
            "rebalance_commitment_root": self.rebalance_commitment_root,
            "private_route_root": self.private_route_root,
            "amount_bucket_upper_bound": self.amount_bucket_upper_bound,
            "post_move_reserve_upper_bound": self.post_move_reserve_upper_bound,
            "post_move_liability_upper_bound": self.post_move_liability_upper_bound,
            "fee_commitment_root": self.fee_commitment_root,
            "max_fee_bps": self.max_fee_bps,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "sponsor_budget_upper_bound": self.sponsor_budget_upper_bound,
            "pq_authorization_root": self.pq_authorization_root,
            "pq_signature_root": self.pq_signature_root,
            "pq_security_bits": self.pq_security_bits,
            "nullifier_root": self.nullifier_root,
            "replay_fence_root": self.replay_fence_root,
            "status": self.status.as_str(),
            "scheduled_at_height": self.scheduled_at_height,
            "expires_at_height": self.expires_at_height,
            "privacy": "roots_only",
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "MONERO-L2-PRIVATE-REBALANCE-COMMITMENT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LpReserveMove {
    pub move_id: String,
    pub commitment_id: String,
    pub action: RebalanceAction,
    pub lane_id: String,
    pub provider_id: String,
    pub lp_move_root: String,
    pub amount_bucket_upper_bound: u64,
    pub fee_commitment_root: String,
    pub low_fee_sponsor_root: Option<String>,
    pub pq_receipt_root: String,
    pub pq_security_bits: u16,
    pub moved_at_height: u64,
}

impl LpReserveMove {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_private_lp_reserve_move",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "move_id": self.move_id,
            "commitment_id": self.commitment_id,
            "action": self.action.as_str(),
            "lane_id": self.lane_id,
            "provider_id": self.provider_id,
            "lp_move_root": self.lp_move_root,
            "amount_bucket_upper_bound": self.amount_bucket_upper_bound,
            "fee_commitment_root": self.fee_commitment_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "pq_receipt_root": self.pq_receipt_root,
            "pq_security_bits": self.pq_security_bits,
            "moved_at_height": self.moved_at_height,
            "privacy": "roots_only",
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("MONERO-L2-PRIVATE-LP-RESERVE-MOVE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub commitment_id: String,
    pub move_id: String,
    pub settlement_receipt_root: String,
    pub settlement_tx_root: String,
    pub reserve_release_root: String,
    pub fee_sponsor_receipt_root: Option<String>,
    pub pq_receipt_root: String,
    pub pq_security_bits: u16,
    pub status: ReceiptStatus,
    pub settled_height: u64,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_private_reserve_rebalance_settlement_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "commitment_id": self.commitment_id,
            "move_id": self.move_id,
            "settlement_receipt_root": self.settlement_receipt_root,
            "settlement_tx_root": self.settlement_tx_root,
            "reserve_release_root": self.reserve_release_root,
            "fee_sponsor_receipt_root": self.fee_sponsor_receipt_root,
            "pq_receipt_root": self.pq_receipt_root,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status.as_str(),
            "settled_height": self.settled_height,
            "privacy": "roots_only",
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "MONERO-L2-PRIVATE-RESERVE-SETTLEMENT-RECEIPT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub reserve_observation_root: String,
    pub watcher_quorum_root: String,
    pub rebalance_commitment_root: String,
    pub lp_move_root: String,
    pub settlement_receipt_root: String,
    pub nullifier_root: String,
    pub replay_fence_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_private_reserve_proof_rebalancer_roots",
            "config_root": self.config_root,
            "reserve_observation_root": self.reserve_observation_root,
            "watcher_quorum_root": self.watcher_quorum_root,
            "rebalance_commitment_root": self.rebalance_commitment_root,
            "lp_move_root": self.lp_move_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "nullifier_root": self.nullifier_root,
            "replay_fence_root": self.replay_fence_root,
            "privacy": "roots_only",
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "MONERO-L2-PRIVATE-RESERVE-REBALANCER-ROOTS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub reserve_observations: BTreeMap<String, ReserveObservationRecord>,
    pub watcher_quorums: BTreeMap<String, PqWatcherQuorumAttestation>,
    pub rebalance_commitments: BTreeMap<String, PrivateRebalanceCommitment>,
    pub lp_moves: BTreeMap<String, LpReserveMove>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub used_nullifiers: BTreeSet<String>,
    pub used_replay_fences: BTreeSet<String>,
    pub roots: Roots,
    pub counters: Counters,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            height: MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_DEVNET_HEIGHT,
            config: Config::devnet(),
            reserve_observations: BTreeMap::new(),
            watcher_quorums: BTreeMap::new(),
            rebalance_commitments: BTreeMap::new(),
            lp_moves: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            used_nullifiers: BTreeSet::new(),
            used_replay_fences: BTreeSet::new(),
            roots: Roots {
                config_root: String::new(),
                reserve_observation_root: String::new(),
                watcher_quorum_root: String::new(),
                rebalance_commitment_root: String::new(),
                lp_move_root: String::new(),
                settlement_receipt_root: String::new(),
                nullifier_root: String::new(),
                replay_fence_root: String::new(),
            },
            counters: Counters {
                reserve_observations: 0,
                accepted_quorums: 0,
                rejected_quorums: 0,
                scheduled_rebalances: 0,
                settled_rebalances: 0,
                failed_rebalances: 0,
                lp_moves: 0,
                low_fee_sponsored_moves: 0,
                replay_rejections: 0,
                reserve_floor_rejections: 0,
                quorum_rejections: 0,
                pq_rejections: 0,
            },
        };
        state.refresh();
        state
    }

    pub fn submit_reserve_observation(
        &mut self,
        request: SubmitReserveObservationRequest,
    ) -> MoneroL2PrivateReserveProofRebalancerResult<ReserveObservationRecord> {
        self.config.validate()?;
        if self.reserve_observations.len()
            >= MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_MAX_OBSERVATIONS
        {
            return Err("reserve observation limit exceeded".to_string());
        }
        if let Err(err) = request.validate(&self.config) {
            if err.contains("pq security") {
                self.counters.pq_rejections = self.counters.pq_rejections.saturating_add(1);
            }
            if err.contains("reserve") || err.contains("exposure") {
                self.counters.reserve_floor_rejections =
                    self.counters.reserve_floor_rejections.saturating_add(1);
            }
            return Err(err);
        }
        let nullifier_root = secret_root("MONERO-L2-PRIVATE-RESERVE-NULLIFIER", &request.nullifier);
        let replay_fence_root = secret_root(
            "MONERO-L2-PRIVATE-RESERVE-REPLAY-FENCE",
            &request.replay_fence,
        );
        self.ensure_unique_replay(&nullifier_root, &replay_fence_root)?;
        let observation_id = reserve_observation_id(
            self.counters.reserve_observations.saturating_add(1),
            request.reserve_epoch,
            request.proof_kind,
            &request.reserve_commitment_root,
            &nullifier_root,
            &request.request_nonce,
        );
        let reserve_floor_bps = if request.proof_kind.requires_emergency_floor() {
            self.config.emergency_floor_bps
        } else {
            self.config.min_reserve_floor_bps
        };
        let record = ReserveObservationRecord {
            observation_id: observation_id.clone(),
            proof_kind: request.proof_kind,
            reserve_epoch: request.reserve_epoch,
            observed_height: request.observed_height,
            reserve_commitment_root: request.reserve_commitment_root,
            liability_commitment_root: request.liability_commitment_root,
            decoy_set_root: request.decoy_set_root,
            view_tag_set_root: request.view_tag_set_root,
            reserve_amount_upper_bound: request.reserve_amount_upper_bound,
            liability_amount_upper_bound: request.liability_amount_upper_bound,
            locked_fast_exit_upper_bound: request.locked_fast_exit_upper_bound,
            reserve_floor_bps,
            privacy_set_size: request.privacy_set_size,
            pq_proof_root: request.pq_proof_root,
            pq_signature_root: request.pq_signature_root,
            pq_security_bits: request.pq_security_bits,
            watcher_hint_root: request.watcher_hint_root,
            nullifier_root: nullifier_root.clone(),
            replay_fence_root: replay_fence_root.clone(),
            submitted_at_height: request.submitted_at_height,
            expires_at_height: request
                .submitted_at_height
                .saturating_add(self.config.observation_ttl_blocks),
        };
        self.reserve_observations
            .insert(observation_id, record.clone());
        self.used_nullifiers.insert(nullifier_root);
        self.used_replay_fences.insert(replay_fence_root);
        self.counters.reserve_observations = self.counters.reserve_observations.saturating_add(1);
        self.height = self.height.max(record.submitted_at_height);
        self.refresh();
        Ok(record)
    }

    pub fn attest_quorum(
        &mut self,
        request: AttestQuorumRequest,
    ) -> MoneroL2PrivateReserveProofRebalancerResult<PqWatcherQuorumAttestation> {
        self.config.validate()?;
        if self.watcher_quorums.len() >= MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_MAX_QUORUMS {
            return Err("watcher quorum limit exceeded".to_string());
        }
        if let Err(err) = request.validate(&self.config) {
            if err.contains("pq security") {
                self.counters.pq_rejections = self.counters.pq_rejections.saturating_add(1);
            } else {
                self.counters.quorum_rejections = self.counters.quorum_rejections.saturating_add(1);
            }
            return Err(err);
        }
        let observation = self
            .reserve_observations
            .get(&request.observation_id)
            .ok_or_else(|| "quorum references unknown reserve observation".to_string())?;
        if request.attested_height > observation.expires_at_height {
            self.counters.quorum_rejections = self.counters.quorum_rejections.saturating_add(1);
            return Err("quorum attestation is outside observation ttl".to_string());
        }
        let quorum_id = watcher_quorum_id(
            self.counters
                .accepted_quorums
                .saturating_add(self.counters.rejected_quorums)
                .saturating_add(1),
            &request.observation_id,
            &request.attestation_root,
            &request.attestation_nonce,
        );
        let record = PqWatcherQuorumAttestation {
            quorum_id: quorum_id.clone(),
            observation_id: request.observation_id,
            watcher_set_root: request.watcher_set_root,
            attestation_root: request.attestation_root,
            pq_signature_batch_root: request.pq_signature_batch_root,
            watcher_weight: request.watcher_weight,
            watcher_count: request.watcher_count,
            pq_security_bits: request.pq_security_bits,
            status: request.status,
            attested_height: request.attested_height,
        };
        if record.status.usable() {
            self.counters.accepted_quorums = self.counters.accepted_quorums.saturating_add(1);
        } else {
            self.counters.rejected_quorums = self.counters.rejected_quorums.saturating_add(1);
        }
        self.height = self.height.max(record.attested_height);
        self.watcher_quorums.insert(quorum_id, record.clone());
        self.refresh();
        Ok(record)
    }

    pub fn schedule_rebalance(
        &mut self,
        request: ScheduleRebalanceRequest,
    ) -> MoneroL2PrivateReserveProofRebalancerResult<PrivateRebalanceCommitment> {
        self.config.validate()?;
        if self.rebalance_commitments.len()
            >= MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_MAX_COMMITMENTS
        {
            return Err("rebalance commitment limit exceeded".to_string());
        }
        if let Err(err) = request.validate(&self.config) {
            if err.contains("pq security") {
                self.counters.pq_rejections = self.counters.pq_rejections.saturating_add(1);
            }
            if err.contains("reserve") {
                self.counters.reserve_floor_rejections =
                    self.counters.reserve_floor_rejections.saturating_add(1);
            }
            return Err(err);
        }
        let observation = self
            .reserve_observations
            .get(&request.observation_id)
            .ok_or_else(|| "rebalance references unknown reserve observation".to_string())?;
        let quorum = self
            .watcher_quorums
            .get(&request.quorum_id)
            .ok_or_else(|| "rebalance references unknown watcher quorum".to_string())?;
        if quorum.observation_id != observation.observation_id || !quorum.status.usable() {
            self.counters.quorum_rejections = self.counters.quorum_rejections.saturating_add(1);
            return Err("rebalance requires accepted quorum for the same observation".to_string());
        }
        if request.scheduled_at_height > observation.expires_at_height {
            return Err("rebalance cannot be scheduled after observation expiry".to_string());
        }
        let nullifier_root =
            secret_root("MONERO-L2-PRIVATE-REBALANCE-NULLIFIER", &request.nullifier);
        let replay_fence_root = secret_root(
            "MONERO-L2-PRIVATE-REBALANCE-REPLAY-FENCE",
            &request.replay_fence,
        );
        self.ensure_unique_replay(&nullifier_root, &replay_fence_root)?;
        let commitment_id = rebalance_commitment_id(
            self.counters.scheduled_rebalances.saturating_add(1),
            &request.observation_id,
            &request.quorum_id,
            request.action,
            &request.rebalance_commitment_root,
            &nullifier_root,
            &request.request_nonce,
        );
        let record = PrivateRebalanceCommitment {
            commitment_id: commitment_id.clone(),
            observation_id: request.observation_id,
            quorum_id: request.quorum_id,
            action: request.action,
            lane_id: request.lane_id,
            provider_id: request.provider_id,
            rebalance_commitment_root: request.rebalance_commitment_root,
            private_route_root: request.private_route_root,
            amount_bucket_upper_bound: request.amount_bucket_upper_bound,
            post_move_reserve_upper_bound: request.post_move_reserve_upper_bound,
            post_move_liability_upper_bound: request.post_move_liability_upper_bound,
            fee_commitment_root: request.fee_commitment_root,
            max_fee_bps: request.max_fee_bps,
            low_fee_sponsor_root: request.low_fee_sponsor_root,
            sponsor_budget_upper_bound: request.sponsor_budget_upper_bound,
            pq_authorization_root: request.pq_authorization_root,
            pq_signature_root: request.pq_signature_root,
            pq_security_bits: request.pq_security_bits,
            nullifier_root: nullifier_root.clone(),
            replay_fence_root: replay_fence_root.clone(),
            status: ReceiptStatus::Scheduled,
            scheduled_at_height: request.scheduled_at_height,
            expires_at_height: request
                .scheduled_at_height
                .saturating_add(self.config.rebalance_ttl_blocks),
        };
        if record.action.requires_sponsor() {
            self.counters.low_fee_sponsored_moves =
                self.counters.low_fee_sponsored_moves.saturating_add(1);
        }
        self.rebalance_commitments
            .insert(commitment_id, record.clone());
        self.used_nullifiers.insert(nullifier_root);
        self.used_replay_fences.insert(replay_fence_root);
        self.counters.scheduled_rebalances = self.counters.scheduled_rebalances.saturating_add(1);
        self.height = self.height.max(record.scheduled_at_height);
        self.refresh();
        Ok(record)
    }

    pub fn settle_rebalance(
        &mut self,
        request: SettleRebalanceRequest,
    ) -> MoneroL2PrivateReserveProofRebalancerResult<SettlementReceipt> {
        self.config.validate()?;
        if self.lp_moves.len() >= MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_MAX_MOVES {
            return Err("lp reserve move limit exceeded".to_string());
        }
        if self.settlement_receipts.len() >= MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_MAX_RECEIPTS
        {
            return Err("settlement receipt limit exceeded".to_string());
        }
        request.validate(&self.config)?;
        let commitment = self
            .rebalance_commitments
            .get_mut(&request.commitment_id)
            .ok_or_else(|| "settlement references unknown rebalance commitment".to_string())?;
        if commitment.status.terminal() {
            return Err("rebalance commitment is already terminal".to_string());
        }
        if request.settled_height
            > commitment
                .expires_at_height
                .saturating_add(self.config.settlement_ttl_blocks)
        {
            commitment.status = ReceiptStatus::Expired;
            self.counters.failed_rebalances = self.counters.failed_rebalances.saturating_add(1);
            self.refresh();
            return Err("settlement is outside configured ttl".to_string());
        }
        if commitment.action.requires_sponsor() && request.fee_sponsor_receipt_root.is_none() {
            return Err("low fee sponsored settlement requires sponsor receipt root".to_string());
        }
        commitment.status = request.receipt_status;
        let move_id = lp_reserve_move_id(
            self.counters.lp_moves.saturating_add(1),
            &commitment.commitment_id,
            &request.lp_move_root,
            &request.settlement_nonce,
        );
        let lp_move = LpReserveMove {
            move_id: move_id.clone(),
            commitment_id: commitment.commitment_id.clone(),
            action: commitment.action,
            lane_id: commitment.lane_id.clone(),
            provider_id: commitment.provider_id.clone(),
            lp_move_root: request.lp_move_root,
            amount_bucket_upper_bound: commitment.amount_bucket_upper_bound,
            fee_commitment_root: commitment.fee_commitment_root.clone(),
            low_fee_sponsor_root: commitment.low_fee_sponsor_root.clone(),
            pq_receipt_root: request.pq_receipt_root.clone(),
            pq_security_bits: request.pq_security_bits,
            moved_at_height: request.settled_height,
        };
        let receipt_id = settlement_receipt_id(
            self.counters
                .settled_rebalances
                .saturating_add(self.counters.failed_rebalances)
                .saturating_add(1),
            &commitment.commitment_id,
            &move_id,
            &request.settlement_receipt_root,
            &request.settlement_nonce,
        );
        let receipt = SettlementReceipt {
            receipt_id: receipt_id.clone(),
            commitment_id: commitment.commitment_id.clone(),
            move_id,
            settlement_receipt_root: request.settlement_receipt_root,
            settlement_tx_root: request.settlement_tx_root,
            reserve_release_root: request.reserve_release_root,
            fee_sponsor_receipt_root: request.fee_sponsor_receipt_root,
            pq_receipt_root: request.pq_receipt_root,
            pq_security_bits: request.pq_security_bits,
            status: request.receipt_status,
            settled_height: request.settled_height,
        };
        if receipt.status == ReceiptStatus::Settled {
            self.counters.settled_rebalances = self.counters.settled_rebalances.saturating_add(1);
        } else {
            self.counters.failed_rebalances = self.counters.failed_rebalances.saturating_add(1);
        }
        self.counters.lp_moves = self.counters.lp_moves.saturating_add(1);
        self.lp_moves.insert(lp_move.move_id.clone(), lp_move);
        self.settlement_receipts.insert(receipt_id, receipt.clone());
        self.height = self.height.max(receipt.settled_height);
        self.refresh();
        Ok(receipt)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: payload_root(
                "MONERO-L2-PRIVATE-RESERVE-REBALANCER-CONFIG",
                &self.config.public_record(),
            ),
            reserve_observation_root: map_root(
                "MONERO-L2-PRIVATE-RESERVE-OBSERVATION-MAP",
                &self.reserve_observations,
                ReserveObservationRecord::public_record,
            ),
            watcher_quorum_root: map_root(
                "MONERO-L2-PRIVATE-RESERVE-WATCHER-QUORUM-MAP",
                &self.watcher_quorums,
                PqWatcherQuorumAttestation::public_record,
            ),
            rebalance_commitment_root: map_root(
                "MONERO-L2-PRIVATE-REBALANCE-COMMITMENT-MAP",
                &self.rebalance_commitments,
                PrivateRebalanceCommitment::public_record,
            ),
            lp_move_root: map_root(
                "MONERO-L2-PRIVATE-LP-RESERVE-MOVE-MAP",
                &self.lp_moves,
                LpReserveMove::public_record,
            ),
            settlement_receipt_root: map_root(
                "MONERO-L2-PRIVATE-RESERVE-SETTLEMENT-RECEIPT-MAP",
                &self.settlement_receipts,
                SettlementReceipt::public_record,
            ),
            nullifier_root: set_root(
                "MONERO-L2-PRIVATE-RESERVE-NULLIFIER-SET",
                &self.used_nullifiers,
            ),
            replay_fence_root: set_root(
                "MONERO-L2-PRIVATE-RESERVE-REPLAY-FENCE-SET",
                &self.used_replay_fences,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "monero_l2_private_reserve_proof_rebalancer_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.state_root(),
            "counters": self.counters.public_record(),
            "state_root": self.state_root(),
            "privacy": "roots_only",
        })
    }

    pub fn state_root(&self) -> String {
        monero_l2_private_reserve_proof_rebalancer_state_root_from_record(
            &self.public_record_without_state_root(),
        )
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "monero_l2_private_reserve_proof_rebalancer_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.state_root(),
            "counters": self.counters.public_record(),
            "privacy": "roots_only",
        })
    }

    fn refresh(&mut self) {
        self.roots = self.roots();
    }

    fn ensure_unique_replay(
        &mut self,
        nullifier_root: &str,
        replay_fence_root: &str,
    ) -> MoneroL2PrivateReserveProofRebalancerResult<()> {
        if self.used_nullifiers.contains(nullifier_root)
            || self.used_replay_fences.contains(replay_fence_root)
        {
            self.counters.replay_rejections = self.counters.replay_rejections.saturating_add(1);
            return Err("nullifier or replay fence has already been consumed".to_string());
        }
        Ok(())
    }
}

pub fn monero_l2_private_reserve_proof_rebalancer_state_root_from_record(record: &Value) -> String {
    payload_root("MONERO-L2-PRIVATE-RESERVE-PROOF-REBALANCER-STATE", record)
}

pub fn reserve_observation_id(
    sequence: u64,
    reserve_epoch: u64,
    proof_kind: ReserveProofKind,
    reserve_commitment_root: &str,
    nullifier_root: &str,
    nonce: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PRIVATE-RESERVE-OBSERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Int(reserve_epoch as i128),
            HashPart::Str(proof_kind.as_str()),
            HashPart::Str(reserve_commitment_root),
            HashPart::Str(nullifier_root),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn watcher_quorum_id(
    sequence: u64,
    observation_id: &str,
    attestation_root: &str,
    nonce: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PRIVATE-RESERVE-WATCHER-QUORUM-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(observation_id),
            HashPart::Str(attestation_root),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn rebalance_commitment_id(
    sequence: u64,
    observation_id: &str,
    quorum_id: &str,
    action: RebalanceAction,
    rebalance_commitment_root: &str,
    nullifier_root: &str,
    nonce: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PRIVATE-REBALANCE-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(observation_id),
            HashPart::Str(quorum_id),
            HashPart::Str(action.as_str()),
            HashPart::Str(rebalance_commitment_root),
            HashPart::Str(nullifier_root),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn lp_reserve_move_id(
    sequence: u64,
    commitment_id: &str,
    lp_move_root: &str,
    nonce: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PRIVATE-LP-RESERVE-MOVE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(commitment_id),
            HashPart::Str(lp_move_root),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn settlement_receipt_id(
    sequence: u64,
    commitment_id: &str,
    move_id: &str,
    settlement_receipt_root: &str,
    nonce: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PRIVATE-RESERVE-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(commitment_id),
            HashPart::Str(move_id),
            HashPart::Str(settlement_receipt_root),
            HashPart::Str(nonce),
        ],
        32,
    )
}

fn require_root(label: &str, value: &str) -> MoneroL2PrivateReserveProofRebalancerResult<()> {
    if value.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn require_secret_root(
    label: &str,
    value: &str,
) -> MoneroL2PrivateReserveProofRebalancerResult<()> {
    if value.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn ensure_reserve_floor(
    reserve_upper_bound: u64,
    liability_upper_bound: u64,
    floor_bps: u64,
) -> MoneroL2PrivateReserveProofRebalancerResult<()> {
    if liability_upper_bound == 0 {
        return Err("liability upper bound must be positive for reserve floor checks".to_string());
    }
    if reserve_upper_bound.saturating_mul(MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_MAX_BPS)
        < liability_upper_bound.saturating_mul(floor_bps)
    {
        return Err("reserve proof would violate configured reserve safety floor".to_string());
    }
    Ok(())
}

fn ensure_exposure_cap(
    exposure_upper_bound: u64,
    reserve_upper_bound: u64,
    cap_bps: u64,
    label: &str,
) -> MoneroL2PrivateReserveProofRebalancerResult<()> {
    if reserve_upper_bound == 0 {
        return Err("reserve upper bound must be positive for exposure checks".to_string());
    }
    if exposure_upper_bound.saturating_mul(MONERO_L2_PRIVATE_RESERVE_PROOF_REBALANCER_MAX_BPS)
        > reserve_upper_bound.saturating_mul(cap_bps)
    {
        return Err(format!("{label} exceeds configured cap"));
    }
    Ok(())
}

fn payload_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn secret_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": public_record(value) }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| Value::String(value.clone()))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}
