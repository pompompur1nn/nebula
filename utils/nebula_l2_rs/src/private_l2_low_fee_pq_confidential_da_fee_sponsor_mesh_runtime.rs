use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_DA_FEE_SPONSOR_MESH_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-da-fee-sponsor-mesh-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_DA_FEE_SPONSOR_MESH_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-da-fee-sponsor-mesh-v1";
pub const MESH_SUITE: &str = "low-fee-pq-confidential-da-fee-sponsor-mesh-runtime-v1";
pub const SPONSOR_LIQUIDITY_SCHEME: &str = "pq-confidential-da-fee-sponsor-liquidity-note-v1";
pub const PRIVATE_BUNDLE_SCHEME: &str = "private-l2-confidential-da-fee-bundle-commitment-v1";
pub const REBATE_VOUCHER_SCHEME: &str = "proof-blob-da-fee-rebate-voucher-v1";
pub const CONGESTION_REBATE_SCHEME: &str = "congestion-aware-confidential-da-rebate-curve-v1";
pub const PQ_SETTLEMENT_SCHEME: &str = "pq-authenticated-sponsor-settlement-ticket-v1";
pub const BRIDGE_EXIT_OFFSET_SCHEME: &str = "monero-bridge-exit-da-fee-offset-v1";
pub const MICROBATCH_SHARE_SCHEME: &str = "private-microbatch-da-fee-sharing-note-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str = "roots-only-da-fee-sponsor-mesh-operator-summary-v1";
pub const PUBLIC_STATE_SCHEME: &str = "roots-only-da-fee-sponsor-mesh-public-state-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_CHAIN_ID: u64 = 731_337;
pub const DEVNET_HEIGHT: u64 = 2_936_960;
pub const DEVNET_EPOCH: u64 = 6_011;
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_REBATE_ASSET_ID: &str = "wxmr-devnet";
pub const DEFAULT_QUOTE_ASSET_ID: &str = "dusd-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_SPONSOR_LIQUIDITY_PICONERO: u128 = 10_000_000_000;
pub const DEFAULT_TARGET_USER_FEE_BPS: u64 = 6;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 14;
pub const DEFAULT_BASE_REBATE_BPS: u64 = 6_500;
pub const DEFAULT_PROOF_REBATE_BPS: u64 = 1_500;
pub const DEFAULT_BLOB_REBATE_BPS: u64 = 2_000;
pub const DEFAULT_SPONSOR_RESERVE_BPS: u64 = 1_600;
pub const DEFAULT_BRIDGE_EXIT_OFFSET_BPS: u64 = 3_000;
pub const DEFAULT_MICROBATCH_SHARE_BPS: u64 = 8_250;
pub const DEFAULT_OPERATOR_FEE_BPS: u64 = 35;
pub const DEFAULT_CONGESTION_SOFT_CAP_BPS: u64 = 6_500;
pub const DEFAULT_CONGESTION_HARD_CAP_BPS: u64 = 9_000;
pub const DEFAULT_CONGESTION_REBATE_STEP_BPS: u64 = 500;
pub const DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 8_640;
pub const DEFAULT_BUNDLE_TTL_BLOCKS: u64 = 160;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_EXIT_OFFSET_TTL_BLOCKS: u64 = 4_320;
pub const DEFAULT_MICROBATCH_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_SUMMARY_TTL_BLOCKS: u64 = 720;
pub const MAX_SPONSORS: usize = 1_048_576;
pub const MAX_BUNDLE_COMMITMENTS: usize = 8_388_608;
pub const MAX_REBATE_VOUCHERS: usize = 8_388_608;
pub const MAX_SETTLEMENTS: usize = 4_194_304;
pub const MAX_EXIT_OFFSETS: usize = 4_194_304;
pub const MAX_MICROBATCHES: usize = 4_194_304;
pub const MAX_OPERATOR_SUMMARIES: usize = 1_048_576;
pub const MAX_PRIVACY_FENCES: usize = 8_388_608;
pub const MAX_PUBLIC_EVENTS: usize = 16_777_216;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshLane {
    PrivateTransfer,
    ConfidentialContractCall,
    DefiBundle,
    RecursiveProof,
    BlobDa,
    MoneroBridgeExit,
    WalletFastSync,
    EmergencyEscape,
}

impl MeshLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::ConfidentialContractCall => "confidential_contract_call",
            Self::DefiBundle => "defi_bundle",
            Self::RecursiveProof => "recursive_proof",
            Self::BlobDa => "blob_da",
            Self::MoneroBridgeExit => "monero_bridge_exit",
            Self::WalletFastSync => "wallet_fast_sync",
            Self::EmergencyEscape => "emergency_escape",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::PrivateTransfer => 3,
            Self::ConfidentialContractCall => 5,
            Self::DefiBundle => 7,
            Self::RecursiveProof => 6,
            Self::BlobDa => 4,
            Self::MoneroBridgeExit => 8,
            Self::WalletFastSync => 2,
            Self::EmergencyEscape => 10,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorStatus {
    Pledged,
    Active,
    Allocating,
    PayingRebates,
    Settling,
    Exhausted,
    Paused,
    Retired,
    Slashed,
}

impl SponsorStatus {
    pub fn usable(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Allocating | Self::PayingRebates | Self::Settling
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleStatus {
    Proposed,
    LiquidityReserved,
    ProofPriced,
    BlobPriced,
    Microbatched,
    SettlementQueued,
    Rebated,
    Expired,
    Rejected,
}

impl BundleStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Proposed
                | Self::LiquidityReserved
                | Self::ProofPriced
                | Self::BlobPriced
                | Self::Microbatched
                | Self::SettlementQueued
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Quoted,
    Reserved,
    CongestionAdjusted,
    SettlementLinked,
    Paid,
    Recycled,
    Disputed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Open,
    PqAuthenticated,
    Netting,
    Submitted,
    Settled,
    Disputed,
    Slashed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MicrobatchStatus {
    Open,
    BundlesLinked,
    SharesComputed,
    SettlementQueued,
    Settled,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CongestionBand {
    Empty,
    Low,
    Normal,
    Busy,
    Surge,
    Critical,
}

impl CongestionBand {
    pub fn from_utilization_bps(
        utilization_bps: u64,
        soft_cap_bps: u64,
        hard_cap_bps: u64,
    ) -> Self {
        if utilization_bps == 0 {
            Self::Empty
        } else if utilization_bps < soft_cap_bps / 2 {
            Self::Low
        } else if utilization_bps < soft_cap_bps {
            Self::Normal
        } else if utilization_bps < hard_cap_bps {
            Self::Busy
        } else if utilization_bps < MAX_BPS {
            Self::Surge
        } else {
            Self::Critical
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Low => "low",
            Self::Normal => "normal",
            Self::Busy => "busy",
            Self::Surge => "surge",
            Self::Critical => "critical",
        }
    }

    pub fn rebate_multiplier_bps(self) -> u64 {
        match self {
            Self::Empty => 7_500,
            Self::Low => 8_500,
            Self::Normal => 10_000,
            Self::Busy => 11_500,
            Self::Surge => 13_000,
            Self::Critical => 15_000,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub quote_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_sponsor_liquidity_piconero: u128,
    pub target_user_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub base_rebate_bps: u64,
    pub proof_rebate_bps: u64,
    pub blob_rebate_bps: u64,
    pub sponsor_reserve_bps: u64,
    pub bridge_exit_offset_bps: u64,
    pub microbatch_share_bps: u64,
    pub operator_fee_bps: u64,
    pub congestion_soft_cap_bps: u64,
    pub congestion_hard_cap_bps: u64,
    pub congestion_rebate_step_bps: u64,
    pub epoch_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub bundle_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub exit_offset_ttl_blocks: u64,
    pub microbatch_ttl_blocks: u64,
    pub summary_ttl_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: DEVNET_CHAIN_ID,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEFAULT_REBATE_ASSET_ID.to_string(),
            quote_asset_id: DEFAULT_QUOTE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_sponsor_liquidity_piconero: DEFAULT_MIN_SPONSOR_LIQUIDITY_PICONERO,
            target_user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            base_rebate_bps: DEFAULT_BASE_REBATE_BPS,
            proof_rebate_bps: DEFAULT_PROOF_REBATE_BPS,
            blob_rebate_bps: DEFAULT_BLOB_REBATE_BPS,
            sponsor_reserve_bps: DEFAULT_SPONSOR_RESERVE_BPS,
            bridge_exit_offset_bps: DEFAULT_BRIDGE_EXIT_OFFSET_BPS,
            microbatch_share_bps: DEFAULT_MICROBATCH_SHARE_BPS,
            operator_fee_bps: DEFAULT_OPERATOR_FEE_BPS,
            congestion_soft_cap_bps: DEFAULT_CONGESTION_SOFT_CAP_BPS,
            congestion_hard_cap_bps: DEFAULT_CONGESTION_HARD_CAP_BPS,
            congestion_rebate_step_bps: DEFAULT_CONGESTION_REBATE_STEP_BPS,
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            sponsor_ttl_blocks: DEFAULT_SPONSOR_TTL_BLOCKS,
            bundle_ttl_blocks: DEFAULT_BUNDLE_TTL_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            settlement_ttl_blocks: DEFAULT_SETTLEMENT_TTL_BLOCKS,
            exit_offset_ttl_blocks: DEFAULT_EXIT_OFFSET_TTL_BLOCKS,
            microbatch_ttl_blocks: DEFAULT_MICROBATCH_TTL_BLOCKS,
            summary_ttl_blocks: DEFAULT_SUMMARY_TTL_BLOCKS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_sponsor_liquidity_piconero": self.min_sponsor_liquidity_piconero,
            "target_user_fee_bps": self.target_user_fee_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "base_rebate_bps": self.base_rebate_bps,
            "proof_rebate_bps": self.proof_rebate_bps,
            "blob_rebate_bps": self.blob_rebate_bps,
            "sponsor_reserve_bps": self.sponsor_reserve_bps,
            "bridge_exit_offset_bps": self.bridge_exit_offset_bps,
            "microbatch_share_bps": self.microbatch_share_bps,
            "operator_fee_bps": self.operator_fee_bps,
            "congestion_soft_cap_bps": self.congestion_soft_cap_bps,
            "congestion_hard_cap_bps": self.congestion_hard_cap_bps,
            "congestion_rebate_step_bps": self.congestion_rebate_step_bps,
            "epoch_blocks": self.epoch_blocks,
            "sponsor_ttl_blocks": self.sponsor_ttl_blocks,
            "bundle_ttl_blocks": self.bundle_ttl_blocks,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "exit_offset_ttl_blocks": self.exit_offset_ttl_blocks,
            "microbatch_ttl_blocks": self.microbatch_ttl_blocks,
            "summary_ttl_blocks": self.summary_ttl_blocks,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub sponsors_registered: u64,
    pub sponsor_liquidity_allocations: u64,
    pub bundle_commitments_recorded: u64,
    pub proof_rebates_quoted: u64,
    pub blob_rebates_quoted: u64,
    pub congestion_rebates_adjusted: u64,
    pub settlements_authenticated: u64,
    pub settlements_finalized: u64,
    pub bridge_exit_offsets_issued: u64,
    pub microbatches_opened: u64,
    pub microbatch_shares_computed: u64,
    pub operator_summaries_recorded: u64,
    pub privacy_fences_registered: u64,
    pub public_events: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsors_registered": self.sponsors_registered,
            "sponsor_liquidity_allocations": self.sponsor_liquidity_allocations,
            "bundle_commitments_recorded": self.bundle_commitments_recorded,
            "proof_rebates_quoted": self.proof_rebates_quoted,
            "blob_rebates_quoted": self.blob_rebates_quoted,
            "congestion_rebates_adjusted": self.congestion_rebates_adjusted,
            "settlements_authenticated": self.settlements_authenticated,
            "settlements_finalized": self.settlements_finalized,
            "bridge_exit_offsets_issued": self.bridge_exit_offsets_issued,
            "microbatches_opened": self.microbatches_opened,
            "microbatch_shares_computed": self.microbatch_shares_computed,
            "operator_summaries_recorded": self.operator_summaries_recorded,
            "privacy_fences_registered": self.privacy_fences_registered,
            "public_events": self.public_events,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub sponsors_root: String,
    pub sponsor_indexes_root: String,
    pub bundle_commitments_root: String,
    pub rebate_vouchers_root: String,
    pub settlements_root: String,
    pub exit_offsets_root: String,
    pub microbatches_root: String,
    pub operator_summaries_root: String,
    pub privacy_fences_root: String,
    pub events_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsors_root": self.sponsors_root,
            "sponsor_indexes_root": self.sponsor_indexes_root,
            "bundle_commitments_root": self.bundle_commitments_root,
            "rebate_vouchers_root": self.rebate_vouchers_root,
            "settlements_root": self.settlements_root,
            "exit_offsets_root": self.exit_offsets_root,
            "microbatches_root": self.microbatches_root,
            "operator_summaries_root": self.operator_summaries_root,
            "privacy_fences_root": self.privacy_fences_root,
            "events_root": self.events_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsorLiquidityRequest {
    pub sponsor_commitment: String,
    pub sponsor_label: String,
    pub lane: MeshLane,
    pub liquidity_piconero: u128,
    pub max_fee_bps: u64,
    pub reserve_bps: u64,
    pub pq_public_key_commitment: String,
    pub policy_root: String,
    pub valid_from_height: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsorLiquidityRecord {
    pub sponsor_id: String,
    pub sponsor_commitment: String,
    pub sponsor_label: String,
    pub lane: MeshLane,
    pub status: SponsorStatus,
    pub liquidity_piconero: u128,
    pub reserved_piconero: u128,
    pub spent_piconero: u128,
    pub max_fee_bps: u64,
    pub reserve_bps: u64,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub pq_public_key_commitment: String,
    pub policy_root: String,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
    pub allocation_root: String,
}

impl SponsorLiquidityRecord {
    pub fn from_request(config: &Config, request: SponsorLiquidityRequest) -> Self {
        let sponsor_id = sponsor_id(
            &request.sponsor_commitment,
            request.lane,
            request.valid_from_height,
            request.nonce,
        );
        let allocation_root = domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-FEE-SPONSOR-MESH:SPONSOR-ALLOCATION",
            &[
                HashPart::Str(&sponsor_id),
                HashPart::Str(&request.pq_public_key_commitment),
                HashPart::U64(request.lane.priority_weight()),
                HashPart::Int(i128_from_u128(request.liquidity_piconero)),
            ],
            32,
        );
        Self {
            sponsor_id,
            sponsor_commitment: request.sponsor_commitment,
            sponsor_label: request.sponsor_label,
            lane: request.lane,
            status: SponsorStatus::Active,
            liquidity_piconero: request.liquidity_piconero,
            reserved_piconero: 0,
            spent_piconero: 0,
            max_fee_bps: request.max_fee_bps,
            reserve_bps: request.reserve_bps,
            pq_security_bits: config.min_pq_security_bits,
            privacy_set_size: config.min_privacy_set_size,
            pq_public_key_commitment: request.pq_public_key_commitment,
            policy_root: request.policy_root,
            valid_from_height: request.valid_from_height,
            expires_at_height: request
                .valid_from_height
                .saturating_add(config.sponsor_ttl_blocks),
            allocation_root,
        }
    }

    pub fn free_liquidity(&self) -> u128 {
        self.liquidity_piconero
            .saturating_sub(self.reserved_piconero)
            .saturating_sub(self.spent_piconero)
    }

    pub fn reserve_floor(&self) -> u128 {
        bps_amount(self.liquidity_piconero, self.reserve_bps)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "sponsor_commitment": self.sponsor_commitment,
            "sponsor_label": self.sponsor_label,
            "lane": self.lane.as_str(),
            "status": self.status,
            "liquidity_piconero": self.liquidity_piconero,
            "reserved_piconero": self.reserved_piconero,
            "spent_piconero": self.spent_piconero,
            "free_liquidity_piconero": self.free_liquidity(),
            "reserve_floor_piconero": self.reserve_floor(),
            "max_fee_bps": self.max_fee_bps,
            "reserve_bps": self.reserve_bps,
            "pq_security_bits": self.pq_security_bits,
            "privacy_set_size": self.privacy_set_size,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "policy_root": self.policy_root,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
            "allocation_root": self.allocation_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateBundleCommitmentRequest {
    pub bundle_commitment: String,
    pub lane: MeshLane,
    pub sponsor_id: String,
    pub user_fee_commitment: String,
    pub proof_commitment: String,
    pub blob_commitment: String,
    pub bridge_exit_commitment: String,
    pub bundle_weight: u64,
    pub proof_units: u64,
    pub blob_bytes: u64,
    pub quoted_da_fee_piconero: u128,
    pub privacy_set_size: u64,
    pub created_at_height: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateBundleCommitmentRecord {
    pub bundle_id: String,
    pub bundle_commitment: String,
    pub lane: MeshLane,
    pub sponsor_id: String,
    pub status: BundleStatus,
    pub user_fee_commitment: String,
    pub proof_commitment: String,
    pub blob_commitment: String,
    pub bridge_exit_commitment: String,
    pub bundle_weight: u64,
    pub proof_units: u64,
    pub blob_bytes: u64,
    pub quoted_da_fee_piconero: u128,
    pub reserved_sponsor_piconero: u128,
    pub effective_user_fee_piconero: u128,
    pub privacy_set_size: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub rebate_voucher_id: String,
    pub microbatch_id: String,
    pub commitment_root: String,
}

impl PrivateBundleCommitmentRecord {
    pub fn from_request(
        config: &Config,
        request: PrivateBundleCommitmentRequest,
        reserved_sponsor_piconero: u128,
    ) -> Self {
        let bundle_id = bundle_id(
            &request.bundle_commitment,
            request.lane,
            request.created_at_height,
            request.nonce,
        );
        let effective_user_fee_piconero = request
            .quoted_da_fee_piconero
            .saturating_sub(reserved_sponsor_piconero);
        let commitment_root = domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-FEE-SPONSOR-MESH:BUNDLE-COMMITMENT",
            &[
                HashPart::Str(&bundle_id),
                HashPart::Str(&request.user_fee_commitment),
                HashPart::Str(&request.proof_commitment),
                HashPart::Str(&request.blob_commitment),
                HashPart::Str(&request.bridge_exit_commitment),
                HashPart::U64(request.bundle_weight),
                HashPart::Int(i128_from_u128(request.quoted_da_fee_piconero)),
            ],
            32,
        );
        Self {
            bundle_id,
            bundle_commitment: request.bundle_commitment,
            lane: request.lane,
            sponsor_id: request.sponsor_id,
            status: BundleStatus::LiquidityReserved,
            user_fee_commitment: request.user_fee_commitment,
            proof_commitment: request.proof_commitment,
            blob_commitment: request.blob_commitment,
            bridge_exit_commitment: request.bridge_exit_commitment,
            bundle_weight: request.bundle_weight,
            proof_units: request.proof_units,
            blob_bytes: request.blob_bytes,
            quoted_da_fee_piconero: request.quoted_da_fee_piconero,
            reserved_sponsor_piconero,
            effective_user_fee_piconero,
            privacy_set_size: request.privacy_set_size,
            created_at_height: request.created_at_height,
            expires_at_height: request
                .created_at_height
                .saturating_add(config.bundle_ttl_blocks),
            rebate_voucher_id: String::new(),
            microbatch_id: String::new(),
            commitment_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bundle_id": self.bundle_id,
            "bundle_commitment": self.bundle_commitment,
            "lane": self.lane.as_str(),
            "sponsor_id": self.sponsor_id,
            "status": self.status,
            "user_fee_commitment": self.user_fee_commitment,
            "proof_commitment": self.proof_commitment,
            "blob_commitment": self.blob_commitment,
            "bridge_exit_commitment": self.bridge_exit_commitment,
            "bundle_weight": self.bundle_weight,
            "proof_units": self.proof_units,
            "blob_bytes": self.blob_bytes,
            "quoted_da_fee_piconero": self.quoted_da_fee_piconero,
            "reserved_sponsor_piconero": self.reserved_sponsor_piconero,
            "effective_user_fee_piconero": self.effective_user_fee_piconero,
            "privacy_set_size": self.privacy_set_size,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "rebate_voucher_id": self.rebate_voucher_id,
            "microbatch_id": self.microbatch_id,
            "commitment_root": self.commitment_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RebateVoucherRequest {
    pub bundle_id: String,
    pub sponsor_id: String,
    pub proof_fee_piconero: u128,
    pub blob_fee_piconero: u128,
    pub congestion_utilization_bps: u64,
    pub claim_nullifier: String,
    pub recipient_commitment: String,
    pub quote_height: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RebateVoucherRecord {
    pub voucher_id: String,
    pub bundle_id: String,
    pub sponsor_id: String,
    pub status: RebateStatus,
    pub proof_fee_piconero: u128,
    pub blob_fee_piconero: u128,
    pub proof_rebate_piconero: u128,
    pub blob_rebate_piconero: u128,
    pub congestion_rebate_piconero: u128,
    pub total_rebate_piconero: u128,
    pub congestion_band: CongestionBand,
    pub congestion_utilization_bps: u64,
    pub claim_nullifier: String,
    pub recipient_commitment: String,
    pub quote_height: u64,
    pub expires_at_height: u64,
    pub voucher_root: String,
}

impl RebateVoucherRecord {
    pub fn from_request(config: &Config, request: RebateVoucherRequest) -> Self {
        let congestion_band = CongestionBand::from_utilization_bps(
            request.congestion_utilization_bps,
            config.congestion_soft_cap_bps,
            config.congestion_hard_cap_bps,
        );
        let proof_rebate_piconero = bps_amount(request.proof_fee_piconero, config.proof_rebate_bps);
        let blob_rebate_piconero = bps_amount(request.blob_fee_piconero, config.blob_rebate_bps);
        let base = proof_rebate_piconero.saturating_add(blob_rebate_piconero);
        let congestion_rebate_piconero = bps_amount(
            bps_amount(
                request
                    .proof_fee_piconero
                    .saturating_add(request.blob_fee_piconero),
                config.base_rebate_bps,
            ),
            congestion_band
                .rebate_multiplier_bps()
                .saturating_sub(MAX_BPS)
                .saturating_add(config.congestion_rebate_step_bps),
        );
        let total_rebate_piconero = base.saturating_add(congestion_rebate_piconero);
        let voucher_id = rebate_voucher_id(
            &request.bundle_id,
            &request.claim_nullifier,
            request.quote_height,
            request.nonce,
        );
        let voucher_root = domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-FEE-SPONSOR-MESH:REBATE-VOUCHER",
            &[
                HashPart::Str(&voucher_id),
                HashPart::Str(&request.bundle_id),
                HashPart::Str(&request.sponsor_id),
                HashPart::Str(&request.recipient_commitment),
                HashPart::Int(i128_from_u128(total_rebate_piconero)),
                HashPart::U64(request.congestion_utilization_bps),
            ],
            32,
        );
        Self {
            voucher_id,
            bundle_id: request.bundle_id,
            sponsor_id: request.sponsor_id,
            status: RebateStatus::CongestionAdjusted,
            proof_fee_piconero: request.proof_fee_piconero,
            blob_fee_piconero: request.blob_fee_piconero,
            proof_rebate_piconero,
            blob_rebate_piconero,
            congestion_rebate_piconero,
            total_rebate_piconero,
            congestion_band,
            congestion_utilization_bps: request.congestion_utilization_bps,
            claim_nullifier: request.claim_nullifier,
            recipient_commitment: request.recipient_commitment,
            quote_height: request.quote_height,
            expires_at_height: request
                .quote_height
                .saturating_add(config.rebate_ttl_blocks),
            voucher_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "voucher_id": self.voucher_id,
            "bundle_id": self.bundle_id,
            "sponsor_id": self.sponsor_id,
            "status": self.status,
            "proof_fee_piconero": self.proof_fee_piconero,
            "blob_fee_piconero": self.blob_fee_piconero,
            "proof_rebate_piconero": self.proof_rebate_piconero,
            "blob_rebate_piconero": self.blob_rebate_piconero,
            "congestion_rebate_piconero": self.congestion_rebate_piconero,
            "total_rebate_piconero": self.total_rebate_piconero,
            "congestion_band": self.congestion_band.as_str(),
            "congestion_utilization_bps": self.congestion_utilization_bps,
            "claim_nullifier": self.claim_nullifier,
            "recipient_commitment": self.recipient_commitment,
            "quote_height": self.quote_height,
            "expires_at_height": self.expires_at_height,
            "voucher_root": self.voucher_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqSettlementRequest {
    pub sponsor_id: String,
    pub bundle_id: String,
    pub voucher_id: String,
    pub pq_auth_commitment: String,
    pub settlement_ciphertext_root: String,
    pub debit_piconero: u128,
    pub credit_piconero: u128,
    pub settlement_height: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqSettlementRecord {
    pub settlement_id: String,
    pub sponsor_id: String,
    pub bundle_id: String,
    pub voucher_id: String,
    pub status: SettlementStatus,
    pub pq_auth_commitment: String,
    pub settlement_ciphertext_root: String,
    pub debit_piconero: u128,
    pub credit_piconero: u128,
    pub net_debit_piconero: u128,
    pub settlement_height: u64,
    pub expires_at_height: u64,
    pub settlement_root: String,
}

impl PqSettlementRecord {
    pub fn from_request(config: &Config, request: PqSettlementRequest) -> Self {
        let settlement_id = settlement_id(
            &request.sponsor_id,
            &request.bundle_id,
            &request.voucher_id,
            request.settlement_height,
            request.nonce,
        );
        let net_debit_piconero = request
            .debit_piconero
            .saturating_sub(request.credit_piconero);
        let settlement_root = domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-FEE-SPONSOR-MESH:PQ-SETTLEMENT",
            &[
                HashPart::Str(&settlement_id),
                HashPart::Str(&request.pq_auth_commitment),
                HashPart::Str(&request.settlement_ciphertext_root),
                HashPart::Int(i128_from_u128(request.debit_piconero)),
                HashPart::Int(i128_from_u128(request.credit_piconero)),
            ],
            32,
        );
        Self {
            settlement_id,
            sponsor_id: request.sponsor_id,
            bundle_id: request.bundle_id,
            voucher_id: request.voucher_id,
            status: SettlementStatus::PqAuthenticated,
            pq_auth_commitment: request.pq_auth_commitment,
            settlement_ciphertext_root: request.settlement_ciphertext_root,
            debit_piconero: request.debit_piconero,
            credit_piconero: request.credit_piconero,
            net_debit_piconero,
            settlement_height: request.settlement_height,
            expires_at_height: request
                .settlement_height
                .saturating_add(config.settlement_ttl_blocks),
            settlement_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "sponsor_id": self.sponsor_id,
            "bundle_id": self.bundle_id,
            "voucher_id": self.voucher_id,
            "status": self.status,
            "pq_auth_commitment": self.pq_auth_commitment,
            "settlement_ciphertext_root": self.settlement_ciphertext_root,
            "debit_piconero": self.debit_piconero,
            "credit_piconero": self.credit_piconero,
            "net_debit_piconero": self.net_debit_piconero,
            "settlement_height": self.settlement_height,
            "expires_at_height": self.expires_at_height,
            "settlement_root": self.settlement_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BridgeExitOffsetRequest {
    pub exit_commitment: String,
    pub bundle_id: String,
    pub sponsor_id: String,
    pub exit_fee_piconero: u128,
    pub da_fee_component_piconero: u128,
    pub offset_recipient_commitment: String,
    pub created_at_height: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BridgeExitOffsetRecord {
    pub offset_id: String,
    pub exit_commitment: String,
    pub bundle_id: String,
    pub sponsor_id: String,
    pub exit_fee_piconero: u128,
    pub da_fee_component_piconero: u128,
    pub offset_piconero: u128,
    pub offset_recipient_commitment: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub offset_root: String,
}

impl BridgeExitOffsetRecord {
    pub fn from_request(config: &Config, request: BridgeExitOffsetRequest) -> Self {
        let offset_id = bridge_exit_offset_id(
            &request.exit_commitment,
            &request.bundle_id,
            request.created_at_height,
            request.nonce,
        );
        let offset_piconero = bps_amount(
            request.da_fee_component_piconero,
            config.bridge_exit_offset_bps,
        );
        let offset_root = domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-FEE-SPONSOR-MESH:BRIDGE-EXIT-OFFSET",
            &[
                HashPart::Str(&offset_id),
                HashPart::Str(&request.exit_commitment),
                HashPart::Str(&request.bundle_id),
                HashPart::Str(&request.offset_recipient_commitment),
                HashPart::Int(i128_from_u128(offset_piconero)),
            ],
            32,
        );
        Self {
            offset_id,
            exit_commitment: request.exit_commitment,
            bundle_id: request.bundle_id,
            sponsor_id: request.sponsor_id,
            exit_fee_piconero: request.exit_fee_piconero,
            da_fee_component_piconero: request.da_fee_component_piconero,
            offset_piconero,
            offset_recipient_commitment: request.offset_recipient_commitment,
            created_at_height: request.created_at_height,
            expires_at_height: request
                .created_at_height
                .saturating_add(config.exit_offset_ttl_blocks),
            offset_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "offset_id": self.offset_id,
            "exit_commitment": self.exit_commitment,
            "bundle_id": self.bundle_id,
            "sponsor_id": self.sponsor_id,
            "exit_fee_piconero": self.exit_fee_piconero,
            "da_fee_component_piconero": self.da_fee_component_piconero,
            "offset_piconero": self.offset_piconero,
            "offset_recipient_commitment": self.offset_recipient_commitment,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "offset_root": self.offset_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MicrobatchRequest {
    pub microbatch_commitment: String,
    pub lane: MeshLane,
    pub operator_id: String,
    pub bundle_ids: Vec<String>,
    pub total_da_fee_piconero: u128,
    pub total_weight: u64,
    pub created_at_height: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MicrobatchShareRecord {
    pub microbatch_id: String,
    pub microbatch_commitment: String,
    pub lane: MeshLane,
    pub operator_id: String,
    pub status: MicrobatchStatus,
    pub bundle_ids: Vec<String>,
    pub total_da_fee_piconero: u128,
    pub total_weight: u64,
    pub shared_fee_piconero: u128,
    pub operator_fee_piconero: u128,
    pub per_weight_fee_piconero: u128,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub share_root: String,
}

impl MicrobatchShareRecord {
    pub fn from_request(config: &Config, request: MicrobatchRequest) -> Self {
        let microbatch_id = microbatch_id(
            &request.microbatch_commitment,
            request.lane,
            request.created_at_height,
            request.nonce,
        );
        let shared_fee_piconero =
            bps_amount(request.total_da_fee_piconero, config.microbatch_share_bps);
        let operator_fee_piconero =
            bps_amount(request.total_da_fee_piconero, config.operator_fee_bps);
        let per_weight_fee_piconero = if request.total_weight == 0 {
            0
        } else {
            shared_fee_piconero / u128::from(request.total_weight)
        };
        let bundle_root = merkle_str_root(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-FEE-SPONSOR-MESH:MICROBATCH-BUNDLES",
            request.bundle_ids.iter().map(String::as_str),
        );
        let share_root = domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-FEE-SPONSOR-MESH:MICROBATCH-SHARE",
            &[
                HashPart::Str(&microbatch_id),
                HashPart::Str(&request.operator_id),
                HashPart::Str(&bundle_root),
                HashPart::Int(i128_from_u128(shared_fee_piconero)),
                HashPart::U64(request.total_weight),
            ],
            32,
        );
        Self {
            microbatch_id,
            microbatch_commitment: request.microbatch_commitment,
            lane: request.lane,
            operator_id: request.operator_id,
            status: MicrobatchStatus::SharesComputed,
            bundle_ids: request.bundle_ids,
            total_da_fee_piconero: request.total_da_fee_piconero,
            total_weight: request.total_weight,
            shared_fee_piconero,
            operator_fee_piconero,
            per_weight_fee_piconero,
            created_at_height: request.created_at_height,
            expires_at_height: request
                .created_at_height
                .saturating_add(config.microbatch_ttl_blocks),
            share_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "microbatch_id": self.microbatch_id,
            "microbatch_commitment": self.microbatch_commitment,
            "lane": self.lane.as_str(),
            "operator_id": self.operator_id,
            "status": self.status,
            "bundle_ids": self.bundle_ids,
            "total_da_fee_piconero": self.total_da_fee_piconero,
            "total_weight": self.total_weight,
            "shared_fee_piconero": self.shared_fee_piconero,
            "operator_fee_piconero": self.operator_fee_piconero,
            "per_weight_fee_piconero": self.per_weight_fee_piconero,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "share_root": self.share_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorSummaryRequest {
    pub operator_id: String,
    pub epoch: u64,
    pub lane: MeshLane,
    pub bundle_count: u64,
    pub microbatch_count: u64,
    pub sponsored_fee_piconero: u128,
    pub rebate_paid_piconero: u128,
    pub exit_offset_piconero: u128,
    pub settlement_root: String,
    pub performance_root: String,
    pub posted_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorSummaryRecord {
    pub summary_id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub lane: MeshLane,
    pub bundle_count: u64,
    pub microbatch_count: u64,
    pub sponsored_fee_piconero: u128,
    pub rebate_paid_piconero: u128,
    pub exit_offset_piconero: u128,
    pub settlement_root: String,
    pub performance_root: String,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
    pub summary_root: String,
}

impl OperatorSummaryRecord {
    pub fn from_request(config: &Config, request: OperatorSummaryRequest) -> Self {
        let summary_id = operator_summary_id(&request.operator_id, request.epoch, request.lane);
        let summary_root = domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-FEE-SPONSOR-MESH:OPERATOR-SUMMARY",
            &[
                HashPart::Str(&summary_id),
                HashPart::Str(&request.settlement_root),
                HashPart::Str(&request.performance_root),
                HashPart::U64(request.bundle_count),
                HashPart::Int(i128_from_u128(request.sponsored_fee_piconero)),
            ],
            32,
        );
        Self {
            summary_id,
            operator_id: request.operator_id,
            epoch: request.epoch,
            lane: request.lane,
            bundle_count: request.bundle_count,
            microbatch_count: request.microbatch_count,
            sponsored_fee_piconero: request.sponsored_fee_piconero,
            rebate_paid_piconero: request.rebate_paid_piconero,
            exit_offset_piconero: request.exit_offset_piconero,
            settlement_root: request.settlement_root,
            performance_root: request.performance_root,
            posted_at_height: request.posted_at_height,
            expires_at_height: request
                .posted_at_height
                .saturating_add(config.summary_ttl_blocks),
            summary_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "operator_id": self.operator_id,
            "epoch": self.epoch,
            "lane": self.lane.as_str(),
            "bundle_count": self.bundle_count,
            "microbatch_count": self.microbatch_count,
            "sponsored_fee_piconero": self.sponsored_fee_piconero,
            "rebate_paid_piconero": self.rebate_paid_piconero,
            "exit_offset_piconero": self.exit_offset_piconero,
            "settlement_root": self.settlement_root,
            "performance_root": self.performance_root,
            "posted_at_height": self.posted_at_height,
            "expires_at_height": self.expires_at_height,
            "summary_root": self.summary_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyFenceRecord {
    pub fence_id: String,
    pub nullifier: String,
    pub scope: String,
    pub height: u64,
    pub fence_root: String,
}

impl PrivacyFenceRecord {
    pub fn new(nullifier: impl Into<String>, scope: impl Into<String>, height: u64) -> Self {
        let nullifier = nullifier.into();
        let scope = scope.into();
        let fence_id = privacy_fence_id(&nullifier, &scope, height);
        let fence_root = domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-FEE-SPONSOR-MESH:PRIVACY-FENCE",
            &[
                HashPart::Str(&fence_id),
                HashPart::Str(&nullifier),
                HashPart::Str(&scope),
                HashPart::U64(height),
            ],
            32,
        );
        Self {
            fence_id,
            nullifier,
            scope,
            height,
            fence_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "nullifier": self.nullifier,
            "scope": self.scope,
            "height": self.height,
            "fence_root": self.fence_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub sponsors: BTreeMap<String, SponsorLiquidityRecord>,
    pub sponsors_by_lane: BTreeMap<MeshLane, BTreeSet<String>>,
    pub bundle_commitments: BTreeMap<String, PrivateBundleCommitmentRecord>,
    pub rebate_vouchers: BTreeMap<String, RebateVoucherRecord>,
    pub settlements: BTreeMap<String, PqSettlementRecord>,
    pub exit_offsets: BTreeMap<String, BridgeExitOffsetRecord>,
    pub microbatches: BTreeMap<String, MicrobatchShareRecord>,
    pub operator_summaries: BTreeMap<String, OperatorSummaryRecord>,
    pub privacy_fences: BTreeMap<String, PrivacyFenceRecord>,
    pub public_events: Vec<Value>,
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            sponsors: BTreeMap::new(),
            sponsors_by_lane: BTreeMap::new(),
            bundle_commitments: BTreeMap::new(),
            rebate_vouchers: BTreeMap::new(),
            settlements: BTreeMap::new(),
            exit_offsets: BTreeMap::new(),
            microbatches: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            public_events: Vec::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet())
    }

    pub fn register_sponsor_liquidity(
        &mut self,
        request: SponsorLiquidityRequest,
    ) -> Result<String> {
        ensure!(
            self.sponsors.len() < MAX_SPONSORS,
            "sponsor capacity reached"
        );
        ensure!(
            request.liquidity_piconero >= self.config.min_sponsor_liquidity_piconero,
            "sponsor liquidity below minimum"
        );
        ensure!(
            request.max_fee_bps <= self.config.max_user_fee_bps,
            "sponsor max fee bps exceeds config maximum"
        );
        ensure!(
            request.reserve_bps <= MAX_BPS,
            "sponsor reserve bps exceeds maximum"
        );
        let record = SponsorLiquidityRecord::from_request(&self.config, request);
        ensure!(
            !self.sponsors.contains_key(&record.sponsor_id),
            "duplicate sponsor id {}",
            record.sponsor_id
        );
        let sponsor_id = record.sponsor_id.clone();
        let lane = record.lane;
        self.sponsors.insert(sponsor_id.clone(), record);
        self.sponsors_by_lane
            .entry(lane)
            .or_default()
            .insert(sponsor_id.clone());
        self.counters.sponsors_registered = self.counters.sponsors_registered.saturating_add(1);
        self.emit_event(
            "sponsor_liquidity_registered",
            json!({ "sponsor_id": sponsor_id }),
        );
        self.refresh_roots();
        Ok(sponsor_id)
    }

    pub fn record_private_bundle_commitment(
        &mut self,
        request: PrivateBundleCommitmentRequest,
    ) -> Result<String> {
        ensure!(
            self.bundle_commitments.len() < MAX_BUNDLE_COMMITMENTS,
            "bundle commitment capacity reached"
        );
        ensure!(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "bundle privacy set below minimum"
        );
        ensure!(
            request.quoted_da_fee_piconero > 0,
            "quoted DA fee must be positive"
        );
        let sponsor = self
            .sponsors
            .get(&request.sponsor_id)
            .ok_or_else(|| format!("unknown sponsor {}", request.sponsor_id))?;
        ensure!(sponsor.status.usable(), "sponsor is not usable");
        ensure!(sponsor.lane == request.lane, "sponsor lane mismatch");
        let reserved_sponsor_piconero = self.sponsor_cover_for(&request);
        ensure!(
            sponsor.free_liquidity()
                >= reserved_sponsor_piconero.saturating_add(sponsor.reserve_floor()),
            "insufficient sponsor free liquidity"
        );
        let record = PrivateBundleCommitmentRecord::from_request(
            &self.config,
            request,
            reserved_sponsor_piconero,
        );
        ensure!(
            !self.bundle_commitments.contains_key(&record.bundle_id),
            "duplicate bundle id {}",
            record.bundle_id
        );
        let bundle_id = record.bundle_id.clone();
        let sponsor_id = record.sponsor_id.clone();
        self.bundle_commitments.insert(bundle_id.clone(), record);
        if let Some(sponsor) = self.sponsors.get_mut(&sponsor_id) {
            sponsor.reserved_piconero = sponsor
                .reserved_piconero
                .saturating_add(reserved_sponsor_piconero);
            sponsor.status = SponsorStatus::Allocating;
        }
        self.counters.bundle_commitments_recorded =
            self.counters.bundle_commitments_recorded.saturating_add(1);
        self.counters.sponsor_liquidity_allocations = self
            .counters
            .sponsor_liquidity_allocations
            .saturating_add(1);
        self.emit_event(
            "private_bundle_committed",
            json!({ "bundle_id": bundle_id }),
        );
        self.refresh_roots();
        Ok(bundle_id)
    }

    pub fn quote_rebate_voucher(&mut self, request: RebateVoucherRequest) -> Result<String> {
        ensure!(
            self.rebate_vouchers.len() < MAX_REBATE_VOUCHERS,
            "rebate voucher capacity reached"
        );
        ensure!(
            self.bundle_commitments.contains_key(&request.bundle_id),
            "unknown bundle {}",
            request.bundle_id
        );
        ensure!(
            self.sponsors.contains_key(&request.sponsor_id),
            "unknown sponsor {}",
            request.sponsor_id
        );
        ensure!(
            !self.privacy_fences.contains_key(&privacy_fence_id(
                &request.claim_nullifier,
                "rebate_claim",
                request.quote_height
            )),
            "rebate nullifier already fenced at height"
        );
        let record = RebateVoucherRecord::from_request(&self.config, request);
        ensure!(
            !self.rebate_vouchers.contains_key(&record.voucher_id),
            "duplicate rebate voucher {}",
            record.voucher_id
        );
        let voucher_id = record.voucher_id.clone();
        let bundle_id = record.bundle_id.clone();
        let sponsor_id = record.sponsor_id.clone();
        let claim_nullifier = record.claim_nullifier.clone();
        let quote_height = record.quote_height;
        let total_rebate_piconero = record.total_rebate_piconero;
        self.rebate_vouchers.insert(voucher_id.clone(), record);
        if let Some(bundle) = self.bundle_commitments.get_mut(&bundle_id) {
            bundle.rebate_voucher_id = voucher_id.clone();
            bundle.status = BundleStatus::ProofPriced;
        }
        if let Some(sponsor) = self.sponsors.get_mut(&sponsor_id) {
            sponsor.reserved_piconero = sponsor
                .reserved_piconero
                .saturating_add(total_rebate_piconero);
            sponsor.status = SponsorStatus::PayingRebates;
        }
        self.register_privacy_fence_internal(claim_nullifier, "rebate_claim", quote_height)?;
        self.counters.proof_rebates_quoted = self.counters.proof_rebates_quoted.saturating_add(1);
        self.counters.blob_rebates_quoted = self.counters.blob_rebates_quoted.saturating_add(1);
        self.counters.congestion_rebates_adjusted =
            self.counters.congestion_rebates_adjusted.saturating_add(1);
        self.emit_event("rebate_voucher_quoted", json!({ "voucher_id": voucher_id }));
        self.refresh_roots();
        Ok(voucher_id)
    }

    pub fn authenticate_sponsor_settlement(
        &mut self,
        request: PqSettlementRequest,
    ) -> Result<String> {
        ensure!(
            self.settlements.len() < MAX_SETTLEMENTS,
            "settlement capacity reached"
        );
        ensure!(
            self.sponsors.contains_key(&request.sponsor_id),
            "unknown sponsor {}",
            request.sponsor_id
        );
        ensure!(
            self.bundle_commitments.contains_key(&request.bundle_id),
            "unknown bundle {}",
            request.bundle_id
        );
        ensure!(
            self.rebate_vouchers.contains_key(&request.voucher_id),
            "unknown voucher {}",
            request.voucher_id
        );
        let record = PqSettlementRecord::from_request(&self.config, request);
        ensure!(
            !self.settlements.contains_key(&record.settlement_id),
            "duplicate settlement {}",
            record.settlement_id
        );
        let settlement_id = record.settlement_id.clone();
        let sponsor_id = record.sponsor_id.clone();
        let bundle_id = record.bundle_id.clone();
        let voucher_id = record.voucher_id.clone();
        let net_debit_piconero = record.net_debit_piconero;
        self.settlements.insert(settlement_id.clone(), record);
        if let Some(sponsor) = self.sponsors.get_mut(&sponsor_id) {
            sponsor.reserved_piconero =
                sponsor.reserved_piconero.saturating_sub(net_debit_piconero);
            sponsor.spent_piconero = sponsor.spent_piconero.saturating_add(net_debit_piconero);
            sponsor.status = if sponsor.free_liquidity() <= sponsor.reserve_floor() {
                SponsorStatus::Exhausted
            } else {
                SponsorStatus::Settling
            };
        }
        if let Some(bundle) = self.bundle_commitments.get_mut(&bundle_id) {
            bundle.status = BundleStatus::SettlementQueued;
        }
        if let Some(voucher) = self.rebate_vouchers.get_mut(&voucher_id) {
            voucher.status = RebateStatus::SettlementLinked;
        }
        self.counters.settlements_authenticated =
            self.counters.settlements_authenticated.saturating_add(1);
        self.emit_event(
            "pq_sponsor_settlement_authenticated",
            json!({ "settlement_id": settlement_id }),
        );
        self.refresh_roots();
        Ok(settlement_id)
    }

    pub fn finalize_settlement(&mut self, settlement_id: &str) -> Result<()> {
        let settlement = self
            .settlements
            .get_mut(settlement_id)
            .ok_or_else(|| format!("unknown settlement {}", settlement_id))?;
        ensure!(
            matches!(
                settlement.status,
                SettlementStatus::PqAuthenticated
                    | SettlementStatus::Netting
                    | SettlementStatus::Submitted
            ),
            "settlement cannot be finalized"
        );
        settlement.status = SettlementStatus::Settled;
        if let Some(bundle) = self.bundle_commitments.get_mut(&settlement.bundle_id) {
            bundle.status = BundleStatus::Rebated;
        }
        if let Some(voucher) = self.rebate_vouchers.get_mut(&settlement.voucher_id) {
            voucher.status = RebateStatus::Paid;
        }
        self.counters.settlements_finalized = self.counters.settlements_finalized.saturating_add(1);
        self.emit_event(
            "pq_sponsor_settlement_finalized",
            json!({ "settlement_id": settlement_id }),
        );
        self.refresh_roots();
        Ok(())
    }

    pub fn issue_bridge_exit_offset(&mut self, request: BridgeExitOffsetRequest) -> Result<String> {
        ensure!(
            self.exit_offsets.len() < MAX_EXIT_OFFSETS,
            "bridge exit offset capacity reached"
        );
        ensure!(
            self.bundle_commitments.contains_key(&request.bundle_id),
            "unknown bundle {}",
            request.bundle_id
        );
        ensure!(
            self.sponsors.contains_key(&request.sponsor_id),
            "unknown sponsor {}",
            request.sponsor_id
        );
        let record = BridgeExitOffsetRecord::from_request(&self.config, request);
        ensure!(
            !self.exit_offsets.contains_key(&record.offset_id),
            "duplicate bridge exit offset {}",
            record.offset_id
        );
        let offset_id = record.offset_id.clone();
        let sponsor_id = record.sponsor_id.clone();
        let offset_piconero = record.offset_piconero;
        self.exit_offsets.insert(offset_id.clone(), record);
        if let Some(sponsor) = self.sponsors.get_mut(&sponsor_id) {
            sponsor.reserved_piconero = sponsor.reserved_piconero.saturating_add(offset_piconero);
        }
        self.counters.bridge_exit_offsets_issued =
            self.counters.bridge_exit_offsets_issued.saturating_add(1);
        self.emit_event(
            "bridge_exit_fee_offset_issued",
            json!({ "offset_id": offset_id }),
        );
        self.refresh_roots();
        Ok(offset_id)
    }

    pub fn open_microbatch(&mut self, request: MicrobatchRequest) -> Result<String> {
        ensure!(
            self.microbatches.len() < MAX_MICROBATCHES,
            "microbatch capacity reached"
        );
        ensure!(
            !request.bundle_ids.is_empty(),
            "microbatch requires bundles"
        );
        ensure!(
            request.total_weight > 0,
            "microbatch total weight must be positive"
        );
        for bundle_id in &request.bundle_ids {
            ensure!(
                self.bundle_commitments.contains_key(bundle_id),
                "unknown microbatch bundle {}",
                bundle_id
            );
        }
        let record = MicrobatchShareRecord::from_request(&self.config, request);
        ensure!(
            !self.microbatches.contains_key(&record.microbatch_id),
            "duplicate microbatch {}",
            record.microbatch_id
        );
        let microbatch_id = record.microbatch_id.clone();
        let bundle_ids = record.bundle_ids.clone();
        self.microbatches.insert(microbatch_id.clone(), record);
        for bundle_id in bundle_ids {
            if let Some(bundle) = self.bundle_commitments.get_mut(&bundle_id) {
                bundle.microbatch_id = microbatch_id.clone();
                bundle.status = BundleStatus::Microbatched;
            }
        }
        self.counters.microbatches_opened = self.counters.microbatches_opened.saturating_add(1);
        self.counters.microbatch_shares_computed =
            self.counters.microbatch_shares_computed.saturating_add(1);
        self.emit_event(
            "microbatch_fee_shares_computed",
            json!({ "microbatch_id": microbatch_id }),
        );
        self.refresh_roots();
        Ok(microbatch_id)
    }

    pub fn record_operator_summary(&mut self, request: OperatorSummaryRequest) -> Result<String> {
        ensure!(
            self.operator_summaries.len() < MAX_OPERATOR_SUMMARIES,
            "operator summary capacity reached"
        );
        let record = OperatorSummaryRecord::from_request(&self.config, request);
        ensure!(
            !self.operator_summaries.contains_key(&record.summary_id),
            "duplicate operator summary {}",
            record.summary_id
        );
        let summary_id = record.summary_id.clone();
        self.operator_summaries.insert(summary_id.clone(), record);
        self.counters.operator_summaries_recorded =
            self.counters.operator_summaries_recorded.saturating_add(1);
        self.emit_event(
            "operator_summary_recorded",
            json!({ "summary_id": summary_id }),
        );
        self.refresh_roots();
        Ok(summary_id)
    }

    pub fn register_privacy_fence(
        &mut self,
        nullifier: impl Into<String>,
        scope: impl Into<String>,
        height: u64,
    ) -> Result<String> {
        let fence_id = self.register_privacy_fence_internal(nullifier, scope, height)?;
        self.refresh_roots();
        Ok(fence_id)
    }

    pub fn allocate_best_sponsor(
        &self,
        lane: MeshLane,
        required_piconero: u128,
    ) -> Option<SponsorLiquidityRecord> {
        let ids = self.sponsors_by_lane.get(&lane)?;
        let mut best: Option<SponsorLiquidityRecord> = None;
        for sponsor_id in ids {
            if let Some(candidate) = self.sponsors.get(sponsor_id) {
                let available_after_reserve = candidate
                    .free_liquidity()
                    .saturating_sub(candidate.reserve_floor());
                if candidate.status.usable() && available_after_reserve >= required_piconero {
                    let replace = match best.as_ref() {
                        Some(current) => candidate.free_liquidity() > current.free_liquidity(),
                        None => true,
                    };
                    if replace {
                        best = Some(candidate.clone());
                    }
                }
            }
        }
        best
    }

    pub fn congestion_quote(
        &self,
        lane: MeshLane,
        utilization_bps: u64,
        fee_piconero: u128,
    ) -> Value {
        let band = CongestionBand::from_utilization_bps(
            utilization_bps,
            self.config.congestion_soft_cap_bps,
            self.config.congestion_hard_cap_bps,
        );
        let lane_boost_bps = lane.priority_weight().saturating_mul(100);
        let adjusted_bps = self
            .config
            .base_rebate_bps
            .saturating_add(lane_boost_bps)
            .min(MAX_BPS);
        let base_rebate = bps_amount(fee_piconero, adjusted_bps);
        let congestion_rebate = bps_amount(base_rebate, band.rebate_multiplier_bps());
        json!({
            "lane": lane.as_str(),
            "utilization_bps": utilization_bps,
            "congestion_band": band.as_str(),
            "fee_piconero": fee_piconero,
            "base_rebate_bps": adjusted_bps,
            "rebate_multiplier_bps": band.rebate_multiplier_bps(),
            "estimated_rebate_piconero": congestion_rebate,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_auth_suite": PQ_AUTH_SUITE,
            "mesh_suite": MESH_SUITE,
            "schemes": {
                "sponsor_liquidity": SPONSOR_LIQUIDITY_SCHEME,
                "private_bundle": PRIVATE_BUNDLE_SCHEME,
                "rebate_voucher": REBATE_VOUCHER_SCHEME,
                "congestion_rebate": CONGESTION_REBATE_SCHEME,
                "pq_settlement": PQ_SETTLEMENT_SCHEME,
                "bridge_exit_offset": BRIDGE_EXIT_OFFSET_SCHEME,
                "microbatch_share": MICROBATCH_SHARE_SCHEME,
                "operator_summary": OPERATOR_SUMMARY_SCHEME,
                "public_state": PUBLIC_STATE_SCHEME,
            },
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-FEE-SPONSOR-MESH:STATE",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(SCHEMA_VERSION),
                HashPart::Str(&self.roots.sponsors_root),
                HashPart::Str(&self.roots.bundle_commitments_root),
                HashPart::Str(&self.roots.rebate_vouchers_root),
                HashPart::Str(&self.roots.settlements_root),
                HashPart::Str(&self.roots.exit_offsets_root),
                HashPart::Str(&self.roots.microbatches_root),
                HashPart::Str(&self.roots.operator_summaries_root),
                HashPart::Str(&self.roots.privacy_fences_root),
                HashPart::Str(&self.roots.events_root),
            ],
            32,
        )
    }

    pub fn refresh_roots(&mut self) {
        self.roots.sponsors_root = merkle_str_root(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-FEE-SPONSOR-MESH:SPONSORS",
            self.sponsors
                .values()
                .map(|record| record.allocation_root.as_str()),
        );
        let sponsor_index_leaves = self
            .sponsors_by_lane
            .iter()
            .flat_map(|(lane, ids)| {
                ids.iter().map(move |id| {
                    domain_hash(
                        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-FEE-SPONSOR-MESH:SPONSOR-INDEX",
                        &[HashPart::Str(lane.as_str()), HashPart::Str(id)],
                        32,
                    )
                })
            })
            .map(Value::String)
            .collect::<Vec<_>>();
        self.roots.sponsor_indexes_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-FEE-SPONSOR-MESH:SPONSOR-INDEXES",
            &sponsor_index_leaves,
        );
        self.roots.bundle_commitments_root = merkle_str_root(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-FEE-SPONSOR-MESH:BUNDLES",
            self.bundle_commitments
                .values()
                .map(|record| record.commitment_root.as_str()),
        );
        self.roots.rebate_vouchers_root = merkle_str_root(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-FEE-SPONSOR-MESH:REBATES",
            self.rebate_vouchers
                .values()
                .map(|record| record.voucher_root.as_str()),
        );
        self.roots.settlements_root = merkle_str_root(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-FEE-SPONSOR-MESH:SETTLEMENTS",
            self.settlements
                .values()
                .map(|record| record.settlement_root.as_str()),
        );
        self.roots.exit_offsets_root = merkle_str_root(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-FEE-SPONSOR-MESH:EXIT-OFFSETS",
            self.exit_offsets
                .values()
                .map(|record| record.offset_root.as_str()),
        );
        self.roots.microbatches_root = merkle_str_root(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-FEE-SPONSOR-MESH:MICROBATCHES",
            self.microbatches
                .values()
                .map(|record| record.share_root.as_str()),
        );
        self.roots.operator_summaries_root = merkle_str_root(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-FEE-SPONSOR-MESH:OPERATOR-SUMMARIES",
            self.operator_summaries
                .values()
                .map(|record| record.summary_root.as_str()),
        );
        self.roots.privacy_fences_root = merkle_str_root(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-FEE-SPONSOR-MESH:PRIVACY-FENCES",
            self.privacy_fences
                .values()
                .map(|record| record.fence_root.as_str()),
        );
        let event_leaves = self
            .public_events
            .iter()
            .filter_map(|event| canonical_event_hash(event).ok())
            .map(Value::String)
            .collect::<Vec<_>>();
        self.roots.events_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-FEE-SPONSOR-MESH:EVENTS",
            &event_leaves,
        );
    }

    fn sponsor_cover_for(&self, request: &PrivateBundleCommitmentRequest) -> u128 {
        let base_cover = bps_amount(request.quoted_da_fee_piconero, self.config.base_rebate_bps);
        let proof_cover = bps_amount(
            u128::from(request.proof_units).saturating_mul(1_000),
            self.config.proof_rebate_bps,
        );
        let blob_cover = bps_amount(u128::from(request.blob_bytes), self.config.blob_rebate_bps);
        base_cover
            .saturating_add(proof_cover)
            .saturating_add(blob_cover)
    }

    fn register_privacy_fence_internal(
        &mut self,
        nullifier: impl Into<String>,
        scope: impl Into<String>,
        height: u64,
    ) -> Result<String> {
        ensure!(
            self.privacy_fences.len() < MAX_PRIVACY_FENCES,
            "privacy fence capacity reached"
        );
        let record = PrivacyFenceRecord::new(nullifier, scope, height);
        ensure!(
            !self.privacy_fences.contains_key(&record.fence_id),
            "duplicate privacy fence {}",
            record.fence_id
        );
        let fence_id = record.fence_id.clone();
        self.privacy_fences.insert(fence_id.clone(), record);
        self.counters.privacy_fences_registered =
            self.counters.privacy_fences_registered.saturating_add(1);
        self.emit_event("privacy_fence_registered", json!({ "fence_id": fence_id }));
        Ok(fence_id)
    }

    fn emit_event(&mut self, kind: &str, body: Value) {
        if self.public_events.len() < MAX_PUBLIC_EVENTS {
            let event_index = self.counters.public_events;
            self.public_events.push(json!({
                "event_index": event_index,
                "kind": kind,
                "body": body,
            }));
            self.counters.public_events = self.counters.public_events.saturating_add(1);
        }
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    let mut state = State::devnet();
    let sponsor_id = match state.register_sponsor_liquidity(SponsorLiquidityRequest {
        sponsor_commitment: "demo-sponsor-commitment-alpha".to_string(),
        sponsor_label: "demo-low-fee-da-sponsor".to_string(),
        lane: MeshLane::ConfidentialContractCall,
        liquidity_piconero: 250_000_000_000,
        max_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
        reserve_bps: DEFAULT_SPONSOR_RESERVE_BPS,
        pq_public_key_commitment: "demo-pq-public-key-commitment-alpha".to_string(),
        policy_root: "demo-sponsor-policy-root-alpha".to_string(),
        valid_from_height: DEVNET_HEIGHT,
        nonce: 1,
    }) {
        Ok(value) => value,
        Err(_) => String::new(),
    };
    let bundle_id = match state.record_private_bundle_commitment(PrivateBundleCommitmentRequest {
        bundle_commitment: "demo-private-bundle-commitment-alpha".to_string(),
        lane: MeshLane::ConfidentialContractCall,
        sponsor_id: sponsor_id.clone(),
        user_fee_commitment: "demo-user-fee-commitment-alpha".to_string(),
        proof_commitment: "demo-recursive-proof-commitment-alpha".to_string(),
        blob_commitment: "demo-da-blob-commitment-alpha".to_string(),
        bridge_exit_commitment: "demo-empty-bridge-exit-commitment".to_string(),
        bundle_weight: 12,
        proof_units: 8,
        blob_bytes: 96_000,
        quoted_da_fee_piconero: 7_500_000,
        privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
        created_at_height: DEVNET_HEIGHT.saturating_add(1),
        nonce: 2,
    }) {
        Ok(value) => value,
        Err(_) => String::new(),
    };
    let voucher_id = match state.quote_rebate_voucher(RebateVoucherRequest {
        bundle_id: bundle_id.clone(),
        sponsor_id: sponsor_id.clone(),
        proof_fee_piconero: 1_250_000,
        blob_fee_piconero: 6_250_000,
        congestion_utilization_bps: 7_200,
        claim_nullifier: "demo-rebate-nullifier-alpha".to_string(),
        recipient_commitment: "demo-recipient-commitment-alpha".to_string(),
        quote_height: DEVNET_HEIGHT.saturating_add(2),
        nonce: 3,
    }) {
        Ok(value) => value,
        Err(_) => String::new(),
    };
    let microbatch_id = match state.open_microbatch(MicrobatchRequest {
        microbatch_commitment: "demo-microbatch-commitment-alpha".to_string(),
        lane: MeshLane::ConfidentialContractCall,
        operator_id: "demo-operator-alpha".to_string(),
        bundle_ids: vec![bundle_id.clone()],
        total_da_fee_piconero: 7_500_000,
        total_weight: 12,
        created_at_height: DEVNET_HEIGHT.saturating_add(3),
        nonce: 4,
    }) {
        Ok(value) => value,
        Err(_) => String::new(),
    };
    let settlement_id = match state.authenticate_sponsor_settlement(PqSettlementRequest {
        sponsor_id: sponsor_id.clone(),
        bundle_id: bundle_id.clone(),
        voucher_id,
        pq_auth_commitment: "demo-pq-auth-commitment-alpha".to_string(),
        settlement_ciphertext_root: "demo-settlement-ciphertext-root-alpha".to_string(),
        debit_piconero: 5_000_000,
        credit_piconero: 500_000,
        settlement_height: DEVNET_HEIGHT.saturating_add(4),
        nonce: 5,
    }) {
        Ok(value) => value,
        Err(_) => String::new(),
    };
    let _ = state.finalize_settlement(&settlement_id);
    let _ = state.issue_bridge_exit_offset(BridgeExitOffsetRequest {
        exit_commitment: "demo-bridge-exit-commitment-alpha".to_string(),
        bundle_id: bundle_id.clone(),
        sponsor_id,
        exit_fee_piconero: 9_000_000,
        da_fee_component_piconero: 3_000_000,
        offset_recipient_commitment: "demo-exit-offset-recipient-alpha".to_string(),
        created_at_height: DEVNET_HEIGHT.saturating_add(5),
        nonce: 6,
    });
    let _ = state.record_operator_summary(OperatorSummaryRequest {
        operator_id: "demo-operator-alpha".to_string(),
        epoch: DEVNET_EPOCH,
        lane: MeshLane::ConfidentialContractCall,
        bundle_count: 1,
        microbatch_count: 1,
        sponsored_fee_piconero: 5_000_000,
        rebate_paid_piconero: 4_500_000,
        exit_offset_piconero: 900_000,
        settlement_root: state.roots.settlements_root.clone(),
        performance_root: microbatch_id,
        posted_at_height: DEVNET_HEIGHT.saturating_add(6),
    });
    state
}

pub fn public_record() -> Value {
    demo().public_record()
}

pub fn state_root() -> String {
    demo().state_root()
}

fn bps_amount(amount: u128, bps: u64) -> u128 {
    amount.saturating_mul(u128::from(bps)) / u128::from(MAX_BPS)
}

fn i128_from_u128(value: u128) -> i128 {
    if value > i128::MAX as u128 {
        i128::MAX
    } else {
        value as i128
    }
}

fn merkle_str_root<'a, I>(domain: &str, leaves: I) -> String
where
    I: IntoIterator<Item = &'a str>,
{
    let values = leaves
        .into_iter()
        .map(|leaf| Value::String(leaf.to_string()))
        .collect::<Vec<_>>();
    merkle_root(domain, &values)
}

fn sponsor_id(commitment: &str, lane: MeshLane, height: u64, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-FEE-SPONSOR-MESH:SPONSOR-ID",
        &[
            HashPart::Str(commitment),
            HashPart::Str(lane.as_str()),
            HashPart::U64(height),
            HashPart::U64(nonce),
        ],
        32,
    )
}

fn bundle_id(commitment: &str, lane: MeshLane, height: u64, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-FEE-SPONSOR-MESH:BUNDLE-ID",
        &[
            HashPart::Str(commitment),
            HashPart::Str(lane.as_str()),
            HashPart::U64(height),
            HashPart::U64(nonce),
        ],
        32,
    )
}

fn rebate_voucher_id(bundle_id: &str, nullifier: &str, height: u64, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-FEE-SPONSOR-MESH:REBATE-VOUCHER-ID",
        &[
            HashPart::Str(bundle_id),
            HashPart::Str(nullifier),
            HashPart::U64(height),
            HashPart::U64(nonce),
        ],
        32,
    )
}

fn settlement_id(
    sponsor_id: &str,
    bundle_id: &str,
    voucher_id: &str,
    height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-FEE-SPONSOR-MESH:SETTLEMENT-ID",
        &[
            HashPart::Str(sponsor_id),
            HashPart::Str(bundle_id),
            HashPart::Str(voucher_id),
            HashPart::U64(height),
            HashPart::U64(nonce),
        ],
        32,
    )
}

fn bridge_exit_offset_id(
    exit_commitment: &str,
    bundle_id: &str,
    height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-FEE-SPONSOR-MESH:BRIDGE-EXIT-OFFSET-ID",
        &[
            HashPart::Str(exit_commitment),
            HashPart::Str(bundle_id),
            HashPart::U64(height),
            HashPart::U64(nonce),
        ],
        32,
    )
}

fn microbatch_id(commitment: &str, lane: MeshLane, height: u64, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-FEE-SPONSOR-MESH:MICROBATCH-ID",
        &[
            HashPart::Str(commitment),
            HashPart::Str(lane.as_str()),
            HashPart::U64(height),
            HashPart::U64(nonce),
        ],
        32,
    )
}

fn operator_summary_id(operator_id: &str, epoch: u64, lane: MeshLane) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-FEE-SPONSOR-MESH:OPERATOR-SUMMARY-ID",
        &[
            HashPart::Str(operator_id),
            HashPart::U64(epoch),
            HashPart::Str(lane.as_str()),
        ],
        32,
    )
}

fn privacy_fence_id(nullifier: &str, scope: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-FEE-SPONSOR-MESH:PRIVACY-FENCE-ID",
        &[
            HashPart::Str(nullifier),
            HashPart::Str(scope),
            HashPart::U64(height),
        ],
        32,
    )
}

fn canonical_event_hash(value: &Value) -> Result<String> {
    let encoded = serde_json::to_string(value).map_err(|err| err.to_string())?;
    Ok(domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-FEE-SPONSOR-MESH:EVENT-HASH",
        &[HashPart::Str(&encoded)],
        32,
    ))
}
