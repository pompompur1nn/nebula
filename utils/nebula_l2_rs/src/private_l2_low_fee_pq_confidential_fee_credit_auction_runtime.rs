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

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_FEE_CREDIT_AUCTION_RUNTIME_PROTOCOL_VERSION: &str =
    "private-l2-low-fee-pq-confidential-fee-credit-auction-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_FEE_CREDIT_AUCTION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const PQ_SEALING_SUITE: &str = "ML-KEM-1024+XWing-sealed-bid-envelope";
pub const CONFIDENTIAL_AMOUNT_SCHEME: &str = "ringct-style-fee-credit-commitment-v1";
pub const SETTLEMENT_PROOF_SCHEME: &str = "zk-pq-confidential-fee-credit-auction-settlement-v1";
pub const PRIVACY_FENCE_SCHEME: &str = "monero-l2-fee-credit-nullifier-fence-v1";
pub const ORACLE_ATTESTATION_SCHEME: &str = "pq-fee-credit-oracle-attestation-root-v1";
pub const SPONSOR_VAULT_SCHEME: &str = "private-l2-low-fee-sponsor-vault-root-v1";
pub const REBATE_COUPON_SCHEME: &str = "private-l2-roots-only-rebate-coupon-v1";
pub const FAST_LANE_ALLOCATION_SCHEME: &str = "pq-private-fast-lane-fee-credit-allocation-v1";
pub const SLASHING_EVIDENCE_SCHEME: &str = "pq-private-fee-credit-auction-slasher-v1";
pub const DEVNET_HEIGHT: u64 = 1_826_400;
pub const DEVNET_EPOCH: u64 = 2_537;
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_CREDIT_ASSET: &str = "fee-credit-devnet";
pub const DEVNET_COLLATERAL_ASSET: &str = "wxmr-devnet";
pub const DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_AUCTION_TTL_BLOCKS: u64 = 16;
pub const DEFAULT_BID_TTL_BLOCKS: u64 = 12;
pub const DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 32;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_ORACLE_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_FAST_LANE_TTL_BLOCKS: u64 = 8;
pub const DEFAULT_FENCE_TTL_BLOCKS: u64 = 7_200;
pub const DEFAULT_SLASHING_WINDOW_BLOCKS: u64 = 2_160;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 4_096;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_DECOY_SET_SIZE: u64 = 1_024;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_TARGET_USER_FEE_BPS: u64 = 5;
pub const DEFAULT_MIN_REBATE_BPS: u64 = 2;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 8;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 25;
pub const DEFAULT_SPONSOR_RESERVE_BPS: u64 = 1_500;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_000;
pub const DEFAULT_FAST_LANE_RESERVE_BPS: u64 = 1_000;
pub const DEFAULT_SLASH_BPS: u64 = 2_500;
pub const DEFAULT_ORACLE_QUORUM: u16 = 3;
pub const DEFAULT_MAX_AUCTIONS: usize = 2_097_152;
pub const DEFAULT_MAX_BIDS: usize = 16_777_216;
pub const DEFAULT_MAX_SPONSOR_VAULTS: usize = 1_048_576;
pub const DEFAULT_MAX_REBATE_COUPONS: usize = 8_388_608;
pub const DEFAULT_MAX_SETTLEMENTS: usize = 2_097_152;
pub const DEFAULT_MAX_UTILIZATION_BANDS: usize = 65_536;
pub const DEFAULT_MAX_ORACLE_ATTESTATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_FAST_LANE_ALLOCATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_PRIVACY_FENCES: usize = 8_388_608;
pub const DEFAULT_MAX_SLASHING_EVIDENCE: usize = 1_048_576;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionLane {
    PrivateTransfer,
    ConfidentialSwap,
    StableSwap,
    LendingPool,
    Perpetuals,
    Options,
    BridgeExit,
    ContractCall,
    AccountAbstraction,
    OracleUpdate,
    LiquidationBackstop,
    ProofAggregation,
    StateRentCompression,
    CrossContractSettlement,
    EmergencyFastExit,
}

impl AuctionLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::ConfidentialSwap => "confidential_swap",
            Self::StableSwap => "stable_swap",
            Self::LendingPool => "lending_pool",
            Self::Perpetuals => "perpetuals",
            Self::Options => "options",
            Self::BridgeExit => "bridge_exit",
            Self::ContractCall => "contract_call",
            Self::AccountAbstraction => "account_abstraction",
            Self::OracleUpdate => "oracle_update",
            Self::LiquidationBackstop => "liquidation_backstop",
            Self::ProofAggregation => "proof_aggregation",
            Self::StateRentCompression => "state_rent_compression",
            Self::CrossContractSettlement => "cross_contract_settlement",
            Self::EmergencyFastExit => "emergency_fast_exit",
        }
    }

    pub fn latency_weight(self) -> u64 {
        match self {
            Self::EmergencyFastExit => 10_000,
            Self::LiquidationBackstop => 9_200,
            Self::BridgeExit => 8_700,
            Self::Perpetuals => 8_000,
            Self::Options => 7_700,
            Self::ConfidentialSwap => 7_200,
            Self::StableSwap => 6_800,
            Self::ContractCall => 6_400,
            Self::AccountAbstraction => 6_000,
            Self::PrivateTransfer => 5_500,
            Self::CrossContractSettlement => 5_100,
            Self::ProofAggregation => 4_800,
            Self::OracleUpdate => 4_200,
            Self::LendingPool => 3_800,
            Self::StateRentCompression => 3_200,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Draft,
    Open,
    Sealed,
    Clearing,
    Settled,
    Rebated,
    Cancelled,
    Expired,
    Slashed,
}

impl AuctionStatus {
    pub fn accepts_bids(self) -> bool {
        matches!(self, Self::Draft | Self::Open)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Posted,
    Admitted,
    Shortlisted,
    Selected,
    Settled,
    Rebated,
    Rejected,
    Expired,
    Slashed,
}

impl BidStatus {
    pub fn active(self) -> bool {
        matches!(self, Self::Posted | Self::Admitted | Self::Shortlisted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorVaultStatus {
    Registered,
    Active,
    Draining,
    Paused,
    Frozen,
    Slashed,
    Retired,
}

impl SponsorVaultStatus {
    pub fn can_cover(self) -> bool {
        matches!(self, Self::Registered | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Minted,
    Reserved,
    Redeemed,
    Expired,
    Cancelled,
    Slashed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Proposed,
    OracleChecked,
    Solved,
    Finalized,
    Disputed,
    Reverted,
    Slashed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UtilizationBandKind {
    Cold,
    Normal,
    Warm,
    Hot,
    Congested,
    Emergency,
}

impl UtilizationBandKind {
    pub fn fee_multiplier_bps(self) -> u64 {
        match self {
            Self::Cold => 6_000,
            Self::Normal => 10_000,
            Self::Warm => 11_500,
            Self::Hot => 13_500,
            Self::Congested => 16_000,
            Self::Emergency => 20_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleAttestationStatus {
    Posted,
    Quorum,
    Used,
    Disputed,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FastLaneAllocationStatus {
    Reserved,
    Assigned,
    Consumed,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyFenceStatus {
    Open,
    Locked,
    Spent,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingEvidenceKind {
    BidEquivocation,
    InvalidReveal,
    SponsorUnderCollateralized,
    CouponDoubleSpend,
    OracleMisreport,
    FastLaneWithholding,
    NullifierReuse,
    SettlementFraud,
    PqSignatureFailure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingEvidenceStatus {
    Submitted,
    Accepted,
    Rejected,
    Executed,
    Expired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub fee_credit_asset: String,
    pub collateral_asset: String,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub pq_sealing_suite: String,
    pub confidential_amount_scheme: String,
    pub settlement_proof_scheme: String,
    pub privacy_fence_scheme: String,
    pub oracle_attestation_scheme: String,
    pub sponsor_vault_scheme: String,
    pub rebate_coupon_scheme: String,
    pub fast_lane_allocation_scheme: String,
    pub slashing_evidence_scheme: String,
    pub epoch_blocks: u64,
    pub auction_ttl_blocks: u64,
    pub bid_ttl_blocks: u64,
    pub settlement_window_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub oracle_ttl_blocks: u64,
    pub fast_lane_ttl_blocks: u64,
    pub fence_ttl_blocks: u64,
    pub slashing_window_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_decoy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub target_user_fee_bps: u64,
    pub min_rebate_bps: u64,
    pub target_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub sponsor_reserve_bps: u64,
    pub sponsor_cover_bps: u64,
    pub fast_lane_reserve_bps: u64,
    pub slash_bps: u64,
    pub oracle_quorum: u16,
    pub max_auctions: usize,
    pub max_bids: usize,
    pub max_sponsor_vaults: usize,
    pub max_rebate_coupons: usize,
    pub max_settlements: usize,
    pub max_utilization_bands: usize,
    pub max_oracle_attestations: usize,
    pub max_fast_lane_allocations: usize,
    pub max_privacy_fences: usize,
    pub max_slashing_evidence: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_credit_asset: DEVNET_FEE_CREDIT_ASSET.to_string(),
            collateral_asset: DEVNET_COLLATERAL_ASSET.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_auth_suite: PQ_AUTH_SUITE.to_string(),
            pq_sealing_suite: PQ_SEALING_SUITE.to_string(),
            confidential_amount_scheme: CONFIDENTIAL_AMOUNT_SCHEME.to_string(),
            settlement_proof_scheme: SETTLEMENT_PROOF_SCHEME.to_string(),
            privacy_fence_scheme: PRIVACY_FENCE_SCHEME.to_string(),
            oracle_attestation_scheme: ORACLE_ATTESTATION_SCHEME.to_string(),
            sponsor_vault_scheme: SPONSOR_VAULT_SCHEME.to_string(),
            rebate_coupon_scheme: REBATE_COUPON_SCHEME.to_string(),
            fast_lane_allocation_scheme: FAST_LANE_ALLOCATION_SCHEME.to_string(),
            slashing_evidence_scheme: SLASHING_EVIDENCE_SCHEME.to_string(),
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            auction_ttl_blocks: DEFAULT_AUCTION_TTL_BLOCKS,
            bid_ttl_blocks: DEFAULT_BID_TTL_BLOCKS,
            settlement_window_blocks: DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            oracle_ttl_blocks: DEFAULT_ORACLE_TTL_BLOCKS,
            fast_lane_ttl_blocks: DEFAULT_FAST_LANE_TTL_BLOCKS,
            fence_ttl_blocks: DEFAULT_FENCE_TTL_BLOCKS,
            slashing_window_blocks: DEFAULT_SLASHING_WINDOW_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_decoy_set_size: DEFAULT_MIN_DECOY_SET_SIZE,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            min_rebate_bps: DEFAULT_MIN_REBATE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
            sponsor_reserve_bps: DEFAULT_SPONSOR_RESERVE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            fast_lane_reserve_bps: DEFAULT_FAST_LANE_RESERVE_BPS,
            slash_bps: DEFAULT_SLASH_BPS,
            oracle_quorum: DEFAULT_ORACLE_QUORUM,
            max_auctions: DEFAULT_MAX_AUCTIONS,
            max_bids: DEFAULT_MAX_BIDS,
            max_sponsor_vaults: DEFAULT_MAX_SPONSOR_VAULTS,
            max_rebate_coupons: DEFAULT_MAX_REBATE_COUPONS,
            max_settlements: DEFAULT_MAX_SETTLEMENTS,
            max_utilization_bands: DEFAULT_MAX_UTILIZATION_BANDS,
            max_oracle_attestations: DEFAULT_MAX_ORACLE_ATTESTATIONS,
            max_fast_lane_allocations: DEFAULT_MAX_FAST_LANE_ALLOCATIONS,
            max_privacy_fences: DEFAULT_MAX_PRIVACY_FENCES,
            max_slashing_evidence: DEFAULT_MAX_SLASHING_EVIDENCE,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "fee_credit_asset": self.fee_credit_asset,
            "collateral_asset": self.collateral_asset,
            "hash_suite": self.hash_suite,
            "pq_auth_suite": self.pq_auth_suite,
            "pq_sealing_suite": self.pq_sealing_suite,
            "confidential_amount_scheme": self.confidential_amount_scheme,
            "settlement_proof_scheme": self.settlement_proof_scheme,
            "privacy_fence_scheme": self.privacy_fence_scheme,
            "oracle_attestation_scheme": self.oracle_attestation_scheme,
            "sponsor_vault_scheme": self.sponsor_vault_scheme,
            "rebate_coupon_scheme": self.rebate_coupon_scheme,
            "fast_lane_allocation_scheme": self.fast_lane_allocation_scheme,
            "slashing_evidence_scheme": self.slashing_evidence_scheme,
            "epoch_blocks": self.epoch_blocks,
            "auction_ttl_blocks": self.auction_ttl_blocks,
            "bid_ttl_blocks": self.bid_ttl_blocks,
            "settlement_window_blocks": self.settlement_window_blocks,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "oracle_ttl_blocks": self.oracle_ttl_blocks,
            "fast_lane_ttl_blocks": self.fast_lane_ttl_blocks,
            "fence_ttl_blocks": self.fence_ttl_blocks,
            "slashing_window_blocks": self.slashing_window_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_decoy_set_size": self.min_decoy_set_size,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_user_fee_bps": self.target_user_fee_bps,
            "min_rebate_bps": self.min_rebate_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "sponsor_reserve_bps": self.sponsor_reserve_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "fast_lane_reserve_bps": self.fast_lane_reserve_bps,
            "slash_bps": self.slash_bps,
            "oracle_quorum": self.oracle_quorum,
            "max_auctions": self.max_auctions,
            "max_bids": self.max_bids,
            "max_sponsor_vaults": self.max_sponsor_vaults,
            "max_rebate_coupons": self.max_rebate_coupons,
            "max_settlements": self.max_settlements,
            "max_utilization_bands": self.max_utilization_bands,
            "max_oracle_attestations": self.max_oracle_attestations,
            "max_fast_lane_allocations": self.max_fast_lane_allocations,
            "max_privacy_fences": self.max_privacy_fences,
            "max_slashing_evidence": self.max_slashing_evidence,
        })
    }

    pub fn root(&self) -> String {
        runtime_hash("CONFIG", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.protocol_version == PROTOCOL_VERSION,
            "unsupported protocol version"
        );
        ensure!(self.chain_id == CHAIN_ID, "config chain id mismatch");
        ensure!(self.min_pq_security_bits >= 192, "pq security bits too low");
        ensure!(
            self.min_privacy_set_size > 0,
            "privacy set must be positive"
        );
        ensure!(
            self.target_privacy_set_size >= self.min_privacy_set_size,
            "target privacy set below minimum"
        );
        ensure!(self.max_user_fee_bps <= MAX_BPS, "max fee bps too high");
        ensure!(
            self.target_user_fee_bps <= self.max_user_fee_bps,
            "target fee above cap"
        );
        ensure!(self.max_rebate_bps <= MAX_BPS, "max rebate bps too high");
        ensure!(
            self.min_rebate_bps <= self.target_rebate_bps
                && self.target_rebate_bps <= self.max_rebate_bps,
            "rebate bps ordering invalid"
        );
        ensure!(
            self.sponsor_cover_bps <= MAX_BPS,
            "sponsor cover bps too high"
        );
        ensure!(self.slash_bps <= MAX_BPS, "slash bps too high");
        ensure!(self.oracle_quorum > 0, "oracle quorum must be positive");
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedFeeCreditBid {
    pub bid_id: String,
    pub auction_id: String,
    pub sponsor_vault_id: String,
    pub bidder_commitment: String,
    pub sealed_fee_credit_commitment: String,
    pub encrypted_bid_payload_root: String,
    pub bid_nullifier: String,
    pub decoy_set_root: String,
    pub pq_auth_root: String,
    pub max_fee_bps: u64,
    pub rebate_bps: u64,
    pub priority_score: u64,
    pub capacity_credits: u64,
    pub opened_height: u64,
    pub expires_height: u64,
    pub status: BidStatus,
}

impl SealedFeeCreditBid {
    pub fn new(
        auction_id: &str,
        sponsor_vault_id: &str,
        bidder_commitment: &str,
        sealed_fee_credit_commitment: &str,
        encrypted_bid_payload_root: &str,
        bid_nullifier: &str,
        decoy_set_root: &str,
        pq_auth_root: &str,
        max_fee_bps: u64,
        rebate_bps: u64,
        priority_score: u64,
        capacity_credits: u64,
        opened_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let bid_id = sealed_bid_id(
            auction_id,
            sponsor_vault_id,
            bidder_commitment,
            sealed_fee_credit_commitment,
            bid_nullifier,
        );
        Self {
            bid_id,
            auction_id: auction_id.to_string(),
            sponsor_vault_id: sponsor_vault_id.to_string(),
            bidder_commitment: bidder_commitment.to_string(),
            sealed_fee_credit_commitment: sealed_fee_credit_commitment.to_string(),
            encrypted_bid_payload_root: encrypted_bid_payload_root.to_string(),
            bid_nullifier: bid_nullifier.to_string(),
            decoy_set_root: decoy_set_root.to_string(),
            pq_auth_root: pq_auth_root.to_string(),
            max_fee_bps,
            rebate_bps,
            priority_score,
            capacity_credits,
            opened_height,
            expires_height: opened_height.saturating_add(ttl_blocks),
            status: BidStatus::Posted,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sealed_fee_credit_bid",
            "chain_id": CHAIN_ID,
            "bid_id": self.bid_id,
            "auction_id": self.auction_id,
            "sponsor_vault_id": self.sponsor_vault_id,
            "bidder_commitment": self.bidder_commitment,
            "sealed_fee_credit_commitment": self.sealed_fee_credit_commitment,
            "encrypted_bid_payload_root": self.encrypted_bid_payload_root,
            "bid_nullifier": self.bid_nullifier,
            "decoy_set_root": self.decoy_set_root,
            "pq_auth_root": self.pq_auth_root,
            "max_fee_bps": self.max_fee_bps,
            "rebate_bps": self.rebate_bps,
            "priority_score": self.priority_score,
            "capacity_credits": self.capacity_credits,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "status": self.status,
        })
    }

    pub fn root(&self) -> String {
        runtime_hash("SEALED-BID", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorVault {
    pub vault_id: String,
    pub sponsor_commitment: String,
    pub collateral_asset: String,
    pub encrypted_balance_root: String,
    pub available_credit_commitment: String,
    pub reserve_commitment: String,
    pub policy_root: String,
    pub pq_control_root: String,
    pub lane_allowlist_root: String,
    pub utilization_bps: u64,
    pub cover_bps: u64,
    pub opened_height: u64,
    pub last_rebalanced_height: u64,
    pub status: SponsorVaultStatus,
}

impl SponsorVault {
    pub fn new(
        label: &str,
        sponsor_commitment: &str,
        collateral_asset: &str,
        encrypted_balance_root: &str,
        available_credit_commitment: &str,
        reserve_commitment: &str,
        policy_root: &str,
        pq_control_root: &str,
        lane_allowlist_root: &str,
        cover_bps: u64,
        height: u64,
    ) -> Self {
        let vault_id = sponsor_vault_id(label, sponsor_commitment, collateral_asset, policy_root);
        Self {
            vault_id,
            sponsor_commitment: sponsor_commitment.to_string(),
            collateral_asset: collateral_asset.to_string(),
            encrypted_balance_root: encrypted_balance_root.to_string(),
            available_credit_commitment: available_credit_commitment.to_string(),
            reserve_commitment: reserve_commitment.to_string(),
            policy_root: policy_root.to_string(),
            pq_control_root: pq_control_root.to_string(),
            lane_allowlist_root: lane_allowlist_root.to_string(),
            utilization_bps: 0,
            cover_bps,
            opened_height: height,
            last_rebalanced_height: height,
            status: SponsorVaultStatus::Registered,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sponsor_vault",
            "chain_id": CHAIN_ID,
            "vault_id": self.vault_id,
            "sponsor_commitment": self.sponsor_commitment,
            "collateral_asset": self.collateral_asset,
            "encrypted_balance_root": self.encrypted_balance_root,
            "available_credit_commitment": self.available_credit_commitment,
            "reserve_commitment": self.reserve_commitment,
            "policy_root": self.policy_root,
            "pq_control_root": self.pq_control_root,
            "lane_allowlist_root": self.lane_allowlist_root,
            "utilization_bps": self.utilization_bps,
            "cover_bps": self.cover_bps,
            "opened_height": self.opened_height,
            "last_rebalanced_height": self.last_rebalanced_height,
            "status": self.status,
        })
    }

    pub fn root(&self) -> String {
        runtime_hash("SPONSOR-VAULT", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebateCoupon {
    pub coupon_id: String,
    pub auction_id: String,
    pub bid_id: String,
    pub owner_commitment: String,
    pub sponsor_vault_id: String,
    pub confidential_rebate_commitment: String,
    pub coupon_nullifier: String,
    pub redemption_policy_root: String,
    pub rebate_bps: u64,
    pub minted_height: u64,
    pub expires_height: u64,
    pub status: CouponStatus,
}

impl RebateCoupon {
    pub fn new(
        auction_id: &str,
        bid_id: &str,
        owner_commitment: &str,
        sponsor_vault_id: &str,
        confidential_rebate_commitment: &str,
        coupon_nullifier: &str,
        redemption_policy_root: &str,
        rebate_bps: u64,
        height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let coupon_id = rebate_coupon_id(auction_id, bid_id, owner_commitment, coupon_nullifier);
        Self {
            coupon_id,
            auction_id: auction_id.to_string(),
            bid_id: bid_id.to_string(),
            owner_commitment: owner_commitment.to_string(),
            sponsor_vault_id: sponsor_vault_id.to_string(),
            confidential_rebate_commitment: confidential_rebate_commitment.to_string(),
            coupon_nullifier: coupon_nullifier.to_string(),
            redemption_policy_root: redemption_policy_root.to_string(),
            rebate_bps,
            minted_height: height,
            expires_height: height.saturating_add(ttl_blocks),
            status: CouponStatus::Minted,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "rebate_coupon",
            "chain_id": CHAIN_ID,
            "coupon_id": self.coupon_id,
            "auction_id": self.auction_id,
            "bid_id": self.bid_id,
            "owner_commitment": self.owner_commitment,
            "sponsor_vault_id": self.sponsor_vault_id,
            "confidential_rebate_commitment": self.confidential_rebate_commitment,
            "coupon_nullifier": self.coupon_nullifier,
            "redemption_policy_root": self.redemption_policy_root,
            "rebate_bps": self.rebate_bps,
            "minted_height": self.minted_height,
            "expires_height": self.expires_height,
            "status": self.status,
        })
    }

    pub fn root(&self) -> String {
        runtime_hash("REBATE-COUPON", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementAuction {
    pub auction_id: String,
    pub lane: AuctionLane,
    pub epoch: u64,
    pub batch_commitment_root: String,
    pub encrypted_demand_root: String,
    pub oracle_price_root: String,
    pub utilization_band_id: String,
    pub reserve_price_commitment: String,
    pub clearing_proof_root: String,
    pub selected_bid_root: String,
    pub opened_height: u64,
    pub sealed_height: u64,
    pub settlement_height: u64,
    pub status: AuctionStatus,
}

impl SettlementAuction {
    pub fn new(
        lane: AuctionLane,
        epoch: u64,
        batch_commitment_root: &str,
        encrypted_demand_root: &str,
        oracle_price_root: &str,
        utilization_band_id: &str,
        reserve_price_commitment: &str,
        height: u64,
        ttl_blocks: u64,
        settlement_window: u64,
    ) -> Self {
        let auction_id = settlement_auction_id(
            lane,
            epoch,
            batch_commitment_root,
            encrypted_demand_root,
            utilization_band_id,
        );
        Self {
            auction_id,
            lane,
            epoch,
            batch_commitment_root: batch_commitment_root.to_string(),
            encrypted_demand_root: encrypted_demand_root.to_string(),
            oracle_price_root: oracle_price_root.to_string(),
            utilization_band_id: utilization_band_id.to_string(),
            reserve_price_commitment: reserve_price_commitment.to_string(),
            clearing_proof_root: empty_root("AUCTION-CLEARING-PROOF"),
            selected_bid_root: empty_root("AUCTION-SELECTED-BID"),
            opened_height: height,
            sealed_height: height.saturating_add(ttl_blocks),
            settlement_height: height
                .saturating_add(ttl_blocks)
                .saturating_add(settlement_window),
            status: AuctionStatus::Open,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "settlement_auction",
            "chain_id": CHAIN_ID,
            "auction_id": self.auction_id,
            "lane": self.lane,
            "epoch": self.epoch,
            "batch_commitment_root": self.batch_commitment_root,
            "encrypted_demand_root": self.encrypted_demand_root,
            "oracle_price_root": self.oracle_price_root,
            "utilization_band_id": self.utilization_band_id,
            "reserve_price_commitment": self.reserve_price_commitment,
            "clearing_proof_root": self.clearing_proof_root,
            "selected_bid_root": self.selected_bid_root,
            "opened_height": self.opened_height,
            "sealed_height": self.sealed_height,
            "settlement_height": self.settlement_height,
            "status": self.status,
        })
    }

    pub fn root(&self) -> String {
        runtime_hash(
            "SETTLEMENT-AUCTION",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub settlement_id: String,
    pub auction_id: String,
    pub selected_bid_id: String,
    pub sponsor_vault_id: String,
    pub clearing_price_commitment: String,
    pub filled_credit_commitment: String,
    pub settlement_proof_root: String,
    pub rebate_coupon_root: String,
    pub privacy_fence_root: String,
    pub oracle_attestation_root: String,
    pub settled_height: u64,
    pub status: SettlementStatus,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "settlement_receipt",
            "chain_id": CHAIN_ID,
            "settlement_id": self.settlement_id,
            "auction_id": self.auction_id,
            "selected_bid_id": self.selected_bid_id,
            "sponsor_vault_id": self.sponsor_vault_id,
            "clearing_price_commitment": self.clearing_price_commitment,
            "filled_credit_commitment": self.filled_credit_commitment,
            "settlement_proof_root": self.settlement_proof_root,
            "rebate_coupon_root": self.rebate_coupon_root,
            "privacy_fence_root": self.privacy_fence_root,
            "oracle_attestation_root": self.oracle_attestation_root,
            "settled_height": self.settled_height,
            "status": self.status,
        })
    }

    pub fn root(&self) -> String {
        runtime_hash(
            "SETTLEMENT-RECEIPT",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtilizationBand {
    pub band_id: String,
    pub lane: AuctionLane,
    pub kind: UtilizationBandKind,
    pub min_utilization_bps: u64,
    pub max_utilization_bps: u64,
    pub target_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub fast_lane_share_bps: u64,
    pub oracle_policy_root: String,
    pub active_from_height: u64,
    pub active_until_height: u64,
}

impl UtilizationBand {
    pub fn new(
        lane: AuctionLane,
        kind: UtilizationBandKind,
        min_utilization_bps: u64,
        max_utilization_bps: u64,
        target_fee_bps: u64,
        target_rebate_bps: u64,
        fast_lane_share_bps: u64,
        oracle_policy_root: &str,
        active_from_height: u64,
        active_until_height: u64,
    ) -> Self {
        let band_id = utilization_band_id(lane, kind, min_utilization_bps, max_utilization_bps);
        Self {
            band_id,
            lane,
            kind,
            min_utilization_bps,
            max_utilization_bps,
            target_fee_bps,
            target_rebate_bps,
            fast_lane_share_bps,
            oracle_policy_root: oracle_policy_root.to_string(),
            active_from_height,
            active_until_height,
        }
    }

    pub fn contains(&self, utilization_bps: u64) -> bool {
        self.min_utilization_bps <= utilization_bps && utilization_bps <= self.max_utilization_bps
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "utilization_band",
            "chain_id": CHAIN_ID,
            "band_id": self.band_id,
            "lane": self.lane,
            "band_kind": self.kind,
            "min_utilization_bps": self.min_utilization_bps,
            "max_utilization_bps": self.max_utilization_bps,
            "target_fee_bps": self.target_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "fast_lane_share_bps": self.fast_lane_share_bps,
            "oracle_policy_root": self.oracle_policy_root,
            "active_from_height": self.active_from_height,
            "active_until_height": self.active_until_height,
        })
    }

    pub fn root(&self) -> String {
        runtime_hash("UTILIZATION-BAND", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleAttestation {
    pub attestation_id: String,
    pub lane: AuctionLane,
    pub epoch: u64,
    pub oracle_committee_root: String,
    pub price_commitment_root: String,
    pub utilization_commitment_root: String,
    pub volatility_commitment_root: String,
    pub quorum_signature_root: String,
    pub pq_transcript_root: String,
    pub posted_height: u64,
    pub expires_height: u64,
    pub status: OracleAttestationStatus,
}

impl OracleAttestation {
    pub fn new(
        lane: AuctionLane,
        epoch: u64,
        oracle_committee_root: &str,
        price_commitment_root: &str,
        utilization_commitment_root: &str,
        volatility_commitment_root: &str,
        quorum_signature_root: &str,
        pq_transcript_root: &str,
        height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let attestation_id = oracle_attestation_id(
            lane,
            epoch,
            oracle_committee_root,
            price_commitment_root,
            utilization_commitment_root,
        );
        Self {
            attestation_id,
            lane,
            epoch,
            oracle_committee_root: oracle_committee_root.to_string(),
            price_commitment_root: price_commitment_root.to_string(),
            utilization_commitment_root: utilization_commitment_root.to_string(),
            volatility_commitment_root: volatility_commitment_root.to_string(),
            quorum_signature_root: quorum_signature_root.to_string(),
            pq_transcript_root: pq_transcript_root.to_string(),
            posted_height: height,
            expires_height: height.saturating_add(ttl_blocks),
            status: OracleAttestationStatus::Posted,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "oracle_attestation",
            "chain_id": CHAIN_ID,
            "attestation_id": self.attestation_id,
            "lane": self.lane,
            "epoch": self.epoch,
            "oracle_committee_root": self.oracle_committee_root,
            "price_commitment_root": self.price_commitment_root,
            "utilization_commitment_root": self.utilization_commitment_root,
            "volatility_commitment_root": self.volatility_commitment_root,
            "quorum_signature_root": self.quorum_signature_root,
            "pq_transcript_root": self.pq_transcript_root,
            "posted_height": self.posted_height,
            "expires_height": self.expires_height,
            "status": self.status,
        })
    }

    pub fn root(&self) -> String {
        runtime_hash(
            "ORACLE-ATTESTATION",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastLaneAllocation {
    pub allocation_id: String,
    pub auction_id: String,
    pub bid_id: String,
    pub lane: AuctionLane,
    pub sponsor_vault_id: String,
    pub allocation_commitment: String,
    pub preconfirmation_root: String,
    pub access_token_root: String,
    pub capacity_credits: u64,
    pub reserved_height: u64,
    pub expires_height: u64,
    pub status: FastLaneAllocationStatus,
}

impl FastLaneAllocation {
    pub fn new(
        auction_id: &str,
        bid_id: &str,
        lane: AuctionLane,
        sponsor_vault_id: &str,
        allocation_commitment: &str,
        preconfirmation_root: &str,
        access_token_root: &str,
        capacity_credits: u64,
        height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let allocation_id =
            fast_lane_allocation_id(auction_id, bid_id, sponsor_vault_id, allocation_commitment);
        Self {
            allocation_id,
            auction_id: auction_id.to_string(),
            bid_id: bid_id.to_string(),
            lane,
            sponsor_vault_id: sponsor_vault_id.to_string(),
            allocation_commitment: allocation_commitment.to_string(),
            preconfirmation_root: preconfirmation_root.to_string(),
            access_token_root: access_token_root.to_string(),
            capacity_credits,
            reserved_height: height,
            expires_height: height.saturating_add(ttl_blocks),
            status: FastLaneAllocationStatus::Reserved,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_lane_allocation",
            "chain_id": CHAIN_ID,
            "allocation_id": self.allocation_id,
            "auction_id": self.auction_id,
            "bid_id": self.bid_id,
            "lane": self.lane,
            "sponsor_vault_id": self.sponsor_vault_id,
            "allocation_commitment": self.allocation_commitment,
            "preconfirmation_root": self.preconfirmation_root,
            "access_token_root": self.access_token_root,
            "capacity_credits": self.capacity_credits,
            "reserved_height": self.reserved_height,
            "expires_height": self.expires_height,
            "status": self.status,
        })
    }

    pub fn root(&self) -> String {
        runtime_hash(
            "FAST-LANE-ALLOCATION",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyNullifierFence {
    pub fence_id: String,
    pub lane: AuctionLane,
    pub scope_root: String,
    pub nullifier_root: String,
    pub decoy_set_root: String,
    pub membership_proof_root: String,
    pub minimum_anonymity_set: u64,
    pub opened_height: u64,
    pub expires_height: u64,
    pub status: PrivacyFenceStatus,
}

impl PrivacyNullifierFence {
    pub fn new(
        lane: AuctionLane,
        scope_root: &str,
        nullifier_root: &str,
        decoy_set_root: &str,
        membership_proof_root: &str,
        minimum_anonymity_set: u64,
        height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let fence_id = privacy_fence_id(lane, scope_root, nullifier_root, decoy_set_root);
        Self {
            fence_id,
            lane,
            scope_root: scope_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            decoy_set_root: decoy_set_root.to_string(),
            membership_proof_root: membership_proof_root.to_string(),
            minimum_anonymity_set,
            opened_height: height,
            expires_height: height.saturating_add(ttl_blocks),
            status: PrivacyFenceStatus::Open,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_nullifier_fence",
            "chain_id": CHAIN_ID,
            "fence_id": self.fence_id,
            "lane": self.lane,
            "scope_root": self.scope_root,
            "nullifier_root": self.nullifier_root,
            "decoy_set_root": self.decoy_set_root,
            "membership_proof_root": self.membership_proof_root,
            "minimum_anonymity_set": self.minimum_anonymity_set,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "status": self.status,
        })
    }

    pub fn root(&self) -> String {
        runtime_hash("PRIVACY-FENCE", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub kind: SlashingEvidenceKind,
    pub accused_commitment: String,
    pub related_auction_id: String,
    pub related_bid_id: String,
    pub evidence_root: String,
    pub witness_root: String,
    pub slash_amount_commitment: String,
    pub reporter_commitment: String,
    pub opened_height: u64,
    pub expires_height: u64,
    pub status: SlashingEvidenceStatus,
}

impl SlashingEvidence {
    pub fn new(
        kind: SlashingEvidenceKind,
        accused_commitment: &str,
        related_auction_id: &str,
        related_bid_id: &str,
        evidence_root: &str,
        witness_root: &str,
        slash_amount_commitment: &str,
        reporter_commitment: &str,
        height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let evidence_id = slashing_evidence_id(
            kind,
            accused_commitment,
            related_auction_id,
            related_bid_id,
            evidence_root,
        );
        Self {
            evidence_id,
            kind,
            accused_commitment: accused_commitment.to_string(),
            related_auction_id: related_auction_id.to_string(),
            related_bid_id: related_bid_id.to_string(),
            evidence_root: evidence_root.to_string(),
            witness_root: witness_root.to_string(),
            slash_amount_commitment: slash_amount_commitment.to_string(),
            reporter_commitment: reporter_commitment.to_string(),
            opened_height: height,
            expires_height: height.saturating_add(ttl_blocks),
            status: SlashingEvidenceStatus::Submitted,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "slashing_evidence",
            "chain_id": CHAIN_ID,
            "evidence_id": self.evidence_id,
            "evidence_kind": self.kind,
            "accused_commitment": self.accused_commitment,
            "related_auction_id": self.related_auction_id,
            "related_bid_id": self.related_bid_id,
            "evidence_root": self.evidence_root,
            "witness_root": self.witness_root,
            "slash_amount_commitment": self.slash_amount_commitment,
            "reporter_commitment": self.reporter_commitment,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "status": self.status,
        })
    }

    pub fn root(&self) -> String {
        runtime_hash(
            "SLASHING-EVIDENCE",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub auction_count: u64,
    pub bid_count: u64,
    pub sponsor_vault_count: u64,
    pub rebate_coupon_count: u64,
    pub settlement_count: u64,
    pub utilization_band_count: u64,
    pub oracle_attestation_count: u64,
    pub fast_lane_allocation_count: u64,
    pub privacy_fence_count: u64,
    pub slashing_evidence_count: u64,
    pub active_bid_count: u64,
    pub active_vault_count: u64,
    pub active_coupon_count: u64,
    pub selected_bid_count: u64,
    pub consumed_fast_lane_count: u64,
    pub accepted_slashing_count: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "auction_count": self.auction_count,
            "bid_count": self.bid_count,
            "sponsor_vault_count": self.sponsor_vault_count,
            "rebate_coupon_count": self.rebate_coupon_count,
            "settlement_count": self.settlement_count,
            "utilization_band_count": self.utilization_band_count,
            "oracle_attestation_count": self.oracle_attestation_count,
            "fast_lane_allocation_count": self.fast_lane_allocation_count,
            "privacy_fence_count": self.privacy_fence_count,
            "slashing_evidence_count": self.slashing_evidence_count,
            "active_bid_count": self.active_bid_count,
            "active_vault_count": self.active_vault_count,
            "active_coupon_count": self.active_coupon_count,
            "selected_bid_count": self.selected_bid_count,
            "consumed_fast_lane_count": self.consumed_fast_lane_count,
            "accepted_slashing_count": self.accepted_slashing_count,
        })
    }

    pub fn root(&self) -> String {
        runtime_hash("COUNTERS", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub auction_root: String,
    pub bid_root: String,
    pub sponsor_vault_root: String,
    pub rebate_coupon_root: String,
    pub settlement_root: String,
    pub utilization_band_root: String,
    pub oracle_attestation_root: String,
    pub fast_lane_allocation_root: String,
    pub privacy_fence_root: String,
    pub slashing_evidence_root: String,
    pub nullifier_root: String,
    pub lane_index_root: String,
    pub sponsor_index_root: String,
    pub counters_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "auction_root": self.auction_root,
            "bid_root": self.bid_root,
            "sponsor_vault_root": self.sponsor_vault_root,
            "rebate_coupon_root": self.rebate_coupon_root,
            "settlement_root": self.settlement_root,
            "utilization_band_root": self.utilization_band_root,
            "oracle_attestation_root": self.oracle_attestation_root,
            "fast_lane_allocation_root": self.fast_lane_allocation_root,
            "privacy_fence_root": self.privacy_fence_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "nullifier_root": self.nullifier_root,
            "lane_index_root": self.lane_index_root,
            "sponsor_index_root": self.sponsor_index_root,
            "counters_root": self.counters_root,
        })
    }

    pub fn root(&self) -> String {
        runtime_hash("ROOTS", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub auctions: BTreeMap<String, SettlementAuction>,
    pub bids: BTreeMap<String, SealedFeeCreditBid>,
    pub sponsor_vaults: BTreeMap<String, SponsorVault>,
    pub rebate_coupons: BTreeMap<String, RebateCoupon>,
    pub settlements: BTreeMap<String, SettlementReceipt>,
    pub utilization_bands: BTreeMap<String, UtilizationBand>,
    pub oracle_attestations: BTreeMap<String, OracleAttestation>,
    pub fast_lane_allocations: BTreeMap<String, FastLaneAllocation>,
    pub privacy_fences: BTreeMap<String, PrivacyNullifierFence>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub spent_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self {
            config,
            height: DEVNET_HEIGHT,
            epoch: DEVNET_EPOCH,
            auctions: BTreeMap::new(),
            bids: BTreeMap::new(),
            sponsor_vaults: BTreeMap::new(),
            rebate_coupons: BTreeMap::new(),
            settlements: BTreeMap::new(),
            utilization_bands: BTreeMap::new(),
            oracle_attestations: BTreeMap::new(),
            fast_lane_allocations: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        };
        state.install_devnet_bands();
        state
    }

    pub fn counters(&self) -> Counters {
        Counters {
            auction_count: self.auctions.len() as u64,
            bid_count: self.bids.len() as u64,
            sponsor_vault_count: self.sponsor_vaults.len() as u64,
            rebate_coupon_count: self.rebate_coupons.len() as u64,
            settlement_count: self.settlements.len() as u64,
            utilization_band_count: self.utilization_bands.len() as u64,
            oracle_attestation_count: self.oracle_attestations.len() as u64,
            fast_lane_allocation_count: self.fast_lane_allocations.len() as u64,
            privacy_fence_count: self.privacy_fences.len() as u64,
            slashing_evidence_count: self.slashing_evidence.len() as u64,
            active_bid_count: self.bids.values().filter(|bid| bid.status.active()).count() as u64,
            active_vault_count: self
                .sponsor_vaults
                .values()
                .filter(|vault| vault.status.can_cover())
                .count() as u64,
            active_coupon_count: self
                .rebate_coupons
                .values()
                .filter(|coupon| {
                    matches!(coupon.status, CouponStatus::Minted | CouponStatus::Reserved)
                })
                .count() as u64,
            selected_bid_count: self
                .bids
                .values()
                .filter(|bid| {
                    matches!(
                        bid.status,
                        BidStatus::Selected | BidStatus::Settled | BidStatus::Rebated
                    )
                })
                .count() as u64,
            consumed_fast_lane_count: self
                .fast_lane_allocations
                .values()
                .filter(|allocation| allocation.status == FastLaneAllocationStatus::Consumed)
                .count() as u64,
            accepted_slashing_count: self
                .slashing_evidence
                .values()
                .filter(|evidence| {
                    matches!(
                        evidence.status,
                        SlashingEvidenceStatus::Accepted | SlashingEvidenceStatus::Executed
                    )
                })
                .count() as u64,
        }
    }

    pub fn roots(&self) -> Roots {
        let auction_records = values_public_records(&self.auctions);
        let bid_records = values_public_records(&self.bids);
        let vault_records = values_public_records(&self.sponsor_vaults);
        let coupon_records = values_public_records(&self.rebate_coupons);
        let settlement_records = values_public_records(&self.settlements);
        let band_records = values_public_records(&self.utilization_bands);
        let oracle_records = values_public_records(&self.oracle_attestations);
        let allocation_records = values_public_records(&self.fast_lane_allocations);
        let fence_records = values_public_records(&self.privacy_fences);
        let slashing_records = values_public_records(&self.slashing_evidence);
        let nullifier_records = self
            .spent_nullifiers
            .iter()
            .map(|nullifier| json!({"chain_id": CHAIN_ID, "nullifier": nullifier}))
            .collect::<Vec<_>>();
        let lane_records = self.lane_index_records();
        let sponsor_records = self.sponsor_index_records();
        let counters = self.counters();
        Roots {
            config_root: self.config.root(),
            auction_root: merkle_root("FEE-CREDIT-AUCTION-AUCTION", &auction_records),
            bid_root: merkle_root("FEE-CREDIT-AUCTION-BID", &bid_records),
            sponsor_vault_root: merkle_root("FEE-CREDIT-AUCTION-SPONSOR-VAULT", &vault_records),
            rebate_coupon_root: merkle_root("FEE-CREDIT-AUCTION-REBATE-COUPON", &coupon_records),
            settlement_root: merkle_root("FEE-CREDIT-AUCTION-SETTLEMENT", &settlement_records),
            utilization_band_root: merkle_root(
                "FEE-CREDIT-AUCTION-UTILIZATION-BAND",
                &band_records,
            ),
            oracle_attestation_root: merkle_root("FEE-CREDIT-AUCTION-ORACLE", &oracle_records),
            fast_lane_allocation_root: merkle_root(
                "FEE-CREDIT-AUCTION-FAST-LANE-ALLOCATION",
                &allocation_records,
            ),
            privacy_fence_root: merkle_root("FEE-CREDIT-AUCTION-PRIVACY-FENCE", &fence_records),
            slashing_evidence_root: merkle_root("FEE-CREDIT-AUCTION-SLASHING", &slashing_records),
            nullifier_root: merkle_root("FEE-CREDIT-AUCTION-NULLIFIER", &nullifier_records),
            lane_index_root: merkle_root("FEE-CREDIT-AUCTION-LANE-INDEX", &lane_records),
            sponsor_index_root: merkle_root("FEE-CREDIT-AUCTION-SPONSOR-INDEX", &sponsor_records),
            counters_root: counters.root(),
        }
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_l2_low_fee_pq_confidential_fee_credit_auction_runtime_state",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": self.counters().public_record(),
            "state_root": roots.root(),
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        ensure!(self.config.chain_id == CHAIN_ID, "state chain id mismatch");
        ensure!(
            self.auctions.len() <= self.config.max_auctions,
            "too many auctions"
        );
        ensure!(self.bids.len() <= self.config.max_bids, "too many bids");
        ensure!(
            self.sponsor_vaults.len() <= self.config.max_sponsor_vaults,
            "too many sponsor vaults"
        );
        ensure!(
            self.rebate_coupons.len() <= self.config.max_rebate_coupons,
            "too many rebate coupons"
        );
        ensure!(
            self.settlements.len() <= self.config.max_settlements,
            "too many settlements"
        );
        ensure!(
            self.utilization_bands.len() <= self.config.max_utilization_bands,
            "too many utilization bands"
        );
        ensure!(
            self.oracle_attestations.len() <= self.config.max_oracle_attestations,
            "too many oracle attestations"
        );
        ensure!(
            self.fast_lane_allocations.len() <= self.config.max_fast_lane_allocations,
            "too many fast lane allocations"
        );
        ensure!(
            self.privacy_fences.len() <= self.config.max_privacy_fences,
            "too many privacy fences"
        );
        ensure!(
            self.slashing_evidence.len() <= self.config.max_slashing_evidence,
            "too many slashing evidence records"
        );
        Ok(())
    }

    pub fn open_settlement_auction(
        &mut self,
        lane: AuctionLane,
        batch_commitment_root: &str,
        encrypted_demand_root: &str,
        oracle_price_root: &str,
        utilization_band_id: &str,
        reserve_price_commitment: &str,
    ) -> Result<String> {
        self.validate_capacity("auction")?;
        ensure!(
            self.utilization_bands.contains_key(utilization_band_id),
            "unknown utilization band {utilization_band_id}"
        );
        let auction = SettlementAuction::new(
            lane,
            self.epoch,
            batch_commitment_root,
            encrypted_demand_root,
            oracle_price_root,
            utilization_band_id,
            reserve_price_commitment,
            self.height,
            self.config.auction_ttl_blocks,
            self.config.settlement_window_blocks,
        );
        let auction_id = auction.auction_id.clone();
        ensure!(
            !self.auctions.contains_key(&auction_id),
            "auction already exists"
        );
        self.auctions.insert(auction_id.clone(), auction);
        Ok(auction_id)
    }

    pub fn register_sponsor_vault(
        &mut self,
        label: &str,
        sponsor_commitment: &str,
        encrypted_balance_root: &str,
        available_credit_commitment: &str,
        reserve_commitment: &str,
        policy_root: &str,
        pq_control_root: &str,
        lane_allowlist_root: &str,
        cover_bps: u64,
    ) -> Result<String> {
        self.validate_capacity("sponsor_vault")?;
        ensure!(cover_bps <= MAX_BPS, "cover bps too high");
        let vault = SponsorVault::new(
            label,
            sponsor_commitment,
            &self.config.collateral_asset,
            encrypted_balance_root,
            available_credit_commitment,
            reserve_commitment,
            policy_root,
            pq_control_root,
            lane_allowlist_root,
            cover_bps,
            self.height,
        );
        let vault_id = vault.vault_id.clone();
        ensure!(
            !self.sponsor_vaults.contains_key(&vault_id),
            "sponsor vault exists"
        );
        self.sponsor_vaults.insert(vault_id.clone(), vault);
        Ok(vault_id)
    }

    pub fn activate_sponsor_vault(&mut self, vault_id: &str) -> Result<()> {
        let vault = self
            .sponsor_vaults
            .get_mut(vault_id)
            .ok_or_else(|| format!("unknown sponsor vault {vault_id}"))?;
        ensure!(
            matches!(
                vault.status,
                SponsorVaultStatus::Registered | SponsorVaultStatus::Paused
            ),
            "sponsor vault cannot be activated"
        );
        vault.status = SponsorVaultStatus::Active;
        vault.last_rebalanced_height = self.height;
        Ok(())
    }

    pub fn post_sealed_bid(
        &mut self,
        auction_id: &str,
        sponsor_vault_id: &str,
        bidder_commitment: &str,
        sealed_fee_credit_commitment: &str,
        encrypted_bid_payload_root: &str,
        bid_nullifier: &str,
        decoy_set_root: &str,
        pq_auth_root: &str,
        max_fee_bps: u64,
        rebate_bps: u64,
        priority_score: u64,
        capacity_credits: u64,
    ) -> Result<String> {
        self.validate_capacity("bid")?;
        ensure!(
            !self.spent_nullifiers.contains(bid_nullifier),
            "bid nullifier already spent"
        );
        ensure!(
            max_fee_bps <= self.config.max_user_fee_bps,
            "bid fee above cap"
        );
        ensure!(rebate_bps <= self.config.max_rebate_bps, "rebate above cap");
        ensure!(capacity_credits > 0, "capacity credits must be positive");
        let auction = self
            .auctions
            .get(auction_id)
            .ok_or_else(|| format!("unknown auction {auction_id}"))?;
        ensure!(
            auction.status.accepts_bids(),
            "auction does not accept bids"
        );
        let vault = self
            .sponsor_vaults
            .get(sponsor_vault_id)
            .ok_or_else(|| format!("unknown sponsor vault {sponsor_vault_id}"))?;
        ensure!(vault.status.can_cover(), "sponsor vault cannot cover bids");
        let bid = SealedFeeCreditBid::new(
            auction_id,
            sponsor_vault_id,
            bidder_commitment,
            sealed_fee_credit_commitment,
            encrypted_bid_payload_root,
            bid_nullifier,
            decoy_set_root,
            pq_auth_root,
            max_fee_bps,
            rebate_bps,
            priority_score,
            capacity_credits,
            self.height,
            self.config.bid_ttl_blocks,
        );
        let bid_id = bid.bid_id.clone();
        ensure!(!self.bids.contains_key(&bid_id), "bid already exists");
        self.spent_nullifiers.insert(bid_nullifier.to_string());
        self.bids.insert(bid_id.clone(), bid);
        Ok(bid_id)
    }

    pub fn shortlist_bid(&mut self, bid_id: &str) -> Result<()> {
        let bid = self
            .bids
            .get_mut(bid_id)
            .ok_or_else(|| format!("unknown bid {bid_id}"))?;
        ensure!(
            matches!(bid.status, BidStatus::Posted | BidStatus::Admitted),
            "bid not active"
        );
        ensure!(self.height <= bid.expires_height, "bid expired");
        bid.status = BidStatus::Shortlisted;
        Ok(())
    }

    pub fn post_oracle_attestation(
        &mut self,
        lane: AuctionLane,
        oracle_committee_root: &str,
        price_commitment_root: &str,
        utilization_commitment_root: &str,
        volatility_commitment_root: &str,
        quorum_signature_root: &str,
        pq_transcript_root: &str,
    ) -> Result<String> {
        self.validate_capacity("oracle_attestation")?;
        let attestation = OracleAttestation::new(
            lane,
            self.epoch,
            oracle_committee_root,
            price_commitment_root,
            utilization_commitment_root,
            volatility_commitment_root,
            quorum_signature_root,
            pq_transcript_root,
            self.height,
            self.config.oracle_ttl_blocks,
        );
        let attestation_id = attestation.attestation_id.clone();
        ensure!(
            !self.oracle_attestations.contains_key(&attestation_id),
            "oracle attestation exists"
        );
        self.oracle_attestations
            .insert(attestation_id.clone(), attestation);
        Ok(attestation_id)
    }

    pub fn add_privacy_fence(
        &mut self,
        lane: AuctionLane,
        scope_root: &str,
        nullifier_root: &str,
        decoy_set_root: &str,
        membership_proof_root: &str,
        minimum_anonymity_set: u64,
    ) -> Result<String> {
        self.validate_capacity("privacy_fence")?;
        ensure!(
            minimum_anonymity_set >= self.config.min_privacy_set_size,
            "privacy fence anonymity set below minimum"
        );
        let fence = PrivacyNullifierFence::new(
            lane,
            scope_root,
            nullifier_root,
            decoy_set_root,
            membership_proof_root,
            minimum_anonymity_set,
            self.height,
            self.config.fence_ttl_blocks,
        );
        let fence_id = fence.fence_id.clone();
        ensure!(
            !self.privacy_fences.contains_key(&fence_id),
            "privacy fence exists"
        );
        self.privacy_fences.insert(fence_id.clone(), fence);
        Ok(fence_id)
    }

    pub fn settle_auction(
        &mut self,
        auction_id: &str,
        selected_bid_id: &str,
        clearing_price_commitment: &str,
        filled_credit_commitment: &str,
        settlement_proof_root: &str,
        oracle_attestation_id: &str,
        privacy_fence_id: &str,
    ) -> Result<String> {
        self.validate_capacity("settlement")?;
        let auction = self
            .auctions
            .get_mut(auction_id)
            .ok_or_else(|| format!("unknown auction {auction_id}"))?;
        ensure!(
            matches!(
                auction.status,
                AuctionStatus::Open | AuctionStatus::Sealed | AuctionStatus::Clearing
            ),
            "auction cannot settle"
        );
        let bid = self
            .bids
            .get_mut(selected_bid_id)
            .ok_or_else(|| format!("unknown selected bid {selected_bid_id}"))?;
        ensure!(
            bid.auction_id == auction_id,
            "selected bid belongs to another auction"
        );
        ensure!(
            bid.status.active() || bid.status == BidStatus::Selected,
            "bid not selectable"
        );
        let oracle = self
            .oracle_attestations
            .get_mut(oracle_attestation_id)
            .ok_or_else(|| format!("unknown oracle attestation {oracle_attestation_id}"))?;
        ensure!(
            self.height <= oracle.expires_height,
            "oracle attestation expired"
        );
        let fence = self
            .privacy_fences
            .get_mut(privacy_fence_id)
            .ok_or_else(|| format!("unknown privacy fence {privacy_fence_id}"))?;
        ensure!(self.height <= fence.expires_height, "privacy fence expired");
        let rebate_coupon = RebateCoupon::new(
            auction_id,
            selected_bid_id,
            &bid.bidder_commitment,
            &bid.sponsor_vault_id,
            filled_credit_commitment,
            &coupon_nullifier(selected_bid_id, filled_credit_commitment),
            settlement_proof_root,
            bid.rebate_bps,
            self.height,
            self.config.rebate_ttl_blocks,
        );
        let rebate_coupon_root = rebate_coupon.root();
        let coupon_id = rebate_coupon.coupon_id.clone();
        self.rebate_coupons.insert(coupon_id, rebate_coupon);
        bid.status = BidStatus::Settled;
        oracle.status = OracleAttestationStatus::Used;
        fence.status = PrivacyFenceStatus::Locked;
        auction.status = AuctionStatus::Settled;
        auction.clearing_proof_root = settlement_proof_root.to_string();
        auction.selected_bid_root = bid.root();
        let settlement_id = settlement_receipt_id(
            auction_id,
            selected_bid_id,
            &bid.sponsor_vault_id,
            clearing_price_commitment,
            settlement_proof_root,
        );
        let receipt = SettlementReceipt {
            settlement_id: settlement_id.clone(),
            auction_id: auction_id.to_string(),
            selected_bid_id: selected_bid_id.to_string(),
            sponsor_vault_id: bid.sponsor_vault_id.clone(),
            clearing_price_commitment: clearing_price_commitment.to_string(),
            filled_credit_commitment: filled_credit_commitment.to_string(),
            settlement_proof_root: settlement_proof_root.to_string(),
            rebate_coupon_root,
            privacy_fence_root: fence.root(),
            oracle_attestation_root: oracle.root(),
            settled_height: self.height,
            status: SettlementStatus::Finalized,
        };
        self.settlements.insert(settlement_id.clone(), receipt);
        Ok(settlement_id)
    }

    pub fn allocate_fast_lane(
        &mut self,
        auction_id: &str,
        bid_id: &str,
        allocation_commitment: &str,
        preconfirmation_root: &str,
        access_token_root: &str,
        capacity_credits: u64,
    ) -> Result<String> {
        self.validate_capacity("fast_lane_allocation")?;
        let auction = self
            .auctions
            .get(auction_id)
            .ok_or_else(|| format!("unknown auction {auction_id}"))?;
        let bid = self
            .bids
            .get(bid_id)
            .ok_or_else(|| format!("unknown bid {bid_id}"))?;
        ensure!(
            bid.auction_id == auction_id,
            "bid belongs to another auction"
        );
        ensure!(
            capacity_credits <= bid.capacity_credits,
            "allocation exceeds bid capacity"
        );
        let allocation = FastLaneAllocation::new(
            auction_id,
            bid_id,
            auction.lane,
            &bid.sponsor_vault_id,
            allocation_commitment,
            preconfirmation_root,
            access_token_root,
            capacity_credits,
            self.height,
            self.config.fast_lane_ttl_blocks,
        );
        let allocation_id = allocation.allocation_id.clone();
        ensure!(
            !self.fast_lane_allocations.contains_key(&allocation_id),
            "fast lane allocation exists"
        );
        self.fast_lane_allocations
            .insert(allocation_id.clone(), allocation);
        Ok(allocation_id)
    }

    pub fn redeem_rebate_coupon(
        &mut self,
        coupon_id: &str,
        redemption_nullifier: &str,
    ) -> Result<()> {
        ensure!(
            !self.spent_nullifiers.contains(redemption_nullifier),
            "redemption nullifier already spent"
        );
        let coupon = self
            .rebate_coupons
            .get_mut(coupon_id)
            .ok_or_else(|| format!("unknown rebate coupon {coupon_id}"))?;
        ensure!(
            matches!(coupon.status, CouponStatus::Minted | CouponStatus::Reserved),
            "coupon not redeemable"
        );
        ensure!(self.height <= coupon.expires_height, "coupon expired");
        coupon.status = CouponStatus::Redeemed;
        self.spent_nullifiers
            .insert(redemption_nullifier.to_string());
        Ok(())
    }

    pub fn submit_slashing_evidence(
        &mut self,
        kind: SlashingEvidenceKind,
        accused_commitment: &str,
        related_auction_id: &str,
        related_bid_id: &str,
        evidence_root: &str,
        witness_root: &str,
        slash_amount_commitment: &str,
        reporter_commitment: &str,
    ) -> Result<String> {
        self.validate_capacity("slashing_evidence")?;
        let evidence = SlashingEvidence::new(
            kind,
            accused_commitment,
            related_auction_id,
            related_bid_id,
            evidence_root,
            witness_root,
            slash_amount_commitment,
            reporter_commitment,
            self.height,
            self.config.slashing_window_blocks,
        );
        let evidence_id = evidence.evidence_id.clone();
        ensure!(
            !self.slashing_evidence.contains_key(&evidence_id),
            "slashing evidence exists"
        );
        self.slashing_evidence.insert(evidence_id.clone(), evidence);
        Ok(evidence_id)
    }

    pub fn accept_slashing_evidence(&mut self, evidence_id: &str) -> Result<()> {
        let evidence = self
            .slashing_evidence
            .get_mut(evidence_id)
            .ok_or_else(|| format!("unknown slashing evidence {evidence_id}"))?;
        ensure!(
            evidence.status == SlashingEvidenceStatus::Submitted,
            "evidence not submitted"
        );
        evidence.status = SlashingEvidenceStatus::Accepted;
        if let Some(bid) = self.bids.get_mut(&evidence.related_bid_id) {
            bid.status = BidStatus::Slashed;
        }
        if let Some(auction) = self.auctions.get_mut(&evidence.related_auction_id) {
            auction.status = AuctionStatus::Slashed;
        }
        Ok(())
    }

    pub fn advance_height(&mut self, new_height: u64) -> Result<()> {
        ensure!(new_height >= self.height, "cannot move height backwards");
        self.height = new_height;
        self.epoch = self.height / self.config.epoch_blocks;
        self.expire_stale_records();
        Ok(())
    }

    fn install_devnet_bands(&mut self) {
        let lanes = [
            AuctionLane::PrivateTransfer,
            AuctionLane::ConfidentialSwap,
            AuctionLane::StableSwap,
            AuctionLane::BridgeExit,
            AuctionLane::ContractCall,
            AuctionLane::ProofAggregation,
        ];
        let bands = [
            (UtilizationBandKind::Cold, 0, 2_499, 2, 12, 500),
            (UtilizationBandKind::Normal, 2_500, 6_499, 5, 8, 1_000),
            (UtilizationBandKind::Warm, 6_500, 7_999, 7, 6, 1_200),
            (UtilizationBandKind::Hot, 8_000, 8_999, 9, 4, 1_500),
            (UtilizationBandKind::Congested, 9_000, 9_799, 12, 3, 1_800),
            (UtilizationBandKind::Emergency, 9_800, 10_000, 12, 2, 2_000),
        ];
        for lane in lanes {
            for (kind, min, max, fee, rebate, share) in bands {
                let band = UtilizationBand::new(
                    lane,
                    kind,
                    min,
                    max,
                    fee,
                    rebate,
                    share,
                    &runtime_hash("DEVNET-BAND-ORACLE-POLICY", &[HashPart::Str(lane.as_str())]),
                    self.height,
                    self.height.saturating_add(self.config.epoch_blocks * 16),
                );
                self.utilization_bands.insert(band.band_id.clone(), band);
            }
        }
    }

    fn expire_stale_records(&mut self) {
        for auction in self.auctions.values_mut() {
            if auction.status.accepts_bids() && self.height > auction.sealed_height {
                auction.status = AuctionStatus::Sealed;
            }
            if matches!(
                auction.status,
                AuctionStatus::Sealed | AuctionStatus::Clearing
            ) && self.height > auction.settlement_height
            {
                auction.status = AuctionStatus::Expired;
            }
        }
        for bid in self.bids.values_mut() {
            if bid.status.active() && self.height > bid.expires_height {
                bid.status = BidStatus::Expired;
            }
        }
        for coupon in self.rebate_coupons.values_mut() {
            if matches!(coupon.status, CouponStatus::Minted | CouponStatus::Reserved)
                && self.height > coupon.expires_height
            {
                coupon.status = CouponStatus::Expired;
            }
        }
        for oracle in self.oracle_attestations.values_mut() {
            if matches!(
                oracle.status,
                OracleAttestationStatus::Posted | OracleAttestationStatus::Quorum
            ) && self.height > oracle.expires_height
            {
                oracle.status = OracleAttestationStatus::Expired;
            }
        }
        for allocation in self.fast_lane_allocations.values_mut() {
            if matches!(
                allocation.status,
                FastLaneAllocationStatus::Reserved | FastLaneAllocationStatus::Assigned
            ) && self.height > allocation.expires_height
            {
                allocation.status = FastLaneAllocationStatus::Expired;
            }
        }
        for fence in self.privacy_fences.values_mut() {
            if matches!(
                fence.status,
                PrivacyFenceStatus::Open | PrivacyFenceStatus::Locked
            ) && self.height > fence.expires_height
            {
                fence.status = PrivacyFenceStatus::Expired;
            }
        }
        for evidence in self.slashing_evidence.values_mut() {
            if evidence.status == SlashingEvidenceStatus::Submitted
                && self.height > evidence.expires_height
            {
                evidence.status = SlashingEvidenceStatus::Expired;
            }
        }
    }

    fn validate_capacity(&self, kind: &str) -> Result<()> {
        match kind {
            "auction" => ensure!(
                self.auctions.len() < self.config.max_auctions,
                "auction capacity reached"
            ),
            "bid" => ensure!(
                self.bids.len() < self.config.max_bids,
                "bid capacity reached"
            ),
            "sponsor_vault" => ensure!(
                self.sponsor_vaults.len() < self.config.max_sponsor_vaults,
                "sponsor vault capacity reached"
            ),
            "oracle_attestation" => ensure!(
                self.oracle_attestations.len() < self.config.max_oracle_attestations,
                "oracle attestation capacity reached"
            ),
            "privacy_fence" => ensure!(
                self.privacy_fences.len() < self.config.max_privacy_fences,
                "privacy fence capacity reached"
            ),
            "settlement" => ensure!(
                self.settlements.len() < self.config.max_settlements,
                "settlement capacity reached"
            ),
            "fast_lane_allocation" => ensure!(
                self.fast_lane_allocations.len() < self.config.max_fast_lane_allocations,
                "fast lane allocation capacity reached"
            ),
            "slashing_evidence" => ensure!(
                self.slashing_evidence.len() < self.config.max_slashing_evidence,
                "slashing evidence capacity reached"
            ),
            _ => return Err(format!("unknown capacity kind {kind}")),
        }
        Ok(())
    }

    fn lane_index_records(&self) -> Vec<Value> {
        let mut counts: BTreeMap<String, u64> = BTreeMap::new();
        for auction in self.auctions.values() {
            *counts.entry(auction.lane.as_str().to_string()).or_default() += 1;
        }
        counts
            .into_iter()
            .map(
                |(lane, count)| json!({"chain_id": CHAIN_ID, "lane": lane, "auction_count": count}),
            )
            .collect()
    }

    fn sponsor_index_records(&self) -> Vec<Value> {
        let mut counts: BTreeMap<String, u64> = BTreeMap::new();
        for bid in self.bids.values() {
            *counts.entry(bid.sponsor_vault_id.clone()).or_default() += 1;
        }
        counts
            .into_iter()
            .map(|(sponsor_vault_id, bid_count)| {
                json!({"chain_id": CHAIN_ID, "sponsor_vault_id": sponsor_vault_id, "bid_count": bid_count})
            })
            .collect()
    }
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for SettlementAuction {
    fn public_record(&self) -> Value {
        SettlementAuction::public_record(self)
    }
}

impl PublicRecord for SealedFeeCreditBid {
    fn public_record(&self) -> Value {
        SealedFeeCreditBid::public_record(self)
    }
}

impl PublicRecord for SponsorVault {
    fn public_record(&self) -> Value {
        SponsorVault::public_record(self)
    }
}

impl PublicRecord for RebateCoupon {
    fn public_record(&self) -> Value {
        RebateCoupon::public_record(self)
    }
}

impl PublicRecord for SettlementReceipt {
    fn public_record(&self) -> Value {
        SettlementReceipt::public_record(self)
    }
}

impl PublicRecord for UtilizationBand {
    fn public_record(&self) -> Value {
        UtilizationBand::public_record(self)
    }
}

impl PublicRecord for OracleAttestation {
    fn public_record(&self) -> Value {
        OracleAttestation::public_record(self)
    }
}

impl PublicRecord for FastLaneAllocation {
    fn public_record(&self) -> Value {
        FastLaneAllocation::public_record(self)
    }
}

impl PublicRecord for PrivacyNullifierFence {
    fn public_record(&self) -> Value {
        PrivacyNullifierFence::public_record(self)
    }
}

impl PublicRecord for SlashingEvidence {
    fn public_record(&self) -> Value {
        SlashingEvidence::public_record(self)
    }
}

pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}

pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}

pub fn state_root_from_public_record(record: &Value) -> String {
    runtime_hash("STATE-FROM-PUBLIC-RECORD", &[HashPart::Json(record)])
}

pub fn sealed_bid_id(
    auction_id: &str,
    sponsor_vault_id: &str,
    bidder_commitment: &str,
    sealed_fee_credit_commitment: &str,
    bid_nullifier: &str,
) -> String {
    runtime_hash(
        "SEALED-BID-ID",
        &[
            HashPart::Str(auction_id),
            HashPart::Str(sponsor_vault_id),
            HashPart::Str(bidder_commitment),
            HashPart::Str(sealed_fee_credit_commitment),
            HashPart::Str(bid_nullifier),
        ],
    )
}

pub fn sponsor_vault_id(
    label: &str,
    sponsor_commitment: &str,
    collateral_asset: &str,
    policy_root: &str,
) -> String {
    runtime_hash(
        "SPONSOR-VAULT-ID",
        &[
            HashPart::Str(label),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(collateral_asset),
            HashPart::Str(policy_root),
        ],
    )
}

pub fn rebate_coupon_id(
    auction_id: &str,
    bid_id: &str,
    owner_commitment: &str,
    coupon_nullifier: &str,
) -> String {
    runtime_hash(
        "REBATE-COUPON-ID",
        &[
            HashPart::Str(auction_id),
            HashPart::Str(bid_id),
            HashPart::Str(owner_commitment),
            HashPart::Str(coupon_nullifier),
        ],
    )
}

pub fn settlement_auction_id(
    lane: AuctionLane,
    epoch: u64,
    batch_commitment_root: &str,
    encrypted_demand_root: &str,
    utilization_band_id: &str,
) -> String {
    runtime_hash(
        "SETTLEMENT-AUCTION-ID",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::U64(epoch),
            HashPart::Str(batch_commitment_root),
            HashPart::Str(encrypted_demand_root),
            HashPart::Str(utilization_band_id),
        ],
    )
}

pub fn settlement_receipt_id(
    auction_id: &str,
    selected_bid_id: &str,
    sponsor_vault_id: &str,
    clearing_price_commitment: &str,
    settlement_proof_root: &str,
) -> String {
    runtime_hash(
        "SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(auction_id),
            HashPart::Str(selected_bid_id),
            HashPart::Str(sponsor_vault_id),
            HashPart::Str(clearing_price_commitment),
            HashPart::Str(settlement_proof_root),
        ],
    )
}

pub fn utilization_band_id(
    lane: AuctionLane,
    kind: UtilizationBandKind,
    min_utilization_bps: u64,
    max_utilization_bps: u64,
) -> String {
    runtime_hash(
        "UTILIZATION-BAND-ID",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Str(&format!("{kind:?}")),
            HashPart::U64(min_utilization_bps),
            HashPart::U64(max_utilization_bps),
        ],
    )
}

pub fn oracle_attestation_id(
    lane: AuctionLane,
    epoch: u64,
    oracle_committee_root: &str,
    price_commitment_root: &str,
    utilization_commitment_root: &str,
) -> String {
    runtime_hash(
        "ORACLE-ATTESTATION-ID",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::U64(epoch),
            HashPart::Str(oracle_committee_root),
            HashPart::Str(price_commitment_root),
            HashPart::Str(utilization_commitment_root),
        ],
    )
}

pub fn fast_lane_allocation_id(
    auction_id: &str,
    bid_id: &str,
    sponsor_vault_id: &str,
    allocation_commitment: &str,
) -> String {
    runtime_hash(
        "FAST-LANE-ALLOCATION-ID",
        &[
            HashPart::Str(auction_id),
            HashPart::Str(bid_id),
            HashPart::Str(sponsor_vault_id),
            HashPart::Str(allocation_commitment),
        ],
    )
}

pub fn privacy_fence_id(
    lane: AuctionLane,
    scope_root: &str,
    nullifier_root: &str,
    decoy_set_root: &str,
) -> String {
    runtime_hash(
        "PRIVACY-FENCE-ID",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Str(scope_root),
            HashPart::Str(nullifier_root),
            HashPart::Str(decoy_set_root),
        ],
    )
}

pub fn slashing_evidence_id(
    kind: SlashingEvidenceKind,
    accused_commitment: &str,
    related_auction_id: &str,
    related_bid_id: &str,
    evidence_root: &str,
) -> String {
    runtime_hash(
        "SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(&format!("{kind:?}")),
            HashPart::Str(accused_commitment),
            HashPart::Str(related_auction_id),
            HashPart::Str(related_bid_id),
            HashPart::Str(evidence_root),
        ],
    )
}

pub fn coupon_nullifier(bid_id: &str, filled_credit_commitment: &str) -> String {
    runtime_hash(
        "COUPON-NULLIFIER",
        &[
            HashPart::Str(bid_id),
            HashPart::Str(filled_credit_commitment),
        ],
    )
}

pub fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

fn values_public_records<T: PublicRecord>(values: &BTreeMap<String, T>) -> Vec<Value> {
    values.values().map(PublicRecord::public_record).collect()
}

fn runtime_hash(label: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("{}:{}:{}", PROTOCOL_VERSION, CHAIN_ID, label),
        parts,
        32,
    )
}

pub const LOW_FEE_POLICY_MATRIX: &[&str] = &[
    "policy_0000_pq_auth_required",
    "policy_0001_sealed_bid_payloads_only",
    "policy_0002_no_plaintext_amounts",
    "policy_0003_nullifier_reuse_forbidden",
    "policy_0004_oracle_quorum_required",
    "policy_0005_sponsor_reserve_checked",
    "policy_0006_rebate_coupon_roots_only",
    "policy_0007_fast_lane_capacity_metered",
    "policy_0008_slashing_evidence_canonical",
    "policy_0009_merkle_roots_are_domain_separated",
    "policy_0010_batch_demand_is_confidential",
    "policy_0011_low_fee_cap_enforced",
    "policy_0012_privacy_set_minimum_enforced",
    "policy_0013_decoy_set_minimum_enforced",
    "policy_0014_monero_exit_lane_prioritized",
    "policy_0015_defi_swap_lane_prioritized",
    "policy_0016_liquidation_lane_prioritized",
    "policy_0017_state_rent_lane_discounted",
    "policy_0018_proof_aggregation_discounted",
    "policy_0019_emergency_fast_exit_reserved",
    "policy_0020_pq_transcript_rooted",
    "policy_0021_sponsor_policy_rooted",
    "policy_0022_vault_control_rooted",
    "policy_0023_bid_expiry_deterministic",
    "policy_0024_auction_expiry_deterministic",
    "policy_0025_coupon_expiry_deterministic",
    "policy_0026_oracle_expiry_deterministic",
    "policy_0027_fence_expiry_deterministic",
    "policy_0028_slashing_window_deterministic",
    "policy_0029_no_randomness_dependency",
    "policy_0030_no_wall_clock_dependency",
    "policy_0031_no_default_hasher_dependency",
    "policy_0032_chain_id_bound",
    "policy_0033_protocol_version_bound",
    "policy_0034_schema_version_bound",
    "policy_0035_counters_rooted",
    "policy_0036_lane_index_rooted",
    "policy_0037_sponsor_index_rooted",
    "policy_0038_spent_nullifiers_rooted",
    "policy_0039_public_record_state_rooted",
    "policy_0040_private_transfer_low_fee",
    "policy_0041_confidential_swap_low_fee",
    "policy_0042_stable_swap_low_fee",
    "policy_0043_lending_pool_low_fee",
    "policy_0044_perpetuals_low_fee",
    "policy_0045_options_low_fee",
    "policy_0046_bridge_exit_low_fee",
    "policy_0047_contract_call_low_fee",
    "policy_0048_account_abstraction_low_fee",
    "policy_0049_oracle_update_low_fee",
    "policy_0050_liquidation_backstop_low_fee",
    "policy_0051_proof_aggregation_low_fee",
    "policy_0052_state_rent_compression_low_fee",
    "policy_0053_cross_contract_settlement_low_fee",
    "policy_0054_emergency_fast_exit_low_fee",
    "policy_0055_bid_admission_capacity_checked",
    "policy_0056_vault_admission_capacity_checked",
    "policy_0057_coupon_capacity_checked",
    "policy_0058_settlement_capacity_checked",
    "policy_0059_band_capacity_checked",
    "policy_0060_oracle_capacity_checked",
    "policy_0061_allocation_capacity_checked",
    "policy_0062_fence_capacity_checked",
    "policy_0063_slashing_capacity_checked",
    "policy_0064_rebate_minimum_ordering_checked",
    "policy_0065_rebate_maximum_ordering_checked",
    "policy_0066_fee_target_below_cap",
    "policy_0067_sponsor_cover_below_cap",
    "policy_0068_slash_below_cap",
    "policy_0069_quorum_positive",
    "policy_0070_pq_security_bits_positive",
    "policy_0071_pq_security_bits_256_default",
    "policy_0072_privacy_target_above_minimum",
    "policy_0073_bid_capacity_positive",
    "policy_0074_allocation_capacity_not_over_bid",
    "policy_0075_selected_bid_same_auction",
    "policy_0076_oracle_not_expired_at_settlement",
    "policy_0077_fence_not_expired_at_settlement",
    "policy_0078_coupon_nullifier_deterministic",
    "policy_0079_redeem_nullifier_unique",
    "policy_0080_bid_nullifier_unique",
    "policy_0081_evidence_accuses_known_bid_when_present",
    "policy_0082_slashing_marks_bid_slashed",
    "policy_0083_slashing_marks_auction_slashed",
    "policy_0084_fast_lane_preconfirmation_rooted",
    "policy_0085_fast_lane_access_token_rooted",
    "policy_0086_oracle_price_commitment_rooted",
    "policy_0087_oracle_utilization_commitment_rooted",
    "policy_0088_oracle_volatility_commitment_rooted",
    "policy_0089_oracle_signature_rooted",
    "policy_0090_sponsor_available_credit_commitment_rooted",
    "policy_0091_sponsor_reserve_commitment_rooted",
    "policy_0092_bid_encrypted_payload_rooted",
    "policy_0093_bid_decoy_set_rooted",
    "policy_0094_bid_pq_auth_rooted",
    "policy_0095_auction_batch_commitment_rooted",
    "policy_0096_auction_encrypted_demand_rooted",
    "policy_0097_auction_reserve_price_commitment_rooted",
    "policy_0098_settlement_filled_credit_commitment_rooted",
    "policy_0099_settlement_clearing_price_commitment_rooted",
    "policy_0100_rebate_redemption_policy_rooted",
    "policy_0101_fence_membership_proof_rooted",
    "policy_0102_evidence_witness_rooted",
    "policy_0103_evidence_slash_amount_commitment_rooted",
    "policy_0104_reporter_commitment_rooted",
    "policy_0105_config_public_record_rootable",
    "policy_0106_counters_public_record_rootable",
    "policy_0107_roots_public_record_rootable",
    "policy_0108_state_public_record_rootable",
    "policy_0109_bid_public_record_rootable",
    "policy_0110_vault_public_record_rootable",
    "policy_0111_coupon_public_record_rootable",
    "policy_0112_auction_public_record_rootable",
    "policy_0113_settlement_public_record_rootable",
    "policy_0114_band_public_record_rootable",
    "policy_0115_oracle_public_record_rootable",
    "policy_0116_allocation_public_record_rootable",
    "policy_0117_fence_public_record_rootable",
    "policy_0118_evidence_public_record_rootable",
    "policy_0119_devnet_has_bands",
    "policy_0120_devnet_has_cold_bands",
    "policy_0121_devnet_has_normal_bands",
    "policy_0122_devnet_has_warm_bands",
    "policy_0123_devnet_has_hot_bands",
    "policy_0124_devnet_has_congested_bands",
    "policy_0125_devnet_has_emergency_bands",
    "policy_0126_devnet_private_transfer_band",
    "policy_0127_devnet_confidential_swap_band",
    "policy_0128_devnet_stable_swap_band",
    "policy_0129_devnet_bridge_exit_band",
    "policy_0130_devnet_contract_call_band",
    "policy_0131_devnet_proof_aggregation_band",
    "policy_0132_root_helpers_public",
    "policy_0133_id_helpers_public",
    "policy_0134_runtime_alias_state",
    "policy_0135_result_alias_string_error",
    "policy_0136_serde_config",
    "policy_0137_serde_counters",
    "policy_0138_serde_roots",
    "policy_0139_serde_state",
    "policy_0140_serde_records",
    "policy_0141_btree_maps_for_order",
    "policy_0142_btree_sets_for_nullifiers",
    "policy_0143_no_hashmap_for_roots",
    "policy_0144_roots_only_private_payloads",
    "policy_0145_low_fee_user_cap",
    "policy_0146_defi_fee_market_ready",
    "policy_0147_monero_privacy_ready",
    "policy_0148_quantum_resistance_ready",
    "policy_0149_fast_lane_ready",
    "policy_0150_settlement_auction_ready",
    "policy_0151_sponsor_vault_ready",
    "policy_0152_rebate_coupon_ready",
    "policy_0153_oracle_attestation_ready",
    "policy_0154_privacy_fence_ready",
    "policy_0155_slashing_ready",
    "policy_0156_utilization_band_ready",
    "policy_0157_bid_rebate_bps_limited",
    "policy_0158_bid_fee_bps_limited",
    "policy_0159_vault_cover_bps_limited",
    "policy_0160_deterministic_height_advance",
    "policy_0161_deterministic_epoch_update",
    "policy_0162_stale_bid_expiry",
    "policy_0163_stale_coupon_expiry",
    "policy_0164_stale_oracle_expiry",
    "policy_0165_stale_allocation_expiry",
    "policy_0166_stale_fence_expiry",
    "policy_0167_stale_evidence_expiry",
    "policy_0168_auction_seals_after_ttl",
    "policy_0169_auction_expires_after_settlement",
    "policy_0170_selected_bid_rooted",
    "policy_0171_clearing_proof_rooted",
    "policy_0172_rebate_coupon_minted_on_settlement",
    "policy_0173_oracle_used_on_settlement",
    "policy_0174_fence_locked_on_settlement",
    "policy_0175_auction_settled_on_settlement",
    "policy_0176_bid_settled_on_settlement",
    "policy_0177_fast_lane_reserved_on_allocate",
    "policy_0178_coupon_redeemed_on_redeem",
    "policy_0179_evidence_accepted_on_accept",
    "policy_0180_public_records_no_secret_payload",
    "policy_0181_encrypted_roots_visible",
    "policy_0182_commitments_visible",
    "policy_0183_nullifier_roots_visible",
    "policy_0184_decoy_roots_visible",
    "policy_0185_membership_roots_visible",
    "policy_0186_pq_roots_visible",
    "policy_0187_fee_credit_asset_bound",
    "policy_0188_collateral_asset_bound",
    "policy_0189_monero_network_bound",
    "policy_0190_l2_network_bound",
    "policy_0191_hash_suite_bound",
    "policy_0192_pq_auth_suite_bound",
    "policy_0193_pq_sealing_suite_bound",
    "policy_0194_confidential_amount_scheme_bound",
    "policy_0195_settlement_proof_scheme_bound",
    "policy_0196_privacy_fence_scheme_bound",
    "policy_0197_oracle_scheme_bound",
    "policy_0198_sponsor_scheme_bound",
    "policy_0199_rebate_scheme_bound",
    "policy_0200_fast_lane_scheme_bound",
    "policy_0201_slashing_scheme_bound",
    "policy_0202_epoch_blocks_bound",
    "policy_0203_auction_ttl_bound",
    "policy_0204_bid_ttl_bound",
    "policy_0205_settlement_window_bound",
    "policy_0206_rebate_ttl_bound",
    "policy_0207_oracle_ttl_bound",
    "policy_0208_fast_lane_ttl_bound",
    "policy_0209_fence_ttl_bound",
    "policy_0210_slashing_window_bound",
    "policy_0211_band_multiplier_cold",
    "policy_0212_band_multiplier_normal",
    "policy_0213_band_multiplier_warm",
    "policy_0214_band_multiplier_hot",
    "policy_0215_band_multiplier_congested",
    "policy_0216_band_multiplier_emergency",
    "policy_0217_lane_latency_private_transfer",
    "policy_0218_lane_latency_confidential_swap",
    "policy_0219_lane_latency_stable_swap",
    "policy_0220_lane_latency_lending",
    "policy_0221_lane_latency_perpetuals",
    "policy_0222_lane_latency_options",
    "policy_0223_lane_latency_bridge_exit",
    "policy_0224_lane_latency_contract_call",
    "policy_0225_lane_latency_account_abstraction",
    "policy_0226_lane_latency_oracle_update",
    "policy_0227_lane_latency_liquidation",
    "policy_0228_lane_latency_proof_aggregation",
    "policy_0229_lane_latency_state_rent",
    "policy_0230_lane_latency_cross_contract",
    "policy_0231_lane_latency_emergency",
    "policy_0232_auction_status_draft",
    "policy_0233_auction_status_open",
    "policy_0234_auction_status_sealed",
    "policy_0235_auction_status_clearing",
    "policy_0236_auction_status_settled",
    "policy_0237_auction_status_rebated",
    "policy_0238_auction_status_cancelled",
    "policy_0239_auction_status_expired",
    "policy_0240_auction_status_slashed",
    "policy_0241_bid_status_posted",
    "policy_0242_bid_status_admitted",
    "policy_0243_bid_status_shortlisted",
    "policy_0244_bid_status_selected",
    "policy_0245_bid_status_settled",
    "policy_0246_bid_status_rebated",
    "policy_0247_bid_status_rejected",
    "policy_0248_bid_status_expired",
    "policy_0249_bid_status_slashed",
    "policy_0250_vault_status_registered",
    "policy_0251_vault_status_active",
    "policy_0252_vault_status_draining",
    "policy_0253_vault_status_paused",
    "policy_0254_vault_status_frozen",
    "policy_0255_vault_status_slashed",
    "policy_0256_vault_status_retired",
    "policy_0257_coupon_status_minted",
    "policy_0258_coupon_status_reserved",
    "policy_0259_coupon_status_redeemed",
    "policy_0260_coupon_status_expired",
    "policy_0261_coupon_status_cancelled",
    "policy_0262_coupon_status_slashed",
    "policy_0263_settlement_status_proposed",
    "policy_0264_settlement_status_oracle_checked",
    "policy_0265_settlement_status_solved",
    "policy_0266_settlement_status_finalized",
    "policy_0267_settlement_status_disputed",
    "policy_0268_settlement_status_reverted",
    "policy_0269_settlement_status_slashed",
    "policy_0270_oracle_status_posted",
    "policy_0271_oracle_status_quorum",
    "policy_0272_oracle_status_used",
    "policy_0273_oracle_status_disputed",
    "policy_0274_oracle_status_expired",
    "policy_0275_oracle_status_slashed",
    "policy_0276_allocation_status_reserved",
    "policy_0277_allocation_status_assigned",
    "policy_0278_allocation_status_consumed",
    "policy_0279_allocation_status_expired",
    "policy_0280_allocation_status_slashed",
    "policy_0281_fence_status_open",
    "policy_0282_fence_status_locked",
    "policy_0283_fence_status_spent",
    "policy_0284_fence_status_expired",
    "policy_0285_fence_status_slashed",
    "policy_0286_evidence_kind_bid_equivocation",
    "policy_0287_evidence_kind_invalid_reveal",
    "policy_0288_evidence_kind_under_collateralized",
    "policy_0289_evidence_kind_coupon_double_spend",
    "policy_0290_evidence_kind_oracle_misreport",
    "policy_0291_evidence_kind_fast_lane_withholding",
    "policy_0292_evidence_kind_nullifier_reuse",
    "policy_0293_evidence_kind_settlement_fraud",
    "policy_0294_evidence_kind_pq_signature_failure",
    "policy_0295_evidence_status_submitted",
    "policy_0296_evidence_status_accepted",
    "policy_0297_evidence_status_rejected",
    "policy_0298_evidence_status_executed",
    "policy_0299_evidence_status_expired",
    "policy_0300_reserved_for_fee_market_policy",
    "policy_0301_reserved_for_fee_market_policy",
    "policy_0302_reserved_for_fee_market_policy",
    "policy_0303_reserved_for_fee_market_policy",
    "policy_0304_reserved_for_fee_market_policy",
    "policy_0305_reserved_for_fee_market_policy",
    "policy_0306_reserved_for_fee_market_policy",
    "policy_0307_reserved_for_fee_market_policy",
    "policy_0308_reserved_for_fee_market_policy",
    "policy_0309_reserved_for_fee_market_policy",
    "policy_0310_reserved_for_fee_market_policy",
    "policy_0311_reserved_for_fee_market_policy",
    "policy_0312_reserved_for_fee_market_policy",
    "policy_0313_reserved_for_fee_market_policy",
    "policy_0314_reserved_for_fee_market_policy",
    "policy_0315_reserved_for_fee_market_policy",
    "policy_0316_reserved_for_fee_market_policy",
    "policy_0317_reserved_for_fee_market_policy",
    "policy_0318_reserved_for_fee_market_policy",
    "policy_0319_reserved_for_fee_market_policy",
    "policy_0320_reserved_for_fee_market_policy",
    "policy_0321_reserved_for_fee_market_policy",
    "policy_0322_reserved_for_fee_market_policy",
    "policy_0323_reserved_for_fee_market_policy",
    "policy_0324_reserved_for_fee_market_policy",
    "policy_0325_reserved_for_fee_market_policy",
    "policy_0326_reserved_for_fee_market_policy",
    "policy_0327_reserved_for_fee_market_policy",
    "policy_0328_reserved_for_fee_market_policy",
    "policy_0329_reserved_for_fee_market_policy",
    "policy_0330_reserved_for_fee_market_policy",
    "policy_0331_reserved_for_fee_market_policy",
    "policy_0332_reserved_for_fee_market_policy",
    "policy_0333_reserved_for_fee_market_policy",
    "policy_0334_reserved_for_fee_market_policy",
    "policy_0335_reserved_for_fee_market_policy",
    "policy_0336_reserved_for_fee_market_policy",
    "policy_0337_reserved_for_fee_market_policy",
    "policy_0338_reserved_for_fee_market_policy",
    "policy_0339_reserved_for_fee_market_policy",
    "policy_0340_reserved_for_fee_market_policy",
    "policy_0341_reserved_for_fee_market_policy",
    "policy_0342_reserved_for_fee_market_policy",
    "policy_0343_reserved_for_fee_market_policy",
    "policy_0344_reserved_for_fee_market_policy",
    "policy_0345_reserved_for_fee_market_policy",
    "policy_0346_reserved_for_fee_market_policy",
    "policy_0347_reserved_for_fee_market_policy",
    "policy_0348_reserved_for_fee_market_policy",
    "policy_0349_reserved_for_fee_market_policy",
    "policy_0350_reserved_for_fee_market_policy",
    "policy_0351_reserved_for_fee_market_policy",
    "policy_0352_reserved_for_fee_market_policy",
    "policy_0353_reserved_for_fee_market_policy",
    "policy_0354_reserved_for_fee_market_policy",
    "policy_0355_reserved_for_fee_market_policy",
    "policy_0356_reserved_for_fee_market_policy",
    "policy_0357_reserved_for_fee_market_policy",
    "policy_0358_reserved_for_fee_market_policy",
    "policy_0359_reserved_for_fee_market_policy",
    "policy_0360_reserved_for_fee_market_policy",
    "policy_0361_reserved_for_fee_market_policy",
    "policy_0362_reserved_for_fee_market_policy",
    "policy_0363_reserved_for_fee_market_policy",
    "policy_0364_reserved_for_fee_market_policy",
    "policy_0365_reserved_for_fee_market_policy",
    "policy_0366_reserved_for_fee_market_policy",
    "policy_0367_reserved_for_fee_market_policy",
    "policy_0368_reserved_for_fee_market_policy",
    "policy_0369_reserved_for_fee_market_policy",
    "policy_0370_reserved_for_fee_market_policy",
    "policy_0371_reserved_for_fee_market_policy",
    "policy_0372_reserved_for_fee_market_policy",
    "policy_0373_reserved_for_fee_market_policy",
    "policy_0374_reserved_for_fee_market_policy",
    "policy_0375_reserved_for_fee_market_policy",
    "policy_0376_reserved_for_fee_market_policy",
    "policy_0377_reserved_for_fee_market_policy",
    "policy_0378_reserved_for_fee_market_policy",
    "policy_0379_reserved_for_fee_market_policy",
    "policy_0380_reserved_for_fee_market_policy",
    "policy_0381_reserved_for_fee_market_policy",
    "policy_0382_reserved_for_fee_market_policy",
    "policy_0383_reserved_for_fee_market_policy",
    "policy_0384_reserved_for_fee_market_policy",
    "policy_0385_reserved_for_fee_market_policy",
    "policy_0386_reserved_for_fee_market_policy",
    "policy_0387_reserved_for_fee_market_policy",
    "policy_0388_reserved_for_fee_market_policy",
    "policy_0389_reserved_for_fee_market_policy",
    "policy_0390_reserved_for_fee_market_policy",
    "policy_0391_reserved_for_fee_market_policy",
    "policy_0392_reserved_for_fee_market_policy",
    "policy_0393_reserved_for_fee_market_policy",
    "policy_0394_reserved_for_fee_market_policy",
    "policy_0395_reserved_for_fee_market_policy",
    "policy_0396_reserved_for_fee_market_policy",
    "policy_0397_reserved_for_fee_market_policy",
    "policy_0398_reserved_for_fee_market_policy",
    "policy_0399_reserved_for_fee_market_policy",
    "policy_0400_reserved_for_fee_market_policy",
    "policy_0401_reserved_for_fee_market_policy",
    "policy_0402_reserved_for_fee_market_policy",
    "policy_0403_reserved_for_fee_market_policy",
    "policy_0404_reserved_for_fee_market_policy",
    "policy_0405_reserved_for_fee_market_policy",
    "policy_0406_reserved_for_fee_market_policy",
    "policy_0407_reserved_for_fee_market_policy",
    "policy_0408_reserved_for_fee_market_policy",
    "policy_0409_reserved_for_fee_market_policy",
    "policy_0410_reserved_for_fee_market_policy",
    "policy_0411_reserved_for_fee_market_policy",
    "policy_0412_reserved_for_fee_market_policy",
    "policy_0413_reserved_for_fee_market_policy",
    "policy_0414_reserved_for_fee_market_policy",
    "policy_0415_reserved_for_fee_market_policy",
    "policy_0416_reserved_for_fee_market_policy",
    "policy_0417_reserved_for_fee_market_policy",
    "policy_0418_reserved_for_fee_market_policy",
    "policy_0419_reserved_for_fee_market_policy",
    "policy_0420_reserved_for_fee_market_policy",
    "policy_0421_reserved_for_fee_market_policy",
    "policy_0422_reserved_for_fee_market_policy",
    "policy_0423_reserved_for_fee_market_policy",
    "policy_0424_reserved_for_fee_market_policy",
    "policy_0425_reserved_for_fee_market_policy",
    "policy_0426_reserved_for_fee_market_policy",
    "policy_0427_reserved_for_fee_market_policy",
    "policy_0428_reserved_for_fee_market_policy",
    "policy_0429_reserved_for_fee_market_policy",
    "policy_0430_reserved_for_fee_market_policy",
    "policy_0431_reserved_for_fee_market_policy",
    "policy_0432_reserved_for_fee_market_policy",
    "policy_0433_reserved_for_fee_market_policy",
    "policy_0434_reserved_for_fee_market_policy",
    "policy_0435_reserved_for_fee_market_policy",
    "policy_0436_reserved_for_fee_market_policy",
    "policy_0437_reserved_for_fee_market_policy",
    "policy_0438_reserved_for_fee_market_policy",
    "policy_0439_reserved_for_fee_market_policy",
    "policy_0440_reserved_for_fee_market_policy",
    "policy_0441_reserved_for_fee_market_policy",
    "policy_0442_reserved_for_fee_market_policy",
    "policy_0443_reserved_for_fee_market_policy",
    "policy_0444_reserved_for_fee_market_policy",
    "policy_0445_reserved_for_fee_market_policy",
    "policy_0446_reserved_for_fee_market_policy",
    "policy_0447_reserved_for_fee_market_policy",
    "policy_0448_reserved_for_fee_market_policy",
    "policy_0449_reserved_for_fee_market_policy",
    "policy_0450_reserved_for_fee_market_policy",
    "policy_0451_reserved_for_fee_market_policy",
    "policy_0452_reserved_for_fee_market_policy",
    "policy_0453_reserved_for_fee_market_policy",
    "policy_0454_reserved_for_fee_market_policy",
    "policy_0455_reserved_for_fee_market_policy",
    "policy_0456_reserved_for_fee_market_policy",
    "policy_0457_reserved_for_fee_market_policy",
    "policy_0458_reserved_for_fee_market_policy",
    "policy_0459_reserved_for_fee_market_policy",
    "policy_0460_reserved_for_fee_market_policy",
    "policy_0461_reserved_for_fee_market_policy",
    "policy_0462_reserved_for_fee_market_policy",
    "policy_0463_reserved_for_fee_market_policy",
    "policy_0464_reserved_for_fee_market_policy",
    "policy_0465_reserved_for_fee_market_policy",
    "policy_0466_reserved_for_fee_market_policy",
    "policy_0467_reserved_for_fee_market_policy",
    "policy_0468_reserved_for_fee_market_policy",
    "policy_0469_reserved_for_fee_market_policy",
    "policy_0470_reserved_for_fee_market_policy",
    "policy_0471_reserved_for_fee_market_policy",
    "policy_0472_reserved_for_fee_market_policy",
    "policy_0473_reserved_for_fee_market_policy",
    "policy_0474_reserved_for_fee_market_policy",
    "policy_0475_reserved_for_fee_market_policy",
    "policy_0476_reserved_for_fee_market_policy",
    "policy_0477_reserved_for_fee_market_policy",
    "policy_0478_reserved_for_fee_market_policy",
    "policy_0479_reserved_for_fee_market_policy",
    "policy_0480_reserved_for_fee_market_policy",
    "policy_0481_reserved_for_fee_market_policy",
    "policy_0482_reserved_for_fee_market_policy",
    "policy_0483_reserved_for_fee_market_policy",
    "policy_0484_reserved_for_fee_market_policy",
    "policy_0485_reserved_for_fee_market_policy",
    "policy_0486_reserved_for_fee_market_policy",
    "policy_0487_reserved_for_fee_market_policy",
    "policy_0488_reserved_for_fee_market_policy",
    "policy_0489_reserved_for_fee_market_policy",
    "policy_0490_reserved_for_fee_market_policy",
    "policy_0491_reserved_for_fee_market_policy",
    "policy_0492_reserved_for_fee_market_policy",
    "policy_0493_reserved_for_fee_market_policy",
    "policy_0494_reserved_for_fee_market_policy",
    "policy_0495_reserved_for_fee_market_policy",
    "policy_0496_reserved_for_fee_market_policy",
    "policy_0497_reserved_for_fee_market_policy",
    "policy_0498_reserved_for_fee_market_policy",
    "policy_0499_reserved_for_fee_market_policy",
];
