use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePrivateMempoolBatcherRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-private-mempool-batcher-runtime-v1";
pub const PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_ENCRYPTION_SUITE: &str =
    "ml-kem-1024+kyber-compatible-pq-private-orderflow-lane-v1";
pub const PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_FAIR_ORDER_SUITE: &str =
    "commit-reveal-vdf-fair-private-mempool-order-v1";
pub const PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_PRIVATE_BID_SUITE: &str =
    "zk-private-fee-bid-ceiling-proof-v1";
pub const PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_COUPON_SUITE: &str =
    "roots-only-low-fee-sponsor-coupon-v1";
pub const PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_SETTLEMENT_RECEIPT_SUITE: &str =
    "zk-pq-private-mempool-batch-settlement-receipt-v1";
pub const PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_SLASHING_SUITE: &str =
    "encrypted-orderflow-batcher-slashing-evidence-v1";
pub const PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DA_PROOF_SUITE: &str =
    "recursive-da-proof-amortization-v1";
pub const PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEVNET_L2_HEIGHT: u64 = 1_972_000;
pub const PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEVNET_MONERO_HEIGHT: u64 = 3_618_000;
pub const PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_WINDOW_BLOCKS: u64 = 4;
pub const PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_REVEAL_BLOCKS: u64 = 2;
pub const PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS: u64 = 32;
pub const PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 96;
pub const PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_MAX_LANES: usize = 256;
pub const PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_MAX_ENVELOPES: usize =
    2_097_152;
pub const PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_MAX_BATCHES: usize = 524_288;
pub const PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_MAX_RECEIPTS: usize =
    2_097_152;
pub const PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_MAX_COUPONS: usize = 524_288;
pub const PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_MAX_REBATES: usize = 524_288;
pub const PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_MAX_SLASHING_EVIDENCE: usize =
    262_144;
pub const PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_MAX_ENVELOPES_PER_BATCH:
    usize = 2_048;
pub const PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 =
    16_384;
pub const PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_MIN_LANE_PRIVACY_SIZE: u64 =
    512;
pub const PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 =
    256;
pub const PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_TARGET_USER_FEE_BPS: u64 = 8;
pub const PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_MIN_SPONSOR_COVER_BPS: u64 =
    5_000;
pub const PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_DA_AMORTIZATION_BPS: u64 =
    6_500;
pub const PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_PROOF_AMORTIZATION_BPS: u64 =
    7_200;
pub const PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_REBATE_BPS: u64 = 6;
pub const PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_SLASHING_BOND_MICRO_UNITS:
    u64 = 1_000_000_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneKind {
    WalletTransfer,
    ConfidentialSwap,
    DarkpoolOrder,
    Lending,
    Perpetuals,
    Options,
    Stablecoin,
    TokenMintBurn,
    ContractCall,
    AccountAbstraction,
    OracleThenCall,
    BridgeDeposit,
    BridgeExit,
    SettlementHook,
    Emergency,
}

impl LaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletTransfer => "wallet_transfer",
            Self::ConfidentialSwap => "confidential_swap",
            Self::DarkpoolOrder => "darkpool_order",
            Self::Lending => "lending",
            Self::Perpetuals => "perpetuals",
            Self::Options => "options",
            Self::Stablecoin => "stablecoin",
            Self::TokenMintBurn => "token_mint_burn",
            Self::ContractCall => "contract_call",
            Self::AccountAbstraction => "account_abstraction",
            Self::OracleThenCall => "oracle_then_call",
            Self::BridgeDeposit => "bridge_deposit",
            Self::BridgeExit => "bridge_exit",
            Self::SettlementHook => "settlement_hook",
            Self::Emergency => "emergency",
        }
    }

    pub fn default_priority(self) -> u64 {
        match self {
            Self::Emergency => 10_000,
            Self::SettlementHook => 9_700,
            Self::BridgeExit => 9_400,
            Self::BridgeDeposit => 9_200,
            Self::ConfidentialSwap => 9_000,
            Self::DarkpoolOrder => 8_900,
            Self::Perpetuals => 8_800,
            Self::Lending => 8_600,
            Self::Options => 8_400,
            Self::Stablecoin => 8_250,
            Self::ContractCall => 8_100,
            Self::OracleThenCall => 7_950,
            Self::TokenMintBurn => 7_850,
            Self::AccountAbstraction => 7_700,
            Self::WalletTransfer => 7_500,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Congested,
    CouponOnly,
    Draining,
    Paused,
    Retired,
}

impl LaneStatus {
    pub fn accepts_envelopes(self) -> bool {
        matches!(self, Self::Open | Self::Congested | Self::CouponOnly)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeKind {
    Transfer,
    Swap,
    DarkpoolLimit,
    LendingSupply,
    LendingBorrow,
    PerpOpen,
    PerpClose,
    OptionMint,
    StableMint,
    StableBurn,
    TokenMint,
    TokenBurn,
    ContractCall,
    MultiCall,
    UserOperation,
    OracleReadThenCall,
    BridgeLock,
    BridgeRelease,
    SettlementCallback,
}

impl EnvelopeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Transfer => "transfer",
            Self::Swap => "swap",
            Self::DarkpoolLimit => "darkpool_limit",
            Self::LendingSupply => "lending_supply",
            Self::LendingBorrow => "lending_borrow",
            Self::PerpOpen => "perp_open",
            Self::PerpClose => "perp_close",
            Self::OptionMint => "option_mint",
            Self::StableMint => "stable_mint",
            Self::StableBurn => "stable_burn",
            Self::TokenMint => "token_mint",
            Self::TokenBurn => "token_burn",
            Self::ContractCall => "contract_call",
            Self::MultiCall => "multi_call",
            Self::UserOperation => "user_operation",
            Self::OracleReadThenCall => "oracle_read_then_call",
            Self::BridgeLock => "bridge_lock",
            Self::BridgeRelease => "bridge_release",
            Self::SettlementCallback => "settlement_callback",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeStatus {
    Encrypted,
    FeeBidCommitted,
    CouponReserved,
    Windowed,
    Ordered,
    Packed,
    Settled,
    Rebated,
    Rejected,
    Expired,
}

impl EnvelopeStatus {
    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Encrypted
                | Self::FeeBidCommitted
                | Self::CouponReserved
                | Self::Windowed
                | Self::Ordered
                | Self::Packed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeBidStatus {
    Committed,
    Revealed,
    Accepted,
    Rejected,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Minted,
    Reserved,
    Consumed,
    Released,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowStatus {
    Open,
    Sealed,
    Revealing,
    Ordered,
    Packed,
    Settled,
    Challenged,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Draft,
    Packed,
    DaPosted,
    ProofAmortized,
    Settled,
    Rebated,
    Challenged,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyFenceKind {
    Nullifier,
    KeyImage,
    AccountNonce,
    ContractStorageSlot,
    DefiPosition,
    TokenSerial,
    BridgeTicket,
    CouponSerial,
    ReplayDomain,
    FairOrderCommitment,
}

impl PrivacyFenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nullifier => "nullifier",
            Self::KeyImage => "key_image",
            Self::AccountNonce => "account_nonce",
            Self::ContractStorageSlot => "contract_storage_slot",
            Self::DefiPosition => "defi_position",
            Self::TokenSerial => "token_serial",
            Self::BridgeTicket => "bridge_ticket",
            Self::CouponSerial => "coupon_serial",
            Self::ReplayDomain => "replay_domain",
            Self::FairOrderCommitment => "fair_order_commitment",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Published,
    Finalized,
    Disputed,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    DecryptionWithheld,
    LaneCensorship,
    FeeBidLeakage,
    CouponDoubleSpend,
    InvalidFairOrder,
    PrivacyFenceBreach,
    DaRootMismatch,
    ProofAmortizationFraud,
    ReceiptMismatch,
    RebateTheft,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub encryption_suite: String,
    pub fair_order_suite: String,
    pub private_bid_suite: String,
    pub coupon_suite: String,
    pub settlement_receipt_suite: String,
    pub slashing_suite: String,
    pub da_proof_suite: String,
    pub window_blocks: u64,
    pub reveal_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub max_lanes: usize,
    pub max_envelopes: usize,
    pub max_batches: usize,
    pub max_receipts: usize,
    pub max_coupons: usize,
    pub max_rebates: usize,
    pub max_slashing_evidence: usize,
    pub max_envelopes_per_batch: usize,
    pub min_privacy_set_size: u64,
    pub min_lane_privacy_size: u64,
    pub min_pq_security_bits: u16,
    pub target_user_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub min_sponsor_cover_bps: u64,
    pub da_amortization_bps: u64,
    pub proof_amortization_bps: u64,
    pub default_rebate_bps: u64,
    pub slashing_bond_micro_units: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_HASH_SUITE.to_string(),
            encryption_suite: PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_ENCRYPTION_SUITE
                .to_string(),
            fair_order_suite: PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_FAIR_ORDER_SUITE
                .to_string(),
            private_bid_suite: PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_PRIVATE_BID_SUITE
                .to_string(),
            coupon_suite: PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_COUPON_SUITE
                .to_string(),
            settlement_receipt_suite:
                PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_SETTLEMENT_RECEIPT_SUITE
                    .to_string(),
            slashing_suite: PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_SLASHING_SUITE
                .to_string(),
            da_proof_suite: PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DA_PROOF_SUITE
                .to_string(),
            window_blocks: PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_WINDOW_BLOCKS,
            reveal_blocks: PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_REVEAL_BLOCKS,
            batch_ttl_blocks:
                PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS,
            receipt_ttl_blocks:
                PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_RECEIPT_TTL_BLOCKS,
            max_lanes: PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_MAX_LANES,
            max_envelopes: PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_MAX_ENVELOPES,
            max_batches: PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_MAX_BATCHES,
            max_receipts: PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_MAX_RECEIPTS,
            max_coupons: PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_MAX_COUPONS,
            max_rebates: PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_MAX_REBATES,
            max_slashing_evidence:
                PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_MAX_SLASHING_EVIDENCE,
            max_envelopes_per_batch:
                PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_MAX_ENVELOPES_PER_BATCH,
            min_privacy_set_size:
                PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_lane_privacy_size:
                PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_MIN_LANE_PRIVACY_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            target_user_fee_bps:
                PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_TARGET_USER_FEE_BPS,
            max_user_fee_bps:
                PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            min_sponsor_cover_bps:
                PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_MIN_SPONSOR_COVER_BPS,
            da_amortization_bps:
                PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_DA_AMORTIZATION_BPS,
            proof_amortization_bps:
                PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_PROOF_AMORTIZATION_BPS,
            default_rebate_bps:
                PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_REBATE_BPS,
            slashing_bond_micro_units:
                PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_SLASHING_BOND_MICRO_UNITS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "encryption_suite": self.encryption_suite,
            "fair_order_suite": self.fair_order_suite,
            "private_bid_suite": self.private_bid_suite,
            "coupon_suite": self.coupon_suite,
            "settlement_receipt_suite": self.settlement_receipt_suite,
            "slashing_suite": self.slashing_suite,
            "da_proof_suite": self.da_proof_suite,
            "window_blocks": self.window_blocks,
            "reveal_blocks": self.reveal_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "max_lanes": self.max_lanes,
            "max_envelopes": self.max_envelopes,
            "max_batches": self.max_batches,
            "max_receipts": self.max_receipts,
            "max_coupons": self.max_coupons,
            "max_rebates": self.max_rebates,
            "max_slashing_evidence": self.max_slashing_evidence,
            "max_envelopes_per_batch": self.max_envelopes_per_batch,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_lane_privacy_size": self.min_lane_privacy_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_user_fee_bps": self.target_user_fee_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "min_sponsor_cover_bps": self.min_sponsor_cover_bps,
            "da_amortization_bps": self.da_amortization_bps,
            "proof_amortization_bps": self.proof_amortization_bps,
            "default_rebate_bps": self.default_rebate_bps,
            "slashing_bond_micro_units": self.slashing_bond_micro_units,
        })
    }

    pub fn config_root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-BATCHER-CONFIG",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedLane {
    pub lane_id: String,
    pub kind: LaneKind,
    pub status: LaneStatus,
    pub operator_commitment: String,
    pub encryption_key_root: String,
    pub admission_policy_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub target_fee_bps: u64,
    pub max_fee_bps: u64,
    pub priority: u64,
    pub opened_at_height: u64,
    pub last_batch_height: u64,
    pub pending_envelopes: BTreeSet<String>,
    pub sealed_windows: BTreeSet<String>,
    pub public_tags: BTreeSet<String>,
}

impl EncryptedLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "kind": self.kind,
            "status": self.status,
            "operator_commitment": self.operator_commitment,
            "encryption_key_root": self.encryption_key_root,
            "admission_policy_root": self.admission_policy_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "target_fee_bps": self.target_fee_bps,
            "max_fee_bps": self.max_fee_bps,
            "priority": self.priority,
            "opened_at_height": self.opened_at_height,
            "last_batch_height": self.last_batch_height,
            "pending_envelopes": self.pending_envelopes,
            "sealed_windows": self.sealed_windows,
            "public_tags": self.public_tags,
        })
    }

    pub fn lane_root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-LANE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateFeeBid {
    pub bid_id: String,
    pub envelope_id: String,
    pub bid_commitment: String,
    pub fee_ceiling_proof_root: String,
    pub max_user_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub revealed_fee_bps: Option<u64>,
    pub status: FeeBidStatus,
    pub committed_at_height: u64,
    pub reveal_deadline_height: u64,
}

impl PrivateFeeBid {
    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "envelope_id": self.envelope_id,
            "bid_commitment": self.bid_commitment,
            "fee_ceiling_proof_root": self.fee_ceiling_proof_root,
            "max_user_fee_bps": self.max_user_fee_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "revealed_fee_bps": self.revealed_fee_bps,
            "status": self.status,
            "committed_at_height": self.committed_at_height,
            "reveal_deadline_height": self.reveal_deadline_height,
        })
    }

    pub fn bid_root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-FEE-BID",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorCoupon {
    pub coupon_id: String,
    pub sponsor_id: String,
    pub lane_id: String,
    pub coupon_commitment: String,
    pub coupon_nullifier: String,
    pub covered_fee_bps: u64,
    pub budget_micro_units: u64,
    pub remaining_micro_units: u64,
    pub privacy_set_size: u64,
    pub status: CouponStatus,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub reserved_envelopes: BTreeSet<String>,
}

impl SponsorCoupon {
    pub fn public_record(&self) -> Value {
        json!({
            "coupon_id": self.coupon_id,
            "sponsor_id": self.sponsor_id,
            "lane_id": self.lane_id,
            "coupon_commitment": self.coupon_commitment,
            "coupon_nullifier": self.coupon_nullifier,
            "covered_fee_bps": self.covered_fee_bps,
            "budget_micro_units": self.budget_micro_units,
            "remaining_micro_units": self.remaining_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "status": self.status,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "reserved_envelopes": self.reserved_envelopes,
        })
    }

    pub fn coupon_root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-SPONSOR-COUPON",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub kind: PrivacyFenceKind,
    pub commitment: String,
    pub nullifier: String,
    pub domain: String,
    pub first_seen_height: u64,
    pub envelope_ids: BTreeSet<String>,
}

impl PrivacyFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "kind": self.kind,
            "commitment": self.commitment,
            "nullifier": self.nullifier,
            "domain": self.domain,
            "first_seen_height": self.first_seen_height,
            "envelope_ids": self.envelope_ids,
        })
    }

    pub fn fence_root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-PRIVACY-FENCE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedEnvelope {
    pub envelope_id: String,
    pub lane_id: String,
    pub kind: EnvelopeKind,
    pub status: EnvelopeStatus,
    pub orderflow_ciphertext_root: String,
    pub calldata_commitment: String,
    pub sender_commitment: String,
    pub fee_bid_id: Option<String>,
    pub coupon_id: Option<String>,
    pub fair_order_commitment: String,
    pub arrival_commitment: String,
    pub privacy_fence_ids: BTreeSet<String>,
    pub da_weight_units: u64,
    pub proof_weight_units: u64,
    pub max_fee_bps: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub batch_id: Option<String>,
    pub receipt_id: Option<String>,
    pub tags: BTreeSet<String>,
}

impl EncryptedEnvelope {
    pub fn public_record(&self) -> Value {
        json!({
            "envelope_id": self.envelope_id,
            "lane_id": self.lane_id,
            "kind": self.kind,
            "status": self.status,
            "orderflow_ciphertext_root": self.orderflow_ciphertext_root,
            "calldata_commitment": self.calldata_commitment,
            "sender_commitment": self.sender_commitment,
            "fee_bid_id": self.fee_bid_id,
            "coupon_id": self.coupon_id,
            "fair_order_commitment": self.fair_order_commitment,
            "arrival_commitment": self.arrival_commitment,
            "privacy_fence_ids": self.privacy_fence_ids,
            "da_weight_units": self.da_weight_units,
            "proof_weight_units": self.proof_weight_units,
            "max_fee_bps": self.max_fee_bps,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "batch_id": self.batch_id,
            "receipt_id": self.receipt_id,
            "tags": self.tags,
        })
    }

    pub fn envelope_root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-ENVELOPE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FairOrderingWindow {
    pub window_id: String,
    pub lane_id: String,
    pub status: WindowStatus,
    pub start_height: u64,
    pub seal_height: u64,
    pub reveal_deadline_height: u64,
    pub entropy_commitment: String,
    pub vdf_transcript_root: String,
    pub ordered_envelopes: Vec<String>,
    pub excluded_envelopes: BTreeSet<String>,
    pub fairness_score_bps: u64,
}

impl FairOrderingWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "lane_id": self.lane_id,
            "status": self.status,
            "start_height": self.start_height,
            "seal_height": self.seal_height,
            "reveal_deadline_height": self.reveal_deadline_height,
            "entropy_commitment": self.entropy_commitment,
            "vdf_transcript_root": self.vdf_transcript_root,
            "ordered_envelopes": self.ordered_envelopes,
            "excluded_envelopes": self.excluded_envelopes,
            "fairness_score_bps": self.fairness_score_bps,
        })
    }

    pub fn window_root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-FAIR-WINDOW",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BatchAmortization {
    pub da_root: String,
    pub proof_root: String,
    pub da_cost_micro_units: u64,
    pub proof_cost_micro_units: u64,
    pub da_cost_per_envelope: u64,
    pub proof_cost_per_envelope: u64,
    pub da_amortization_bps: u64,
    pub proof_amortization_bps: u64,
}

impl BatchAmortization {
    pub fn public_record(&self) -> Value {
        json!({
            "da_root": self.da_root,
            "proof_root": self.proof_root,
            "da_cost_micro_units": self.da_cost_micro_units,
            "proof_cost_micro_units": self.proof_cost_micro_units,
            "da_cost_per_envelope": self.da_cost_per_envelope,
            "proof_cost_per_envelope": self.proof_cost_per_envelope,
            "da_amortization_bps": self.da_amortization_bps,
            "proof_amortization_bps": self.proof_amortization_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PackedBatch {
    pub batch_id: String,
    pub lane_id: String,
    pub window_id: String,
    pub status: BatchStatus,
    pub sequencer_id: String,
    pub envelope_ids: Vec<String>,
    pub excluded_envelopes: BTreeSet<String>,
    pub ordered_envelope_root: String,
    pub privacy_fence_root: String,
    pub fee_bid_root: String,
    pub coupon_root: String,
    pub amortization: BatchAmortization,
    pub aggregate_fee_bps: u64,
    pub user_fee_micro_units: u64,
    pub sponsor_fee_micro_units: u64,
    pub rebate_pool_micro_units: u64,
    pub packed_at_height: u64,
    pub expires_at_height: u64,
}

impl PackedBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "window_id": self.window_id,
            "status": self.status,
            "sequencer_id": self.sequencer_id,
            "envelope_ids": self.envelope_ids,
            "excluded_envelopes": self.excluded_envelopes,
            "ordered_envelope_root": self.ordered_envelope_root,
            "privacy_fence_root": self.privacy_fence_root,
            "fee_bid_root": self.fee_bid_root,
            "coupon_root": self.coupon_root,
            "amortization": self.amortization.public_record(),
            "aggregate_fee_bps": self.aggregate_fee_bps,
            "user_fee_micro_units": self.user_fee_micro_units,
            "sponsor_fee_micro_units": self.sponsor_fee_micro_units,
            "rebate_pool_micro_units": self.rebate_pool_micro_units,
            "packed_at_height": self.packed_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn batch_root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-PACKED-BATCH",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub status: ReceiptStatus,
    pub settlement_root: String,
    pub post_state_root: String,
    pub receipt_proof_root: String,
    pub included_envelopes: BTreeSet<String>,
    pub rejected_envelopes: BTreeSet<String>,
    pub settled_fee_micro_units: u64,
    pub settled_at_height: u64,
    pub finality_height: u64,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "status": self.status,
            "settlement_root": self.settlement_root,
            "post_state_root": self.post_state_root,
            "receipt_proof_root": self.receipt_proof_root,
            "included_envelopes": self.included_envelopes,
            "rejected_envelopes": self.rejected_envelopes,
            "settled_fee_micro_units": self.settled_fee_micro_units,
            "settled_at_height": self.settled_at_height,
            "finality_height": self.finality_height,
        })
    }

    pub fn receipt_root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-SETTLEMENT-RECEIPT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub receipt_id: String,
    pub batch_id: String,
    pub beneficiary_commitment: String,
    pub rebate_nullifier: String,
    pub amount_micro_units: u64,
    pub source_coupon_id: Option<String>,
    pub proof_root: String,
    pub paid_at_height: u64,
}

impl FeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "rebate_nullifier": self.rebate_nullifier,
            "amount_micro_units": self.amount_micro_units,
            "source_coupon_id": self.source_coupon_id,
            "proof_root": self.proof_root,
            "paid_at_height": self.paid_at_height,
        })
    }

    pub fn rebate_root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-REBATE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub kind: EvidenceKind,
    pub accused_id: String,
    pub batch_id: Option<String>,
    pub envelope_id: Option<String>,
    pub lane_id: Option<String>,
    pub evidence_root: String,
    pub witness_root: String,
    pub penalty_micro_units: u64,
    pub accepted: bool,
    pub submitted_at_height: u64,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "kind": self.kind,
            "accused_id": self.accused_id,
            "batch_id": self.batch_id,
            "envelope_id": self.envelope_id,
            "lane_id": self.lane_id,
            "evidence_root": self.evidence_root,
            "witness_root": self.witness_root,
            "penalty_micro_units": self.penalty_micro_units,
            "accepted": self.accepted,
            "submitted_at_height": self.submitted_at_height,
        })
    }

    pub fn slashing_root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-SLASHING-EVIDENCE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub l2_height: u64,
    pub monero_height: u64,
    pub lanes: BTreeMap<String, EncryptedLane>,
    pub envelopes: BTreeMap<String, EncryptedEnvelope>,
    pub fee_bids: BTreeMap<String, PrivateFeeBid>,
    pub coupons: BTreeMap<String, SponsorCoupon>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub windows: BTreeMap<String, FairOrderingWindow>,
    pub batches: BTreeMap<String, PackedBatch>,
    pub receipts: BTreeMap<String, SettlementReceipt>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub active_batches_by_lane: BTreeMap<String, BTreeSet<String>>,
    pub receipts_by_batch: BTreeMap<String, BTreeSet<String>>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            l2_height: PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEVNET_L2_HEIGHT,
            monero_height: PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEVNET_MONERO_HEIGHT,
            lanes: BTreeMap::new(),
            envelopes: BTreeMap::new(),
            fee_bids: BTreeMap::new(),
            coupons: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            windows: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            active_batches_by_lane: BTreeMap::new(),
            receipts_by_batch: BTreeMap::new(),
        };
        let _ = state.open_lane(
            LaneKind::WalletTransfer,
            "devnet-wallet-transfer-operator",
            "devnet-wallet-transfer-key-root",
            "devnet-wallet-transfer-policy-root",
            PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            BTreeSet::from(["wallet".to_string(), "low_fee".to_string()]),
        );
        let _ = state.open_lane(
            LaneKind::ConfidentialSwap,
            "devnet-confidential-swap-operator",
            "devnet-confidential-swap-key-root",
            "devnet-confidential-swap-policy-root",
            PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE * 2,
            BTreeSet::from(["defi".to_string(), "swap".to_string()]),
        );
        let _ = state.open_lane(
            LaneKind::ContractCall,
            "devnet-contract-call-operator",
            "devnet-contract-call-key-root",
            "devnet-contract-call-policy-root",
            PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            BTreeSet::from(["smart_contracts".to_string(), "tokens".to_string()]),
        );
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "lane_root": map_root("PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-LANES", &self.lanes, EncryptedLane::public_record),
            "envelope_root": map_root("PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-ENVELOPES", &self.envelopes, EncryptedEnvelope::public_record),
            "fee_bid_root": map_root("PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-FEE-BIDS", &self.fee_bids, PrivateFeeBid::public_record),
            "coupon_root": map_root("PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-COUPONS", &self.coupons, SponsorCoupon::public_record),
            "privacy_fence_root": map_root("PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-PRIVACY-FENCES", &self.privacy_fences, PrivacyFence::public_record),
            "window_root": map_root("PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-WINDOWS", &self.windows, FairOrderingWindow::public_record),
            "batch_root": map_root("PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-BATCHES", &self.batches, PackedBatch::public_record),
            "receipt_root": map_root("PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-RECEIPTS", &self.receipts, SettlementReceipt::public_record),
            "rebate_root": map_root("PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-REBATES", &self.rebates, FeeRebate::public_record),
            "slashing_evidence_root": map_root("PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-SLASHING", &self.slashing_evidence, SlashingEvidence::public_record),
            "consumed_nullifier_root": set_root("PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-CONSUMED-NULLIFIERS", &self.consumed_nullifiers),
            "active_batches_by_lane": self.active_batches_by_lane,
            "receipts_by_batch": self.receipts_by_batch,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-BATCHER-STATE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn advance_height(&mut self, l2_height: u64, monero_height: u64) -> Result<()> {
        require!(
            l2_height >= self.l2_height,
            "l2 height cannot move backward"
        );
        require!(
            monero_height >= self.monero_height,
            "monero height cannot move backward"
        );
        self.l2_height = l2_height;
        self.monero_height = monero_height;
        Ok(())
    }

    pub fn open_lane(
        &mut self,
        kind: LaneKind,
        operator_commitment: &str,
        encryption_key_root: &str,
        admission_policy_root: &str,
        privacy_set_size: u64,
        public_tags: BTreeSet<String>,
    ) -> Result<String> {
        require_capacity(self.lanes.len(), self.config.max_lanes, "lanes")?;
        require_nonempty(operator_commitment, "operator commitment")?;
        require_nonempty(encryption_key_root, "encryption key root")?;
        require_nonempty(admission_policy_root, "admission policy root")?;
        require!(
            privacy_set_size >= self.config.min_lane_privacy_size,
            "lane privacy set below minimum"
        );
        let lane_id = lane_id(
            &self.config.chain_id,
            kind,
            operator_commitment,
            encryption_key_root,
            self.l2_height,
        );
        require!(!self.lanes.contains_key(&lane_id), "lane already exists");
        let lane = EncryptedLane {
            lane_id: lane_id.clone(),
            kind,
            status: LaneStatus::Open,
            operator_commitment: operator_commitment.to_string(),
            encryption_key_root: encryption_key_root.to_string(),
            admission_policy_root: admission_policy_root.to_string(),
            privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
            target_fee_bps: self.config.target_user_fee_bps,
            max_fee_bps: self.config.max_user_fee_bps,
            priority: kind.default_priority(),
            opened_at_height: self.l2_height,
            last_batch_height: 0,
            pending_envelopes: BTreeSet::new(),
            sealed_windows: BTreeSet::new(),
            public_tags,
        };
        self.active_batches_by_lane
            .entry(lane_id.clone())
            .or_default();
        self.lanes.insert(lane_id.clone(), lane);
        Ok(lane_id)
    }

    pub fn set_lane_status(&mut self, lane_id: &str, status: LaneStatus) -> Result<()> {
        let lane = self
            .lanes
            .get_mut(lane_id)
            .ok_or_else(|| format!("unknown lane: {lane_id}"))?;
        lane.status = status;
        Ok(())
    }

    pub fn submit_envelope(
        &mut self,
        lane_id: &str,
        kind: EnvelopeKind,
        orderflow_ciphertext_root: &str,
        calldata_commitment: &str,
        sender_commitment: &str,
        max_fee_bps: u64,
        da_weight_units: u64,
        proof_weight_units: u64,
        ttl_blocks: u64,
        tags: BTreeSet<String>,
    ) -> Result<String> {
        require_capacity(self.envelopes.len(), self.config.max_envelopes, "envelopes")?;
        require_nonempty(orderflow_ciphertext_root, "orderflow ciphertext root")?;
        require_nonempty(calldata_commitment, "calldata commitment")?;
        require_nonempty(sender_commitment, "sender commitment")?;
        require_bps(max_fee_bps, "max fee bps")?;
        require!(
            max_fee_bps <= self.config.max_user_fee_bps,
            "envelope fee exceeds runtime ceiling"
        );
        require!(da_weight_units > 0, "da weight must be positive");
        require!(proof_weight_units > 0, "proof weight must be positive");
        let lane = self
            .lanes
            .get_mut(lane_id)
            .ok_or_else(|| format!("unknown lane: {lane_id}"))?;
        require!(
            lane.status.accepts_envelopes(),
            "lane is not accepting envelopes"
        );
        let expires_at_height = self.l2_height + ttl_blocks.max(1);
        let arrival_commitment =
            arrival_commitment(lane_id, orderflow_ciphertext_root, self.l2_height);
        let fair_order_commitment =
            fair_order_commitment(lane_id, &arrival_commitment, calldata_commitment);
        let envelope_id = envelope_id(
            &self.config.chain_id,
            lane_id,
            orderflow_ciphertext_root,
            calldata_commitment,
            &arrival_commitment,
        );
        require!(
            !self.envelopes.contains_key(&envelope_id),
            "envelope already exists"
        );
        let envelope = EncryptedEnvelope {
            envelope_id: envelope_id.clone(),
            lane_id: lane_id.to_string(),
            kind,
            status: EnvelopeStatus::Encrypted,
            orderflow_ciphertext_root: orderflow_ciphertext_root.to_string(),
            calldata_commitment: calldata_commitment.to_string(),
            sender_commitment: sender_commitment.to_string(),
            fee_bid_id: None,
            coupon_id: None,
            fair_order_commitment,
            arrival_commitment,
            privacy_fence_ids: BTreeSet::new(),
            da_weight_units,
            proof_weight_units,
            max_fee_bps,
            submitted_at_height: self.l2_height,
            expires_at_height,
            batch_id: None,
            receipt_id: None,
            tags,
        };
        lane.pending_envelopes.insert(envelope_id.clone());
        self.envelopes.insert(envelope_id.clone(), envelope);
        Ok(envelope_id)
    }

    pub fn commit_private_fee_bid(
        &mut self,
        envelope_id: &str,
        bid_commitment: &str,
        fee_ceiling_proof_root: &str,
        max_user_fee_bps: u64,
        sponsor_cover_bps: u64,
    ) -> Result<String> {
        require_capacity(self.fee_bids.len(), self.config.max_envelopes, "fee bids")?;
        require_nonempty(bid_commitment, "bid commitment")?;
        require_nonempty(fee_ceiling_proof_root, "fee ceiling proof root")?;
        require_bps(max_user_fee_bps, "max user fee bps")?;
        require_bps(sponsor_cover_bps, "sponsor cover bps")?;
        require!(
            max_user_fee_bps <= self.config.max_user_fee_bps,
            "private fee bid above user ceiling"
        );
        let envelope = self
            .envelopes
            .get_mut(envelope_id)
            .ok_or_else(|| format!("unknown envelope: {envelope_id}"))?;
        require!(envelope.status.active(), "envelope is not active");
        require!(
            envelope.fee_bid_id.is_none(),
            "envelope already has a fee bid"
        );
        let bid_id = fee_bid_id(envelope_id, bid_commitment, fee_ceiling_proof_root);
        let bid = PrivateFeeBid {
            bid_id: bid_id.clone(),
            envelope_id: envelope_id.to_string(),
            bid_commitment: bid_commitment.to_string(),
            fee_ceiling_proof_root: fee_ceiling_proof_root.to_string(),
            max_user_fee_bps,
            sponsor_cover_bps,
            revealed_fee_bps: None,
            status: FeeBidStatus::Committed,
            committed_at_height: self.l2_height,
            reveal_deadline_height: self.l2_height + self.config.reveal_blocks,
        };
        envelope.fee_bid_id = Some(bid_id.clone());
        envelope.status = EnvelopeStatus::FeeBidCommitted;
        self.fee_bids.insert(bid_id.clone(), bid);
        Ok(bid_id)
    }

    pub fn reveal_private_fee_bid(&mut self, bid_id: &str, revealed_fee_bps: u64) -> Result<()> {
        require_bps(revealed_fee_bps, "revealed fee bps")?;
        let bid = self
            .fee_bids
            .get_mut(bid_id)
            .ok_or_else(|| format!("unknown fee bid: {bid_id}"))?;
        require!(
            bid.status == FeeBidStatus::Committed,
            "bid is not committed"
        );
        require!(
            self.l2_height <= bid.reveal_deadline_height,
            "fee bid reveal deadline passed"
        );
        require!(
            revealed_fee_bps <= bid.max_user_fee_bps,
            "revealed fee exceeds private ceiling"
        );
        bid.revealed_fee_bps = Some(revealed_fee_bps);
        bid.status = FeeBidStatus::Revealed;
        Ok(())
    }

    pub fn mint_sponsor_coupon(
        &mut self,
        sponsor_id: &str,
        lane_id: &str,
        coupon_commitment: &str,
        covered_fee_bps: u64,
        budget_micro_units: u64,
        ttl_blocks: u64,
    ) -> Result<String> {
        require_capacity(self.coupons.len(), self.config.max_coupons, "coupons")?;
        require_nonempty(sponsor_id, "sponsor id")?;
        require_nonempty(coupon_commitment, "coupon commitment")?;
        require_bps(covered_fee_bps, "covered fee bps")?;
        require!(
            covered_fee_bps >= self.config.min_sponsor_cover_bps,
            "coupon sponsor cover below minimum"
        );
        require!(budget_micro_units > 0, "coupon budget must be positive");
        let lane = self
            .lanes
            .get(lane_id)
            .ok_or_else(|| format!("unknown lane: {lane_id}"))?;
        let coupon_nullifier = coupon_nullifier(sponsor_id, lane_id, coupon_commitment);
        require!(
            !self.consumed_nullifiers.contains(&coupon_nullifier),
            "coupon nullifier already consumed"
        );
        let coupon_id = coupon_id(sponsor_id, lane_id, coupon_commitment, self.l2_height);
        let coupon = SponsorCoupon {
            coupon_id: coupon_id.clone(),
            sponsor_id: sponsor_id.to_string(),
            lane_id: lane_id.to_string(),
            coupon_commitment: coupon_commitment.to_string(),
            coupon_nullifier,
            covered_fee_bps,
            budget_micro_units,
            remaining_micro_units: budget_micro_units,
            privacy_set_size: lane.privacy_set_size,
            status: CouponStatus::Minted,
            issued_at_height: self.l2_height,
            expires_at_height: self.l2_height + ttl_blocks.max(1),
            reserved_envelopes: BTreeSet::new(),
        };
        self.coupons.insert(coupon_id.clone(), coupon);
        Ok(coupon_id)
    }

    pub fn reserve_coupon_for_envelope(
        &mut self,
        coupon_id: &str,
        envelope_id: &str,
        reserve_micro_units: u64,
    ) -> Result<()> {
        require!(reserve_micro_units > 0, "reserve amount must be positive");
        let envelope = self
            .envelopes
            .get_mut(envelope_id)
            .ok_or_else(|| format!("unknown envelope: {envelope_id}"))?;
        require!(envelope.coupon_id.is_none(), "envelope already has coupon");
        let coupon = self
            .coupons
            .get_mut(coupon_id)
            .ok_or_else(|| format!("unknown coupon: {coupon_id}"))?;
        require!(
            coupon.status == CouponStatus::Minted || coupon.status == CouponStatus::Reserved,
            "coupon not reservable"
        );
        require!(coupon.lane_id == envelope.lane_id, "coupon lane mismatch");
        require!(self.l2_height <= coupon.expires_at_height, "coupon expired");
        require!(
            coupon.remaining_micro_units >= reserve_micro_units,
            "coupon budget exhausted"
        );
        coupon.remaining_micro_units -= reserve_micro_units;
        coupon.status = CouponStatus::Reserved;
        coupon.reserved_envelopes.insert(envelope_id.to_string());
        envelope.coupon_id = Some(coupon_id.to_string());
        envelope.status = EnvelopeStatus::CouponReserved;
        Ok(())
    }

    pub fn attach_privacy_fence(
        &mut self,
        envelope_id: &str,
        kind: PrivacyFenceKind,
        commitment: &str,
        nullifier: &str,
        domain: &str,
    ) -> Result<String> {
        require_nonempty(commitment, "fence commitment")?;
        require_nonempty(nullifier, "fence nullifier")?;
        require_nonempty(domain, "fence domain")?;
        require!(
            !self.consumed_nullifiers.contains(nullifier),
            "privacy fence nullifier already consumed"
        );
        let envelope = self
            .envelopes
            .get_mut(envelope_id)
            .ok_or_else(|| format!("unknown envelope: {envelope_id}"))?;
        let fence_id = privacy_fence_id(kind, commitment, nullifier, domain);
        let fence = self
            .privacy_fences
            .entry(fence_id.clone())
            .or_insert_with(|| PrivacyFence {
                fence_id: fence_id.clone(),
                kind,
                commitment: commitment.to_string(),
                nullifier: nullifier.to_string(),
                domain: domain.to_string(),
                first_seen_height: self.l2_height,
                envelope_ids: BTreeSet::new(),
            });
        require!(fence.kind == kind, "privacy fence kind mismatch");
        require!(
            fence.nullifier == nullifier,
            "privacy fence nullifier mismatch"
        );
        fence.envelope_ids.insert(envelope_id.to_string());
        envelope.privacy_fence_ids.insert(fence_id.clone());
        Ok(fence_id)
    }

    pub fn seal_fair_ordering_window(
        &mut self,
        lane_id: &str,
        entropy_commitment: &str,
        vdf_transcript_root: &str,
        envelope_limit: usize,
    ) -> Result<String> {
        require_nonempty(entropy_commitment, "entropy commitment")?;
        require_nonempty(vdf_transcript_root, "vdf transcript root")?;
        let lane = self
            .lanes
            .get_mut(lane_id)
            .ok_or_else(|| format!("unknown lane: {lane_id}"))?;
        require!(envelope_limit > 0, "envelope limit must be positive");
        let mut candidates = lane
            .pending_envelopes
            .iter()
            .filter_map(|id| self.envelopes.get(id))
            .filter(|envelope| {
                envelope.status.active() && self.l2_height <= envelope.expires_at_height
            })
            .map(|envelope| {
                (
                    fair_sort_key(envelope, entropy_commitment, vdf_transcript_root),
                    envelope.envelope_id.clone(),
                )
            })
            .collect::<Vec<_>>();
        candidates.sort();
        let ordered_envelopes = candidates
            .iter()
            .take(envelope_limit)
            .map(|(_, id)| id.clone())
            .collect::<Vec<_>>();
        require!(
            !ordered_envelopes.is_empty(),
            "no envelopes available for window"
        );
        let selected = ordered_envelopes.iter().cloned().collect::<BTreeSet<_>>();
        let excluded_envelopes = lane
            .pending_envelopes
            .difference(&selected)
            .cloned()
            .collect::<BTreeSet<_>>();
        let window_id = window_id(
            lane_id,
            entropy_commitment,
            vdf_transcript_root,
            self.l2_height,
        );
        let window = FairOrderingWindow {
            window_id: window_id.clone(),
            lane_id: lane_id.to_string(),
            status: WindowStatus::Ordered,
            start_height: self.l2_height,
            seal_height: self.l2_height + self.config.window_blocks,
            reveal_deadline_height: self.l2_height
                + self.config.window_blocks
                + self.config.reveal_blocks,
            entropy_commitment: entropy_commitment.to_string(),
            vdf_transcript_root: vdf_transcript_root.to_string(),
            ordered_envelopes: ordered_envelopes.clone(),
            excluded_envelopes,
            fairness_score_bps: fairness_score_bps(
                &ordered_envelopes,
                lane.pending_envelopes.len(),
            ),
        };
        for envelope_id in &ordered_envelopes {
            if let Some(envelope) = self.envelopes.get_mut(envelope_id) {
                envelope.status = EnvelopeStatus::Ordered;
            }
            lane.pending_envelopes.remove(envelope_id);
        }
        lane.sealed_windows.insert(window_id.clone());
        self.windows.insert(window_id.clone(), window);
        Ok(window_id)
    }

    pub fn pack_batch(
        &mut self,
        window_id: &str,
        sequencer_id: &str,
        da_cost_micro_units: u64,
        proof_cost_micro_units: u64,
    ) -> Result<String> {
        require_capacity(self.batches.len(), self.config.max_batches, "batches")?;
        require_nonempty(sequencer_id, "sequencer id")?;
        let window = self
            .windows
            .get_mut(window_id)
            .ok_or_else(|| format!("unknown window: {window_id}"))?;
        require!(
            window.status == WindowStatus::Ordered,
            "window is not ordered"
        );
        let envelope_ids = window
            .ordered_envelopes
            .iter()
            .take(self.config.max_envelopes_per_batch)
            .cloned()
            .collect::<Vec<_>>();
        require!(!envelope_ids.is_empty(), "batch has no envelopes");
        let envelope_count = envelope_ids.len() as u64;
        let ordered_records = envelope_ids
            .iter()
            .filter_map(|id| self.envelopes.get(id).map(EncryptedEnvelope::public_record))
            .collect::<Vec<_>>();
        let fence_records = envelope_ids
            .iter()
            .filter_map(|id| self.envelopes.get(id))
            .flat_map(|envelope| envelope.privacy_fence_ids.iter())
            .filter_map(|id| self.privacy_fences.get(id).map(PrivacyFence::public_record))
            .collect::<Vec<_>>();
        let bid_records = envelope_ids
            .iter()
            .filter_map(|id| {
                self.envelopes
                    .get(id)
                    .and_then(|env| env.fee_bid_id.as_ref())
            })
            .filter_map(|id| self.fee_bids.get(id).map(PrivateFeeBid::public_record))
            .collect::<Vec<_>>();
        let coupon_records = envelope_ids
            .iter()
            .filter_map(|id| {
                self.envelopes
                    .get(id)
                    .and_then(|env| env.coupon_id.as_ref())
            })
            .filter_map(|id| self.coupons.get(id).map(SponsorCoupon::public_record))
            .collect::<Vec<_>>();
        let aggregate_fee_bps = aggregate_fee_bps(&envelope_ids, &self.envelopes, &self.fee_bids);
        require!(
            aggregate_fee_bps <= self.config.max_user_fee_bps,
            "batch aggregate fee exceeds ceiling"
        );
        let da_cost_per_envelope = amortized_cost(
            da_cost_micro_units,
            envelope_count,
            self.config.da_amortization_bps,
        );
        let proof_cost_per_envelope = amortized_cost(
            proof_cost_micro_units,
            envelope_count,
            self.config.proof_amortization_bps,
        );
        let sponsor_fee_micro_units = coupon_records
            .len()
            .saturating_mul(da_cost_per_envelope.saturating_add(proof_cost_per_envelope) as usize)
            as u64;
        let user_fee_micro_units = envelope_count
            .saturating_mul(da_cost_per_envelope.saturating_add(proof_cost_per_envelope));
        let rebate_pool_micro_units = user_fee_micro_units
            .saturating_mul(self.config.default_rebate_bps)
            / PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_MAX_BPS;
        let batch_id = batch_id(window_id, sequencer_id, &ordered_records);
        let amortization = BatchAmortization {
            da_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-BATCH-DA",
                &ordered_records,
            ),
            proof_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-BATCH-PROOF",
                &ordered_records,
            ),
            da_cost_micro_units,
            proof_cost_micro_units,
            da_cost_per_envelope,
            proof_cost_per_envelope,
            da_amortization_bps: self.config.da_amortization_bps,
            proof_amortization_bps: self.config.proof_amortization_bps,
        };
        let batch = PackedBatch {
            batch_id: batch_id.clone(),
            lane_id: window.lane_id.clone(),
            window_id: window_id.to_string(),
            status: BatchStatus::Packed,
            sequencer_id: sequencer_id.to_string(),
            envelope_ids: envelope_ids.clone(),
            excluded_envelopes: window.excluded_envelopes.clone(),
            ordered_envelope_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-BATCH-ORDER",
                &ordered_records,
            ),
            privacy_fence_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-BATCH-FENCES",
                &fence_records,
            ),
            fee_bid_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-BATCH-BIDS",
                &bid_records,
            ),
            coupon_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-BATCH-COUPONS",
                &coupon_records,
            ),
            amortization,
            aggregate_fee_bps,
            user_fee_micro_units,
            sponsor_fee_micro_units,
            rebate_pool_micro_units,
            packed_at_height: self.l2_height,
            expires_at_height: self.l2_height + self.config.batch_ttl_blocks,
        };
        for envelope_id in &envelope_ids {
            let envelope = self
                .envelopes
                .get_mut(envelope_id)
                .ok_or_else(|| format!("unknown envelope in batch: {envelope_id}"))?;
            envelope.status = EnvelopeStatus::Packed;
            envelope.batch_id = Some(batch_id.clone());
            for fence_id in &envelope.privacy_fence_ids {
                if let Some(fence) = self.privacy_fences.get(fence_id) {
                    self.consumed_nullifiers.insert(fence.nullifier.clone());
                }
            }
        }
        if let Some(lane) = self.lanes.get_mut(&window.lane_id) {
            lane.last_batch_height = self.l2_height;
        }
        self.active_batches_by_lane
            .entry(window.lane_id.clone())
            .or_default()
            .insert(batch_id.clone());
        window.status = WindowStatus::Packed;
        self.batches.insert(batch_id.clone(), batch);
        Ok(batch_id)
    }

    pub fn mark_da_posted(&mut self, batch_id: &str, da_root: &str) -> Result<()> {
        require_nonempty(da_root, "da root")?;
        let batch = self
            .batches
            .get_mut(batch_id)
            .ok_or_else(|| format!("unknown batch: {batch_id}"))?;
        require!(batch.status == BatchStatus::Packed, "batch is not packed");
        require!(batch.amortization.da_root == da_root, "da root mismatch");
        batch.status = BatchStatus::DaPosted;
        Ok(())
    }

    pub fn mark_proof_amortized(&mut self, batch_id: &str, proof_root: &str) -> Result<()> {
        require_nonempty(proof_root, "proof root")?;
        let batch = self
            .batches
            .get_mut(batch_id)
            .ok_or_else(|| format!("unknown batch: {batch_id}"))?;
        require!(batch.status == BatchStatus::DaPosted, "batch da not posted");
        require!(
            batch.amortization.proof_root == proof_root,
            "proof root mismatch"
        );
        batch.status = BatchStatus::ProofAmortized;
        Ok(())
    }

    pub fn publish_settlement_receipt(
        &mut self,
        batch_id: &str,
        settlement_root: &str,
        post_state_root: &str,
        receipt_proof_root: &str,
        rejected_envelopes: BTreeSet<String>,
    ) -> Result<String> {
        require_capacity(self.receipts.len(), self.config.max_receipts, "receipts")?;
        require_nonempty(settlement_root, "settlement root")?;
        require_nonempty(post_state_root, "post state root")?;
        require_nonempty(receipt_proof_root, "receipt proof root")?;
        let batch = self
            .batches
            .get_mut(batch_id)
            .ok_or_else(|| format!("unknown batch: {batch_id}"))?;
        require!(
            matches!(
                batch.status,
                BatchStatus::ProofAmortized | BatchStatus::DaPosted | BatchStatus::Packed
            ),
            "batch cannot be settled"
        );
        let included_envelopes = batch
            .envelope_ids
            .iter()
            .filter(|id| !rejected_envelopes.contains(*id))
            .cloned()
            .collect::<BTreeSet<_>>();
        let receipt_id = receipt_id(
            batch_id,
            settlement_root,
            post_state_root,
            receipt_proof_root,
        );
        let receipt = SettlementReceipt {
            receipt_id: receipt_id.clone(),
            batch_id: batch_id.to_string(),
            status: ReceiptStatus::Published,
            settlement_root: settlement_root.to_string(),
            post_state_root: post_state_root.to_string(),
            receipt_proof_root: receipt_proof_root.to_string(),
            included_envelopes: included_envelopes.clone(),
            rejected_envelopes: rejected_envelopes.clone(),
            settled_fee_micro_units: batch.user_fee_micro_units + batch.sponsor_fee_micro_units,
            settled_at_height: self.l2_height,
            finality_height: self.l2_height + self.config.receipt_ttl_blocks,
        };
        for envelope_id in &included_envelopes {
            if let Some(envelope) = self.envelopes.get_mut(envelope_id) {
                envelope.status = EnvelopeStatus::Settled;
                envelope.receipt_id = Some(receipt_id.clone());
            }
        }
        for envelope_id in &rejected_envelopes {
            if let Some(envelope) = self.envelopes.get_mut(envelope_id) {
                envelope.status = EnvelopeStatus::Rejected;
                envelope.receipt_id = Some(receipt_id.clone());
            }
        }
        batch.status = BatchStatus::Settled;
        self.receipts_by_batch
            .entry(batch_id.to_string())
            .or_default()
            .insert(receipt_id.clone());
        self.receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn finalize_receipt(&mut self, receipt_id: &str) -> Result<()> {
        let receipt = self
            .receipts
            .get_mut(receipt_id)
            .ok_or_else(|| format!("unknown receipt: {receipt_id}"))?;
        require!(
            receipt.status == ReceiptStatus::Published,
            "receipt not published"
        );
        require!(
            self.l2_height >= receipt.finality_height,
            "receipt finality height not reached"
        );
        receipt.status = ReceiptStatus::Finalized;
        Ok(())
    }

    pub fn pay_rebate(
        &mut self,
        receipt_id: &str,
        beneficiary_commitment: &str,
        amount_micro_units: u64,
        source_coupon_id: Option<String>,
        proof_root: &str,
    ) -> Result<String> {
        require_capacity(self.rebates.len(), self.config.max_rebates, "rebates")?;
        require_nonempty(beneficiary_commitment, "beneficiary commitment")?;
        require_nonempty(proof_root, "rebate proof root")?;
        require!(amount_micro_units > 0, "rebate amount must be positive");
        let receipt = self
            .receipts
            .get(receipt_id)
            .ok_or_else(|| format!("unknown receipt: {receipt_id}"))?;
        let batch = self
            .batches
            .get_mut(&receipt.batch_id)
            .ok_or_else(|| format!("unknown batch: {}", receipt.batch_id))?;
        require!(
            amount_micro_units <= batch.rebate_pool_micro_units,
            "rebate exceeds batch pool"
        );
        let rebate_nullifier = rebate_nullifier(receipt_id, beneficiary_commitment, proof_root);
        require!(
            !self.consumed_nullifiers.contains(&rebate_nullifier),
            "rebate nullifier already consumed"
        );
        let rebate_id = rebate_id(
            receipt_id,
            beneficiary_commitment,
            amount_micro_units,
            proof_root,
        );
        let rebate = FeeRebate {
            rebate_id: rebate_id.clone(),
            receipt_id: receipt_id.to_string(),
            batch_id: receipt.batch_id.clone(),
            beneficiary_commitment: beneficiary_commitment.to_string(),
            rebate_nullifier: rebate_nullifier.clone(),
            amount_micro_units,
            source_coupon_id,
            proof_root: proof_root.to_string(),
            paid_at_height: self.l2_height,
        };
        batch.rebate_pool_micro_units -= amount_micro_units;
        if batch.rebate_pool_micro_units == 0 {
            batch.status = BatchStatus::Rebated;
        }
        self.consumed_nullifiers.insert(rebate_nullifier);
        self.rebates.insert(rebate_id.clone(), rebate);
        Ok(rebate_id)
    }

    pub fn submit_slashing_evidence(
        &mut self,
        kind: EvidenceKind,
        accused_id: &str,
        batch_id: Option<String>,
        envelope_id: Option<String>,
        lane_id: Option<String>,
        evidence_root: &str,
        witness_root: &str,
        accept: bool,
    ) -> Result<String> {
        require_capacity(
            self.slashing_evidence.len(),
            self.config.max_slashing_evidence,
            "slashing evidence",
        )?;
        require_nonempty(accused_id, "accused id")?;
        require_nonempty(evidence_root, "evidence root")?;
        require_nonempty(witness_root, "witness root")?;
        let evidence_id = slashing_evidence_id(kind, accused_id, evidence_root, witness_root);
        let evidence = SlashingEvidence {
            evidence_id: evidence_id.clone(),
            kind,
            accused_id: accused_id.to_string(),
            batch_id: batch_id.clone(),
            envelope_id: envelope_id.clone(),
            lane_id: lane_id.clone(),
            evidence_root: evidence_root.to_string(),
            witness_root: witness_root.to_string(),
            penalty_micro_units: if accept {
                self.config.slashing_bond_micro_units
            } else {
                0
            },
            accepted: accept,
            submitted_at_height: self.l2_height,
        };
        if accept {
            if let Some(batch_id) = batch_id {
                if let Some(batch) = self.batches.get_mut(&batch_id) {
                    batch.status = BatchStatus::Slashed;
                }
            }
            if let Some(lane_id) = lane_id {
                if let Some(lane) = self.lanes.get_mut(&lane_id) {
                    lane.status = LaneStatus::Draining;
                }
            }
            if let Some(envelope_id) = envelope_id {
                if let Some(envelope) = self.envelopes.get_mut(&envelope_id) {
                    envelope.status = EnvelopeStatus::Rejected;
                }
            }
        }
        self.slashing_evidence.insert(evidence_id.clone(), evidence);
        Ok(evidence_id)
    }

    pub fn expire_stale_records(&mut self) -> usize {
        let mut expired = 0_usize;
        for envelope in self.envelopes.values_mut() {
            if envelope.status.active() && self.l2_height > envelope.expires_at_height {
                envelope.status = EnvelopeStatus::Expired;
                expired += 1;
            }
        }
        for bid in self.fee_bids.values_mut() {
            if bid.status == FeeBidStatus::Committed && self.l2_height > bid.reveal_deadline_height
            {
                bid.status = FeeBidStatus::Expired;
                expired += 1;
            }
        }
        for coupon in self.coupons.values_mut() {
            if matches!(coupon.status, CouponStatus::Minted | CouponStatus::Reserved)
                && self.l2_height > coupon.expires_at_height
            {
                coupon.status = CouponStatus::Expired;
                expired += 1;
            }
        }
        for batch in self.batches.values_mut() {
            if matches!(batch.status, BatchStatus::Packed | BatchStatus::DaPosted)
                && self.l2_height > batch.expires_at_height
            {
                batch.status = BatchStatus::Challenged;
                expired += 1;
            }
        }
        expired
    }
}

#[macro_export]
macro_rules! private_l2_low_fee_private_mempool_batcher_require {
    ($condition:expr, $message:expr $(,)?) => {
        if !$condition {
            return Err($message.to_string());
        }
    };
}

use private_l2_low_fee_private_mempool_batcher_require as require;

pub fn lane_id(
    chain_id: &str,
    kind: LaneKind,
    operator_commitment: &str,
    encryption_key_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-LANE-ID",
        &[
            HashPart::Str(chain_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(operator_commitment),
            HashPart::Str(encryption_key_root),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn envelope_id(
    chain_id: &str,
    lane_id: &str,
    orderflow_ciphertext_root: &str,
    calldata_commitment: &str,
    arrival_commitment: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-ENVELOPE-ID",
        &[
            HashPart::Str(chain_id),
            HashPart::Str(lane_id),
            HashPart::Str(orderflow_ciphertext_root),
            HashPart::Str(calldata_commitment),
            HashPart::Str(arrival_commitment),
        ],
        32,
    )
}

pub fn fee_bid_id(envelope_id: &str, bid_commitment: &str, fee_ceiling_proof_root: &str) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-FEE-BID-ID",
        &[
            HashPart::Str(envelope_id),
            HashPart::Str(bid_commitment),
            HashPart::Str(fee_ceiling_proof_root),
        ],
        32,
    )
}

pub fn coupon_id(sponsor_id: &str, lane_id: &str, coupon_commitment: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-COUPON-ID",
        &[
            HashPart::Str(sponsor_id),
            HashPart::Str(lane_id),
            HashPart::Str(coupon_commitment),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn coupon_nullifier(sponsor_id: &str, lane_id: &str, coupon_commitment: &str) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-COUPON-NULLIFIER",
        &[
            HashPart::Str(sponsor_id),
            HashPart::Str(lane_id),
            HashPart::Str(coupon_commitment),
        ],
        32,
    )
}

pub fn privacy_fence_id(
    kind: PrivacyFenceKind,
    commitment: &str,
    nullifier: &str,
    domain: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-PRIVACY-FENCE-ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(commitment),
            HashPart::Str(nullifier),
            HashPart::Str(domain),
        ],
        32,
    )
}

pub fn arrival_commitment(lane_id: &str, orderflow_ciphertext_root: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-ARRIVAL-COMMITMENT",
        &[
            HashPart::Str(lane_id),
            HashPart::Str(orderflow_ciphertext_root),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn fair_order_commitment(
    lane_id: &str,
    arrival_commitment: &str,
    calldata_commitment: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-FAIR-ORDER-COMMITMENT",
        &[
            HashPart::Str(lane_id),
            HashPart::Str(arrival_commitment),
            HashPart::Str(calldata_commitment),
        ],
        32,
    )
}

pub fn window_id(
    lane_id: &str,
    entropy_commitment: &str,
    vdf_transcript_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-WINDOW-ID",
        &[
            HashPart::Str(lane_id),
            HashPart::Str(entropy_commitment),
            HashPart::Str(vdf_transcript_root),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn batch_id(window_id: &str, sequencer_id: &str, ordered_records: &[Value]) -> String {
    let ordered_root = merkle_root(
        "PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-BATCH-ID-ORDER",
        ordered_records,
    );
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-BATCH-ID",
        &[
            HashPart::Str(window_id),
            HashPart::Str(sequencer_id),
            HashPart::Str(&ordered_root),
        ],
        32,
    )
}

pub fn receipt_id(
    batch_id: &str,
    settlement_root: &str,
    post_state_root: &str,
    receipt_proof_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-RECEIPT-ID",
        &[
            HashPart::Str(batch_id),
            HashPart::Str(settlement_root),
            HashPart::Str(post_state_root),
            HashPart::Str(receipt_proof_root),
        ],
        32,
    )
}

pub fn rebate_id(
    receipt_id: &str,
    beneficiary_commitment: &str,
    amount_micro_units: u64,
    proof_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-REBATE-ID",
        &[
            HashPart::Str(receipt_id),
            HashPart::Str(beneficiary_commitment),
            HashPart::U64(amount_micro_units),
            HashPart::Str(proof_root),
        ],
        32,
    )
}

pub fn rebate_nullifier(
    receipt_id: &str,
    beneficiary_commitment: &str,
    proof_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-REBATE-NULLIFIER",
        &[
            HashPart::Str(receipt_id),
            HashPart::Str(beneficiary_commitment),
            HashPart::Str(proof_root),
        ],
        32,
    )
}

pub fn slashing_evidence_id(
    kind: EvidenceKind,
    accused_id: &str,
    evidence_root: &str,
    witness_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(&format!("{kind:?}")),
            HashPart::Str(accused_id),
            HashPart::Str(evidence_root),
            HashPart::Str(witness_root),
        ],
        32,
    )
}

pub fn fair_sort_key(
    envelope: &EncryptedEnvelope,
    entropy_commitment: &str,
    vdf_transcript_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PRIVATE-MEMPOOL-FAIR-SORT-KEY",
        &[
            HashPart::Str(&envelope.fair_order_commitment),
            HashPart::Str(&envelope.arrival_commitment),
            HashPart::Str(entropy_commitment),
            HashPart::Str(vdf_transcript_root),
        ],
        32,
    )
}

pub fn map_root<T, F>(domain: &str, values: &BTreeMap<String, T>, record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = values
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": record(value) }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn fairness_score_bps(ordered_envelopes: &[String], pending_count: usize) -> u64 {
    if pending_count == 0 {
        return PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_MAX_BPS;
    }
    let selected = ordered_envelopes.len() as u64;
    let pending = pending_count as u64;
    selected.saturating_mul(PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_MAX_BPS) / pending
}

pub fn amortized_cost(total_cost: u64, count: u64, amortization_bps: u64) -> u64 {
    if count == 0 {
        return 0;
    }
    total_cost
        .saturating_mul(amortization_bps)
        .saturating_div(PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_MAX_BPS)
        .saturating_div(count)
}

pub fn aggregate_fee_bps(
    envelope_ids: &[String],
    envelopes: &BTreeMap<String, EncryptedEnvelope>,
    bids: &BTreeMap<String, PrivateFeeBid>,
) -> u64 {
    if envelope_ids.is_empty() {
        return 0;
    }
    let total = envelope_ids
        .iter()
        .filter_map(|id| envelopes.get(id))
        .map(|envelope| {
            envelope
                .fee_bid_id
                .as_ref()
                .and_then(|bid_id| bids.get(bid_id))
                .and_then(|bid| bid.revealed_fee_bps)
                .unwrap_or(envelope.max_fee_bps)
        })
        .sum::<u64>();
    total / envelope_ids.len() as u64
}

pub fn validate_config(config: &Config) -> Result<()> {
    require!(
        !config.protocol_version.is_empty(),
        "missing protocol version"
    );
    require!(!config.chain_id.is_empty(), "missing chain id");
    require!(config.window_blocks > 0, "window blocks must be positive");
    require!(config.reveal_blocks > 0, "reveal blocks must be positive");
    require!(config.batch_ttl_blocks > 0, "batch ttl must be positive");
    require!(
        config.receipt_ttl_blocks > 0,
        "receipt ttl must be positive"
    );
    require!(config.max_lanes > 0, "max lanes must be positive");
    require!(config.max_envelopes > 0, "max envelopes must be positive");
    require!(config.max_batches > 0, "max batches must be positive");
    require!(
        config.max_envelopes_per_batch > 0,
        "max envelopes per batch must be positive"
    );
    require!(
        config.min_privacy_set_size >= config.min_lane_privacy_size,
        "global privacy set must cover lane minimum"
    );
    require!(
        config.min_pq_security_bits >= 128,
        "pq security below floor"
    );
    require_bps(config.target_user_fee_bps, "target user fee bps")?;
    require_bps(config.max_user_fee_bps, "max user fee bps")?;
    require_bps(config.min_sponsor_cover_bps, "min sponsor cover bps")?;
    require_bps(config.da_amortization_bps, "da amortization bps")?;
    require_bps(config.proof_amortization_bps, "proof amortization bps")?;
    require_bps(config.default_rebate_bps, "default rebate bps")?;
    require!(
        config.target_user_fee_bps <= config.max_user_fee_bps,
        "target user fee exceeds maximum"
    );
    Ok(())
}

pub fn validate_state(state: &State) -> Result<()> {
    validate_config(&state.config)?;
    require!(
        state.lanes.len() <= state.config.max_lanes,
        "lane capacity exceeded"
    );
    require!(
        state.envelopes.len() <= state.config.max_envelopes,
        "envelope capacity exceeded"
    );
    require!(
        state.batches.len() <= state.config.max_batches,
        "batch capacity exceeded"
    );
    require!(
        state.receipts.len() <= state.config.max_receipts,
        "receipt capacity exceeded"
    );
    require!(
        state.coupons.len() <= state.config.max_coupons,
        "coupon capacity exceeded"
    );
    for lane in state.lanes.values() {
        require!(
            lane.privacy_set_size >= state.config.min_lane_privacy_size,
            "lane privacy set below minimum"
        );
        require!(
            lane.pq_security_bits >= state.config.min_pq_security_bits,
            "lane pq security below minimum"
        );
        require_bps(lane.target_fee_bps, "lane target fee bps")?;
        require_bps(lane.max_fee_bps, "lane max fee bps")?;
    }
    for envelope in state.envelopes.values() {
        require!(
            state.lanes.contains_key(&envelope.lane_id),
            "envelope references unknown lane"
        );
        require_bps(envelope.max_fee_bps, "envelope max fee bps")?;
    }
    for batch in state.batches.values() {
        require!(
            state.windows.contains_key(&batch.window_id),
            "batch references unknown window"
        );
        for envelope_id in &batch.envelope_ids {
            require!(
                state.envelopes.contains_key(envelope_id),
                "batch references unknown envelope"
            );
        }
    }
    Ok(())
}

pub fn require_capacity(current: usize, max: usize, label: &str) -> Result<()> {
    require!(current < max, &format!("{label} capacity exceeded"));
    Ok(())
}

pub fn require_nonempty(value: &str, label: &str) -> Result<()> {
    require!(
        !value.trim().is_empty(),
        &format!("{label} must not be empty")
    );
    Ok(())
}

pub fn require_bps(value: u64, label: &str) -> Result<()> {
    require!(
        value <= PRIVATE_L2_LOW_FEE_PRIVATE_MEMPOOL_BATCHER_RUNTIME_MAX_BPS,
        &format!("{label} exceeds max bps")
    );
    Ok(())
}
