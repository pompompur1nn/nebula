use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_GAS_ESCROW_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-cross-asset-gas-escrow-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_GAS_ESCROW_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ESCROW_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-cross-asset-gas-escrow-v1";
pub const CONFIDENTIAL_ESCROW_SCHEME: &str = "pq-sealed-cross-asset-confidential-gas-escrow-v1";
pub const PAYMASTER_RECEIPT_SCHEME: &str = "private-paymaster-roots-only-receipt-v1";
pub const MICRO_BATCH_NETTING_SCHEME: &str = "low-fee-cross-asset-gas-microbatch-netting-v1";
pub const DA_PROOF_REBATE_SCHEME: &str = "da-proof-rebate-coupon-root-v1";
pub const STABLE_FEE_CORRIDOR_SCHEME: &str = "confidential-stable-fee-corridor-v1";
pub const SPONSOR_RISK_SCHEME: &str = "operator-safe-sponsor-risk-controls-v1";
pub const PRIVACY_REDACTION_SCHEME: &str = "monero-l2-privacy-redaction-root-v1";
pub const PUBLIC_SUMMARY_SCHEME: &str = "operator-safe-public-summary-root-v1";
pub const DEVNET_L2_HEIGHT: u64 = 4_208_144;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_886_720;
pub const DEVNET_EPOCH: u64 = 18_411;
pub const DEFAULT_NATIVE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_STABLE_ASSET_ID: &str = "pdusd-devnet";
pub const DEFAULT_DEFI_GAS_ASSET_ID: &str = "pgas-devnet";
pub const DEFAULT_REBATE_ASSET_ID: &str = "da-rebate-credit-devnet";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_ESCROW_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_QUOTE_TTL_BLOCKS: u64 = 18;
pub const DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_COUPON_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 14;
pub const DEFAULT_MAX_SLIPPAGE_BPS: u64 = 30;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 700;
pub const DEFAULT_SPONSOR_RESERVE_BPS: u64 = 1_600;
pub const DEFAULT_SPONSOR_DRAWDOWN_BPS: u64 = 6_500;
pub const DEFAULT_CORRIDOR_WIDTH_BPS: u64 = 40;
pub const DEFAULT_NETTING_DISCOUNT_BPS: u64 = 1_850;
pub const DEFAULT_OPERATOR_SAFETY_MARGIN_BPS: u64 = 250;
pub const DEFAULT_MICROBATCH_MAX_ITEMS: usize = 4_096;
pub const MAX_BPS: u64 = 10_000;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GasLane {
    WalletTransfer,
    ConfidentialContract,
    DefiSwap,
    LendingVault,
    PerpsMargin,
    BridgeExit,
    RecursiveProof,
    BlobDa,
    EmergencyEscape,
}

impl GasLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletTransfer => "wallet_transfer",
            Self::ConfidentialContract => "confidential_contract",
            Self::DefiSwap => "defi_swap",
            Self::LendingVault => "lending_vault",
            Self::PerpsMargin => "perps_margin",
            Self::BridgeExit => "bridge_exit",
            Self::RecursiveProof => "recursive_proof",
            Self::BlobDa => "blob_da",
            Self::EmergencyEscape => "emergency_escape",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::WalletTransfer => 2,
            Self::ConfidentialContract => 5,
            Self::DefiSwap => 7,
            Self::LendingVault => 7,
            Self::PerpsMargin => 8,
            Self::BridgeExit => 9,
            Self::RecursiveProof => 6,
            Self::BlobDa => 4,
            Self::EmergencyEscape => 10,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeAssetKind {
    NativePiconero,
    PrivateStable,
    ConfidentialGasToken,
    DefiLpShare,
    SponsorCredit,
    DaProofCoupon,
    ProofRebateCredit,
}

impl FeeAssetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NativePiconero => "native_piconero",
            Self::PrivateStable => "private_stable",
            Self::ConfidentialGasToken => "confidential_gas_token",
            Self::DefiLpShare => "defi_lp_share",
            Self::SponsorCredit => "sponsor_credit",
            Self::DaProofCoupon => "da_proof_coupon",
            Self::ProofRebateCredit => "proof_rebate_credit",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Open,
    Quoting,
    Reserving,
    Netting,
    Settling,
    Draining,
    Paused,
    Slashed,
}

impl VaultStatus {
    pub fn accepts_escrow(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Quoting | Self::Reserving | Self::Netting
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Quoting => "quoting",
            Self::Reserving => "reserving",
            Self::Netting => "netting",
            Self::Settling => "settling",
            Self::Draining => "draining",
            Self::Paused => "paused",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Posted,
    Reserved,
    Filled,
    Expired,
    Rejected,
}

impl QuoteStatus {
    pub fn live(self) -> bool {
        matches!(self, Self::Posted | Self::Reserved)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Reserved => "reserved",
            Self::Filled => "filled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EscrowStatus {
    Sealed,
    Quoted,
    Reserved,
    Netted,
    Settled,
    Refunded,
    Expired,
    Slashed,
}

impl EscrowStatus {
    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::Quoted | Self::Reserved | Self::Netted
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Quoted => "quoted",
            Self::Reserved => "reserved",
            Self::Netted => "netted",
            Self::Settled => "settled",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorRiskLevel {
    Green,
    Watch,
    Throttled,
    Frozen,
    SlashingReview,
}

impl SponsorRiskLevel {
    pub fn admits_new_flow(self) -> bool {
        matches!(self, Self::Green | Self::Watch | Self::Throttled)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Green => "green",
            Self::Watch => "watch",
            Self::Throttled => "throttled",
            Self::Frozen => "frozen",
            Self::SlashingReview => "slashing_review",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Building,
    Netted,
    ProofAttached,
    Settled,
    RebateIssued,
    Disputed,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Building => "building",
            Self::Netted => "netted",
            Self::ProofAttached => "proof_attached",
            Self::Settled => "settled",
            Self::RebateIssued => "rebate_issued",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Issued,
    Reserved,
    Applied,
    Claimed,
    Expired,
    Revoked,
}

impl CouponStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Claimed => "claimed",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub native_asset_id: String,
    pub stable_asset_id: String,
    pub defi_gas_asset_id: String,
    pub rebate_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub escrow_ttl_blocks: u64,
    pub quote_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub coupon_ttl_blocks: u64,
    pub max_user_fee_bps: u64,
    pub max_slippage_bps: u64,
    pub target_rebate_bps: u64,
    pub sponsor_reserve_bps: u64,
    pub sponsor_drawdown_bps: u64,
    pub corridor_width_bps: u64,
    pub netting_discount_bps: u64,
    pub operator_safety_margin_bps: u64,
    pub microbatch_max_items: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            native_asset_id: DEFAULT_NATIVE_ASSET_ID.to_string(),
            stable_asset_id: DEFAULT_STABLE_ASSET_ID.to_string(),
            defi_gas_asset_id: DEFAULT_DEFI_GAS_ASSET_ID.to_string(),
            rebate_asset_id: DEFAULT_REBATE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            escrow_ttl_blocks: DEFAULT_ESCROW_TTL_BLOCKS,
            quote_ttl_blocks: DEFAULT_QUOTE_TTL_BLOCKS,
            receipt_ttl_blocks: DEFAULT_RECEIPT_TTL_BLOCKS,
            coupon_ttl_blocks: DEFAULT_COUPON_TTL_BLOCKS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_slippage_bps: DEFAULT_MAX_SLIPPAGE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            sponsor_reserve_bps: DEFAULT_SPONSOR_RESERVE_BPS,
            sponsor_drawdown_bps: DEFAULT_SPONSOR_DRAWDOWN_BPS,
            corridor_width_bps: DEFAULT_CORRIDOR_WIDTH_BPS,
            netting_discount_bps: DEFAULT_NETTING_DISCOUNT_BPS,
            operator_safety_margin_bps: DEFAULT_OPERATOR_SAFETY_MARGIN_BPS,
            microbatch_max_items: DEFAULT_MICROBATCH_MAX_ITEMS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "chain_id": self.chain_id,
            "corridor_width_bps": self.corridor_width_bps,
            "coupon_ttl_blocks": self.coupon_ttl_blocks,
            "defi_gas_asset_id": self.defi_gas_asset_id,
            "escrow_ttl_blocks": self.escrow_ttl_blocks,
            "max_slippage_bps": self.max_slippage_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "microbatch_max_items": self.microbatch_max_items,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "native_asset_id": self.native_asset_id,
            "netting_discount_bps": self.netting_discount_bps,
            "operator_safety_margin_bps": self.operator_safety_margin_bps,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "rebate_asset_id": self.rebate_asset_id,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "sponsor_drawdown_bps": self.sponsor_drawdown_bps,
            "sponsor_reserve_bps": self.sponsor_reserve_bps,
            "stable_asset_id": self.stable_asset_id,
            "target_rebate_bps": self.target_rebate_bps
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub vaults: u64,
    pub quotes: u64,
    pub escrows: u64,
    pub receipts: u64,
    pub sponsors: u64,
    pub microbatches: u64,
    pub coupons: u64,
    pub pq_attestations: u64,
    pub redactions: u64,
    pub public_summaries: u64,
    pub settled_gas_units: u128,
    pub rebated_piconero: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "coupons": self.coupons,
            "escrows": self.escrows,
            "microbatches": self.microbatches,
            "pq_attestations": self.pq_attestations,
            "public_summaries": self.public_summaries,
            "quotes": self.quotes,
            "rebated_piconero": self.rebated_piconero.to_string(),
            "receipts": self.receipts,
            "redactions": self.redactions,
            "settled_gas_units": self.settled_gas_units.to_string(),
            "sponsors": self.sponsors,
            "vaults": self.vaults
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub vault_root: String,
    pub quote_root: String,
    pub escrow_root: String,
    pub paymaster_receipt_root: String,
    pub sponsor_risk_root: String,
    pub microbatch_root: String,
    pub rebate_coupon_root: String,
    pub corridor_root: String,
    pub pq_attestation_root: String,
    pub privacy_redaction_root: String,
    pub operator_summary_root: String,
    pub counters_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            config_root: empty_root("config"),
            vault_root: empty_root("vault"),
            quote_root: empty_root("quote"),
            escrow_root: empty_root("escrow"),
            paymaster_receipt_root: empty_root("paymaster_receipt"),
            sponsor_risk_root: empty_root("sponsor_risk"),
            microbatch_root: empty_root("microbatch"),
            rebate_coupon_root: empty_root("rebate_coupon"),
            corridor_root: empty_root("corridor"),
            pq_attestation_root: empty_root("pq_attestation"),
            privacy_redaction_root: empty_root("privacy_redaction"),
            operator_summary_root: empty_root("operator_summary"),
            counters_root: empty_root("counters"),
            public_record_root: empty_root("public_record"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "corridor_root": self.corridor_root,
            "counters_root": self.counters_root,
            "escrow_root": self.escrow_root,
            "microbatch_root": self.microbatch_root,
            "operator_summary_root": self.operator_summary_root,
            "paymaster_receipt_root": self.paymaster_receipt_root,
            "pq_attestation_root": self.pq_attestation_root,
            "privacy_redaction_root": self.privacy_redaction_root,
            "public_record_root": self.public_record_root,
            "quote_root": self.quote_root,
            "rebate_coupon_root": self.rebate_coupon_root,
            "sponsor_risk_root": self.sponsor_risk_root,
            "vault_root": self.vault_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AssetGasVault {
    pub vault_id: String,
    pub asset_id: String,
    pub asset_kind: FeeAssetKind,
    pub status: VaultStatus,
    pub sealed_liquidity_root: String,
    pub available_commitment_root: String,
    pub min_quote_piconero: u128,
    pub max_quote_piconero: u128,
    pub spread_bps: u64,
    pub privacy_set_size: u64,
    pub sponsor_id: String,
}

impl AssetGasVault {
    pub fn public_record(&self) -> Value {
        json!({
            "asset_id": self.asset_id,
            "asset_kind": self.asset_kind.as_str(),
            "available_commitment_root": self.available_commitment_root,
            "max_quote_piconero": self.max_quote_piconero.to_string(),
            "min_quote_piconero": self.min_quote_piconero.to_string(),
            "privacy_set_size": self.privacy_set_size,
            "sealed_liquidity_root": self.sealed_liquidity_root,
            "sponsor_id": self.sponsor_id,
            "spread_bps": self.spread_bps,
            "status": self.status.as_str(),
            "vault_id": self.vault_id
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TokenGasQuoteRequest {
    pub quote_id: String,
    pub vault_id: String,
    pub asset_id: String,
    pub lane: GasLane,
    pub gas_units: u64,
    pub max_fee_piconero: u128,
    pub max_slippage_bps: u64,
    pub user_note_commitment: String,
    pub expires_at_height: u64,
}

impl TokenGasQuoteRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "asset_id": self.asset_id,
            "expires_at_height": self.expires_at_height,
            "gas_units": self.gas_units,
            "lane": self.lane.as_str(),
            "max_fee_piconero": self.max_fee_piconero.to_string(),
            "max_slippage_bps": self.max_slippage_bps,
            "quote_id": self.quote_id,
            "user_note_commitment": self.user_note_commitment,
            "vault_id": self.vault_id
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TokenGasQuoteRecord {
    pub quote_id: String,
    pub request: TokenGasQuoteRequest,
    pub quoted_fee_piconero: u128,
    pub asset_amount_commitment: String,
    pub corridor_id: String,
    pub status: QuoteStatus,
    pub pq_quote_root: String,
}

impl TokenGasQuoteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "asset_amount_commitment": self.asset_amount_commitment,
            "corridor_id": self.corridor_id,
            "pq_quote_root": self.pq_quote_root,
            "quote_id": self.quote_id,
            "quoted_fee_piconero": self.quoted_fee_piconero.to_string(),
            "request": self.request.public_record(),
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CrossAssetEscrowRequest {
    pub escrow_id: String,
    pub quote_id: String,
    pub paymaster_id: String,
    pub sponsor_id: String,
    pub lane: GasLane,
    pub call_commitment_root: String,
    pub sealed_asset_amount_root: String,
    pub nullifier_root: String,
    pub privacy_set_size: u64,
    pub pq_public_key_root: String,
    pub expires_at_height: u64,
}

impl CrossAssetEscrowRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "call_commitment_root": self.call_commitment_root,
            "escrow_id": self.escrow_id,
            "expires_at_height": self.expires_at_height,
            "lane": self.lane.as_str(),
            "nullifier_root": self.nullifier_root,
            "paymaster_id": self.paymaster_id,
            "pq_public_key_root": self.pq_public_key_root,
            "privacy_set_size": self.privacy_set_size,
            "quote_id": self.quote_id,
            "sealed_asset_amount_root": self.sealed_asset_amount_root,
            "sponsor_id": self.sponsor_id
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CrossAssetEscrowRecord {
    pub escrow_id: String,
    pub request: CrossAssetEscrowRequest,
    pub status: EscrowStatus,
    pub reserved_fee_piconero: u128,
    pub netted_fee_piconero: u128,
    pub private_receipt_id: Option<String>,
    pub rebate_coupon_id: Option<String>,
    pub attestation_id: String,
}

impl CrossAssetEscrowRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "escrow_id": self.escrow_id,
            "netted_fee_piconero": self.netted_fee_piconero.to_string(),
            "private_receipt_id": self.private_receipt_id,
            "rebate_coupon_id": self.rebate_coupon_id,
            "request": self.request.public_record(),
            "reserved_fee_piconero": self.reserved_fee_piconero.to_string(),
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivatePaymasterReceipt {
    pub receipt_id: String,
    pub escrow_id: String,
    pub paymaster_id: String,
    pub lane: GasLane,
    pub gas_units: u64,
    pub settled_fee_piconero: u128,
    pub private_execution_root: String,
    pub redaction_root: String,
    pub operator_summary_id: String,
    pub finalized_height: u64,
}

impl PrivatePaymasterReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "escrow_id": self.escrow_id,
            "finalized_height": self.finalized_height,
            "gas_units": self.gas_units,
            "lane": self.lane.as_str(),
            "operator_summary_id": self.operator_summary_id,
            "paymaster_id": self.paymaster_id,
            "private_execution_root": self.private_execution_root,
            "receipt_id": self.receipt_id,
            "redaction_root": self.redaction_root,
            "settled_fee_piconero": self.settled_fee_piconero.to_string()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsorRiskControl {
    pub sponsor_id: String,
    pub risk_level: SponsorRiskLevel,
    pub max_open_exposure_piconero: u128,
    pub current_open_exposure_piconero: u128,
    pub reserve_commitment_root: String,
    pub allowed_lanes: BTreeSet<GasLane>,
    pub throttled_assets: BTreeSet<String>,
    pub last_review_height: u64,
}

impl SponsorRiskControl {
    pub fn public_record(&self) -> Value {
        json!({
            "allowed_lanes": self.allowed_lanes.iter().map(|lane| lane.as_str()).collect::<Vec<_>>(),
            "current_open_exposure_piconero": self.current_open_exposure_piconero.to_string(),
            "last_review_height": self.last_review_height,
            "max_open_exposure_piconero": self.max_open_exposure_piconero.to_string(),
            "reserve_commitment_root": self.reserve_commitment_root,
            "risk_level": self.risk_level.as_str(),
            "sponsor_id": self.sponsor_id,
            "throttled_assets": self.throttled_assets.iter().cloned().collect::<Vec<_>>()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MicrobatchGasNettingRecord {
    pub batch_id: String,
    pub lane: GasLane,
    pub escrow_ids: Vec<String>,
    pub input_fee_piconero: u128,
    pub netted_fee_piconero: u128,
    pub discount_bps: u64,
    pub proof_root: String,
    pub da_root: String,
    pub status: BatchStatus,
    pub settled_height: Option<u64>,
}

impl MicrobatchGasNettingRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "da_root": self.da_root,
            "discount_bps": self.discount_bps,
            "escrow_ids": self.escrow_ids,
            "input_fee_piconero": self.input_fee_piconero.to_string(),
            "lane": self.lane.as_str(),
            "netted_fee_piconero": self.netted_fee_piconero.to_string(),
            "proof_root": self.proof_root,
            "settled_height": self.settled_height,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DaProofRebateCoupon {
    pub coupon_id: String,
    pub batch_id: String,
    pub beneficiary_commitment_root: String,
    pub rebate_asset_id: String,
    pub rebate_piconero: u128,
    pub proof_cost_root: String,
    pub da_cost_root: String,
    pub expires_at_height: u64,
    pub status: CouponStatus,
}

impl DaProofRebateCoupon {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "beneficiary_commitment_root": self.beneficiary_commitment_root,
            "coupon_id": self.coupon_id,
            "da_cost_root": self.da_cost_root,
            "expires_at_height": self.expires_at_height,
            "proof_cost_root": self.proof_cost_root,
            "rebate_asset_id": self.rebate_asset_id,
            "rebate_piconero": self.rebate_piconero.to_string(),
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StableFeeCorridor {
    pub corridor_id: String,
    pub asset_id: String,
    pub lower_fee_piconero: u128,
    pub target_fee_piconero: u128,
    pub upper_fee_piconero: u128,
    pub width_bps: u64,
    pub oracle_root: String,
    pub valid_until_height: u64,
}

impl StableFeeCorridor {
    pub fn public_record(&self) -> Value {
        json!({
            "asset_id": self.asset_id,
            "corridor_id": self.corridor_id,
            "lower_fee_piconero": self.lower_fee_piconero.to_string(),
            "oracle_root": self.oracle_root,
            "target_fee_piconero": self.target_fee_piconero.to_string(),
            "upper_fee_piconero": self.upper_fee_piconero.to_string(),
            "valid_until_height": self.valid_until_height,
            "width_bps": self.width_bps
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqEscrowAttestation {
    pub attestation_id: String,
    pub escrow_id: String,
    pub quote_id: String,
    pub pq_suite: String,
    pub attested_root: String,
    pub signer_committee_root: String,
    pub min_security_bits: u16,
    pub signature_root: String,
}

impl PqEscrowAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "attested_root": self.attested_root,
            "escrow_id": self.escrow_id,
            "min_security_bits": self.min_security_bits,
            "pq_suite": self.pq_suite,
            "quote_id": self.quote_id,
            "signature_root": self.signature_root,
            "signer_committee_root": self.signer_committee_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyRedactionRoot {
    pub redaction_id: String,
    pub subject_id: String,
    pub nullifier_root: String,
    pub view_tag_root: String,
    pub selective_disclosure_root: String,
    pub operator_visible_fields: BTreeSet<String>,
}

impl PrivacyRedactionRoot {
    pub fn public_record(&self) -> Value {
        json!({
            "nullifier_root": self.nullifier_root,
            "operator_visible_fields": self.operator_visible_fields.iter().cloned().collect::<Vec<_>>(),
            "redaction_id": self.redaction_id,
            "selective_disclosure_root": self.selective_disclosure_root,
            "subject_id": self.subject_id,
            "view_tag_root": self.view_tag_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorPublicSummary {
    pub summary_id: String,
    pub lane: GasLane,
    pub asset_ids: BTreeSet<String>,
    pub escrow_count: u64,
    pub gas_units: u64,
    pub fee_floor_piconero: u128,
    pub fee_ceiling_piconero: u128,
    pub rebate_piconero: u128,
    pub privacy_redaction_root: String,
    pub settlement_root: String,
}

impl OperatorPublicSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "asset_ids": self.asset_ids.iter().cloned().collect::<Vec<_>>(),
            "escrow_count": self.escrow_count,
            "fee_ceiling_piconero": self.fee_ceiling_piconero.to_string(),
            "fee_floor_piconero": self.fee_floor_piconero.to_string(),
            "gas_units": self.gas_units,
            "lane": self.lane.as_str(),
            "privacy_redaction_root": self.privacy_redaction_root,
            "rebate_piconero": self.rebate_piconero.to_string(),
            "settlement_root": self.settlement_root,
            "summary_id": self.summary_id
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub vaults: BTreeMap<String, AssetGasVault>,
    pub quotes: BTreeMap<String, TokenGasQuoteRecord>,
    pub escrows: BTreeMap<String, CrossAssetEscrowRecord>,
    pub receipts: BTreeMap<String, PrivatePaymasterReceipt>,
    pub sponsor_risk: BTreeMap<String, SponsorRiskControl>,
    pub microbatches: BTreeMap<String, MicrobatchGasNettingRecord>,
    pub coupons: BTreeMap<String, DaProofRebateCoupon>,
    pub corridors: BTreeMap<String, StableFeeCorridor>,
    pub pq_attestations: BTreeMap<String, PqEscrowAttestation>,
    pub redactions: BTreeMap<String, PrivacyRedactionRoot>,
    pub public_summaries: BTreeMap<String, OperatorPublicSummary>,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            counters: Counters::default(),
            roots: Roots::empty(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            epoch: DEVNET_EPOCH,
            vaults: BTreeMap::new(),
            quotes: BTreeMap::new(),
            escrows: BTreeMap::new(),
            receipts: BTreeMap::new(),
            sponsor_risk: BTreeMap::new(),
            microbatches: BTreeMap::new(),
            coupons: BTreeMap::new(),
            corridors: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            redactions: BTreeMap::new(),
            public_summaries: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        seed_devnet(&mut state);
        state.refresh_roots();
        state
    }

    pub fn demo() -> Self {
        Self::devnet()
    }

    pub fn register_vault(&mut self, vault: AssetGasVault) -> Result<()> {
        ensure!(
            !self.vaults.contains_key(&vault.vault_id),
            "vault exists: {}",
            vault.vault_id
        );
        ensure!(
            vault.privacy_set_size >= self.config.min_privacy_set_size,
            "vault privacy set below configured minimum"
        );
        self.vaults.insert(vault.vault_id.clone(), vault);
        self.counters.vaults = self.vaults.len() as u64;
        self.refresh_roots();
        Ok(())
    }

    pub fn set_sponsor_risk(&mut self, risk: SponsorRiskControl) -> Result<()> {
        ensure!(
            risk.sponsor_drawdown_bps_safe(self.config.sponsor_drawdown_bps),
            "sponsor exposure exceeds configured drawdown"
        );
        self.sponsor_risk.insert(risk.sponsor_id.clone(), risk);
        self.counters.sponsors = self.sponsor_risk.len() as u64;
        self.refresh_roots();
        Ok(())
    }

    pub fn quote_token_gas(
        &mut self,
        request: TokenGasQuoteRequest,
    ) -> Result<TokenGasQuoteRecord> {
        ensure!(
            !self.quotes.contains_key(&request.quote_id),
            "quote exists: {}",
            request.quote_id
        );
        ensure!(
            request.max_slippage_bps <= self.config.max_slippage_bps,
            "slippage too high"
        );
        ensure!(
            request.expires_at_height > self.l2_height,
            "quote already expired"
        );
        let vault = self
            .vaults
            .get(&request.vault_id)
            .ok_or_else(|| format!("unknown vault: {}", request.vault_id))?;
        ensure!(
            vault.status.accepts_escrow(),
            "vault is not accepting escrow"
        );
        let corridor = self
            .corridors
            .values()
            .find(|corridor| {
                corridor.asset_id == request.asset_id
                    && corridor.valid_until_height > self.l2_height
            })
            .ok_or_else(|| format!("no live fee corridor for asset: {}", request.asset_id))?;
        let weighted_fee = (request.gas_units as u128)
            .saturating_mul(corridor.target_fee_piconero)
            .saturating_mul(request.lane.priority_weight() as u128)
            / 1_000_000;
        let quoted_fee = weighted_fee
            .saturating_add(weighted_fee.saturating_mul(vault.spread_bps as u128) / MAX_BPS as u128)
            .clamp(vault.min_quote_piconero, vault.max_quote_piconero);
        ensure!(
            quoted_fee <= request.max_fee_piconero,
            "quote exceeds caller max fee"
        );
        let quote = TokenGasQuoteRecord {
            quote_id: request.quote_id.clone(),
            asset_amount_commitment: record_root(
                "quote_asset_amount",
                &json!({"quote_id": request.quote_id, "quoted_fee_piconero": quoted_fee.to_string()}),
            ),
            corridor_id: corridor.corridor_id.clone(),
            status: QuoteStatus::Posted,
            pq_quote_root: record_root("pq_quote", &request.public_record()),
            quoted_fee_piconero: quoted_fee,
            request,
        };
        self.quotes.insert(quote.quote_id.clone(), quote.clone());
        self.counters.quotes = self.quotes.len() as u64;
        self.refresh_roots();
        Ok(quote)
    }

    pub fn reserve_escrow(
        &mut self,
        request: CrossAssetEscrowRequest,
    ) -> Result<CrossAssetEscrowRecord> {
        ensure!(
            !self.escrows.contains_key(&request.escrow_id),
            "escrow exists: {}",
            request.escrow_id
        );
        ensure!(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "escrow privacy set below configured minimum"
        );
        ensure!(
            request.expires_at_height > self.l2_height,
            "escrow already expired"
        );
        let quote = self
            .quotes
            .get_mut(&request.quote_id)
            .ok_or_else(|| format!("unknown quote: {}", request.quote_id))?;
        ensure!(quote.status.live(), "quote is not live");
        let risk = self
            .sponsor_risk
            .get_mut(&request.sponsor_id)
            .ok_or_else(|| format!("unknown sponsor: {}", request.sponsor_id))?;
        ensure!(
            risk.risk_level.admits_new_flow(),
            "sponsor risk blocks new flow"
        );
        ensure!(
            risk.allowed_lanes.contains(&request.lane),
            "sponsor lane not allowed"
        );
        let new_exposure = risk
            .current_open_exposure_piconero
            .saturating_add(quote.quoted_fee_piconero);
        ensure!(
            new_exposure <= risk.max_open_exposure_piconero,
            "sponsor exposure cap exceeded"
        );
        quote.status = QuoteStatus::Reserved;
        risk.current_open_exposure_piconero = new_exposure;
        let attestation_id = format!("pq-attest-{}", request.escrow_id);
        let attestation = PqEscrowAttestation {
            attestation_id: attestation_id.clone(),
            escrow_id: request.escrow_id.clone(),
            quote_id: request.quote_id.clone(),
            pq_suite: PQ_ESCROW_ATTESTATION_SUITE.to_string(),
            attested_root: record_root("escrow_request", &request.public_record()),
            signer_committee_root: deterministic_root("pq_committee", &request.paymaster_id),
            min_security_bits: self.config.min_pq_security_bits,
            signature_root: deterministic_root("pq_signature", &request.escrow_id),
        };
        let escrow = CrossAssetEscrowRecord {
            escrow_id: request.escrow_id.clone(),
            reserved_fee_piconero: quote.quoted_fee_piconero,
            netted_fee_piconero: quote.quoted_fee_piconero,
            private_receipt_id: None,
            rebate_coupon_id: None,
            status: EscrowStatus::Reserved,
            attestation_id: attestation_id.clone(),
            request,
        };
        self.pq_attestations.insert(attestation_id, attestation);
        self.escrows
            .insert(escrow.escrow_id.clone(), escrow.clone());
        self.counters.escrows = self.escrows.len() as u64;
        self.counters.pq_attestations = self.pq_attestations.len() as u64;
        self.refresh_roots();
        Ok(escrow)
    }

    pub fn settle_microbatch(
        &mut self,
        batch_id: String,
        lane: GasLane,
        escrow_ids: Vec<String>,
    ) -> Result<MicrobatchGasNettingRecord> {
        ensure!(
            !self.microbatches.contains_key(&batch_id),
            "batch exists: {}",
            batch_id
        );
        ensure!(
            !escrow_ids.is_empty(),
            "microbatch requires at least one escrow"
        );
        ensure!(
            escrow_ids.len() <= self.config.microbatch_max_items,
            "microbatch exceeds configured max items"
        );
        let mut input_fee = 0_u128;
        for escrow_id in &escrow_ids {
            let escrow = self
                .escrows
                .get(escrow_id)
                .ok_or_else(|| format!("unknown escrow: {}", escrow_id))?;
            ensure!(escrow.status.active(), "escrow not active: {}", escrow_id);
            ensure!(
                escrow.request.lane == lane,
                "escrow lane mismatch: {}",
                escrow_id
            );
            input_fee = input_fee.saturating_add(escrow.reserved_fee_piconero);
        }
        let netted_fee = input_fee
            .saturating_mul((MAX_BPS - self.config.netting_discount_bps) as u128)
            / MAX_BPS as u128;
        for escrow_id in &escrow_ids {
            if let Some(escrow) = self.escrows.get_mut(escrow_id) {
                escrow.status = EscrowStatus::Netted;
                escrow.netted_fee_piconero = escrow
                    .reserved_fee_piconero
                    .saturating_mul((MAX_BPS - self.config.netting_discount_bps) as u128)
                    / MAX_BPS as u128;
            }
        }
        let batch = MicrobatchGasNettingRecord {
            batch_id: batch_id.clone(),
            lane,
            escrow_ids,
            input_fee_piconero: input_fee,
            netted_fee_piconero: netted_fee,
            discount_bps: self.config.netting_discount_bps,
            proof_root: deterministic_root("microbatch_proof", &batch_id),
            da_root: deterministic_root("microbatch_da", &batch_id),
            status: BatchStatus::Netted,
            settled_height: None,
        };
        self.microbatches.insert(batch_id, batch.clone());
        self.counters.microbatches = self.microbatches.len() as u64;
        self.refresh_roots();
        Ok(batch)
    }

    pub fn finalize_paymaster_receipt(
        &mut self,
        receipt: PrivatePaymasterReceipt,
    ) -> Result<DaProofRebateCoupon> {
        ensure!(
            !self.receipts.contains_key(&receipt.receipt_id),
            "receipt exists: {}",
            receipt.receipt_id
        );
        let escrow = self
            .escrows
            .get_mut(&receipt.escrow_id)
            .ok_or_else(|| format!("unknown escrow: {}", receipt.escrow_id))?;
        ensure!(escrow.status.active(), "escrow is not active");
        escrow.status = EscrowStatus::Settled;
        escrow.private_receipt_id = Some(receipt.receipt_id.clone());
        let coupon_id = format!("coupon-{}", receipt.receipt_id);
        let rebate = receipt
            .settled_fee_piconero
            .saturating_mul(self.config.target_rebate_bps as u128)
            / MAX_BPS as u128;
        let coupon = DaProofRebateCoupon {
            coupon_id: coupon_id.clone(),
            batch_id: receipt.operator_summary_id.clone(),
            beneficiary_commitment_root: deterministic_root(
                "rebate_beneficiary",
                &receipt.receipt_id,
            ),
            rebate_asset_id: self.config.rebate_asset_id.clone(),
            rebate_piconero: rebate,
            proof_cost_root: deterministic_root("proof_cost", &receipt.receipt_id),
            da_cost_root: deterministic_root("da_cost", &receipt.receipt_id),
            expires_at_height: self.l2_height + self.config.coupon_ttl_blocks,
            status: CouponStatus::Issued,
        };
        escrow.rebate_coupon_id = Some(coupon_id.clone());
        self.receipts.insert(receipt.receipt_id.clone(), receipt);
        self.coupons.insert(coupon_id, coupon.clone());
        self.counters.receipts = self.receipts.len() as u64;
        self.counters.coupons = self.coupons.len() as u64;
        self.counters.rebated_piconero = self
            .coupons
            .values()
            .map(|coupon| coupon.rebate_piconero)
            .sum();
        self.counters.settled_gas_units = self
            .receipts
            .values()
            .map(|receipt| receipt.gas_units as u128)
            .sum();
        self.refresh_roots();
        Ok(coupon)
    }

    pub fn publish_operator_summary(&mut self, summary: OperatorPublicSummary) -> Result<()> {
        ensure!(
            !self.public_summaries.contains_key(&summary.summary_id),
            "summary exists: {}",
            summary.summary_id
        );
        self.public_summaries
            .insert(summary.summary_id.clone(), summary);
        self.counters.public_summaries = self.public_summaries.len() as u64;
        self.refresh_roots();
        Ok(())
    }

    pub fn refresh_roots(&mut self) {
        self.roots.config_root = record_root("config", &self.config.public_record());
        self.roots.vault_root = map_root("vaults", &self.vaults, AssetGasVault::public_record);
        self.roots.quote_root =
            map_root("quotes", &self.quotes, TokenGasQuoteRecord::public_record);
        self.roots.escrow_root = map_root(
            "escrows",
            &self.escrows,
            CrossAssetEscrowRecord::public_record,
        );
        self.roots.paymaster_receipt_root = map_root(
            "receipts",
            &self.receipts,
            PrivatePaymasterReceipt::public_record,
        );
        self.roots.sponsor_risk_root = map_root(
            "sponsor_risk",
            &self.sponsor_risk,
            SponsorRiskControl::public_record,
        );
        self.roots.microbatch_root = map_root(
            "microbatches",
            &self.microbatches,
            MicrobatchGasNettingRecord::public_record,
        );
        self.roots.rebate_coupon_root =
            map_root("coupons", &self.coupons, DaProofRebateCoupon::public_record);
        self.roots.corridor_root = map_root(
            "corridors",
            &self.corridors,
            StableFeeCorridor::public_record,
        );
        self.roots.pq_attestation_root = map_root(
            "pq_attestations",
            &self.pq_attestations,
            PqEscrowAttestation::public_record,
        );
        self.roots.privacy_redaction_root = map_root(
            "redactions",
            &self.redactions,
            PrivacyRedactionRoot::public_record,
        );
        self.roots.operator_summary_root = map_root(
            "public_summaries",
            &self.public_summaries,
            OperatorPublicSummary::public_record,
        );
        self.roots.counters_root = record_root("counters", &self.counters.public_record());
        let record = self.public_record_without_state_root();
        self.roots.public_record_root = record_root("public_record", &record);
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "epoch": self.epoch,
            "hash_suite": HASH_SUITE,
            "kind": "private_l2_low_fee_pq_confidential_cross_asset_gas_escrow_runtime",
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "protocol_version": PROTOCOL_VERSION,
            "roots": self.roots.public_record(),
            "schema_version": SCHEMA_VERSION,
            "suites": {
                "confidential_escrow": CONFIDENTIAL_ESCROW_SCHEME,
                "da_proof_rebate": DA_PROOF_REBATE_SCHEME,
                "microbatch_netting": MICRO_BATCH_NETTING_SCHEME,
                "paymaster_receipt": PAYMASTER_RECEIPT_SCHEME,
                "pq_escrow_attestation": PQ_ESCROW_ATTESTATION_SUITE,
                "privacy_redaction": PRIVACY_REDACTION_SCHEME,
                "public_summary": PUBLIC_SUMMARY_SCHEME,
                "sponsor_risk": SPONSOR_RISK_SCHEME,
                "stable_fee_corridor": STABLE_FEE_CORRIDOR_SCHEME
            }
        })
    }
}

impl SponsorRiskControl {
    fn sponsor_drawdown_bps_safe(&self, max_drawdown_bps: u64) -> bool {
        if self.max_open_exposure_piconero == 0 {
            return false;
        }
        self.current_open_exposure_piconero
            .saturating_mul(MAX_BPS as u128)
            / self.max_open_exposure_piconero
            <= max_drawdown_bps as u128
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

fn seed_devnet(state: &mut State) {
    let stable_corridor = StableFeeCorridor {
        corridor_id: "corridor-pdusd-fast-defi".to_string(),
        asset_id: DEFAULT_STABLE_ASSET_ID.to_string(),
        lower_fee_piconero: 92,
        target_fee_piconero: 100,
        upper_fee_piconero: 108,
        width_bps: state.config.corridor_width_bps,
        oracle_root: deterministic_root("oracle", "pdusd-fast-defi"),
        valid_until_height: DEVNET_L2_HEIGHT + 144,
    };
    let gas_corridor = StableFeeCorridor {
        corridor_id: "corridor-pgas-contracts".to_string(),
        asset_id: DEFAULT_DEFI_GAS_ASSET_ID.to_string(),
        lower_fee_piconero: 75,
        target_fee_piconero: 82,
        upper_fee_piconero: 91,
        width_bps: state.config.corridor_width_bps,
        oracle_root: deterministic_root("oracle", "pgas-contracts"),
        valid_until_height: DEVNET_L2_HEIGHT + 144,
    };
    state
        .corridors
        .insert(stable_corridor.corridor_id.clone(), stable_corridor);
    state
        .corridors
        .insert(gas_corridor.corridor_id.clone(), gas_corridor);

    let vault = AssetGasVault {
        vault_id: "vault-pdusd-paymaster-a".to_string(),
        asset_id: DEFAULT_STABLE_ASSET_ID.to_string(),
        asset_kind: FeeAssetKind::PrivateStable,
        status: VaultStatus::Open,
        sealed_liquidity_root: deterministic_root("sealed_liquidity", "vault-pdusd-paymaster-a"),
        available_commitment_root: deterministic_root(
            "available_liquidity",
            "vault-pdusd-paymaster-a",
        ),
        min_quote_piconero: 25_000,
        max_quote_piconero: 40_000_000,
        spread_bps: 9,
        privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
        sponsor_id: "sponsor-fast-defi".to_string(),
    };
    let gas_vault = AssetGasVault {
        vault_id: "vault-pgas-contracts-b".to_string(),
        asset_id: DEFAULT_DEFI_GAS_ASSET_ID.to_string(),
        asset_kind: FeeAssetKind::ConfidentialGasToken,
        status: VaultStatus::Netting,
        sealed_liquidity_root: deterministic_root("sealed_liquidity", "vault-pgas-contracts-b"),
        available_commitment_root: deterministic_root(
            "available_liquidity",
            "vault-pgas-contracts-b",
        ),
        min_quote_piconero: 10_000,
        max_quote_piconero: 25_000_000,
        spread_bps: 7,
        privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
        sponsor_id: "sponsor-contract-cache".to_string(),
    };
    state.vaults.insert(vault.vault_id.clone(), vault);
    state.vaults.insert(gas_vault.vault_id.clone(), gas_vault);

    let mut lanes = BTreeSet::new();
    lanes.insert(GasLane::ConfidentialContract);
    lanes.insert(GasLane::DefiSwap);
    lanes.insert(GasLane::LendingVault);
    lanes.insert(GasLane::RecursiveProof);
    let risk = SponsorRiskControl {
        sponsor_id: "sponsor-fast-defi".to_string(),
        risk_level: SponsorRiskLevel::Green,
        max_open_exposure_piconero: 9_000_000_000,
        current_open_exposure_piconero: 0,
        reserve_commitment_root: deterministic_root("sponsor_reserve", "sponsor-fast-defi"),
        allowed_lanes: lanes,
        throttled_assets: BTreeSet::new(),
        last_review_height: DEVNET_L2_HEIGHT,
    };
    state.sponsor_risk.insert(risk.sponsor_id.clone(), risk);

    let mut contract_lanes = BTreeSet::new();
    contract_lanes.insert(GasLane::ConfidentialContract);
    contract_lanes.insert(GasLane::BlobDa);
    contract_lanes.insert(GasLane::RecursiveProof);
    let contract_risk = SponsorRiskControl {
        sponsor_id: "sponsor-contract-cache".to_string(),
        risk_level: SponsorRiskLevel::Watch,
        max_open_exposure_piconero: 4_500_000_000,
        current_open_exposure_piconero: 0,
        reserve_commitment_root: deterministic_root("sponsor_reserve", "sponsor-contract-cache"),
        allowed_lanes: contract_lanes,
        throttled_assets: BTreeSet::new(),
        last_review_height: DEVNET_L2_HEIGHT,
    };
    state
        .sponsor_risk
        .insert(contract_risk.sponsor_id.clone(), contract_risk);

    let quote_request = TokenGasQuoteRequest {
        quote_id: "quote-defi-0001".to_string(),
        vault_id: "vault-pdusd-paymaster-a".to_string(),
        asset_id: DEFAULT_STABLE_ASSET_ID.to_string(),
        lane: GasLane::DefiSwap,
        gas_units: 740_000,
        max_fee_piconero: 1_000_000,
        max_slippage_bps: 12,
        user_note_commitment: deterministic_root("user_note", "quote-defi-0001"),
        expires_at_height: DEVNET_L2_HEIGHT + DEFAULT_QUOTE_TTL_BLOCKS,
    };
    let quote = TokenGasQuoteRecord {
        quote_id: quote_request.quote_id.clone(),
        request: quote_request,
        quoted_fee_piconero: 518,
        asset_amount_commitment: deterministic_root("asset_amount", "quote-defi-0001"),
        corridor_id: "corridor-pdusd-fast-defi".to_string(),
        status: QuoteStatus::Reserved,
        pq_quote_root: deterministic_root("pq_quote", "quote-defi-0001"),
    };
    state.quotes.insert(quote.quote_id.clone(), quote);

    let escrow_request = CrossAssetEscrowRequest {
        escrow_id: "escrow-defi-0001".to_string(),
        quote_id: "quote-defi-0001".to_string(),
        paymaster_id: "paymaster-alpha".to_string(),
        sponsor_id: "sponsor-fast-defi".to_string(),
        lane: GasLane::DefiSwap,
        call_commitment_root: deterministic_root("call", "swap-xmr-pdusd-private"),
        sealed_asset_amount_root: deterministic_root("sealed_amount", "escrow-defi-0001"),
        nullifier_root: deterministic_root("nullifier", "escrow-defi-0001"),
        privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
        pq_public_key_root: deterministic_root("pq_key", "escrow-defi-0001"),
        expires_at_height: DEVNET_L2_HEIGHT + DEFAULT_ESCROW_TTL_BLOCKS,
    };
    let attestation = PqEscrowAttestation {
        attestation_id: "pq-attest-escrow-defi-0001".to_string(),
        escrow_id: escrow_request.escrow_id.clone(),
        quote_id: escrow_request.quote_id.clone(),
        pq_suite: PQ_ESCROW_ATTESTATION_SUITE.to_string(),
        attested_root: record_root("escrow_request", &escrow_request.public_record()),
        signer_committee_root: deterministic_root("pq_committee", "paymaster-alpha"),
        min_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        signature_root: deterministic_root("pq_signature", "escrow-defi-0001"),
    };
    state
        .pq_attestations
        .insert(attestation.attestation_id.clone(), attestation);
    let escrow = CrossAssetEscrowRecord {
        escrow_id: escrow_request.escrow_id.clone(),
        request: escrow_request,
        status: EscrowStatus::Netted,
        reserved_fee_piconero: 518,
        netted_fee_piconero: 422,
        private_receipt_id: Some("receipt-defi-0001".to_string()),
        rebate_coupon_id: Some("coupon-rebate-0001".to_string()),
        attestation_id: "pq-attest-escrow-defi-0001".to_string(),
    };
    state.escrows.insert(escrow.escrow_id.clone(), escrow);

    let redaction = PrivacyRedactionRoot {
        redaction_id: "redact-defi-0001".to_string(),
        subject_id: "receipt-defi-0001".to_string(),
        nullifier_root: deterministic_root("redaction_nullifier", "receipt-defi-0001"),
        view_tag_root: deterministic_root("view_tag", "receipt-defi-0001"),
        selective_disclosure_root: deterministic_root("selective_disclosure", "receipt-defi-0001"),
        operator_visible_fields: ["lane", "gas_units", "fee_floor", "fee_ceiling"]
            .iter()
            .map(|field| field.to_string())
            .collect(),
    };
    state
        .redactions
        .insert(redaction.redaction_id.clone(), redaction);

    let summary = OperatorPublicSummary {
        summary_id: "summary-defi-0001".to_string(),
        lane: GasLane::DefiSwap,
        asset_ids: [DEFAULT_STABLE_ASSET_ID.to_string()].into_iter().collect(),
        escrow_count: 1,
        gas_units: 740_000,
        fee_floor_piconero: 400,
        fee_ceiling_piconero: 600,
        rebate_piconero: 29,
        privacy_redaction_root: deterministic_root("summary_redaction", "summary-defi-0001"),
        settlement_root: deterministic_root("summary_settlement", "summary-defi-0001"),
    };
    state
        .public_summaries
        .insert(summary.summary_id.clone(), summary);

    let receipt = PrivatePaymasterReceipt {
        receipt_id: "receipt-defi-0001".to_string(),
        escrow_id: "escrow-defi-0001".to_string(),
        paymaster_id: "paymaster-alpha".to_string(),
        lane: GasLane::DefiSwap,
        gas_units: 740_000,
        settled_fee_piconero: 422,
        private_execution_root: deterministic_root("execution", "receipt-defi-0001"),
        redaction_root: deterministic_root("redaction", "receipt-defi-0001"),
        operator_summary_id: "summary-defi-0001".to_string(),
        finalized_height: DEVNET_L2_HEIGHT + 2,
    };
    state.receipts.insert(receipt.receipt_id.clone(), receipt);

    let batch = MicrobatchGasNettingRecord {
        batch_id: "microbatch-defi-0001".to_string(),
        lane: GasLane::DefiSwap,
        escrow_ids: vec!["escrow-defi-0001".to_string()],
        input_fee_piconero: 518,
        netted_fee_piconero: 422,
        discount_bps: DEFAULT_NETTING_DISCOUNT_BPS,
        proof_root: deterministic_root("microbatch_proof", "microbatch-defi-0001"),
        da_root: deterministic_root("microbatch_da", "microbatch-defi-0001"),
        status: BatchStatus::RebateIssued,
        settled_height: Some(DEVNET_L2_HEIGHT + 2),
    };
    state.microbatches.insert(batch.batch_id.clone(), batch);

    let coupon = DaProofRebateCoupon {
        coupon_id: "coupon-rebate-0001".to_string(),
        batch_id: "microbatch-defi-0001".to_string(),
        beneficiary_commitment_root: deterministic_root("rebate_beneficiary", "receipt-defi-0001"),
        rebate_asset_id: DEFAULT_REBATE_ASSET_ID.to_string(),
        rebate_piconero: 29,
        proof_cost_root: deterministic_root("proof_cost", "receipt-defi-0001"),
        da_cost_root: deterministic_root("da_cost", "receipt-defi-0001"),
        expires_at_height: DEVNET_L2_HEIGHT + DEFAULT_COUPON_TTL_BLOCKS,
        status: CouponStatus::Issued,
    };
    state.coupons.insert(coupon.coupon_id.clone(), coupon);

    state.counters.vaults = state.vaults.len() as u64;
    state.counters.quotes = state.quotes.len() as u64;
    state.counters.escrows = state.escrows.len() as u64;
    state.counters.receipts = state.receipts.len() as u64;
    state.counters.sponsors = state.sponsor_risk.len() as u64;
    state.counters.microbatches = state.microbatches.len() as u64;
    state.counters.coupons = state.coupons.len() as u64;
    state.counters.pq_attestations = state.pq_attestations.len() as u64;
    state.counters.redactions = state.redactions.len() as u64;
    state.counters.public_summaries = state.public_summaries.len() as u64;
    state.counters.settled_gas_units = 740_000;
    state.counters.rebated_piconero = 29;
}

fn empty_root(label: &str) -> String {
    merkle_root(
        &format!("{PROTOCOL_VERSION}:{label}:empty"),
        &[json!({"empty": true, "label": label, "protocol_version": PROTOCOL_VERSION})],
    )
}

fn deterministic_root(domain: &str, label: &str) -> String {
    domain_hash(
        &format!("{PROTOCOL_VERSION}:{domain}"),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(label)],
        32,
    )
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("{PROTOCOL_VERSION}:{domain}"),
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
            HashPart::U64(SCHEMA_VERSION),
        ],
        32,
    )
}

fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "private_l2_low_fee_pq_confidential_cross_asset_gas_escrow_state_root",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
            HashPart::U64(SCHEMA_VERSION),
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
        .map(|(id, value)| json!({"id": id, "record": public_record(value)}))
        .collect::<Vec<_>>();
    if leaves.is_empty() {
        empty_root(domain)
    } else {
        merkle_root(&format!("{PROTOCOL_VERSION}:{domain}"), &leaves)
    }
}
