use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_FEE_INTENT_NETTING_BATCH_AUCTION_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-low-fee-pq-confidential-fee-intent-netting-batch-auction-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_FEE_INTENT_NETTING_BATCH_AUCTION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-fee-intent-netting-v1";
pub const CONFIDENTIAL_INTENT_SCHEME: &str =
    "private-l2-low-fee-pq-confidential-fee-intent-envelope-v1";
pub const BATCH_AUCTION_SCHEME: &str = "private-l2-low-fee-pq-confidential-fee-batch-auction-v1";
pub const COUPON_CLEARING_SCHEME: &str = "private-l2-low-fee-pq-confidential-coupon-clearing-v1";
pub const GAS_SWAP_SCHEME: &str = "private-l2-low-fee-confidential-gas-token-swap-v1";
pub const VOUCHER_SCHEME: &str = "private-l2-low-fee-da-proof-voucher-v1";
pub const ANTI_ABUSE_SCHEME: &str = "roots-only-anti-abuse-quarantine-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str = "roots-only-fee-intent-netting-operator-summary-v1";
pub const PUBLIC_RECORD_SCHEME: &str = "roots-only-fee-intent-netting-public-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_CHAIN_ID: u64 = 731_337;
pub const DEVNET_HEIGHT: u64 = 3_181_120;
pub const DEVNET_EPOCH: u64 = 6_481;
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_REBATE_ASSET_ID: &str = "wxmr-devnet";
pub const DEFAULT_GAS_ASSET_ID: &str = "pgas-devnet";
pub const DEFAULT_QUOTE_ASSET_ID: &str = "dusd-devnet";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_INTENT_TTL_BLOCKS: u64 = 80;
pub const DEFAULT_AUCTION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 8_640;
pub const DEFAULT_COUPON_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_SWAP_TTL_BLOCKS: u64 = 120;
pub const DEFAULT_VOUCHER_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_QUARANTINE_TTL_BLOCKS: u64 = 4_320;
pub const DEFAULT_SUMMARY_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_TARGET_USER_FEE_BPS: u64 = 5;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 13;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 1_200;
pub const DEFAULT_COUPON_DISCOUNT_BPS: u64 = 2_500;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 8_750;
pub const DEFAULT_OPERATOR_FEE_BPS: u64 = 22;
pub const DEFAULT_DA_VOUCHER_COVER_BPS: u64 = 2_200;
pub const DEFAULT_PROOF_VOUCHER_COVER_BPS: u64 = 1_800;
pub const DEFAULT_WALLET_DAILY_CAP_PICONERO: u128 = 250_000_000;
pub const DEFAULT_WALLET_BATCH_CAP_PICONERO: u128 = 45_000_000;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_FEE_INTENTS: usize = 8_388_608;
pub const MAX_AUCTIONS: usize = 4_194_304;
pub const MAX_SPONSOR_CREDITS: usize = 4_194_304;
pub const MAX_COUPON_CLEARINGS: usize = 8_388_608;
pub const MAX_GAS_SWAPS: usize = 8_388_608;
pub const MAX_VOUCHERS: usize = 8_388_608;
pub const MAX_ATTESTATIONS: usize = 8_388_608;
pub const MAX_QUARANTINES: usize = 2_097_152;
pub const MAX_WALLET_CAPS: usize = 8_388_608;
pub const MAX_OPERATOR_SUMMARIES: usize = 1_048_576;
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
pub enum FeeLane {
    WalletTransfer,
    ConfidentialContractCall,
    DefiBundle,
    BlobDa,
    RecursiveProof,
    MoneroBridgeExit,
    WalletFastSync,
    EmergencyEscape,
}

impl FeeLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletTransfer => "wallet_transfer",
            Self::ConfidentialContractCall => "confidential_contract_call",
            Self::DefiBundle => "defi_bundle",
            Self::BlobDa => "blob_da",
            Self::RecursiveProof => "recursive_proof",
            Self::MoneroBridgeExit => "monero_bridge_exit",
            Self::WalletFastSync => "wallet_fast_sync",
            Self::EmergencyEscape => "emergency_escape",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyEscape => 10_000,
            Self::MoneroBridgeExit => 8_800,
            Self::DefiBundle => 7_600,
            Self::ConfidentialContractCall => 6_800,
            Self::RecursiveProof => 6_250,
            Self::BlobDa => 5_900,
            Self::WalletTransfer => 4_600,
            Self::WalletFastSync => 3_400,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Encrypted,
    Admitted,
    WalletCapChecked,
    Netted,
    AuctionQueued,
    Cleared,
    Sponsored,
    Settled,
    Quarantined,
    Expired,
}

impl IntentStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Encrypted
                | Self::Admitted
                | Self::WalletCapChecked
                | Self::Netted
                | Self::AuctionQueued
                | Self::Cleared
                | Self::Sponsored
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Open,
    Sealed,
    Netting,
    Clearing,
    CouponClearing,
    Settled,
    Disputed,
    Expired,
}

impl AuctionStatus {
    pub fn can_clear(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Sealed | Self::Netting | Self::Clearing
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorStatus {
    Pledged,
    Active,
    Reserving,
    Settling,
    Exhausted,
    Paused,
    Slashed,
    Retired,
}

impl SponsorStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Reserving | Self::Settling)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Minted,
    Reserved,
    Clearing,
    Applied,
    Recycled,
    Expired,
    Voided,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VoucherKind {
    DataAvailability,
    RecursiveProof,
    BlobInclusion,
    BridgeExit,
    OperatorBackstop,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VoucherStatus {
    Quoted,
    Reserved,
    Applied,
    Settled,
    Disputed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapStatus {
    Quoted,
    Reserved,
    Executed,
    Settled,
    Refunded,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    CapExceeded,
    DuplicateNullifier,
    SponsorAbuse,
    CouponStuffing,
    InvalidPqAttestation,
    PrivacySetTooSmall,
    FeeSpikeProbe,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub gas_asset_id: String,
    pub quote_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub epoch_blocks: u64,
    pub intent_ttl_blocks: u64,
    pub auction_ttl_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub coupon_ttl_blocks: u64,
    pub swap_ttl_blocks: u64,
    pub voucher_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub quarantine_ttl_blocks: u64,
    pub summary_ttl_blocks: u64,
    pub target_user_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub coupon_discount_bps: u64,
    pub sponsor_cover_bps: u64,
    pub operator_fee_bps: u64,
    pub da_voucher_cover_bps: u64,
    pub proof_voucher_cover_bps: u64,
    pub wallet_daily_cap_piconero: u128,
    pub wallet_batch_cap_piconero: u128,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: DEVNET_CHAIN_ID,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEFAULT_REBATE_ASSET_ID.to_string(),
            gas_asset_id: DEFAULT_GAS_ASSET_ID.to_string(),
            quote_asset_id: DEFAULT_QUOTE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            intent_ttl_blocks: DEFAULT_INTENT_TTL_BLOCKS,
            auction_ttl_blocks: DEFAULT_AUCTION_TTL_BLOCKS,
            sponsor_ttl_blocks: DEFAULT_SPONSOR_TTL_BLOCKS,
            coupon_ttl_blocks: DEFAULT_COUPON_TTL_BLOCKS,
            swap_ttl_blocks: DEFAULT_SWAP_TTL_BLOCKS,
            voucher_ttl_blocks: DEFAULT_VOUCHER_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            quarantine_ttl_blocks: DEFAULT_QUARANTINE_TTL_BLOCKS,
            summary_ttl_blocks: DEFAULT_SUMMARY_TTL_BLOCKS,
            target_user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            coupon_discount_bps: DEFAULT_COUPON_DISCOUNT_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            operator_fee_bps: DEFAULT_OPERATOR_FEE_BPS,
            da_voucher_cover_bps: DEFAULT_DA_VOUCHER_COVER_BPS,
            proof_voucher_cover_bps: DEFAULT_PROOF_VOUCHER_COVER_BPS,
            wallet_daily_cap_piconero: DEFAULT_WALLET_DAILY_CAP_PICONERO,
            wallet_batch_cap_piconero: DEFAULT_WALLET_BATCH_CAP_PICONERO,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(self.chain_id > 0, "chain id must be nonzero");
        ensure!(self.epoch_blocks > 0, "epoch blocks must be nonzero");
        ensure!(self.min_pq_security_bits >= 128, "pq security too low");
        ensure!(
            self.target_privacy_set_size >= self.min_privacy_set_size,
            "target privacy set below minimum"
        );
        ensure!(
            self.target_user_fee_bps <= self.max_user_fee_bps,
            "target fee above user cap"
        );
        ensure!(self.max_user_fee_bps <= MAX_BPS, "user fee cap above max");
        ensure!(
            self.target_rebate_bps <= MAX_BPS,
            "rebate target above max bps"
        );
        ensure!(
            self.coupon_discount_bps <= MAX_BPS,
            "coupon discount above max bps"
        );
        ensure!(
            self.sponsor_cover_bps <= MAX_BPS,
            "sponsor cover above max bps"
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "gas_asset_id": self.gas_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "epoch_blocks": self.epoch_blocks,
            "target_user_fee_bps": self.target_user_fee_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "coupon_discount_bps": self.coupon_discount_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "operator_fee_bps": self.operator_fee_bps,
            "da_voucher_cover_bps": self.da_voucher_cover_bps,
            "proof_voucher_cover_bps": self.proof_voucher_cover_bps,
            "wallet_daily_cap_piconero": self.wallet_daily_cap_piconero,
            "wallet_batch_cap_piconero": self.wallet_batch_cap_piconero,
        })
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub fee_intents: u64,
    pub netted_intents: u64,
    pub auctions_opened: u64,
    pub auctions_cleared: u64,
    pub sponsor_credits: u64,
    pub sponsor_credit_piconero: u128,
    pub coupon_clearings: u64,
    pub coupon_discount_piconero: u128,
    pub gas_swaps: u64,
    pub vouchers: u64,
    pub pq_attestations: u64,
    pub quarantines: u64,
    pub wallet_caps: u64,
    pub public_events: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "fee_intents": self.fee_intents,
            "netted_intents": self.netted_intents,
            "auctions_opened": self.auctions_opened,
            "auctions_cleared": self.auctions_cleared,
            "sponsor_credits": self.sponsor_credits,
            "sponsor_credit_piconero": self.sponsor_credit_piconero,
            "coupon_clearings": self.coupon_clearings,
            "coupon_discount_piconero": self.coupon_discount_piconero,
            "gas_swaps": self.gas_swaps,
            "vouchers": self.vouchers,
            "pq_attestations": self.pq_attestations,
            "quarantines": self.quarantines,
            "wallet_caps": self.wallet_caps,
            "public_events": self.public_events,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub fee_intents_root: String,
    pub auctions_root: String,
    pub sponsor_credits_root: String,
    pub coupon_clearings_root: String,
    pub gas_swaps_root: String,
    pub vouchers_root: String,
    pub pq_attestations_root: String,
    pub quarantines_root: String,
    pub wallet_caps_root: String,
    pub nullifier_fences_root: String,
    pub operator_summaries_root: String,
    pub public_events_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "fee_intents_root": self.fee_intents_root,
            "auctions_root": self.auctions_root,
            "sponsor_credits_root": self.sponsor_credits_root,
            "coupon_clearings_root": self.coupon_clearings_root,
            "gas_swaps_root": self.gas_swaps_root,
            "vouchers_root": self.vouchers_root,
            "pq_attestations_root": self.pq_attestations_root,
            "quarantines_root": self.quarantines_root,
            "wallet_caps_root": self.wallet_caps_root,
            "nullifier_fences_root": self.nullifier_fences_root,
            "operator_summaries_root": self.operator_summaries_root,
            "public_events_root": self.public_events_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeIntent {
    pub intent_id: String,
    pub wallet_commitment: String,
    pub encrypted_intent_root: String,
    pub lane: FeeLane,
    pub fee_budget_piconero: u128,
    pub max_fee_bps: u64,
    pub coupon_commitment: Option<String>,
    pub voucher_commitment: Option<String>,
    pub nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub status: IntentStatus,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
}

impl FeeIntent {
    pub fn new(
        config: &Config,
        lane: FeeLane,
        wallet_commitment: impl Into<String>,
        encrypted_intent_root: impl Into<String>,
        fee_budget_piconero: u128,
        nonce: u64,
    ) -> Self {
        let wallet_commitment = wallet_commitment.into();
        let encrypted_intent_root = encrypted_intent_root.into();
        let intent_id = record_id(
            "intent",
            &[
                wallet_commitment.as_str(),
                encrypted_intent_root.as_str(),
                lane.as_str(),
                &nonce.to_string(),
            ],
        );
        let nullifier = record_id(
            "nullifier",
            &[intent_id.as_str(), wallet_commitment.as_str()],
        );
        Self {
            intent_id,
            wallet_commitment,
            encrypted_intent_root,
            lane,
            fee_budget_piconero,
            max_fee_bps: config.max_user_fee_bps,
            coupon_commitment: None,
            voucher_commitment: None,
            nullifier,
            privacy_set_size: config.target_privacy_set_size,
            pq_security_bits: config.min_pq_security_bits,
            status: IntentStatus::Encrypted,
            valid_from_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT.saturating_add(config.intent_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "encrypted_intent_root": self.encrypted_intent_root,
            "lane": self.lane,
            "fee_budget_piconero": self.fee_budget_piconero,
            "max_fee_bps": self.max_fee_bps,
            "coupon_commitment": self.coupon_commitment,
            "voucher_commitment": self.voucher_commitment,
            "nullifier": self.nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BatchAuction {
    pub auction_id: String,
    pub lane: FeeLane,
    pub epoch: u64,
    pub encrypted_batch_root: String,
    pub intent_count: u64,
    pub gross_fee_piconero: u128,
    pub net_fee_piconero: u128,
    pub clearing_fee_bps: u64,
    pub sponsor_credit_piconero: u128,
    pub coupon_discount_piconero: u128,
    pub voucher_cover_piconero: u128,
    pub operator_fee_piconero: u128,
    pub status: AuctionStatus,
    pub opens_at_height: u64,
    pub closes_at_height: u64,
}

impl BatchAuction {
    pub fn new(
        config: &Config,
        lane: FeeLane,
        epoch: u64,
        encrypted_batch_root: impl Into<String>,
        nonce: u64,
    ) -> Self {
        let encrypted_batch_root = encrypted_batch_root.into();
        let auction_id = record_id(
            "auction",
            &[
                lane.as_str(),
                &epoch.to_string(),
                encrypted_batch_root.as_str(),
                &nonce.to_string(),
            ],
        );
        Self {
            auction_id,
            lane,
            epoch,
            encrypted_batch_root,
            intent_count: 0,
            gross_fee_piconero: 0,
            net_fee_piconero: 0,
            clearing_fee_bps: config.target_user_fee_bps,
            sponsor_credit_piconero: 0,
            coupon_discount_piconero: 0,
            voucher_cover_piconero: 0,
            operator_fee_piconero: 0,
            status: AuctionStatus::Open,
            opens_at_height: DEVNET_HEIGHT,
            closes_at_height: DEVNET_HEIGHT.saturating_add(config.auction_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "auction_id": self.auction_id,
            "lane": self.lane,
            "epoch": self.epoch,
            "encrypted_batch_root": self.encrypted_batch_root,
            "intent_count": self.intent_count,
            "gross_fee_piconero": self.gross_fee_piconero,
            "net_fee_piconero": self.net_fee_piconero,
            "clearing_fee_bps": self.clearing_fee_bps,
            "sponsor_credit_piconero": self.sponsor_credit_piconero,
            "coupon_discount_piconero": self.coupon_discount_piconero,
            "voucher_cover_piconero": self.voucher_cover_piconero,
            "operator_fee_piconero": self.operator_fee_piconero,
            "status": self.status,
            "opens_at_height": self.opens_at_height,
            "closes_at_height": self.closes_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorCredit {
    pub sponsor_id: String,
    pub lane: FeeLane,
    pub credit_commitment: String,
    pub available_piconero: u128,
    pub reserved_piconero: u128,
    pub cover_bps: u64,
    pub status: SponsorStatus,
    pub pq_attestation_root: String,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
}

impl SponsorCredit {
    pub fn new(
        config: &Config,
        lane: FeeLane,
        credit_commitment: impl Into<String>,
        available_piconero: u128,
        nonce: u64,
    ) -> Self {
        let credit_commitment = credit_commitment.into();
        let sponsor_id = record_id(
            "sponsor",
            &[
                lane.as_str(),
                credit_commitment.as_str(),
                &nonce.to_string(),
            ],
        );
        let pq_attestation_root =
            record_id("sponsor-pq", &[sponsor_id.as_str(), PQ_ATTESTATION_SUITE]);
        Self {
            sponsor_id,
            lane,
            credit_commitment,
            available_piconero,
            reserved_piconero: 0,
            cover_bps: config.sponsor_cover_bps,
            status: SponsorStatus::Active,
            pq_attestation_root,
            valid_from_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT.saturating_add(config.sponsor_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "lane": self.lane,
            "credit_commitment": self.credit_commitment,
            "available_piconero": self.available_piconero,
            "reserved_piconero": self.reserved_piconero,
            "cover_bps": self.cover_bps,
            "status": self.status,
            "pq_attestation_root": self.pq_attestation_root,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CouponClearing {
    pub clearing_id: String,
    pub coupon_commitment: String,
    pub auction_id: String,
    pub discount_piconero: u128,
    pub status: CouponStatus,
    pub expires_at_height: u64,
}

impl CouponClearing {
    pub fn public_record(&self) -> Value {
        json!({
            "clearing_id": self.clearing_id,
            "coupon_commitment": self.coupon_commitment,
            "auction_id": self.auction_id,
            "discount_piconero": self.discount_piconero,
            "status": self.status,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GasTokenSwap {
    pub swap_id: String,
    pub wallet_commitment: String,
    pub source_asset_id: String,
    pub gas_asset_id: String,
    pub source_amount: u128,
    pub gas_amount_piconero: u128,
    pub price_commitment: String,
    pub status: SwapStatus,
    pub expires_at_height: u64,
}

impl GasTokenSwap {
    pub fn public_record(&self) -> Value {
        json!({
            "swap_id": self.swap_id,
            "source_asset_id": self.source_asset_id,
            "gas_asset_id": self.gas_asset_id,
            "source_amount": self.source_amount,
            "gas_amount_piconero": self.gas_amount_piconero,
            "price_commitment": self.price_commitment,
            "status": self.status,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DaProofVoucher {
    pub voucher_id: String,
    pub kind: VoucherKind,
    pub lane: FeeLane,
    pub voucher_commitment: String,
    pub cover_piconero: u128,
    pub cover_bps: u64,
    pub status: VoucherStatus,
    pub expires_at_height: u64,
}

impl DaProofVoucher {
    pub fn public_record(&self) -> Value {
        json!({
            "voucher_id": self.voucher_id,
            "kind": self.kind,
            "lane": self.lane,
            "voucher_commitment": self.voucher_commitment,
            "cover_piconero": self.cover_piconero,
            "cover_bps": self.cover_bps,
            "status": self.status,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestation {
    pub attestation_id: String,
    pub subject_id: String,
    pub attester_commitment: String,
    pub attestation_root: String,
    pub pq_security_bits: u16,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
}

impl PqAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "subject_id": self.subject_id,
            "attester_commitment": self.attester_commitment,
            "attestation_root": self.attestation_root,
            "pq_security_bits": self.pq_security_bits,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuarantineRecord {
    pub quarantine_id: String,
    pub subject_id: String,
    pub reason: QuarantineReason,
    pub evidence_root: String,
    pub release_height: u64,
}

impl QuarantineRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "quarantine_id": self.quarantine_id,
            "subject_id": self.subject_id,
            "reason": self.reason,
            "evidence_root": self.evidence_root,
            "release_height": self.release_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletCap {
    pub wallet_cap_id: String,
    pub wallet_commitment: String,
    pub lane: FeeLane,
    pub daily_cap_piconero: u128,
    pub batch_cap_piconero: u128,
    pub spent_today_piconero: u128,
    pub epoch: u64,
    pub cap_root: String,
}

impl WalletCap {
    pub fn public_record(&self) -> Value {
        json!({
            "wallet_cap_id": self.wallet_cap_id,
            "lane": self.lane,
            "daily_cap_piconero": self.daily_cap_piconero,
            "batch_cap_piconero": self.batch_cap_piconero,
            "spent_today_piconero": self.spent_today_piconero,
            "epoch": self.epoch,
            "cap_root": self.cap_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub lane: FeeLane,
    pub live_intents: u64,
    pub cleared_auctions: u64,
    pub gross_fee_piconero: u128,
    pub net_fee_piconero: u128,
    pub sponsor_credit_piconero: u128,
    pub coupon_discount_piconero: u128,
    pub voucher_cover_piconero: u128,
    pub quarantined_subjects: u64,
    pub summary_root: String,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "operator_id": self.operator_id,
            "epoch": self.epoch,
            "lane": self.lane,
            "live_intents": self.live_intents,
            "cleared_auctions": self.cleared_auctions,
            "gross_fee_piconero": self.gross_fee_piconero,
            "net_fee_piconero": self.net_fee_piconero,
            "sponsor_credit_piconero": self.sponsor_credit_piconero,
            "coupon_discount_piconero": self.coupon_discount_piconero,
            "voucher_cover_piconero": self.voucher_cover_piconero,
            "quarantined_subjects": self.quarantined_subjects,
            "summary_root": self.summary_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicEvent {
    pub event_id: String,
    pub kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub state_root: String,
    pub sequence: u64,
}

impl PublicEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "state_root": self.state_root,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub fee_intents: BTreeMap<String, FeeIntent>,
    pub auctions: BTreeMap<String, BatchAuction>,
    pub sponsor_credits: BTreeMap<String, SponsorCredit>,
    pub coupon_clearings: BTreeMap<String, CouponClearing>,
    pub gas_swaps: BTreeMap<String, GasTokenSwap>,
    pub vouchers: BTreeMap<String, DaProofVoucher>,
    pub pq_attestations: BTreeMap<String, PqAttestation>,
    pub quarantines: BTreeMap<String, QuarantineRecord>,
    pub wallet_caps: BTreeMap<String, WalletCap>,
    pub nullifier_fences: BTreeSet<String>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub public_events: Vec<PublicEvent>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            height: DEVNET_HEIGHT,
            epoch: DEVNET_EPOCH,
            counters: Counters::default(),
            roots: Roots::default(),
            fee_intents: BTreeMap::new(),
            auctions: BTreeMap::new(),
            sponsor_credits: BTreeMap::new(),
            coupon_clearings: BTreeMap::new(),
            gas_swaps: BTreeMap::new(),
            vouchers: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            quarantines: BTreeMap::new(),
            wallet_caps: BTreeMap::new(),
            nullifier_fences: BTreeSet::new(),
            operator_summaries: BTreeMap::new(),
            public_events: Vec::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let intent = FeeIntent::new(
            &state.config,
            FeeLane::WalletTransfer,
            "wallet:commitment:devnet:0",
            "enc-intent-root-devnet-0",
            20_000_000,
            0,
        );
        let auction = BatchAuction::new(
            &state.config,
            FeeLane::WalletTransfer,
            DEVNET_EPOCH,
            "enc-fee-batch-root-devnet-0",
            0,
        );
        let auction_id = auction.auction_id.clone();
        let sponsor = SponsorCredit::new(
            &state.config,
            FeeLane::WalletTransfer,
            "sponsor-credit-commitment-devnet-0",
            500_000_000,
            0,
        );
        let _ = state.register_sponsor_credit(sponsor);
        let _ = state.admit_fee_intent(intent);
        let _ = state.open_batch_auction(auction);
        let _ = state.record_wallet_cap(
            "wallet:commitment:devnet:0",
            FeeLane::WalletTransfer,
            20_000_000,
        );
        let _ = state.reserve_gas_swap(
            "wallet:commitment:devnet:0",
            DEFAULT_REBATE_ASSET_ID,
            24_000_000,
            20_000_000,
            "price-root-devnet-0",
        );
        let _ = state.issue_coupon_clearing(
            "coupon-commitment-devnet-0",
            auction_id.as_str(),
            2_000_000,
        );
        let _ = state.issue_voucher(
            VoucherKind::DataAvailability,
            FeeLane::WalletTransfer,
            "voucher-commitment-devnet-0",
            1_200_000,
        );
        let _ = state.record_pq_attestation(
            "wallet-attestation-subject-devnet-0",
            "attester-commitment-devnet-0",
            "pq-attestation-root-devnet-0",
        );
        let _ = state.net_and_clear_auction(auction_id.as_str());
        let _ =
            state.publish_operator_summary("operator:devnet:fee-netting", FeeLane::WalletTransfer);
        state.refresh_roots();
        state
    }

    pub fn admit_fee_intent(&mut self, mut intent: FeeIntent) -> Result<String> {
        self.config.validate()?;
        ensure!(
            self.fee_intents.len() < MAX_FEE_INTENTS,
            "fee intent capacity reached"
        );
        ensure!(
            intent.pq_security_bits >= self.config.min_pq_security_bits,
            "fee intent pq security below minimum"
        );
        ensure!(
            intent.privacy_set_size >= self.config.min_privacy_set_size,
            "fee intent privacy set below minimum"
        );
        ensure!(
            !self.nullifier_fences.contains(&intent.nullifier),
            "fee intent duplicate nullifier"
        );
        intent.status = IntentStatus::Admitted;
        let intent_id = intent.intent_id.clone();
        let nullifier = intent.nullifier.clone();
        self.fee_intents.insert(intent_id.clone(), intent);
        self.nullifier_fences.insert(nullifier);
        self.counters.fee_intents = self.counters.fee_intents.saturating_add(1);
        self.note_event("fee_intent_admitted", &intent_id);
        self.refresh_roots();
        Ok(self.state_root())
    }

    pub fn open_batch_auction(&mut self, auction: BatchAuction) -> Result<String> {
        ensure!(
            self.auctions.len() < MAX_AUCTIONS,
            "auction capacity reached"
        );
        let auction_id = auction.auction_id.clone();
        self.auctions.insert(auction_id.clone(), auction);
        self.counters.auctions_opened = self.counters.auctions_opened.saturating_add(1);
        self.note_event("batch_auction_opened", &auction_id);
        self.refresh_roots();
        Ok(self.state_root())
    }

    pub fn register_sponsor_credit(&mut self, sponsor: SponsorCredit) -> Result<String> {
        ensure!(
            self.sponsor_credits.len() < MAX_SPONSOR_CREDITS,
            "sponsor credit capacity reached"
        );
        ensure!(sponsor.status.usable(), "sponsor credit not usable");
        let sponsor_id = sponsor.sponsor_id.clone();
        self.counters.sponsor_credits = self.counters.sponsor_credits.saturating_add(1);
        self.counters.sponsor_credit_piconero = self
            .counters
            .sponsor_credit_piconero
            .saturating_add(sponsor.available_piconero);
        self.sponsor_credits.insert(sponsor_id.clone(), sponsor);
        self.note_event("sponsor_credit_registered", &sponsor_id);
        self.refresh_roots();
        Ok(self.state_root())
    }

    pub fn issue_coupon_clearing(
        &mut self,
        coupon_commitment: impl Into<String>,
        auction_id: impl Into<String>,
        face_value_piconero: u128,
    ) -> Result<String> {
        ensure!(
            self.coupon_clearings.len() < MAX_COUPON_CLEARINGS,
            "coupon clearing capacity reached"
        );
        let coupon_commitment = coupon_commitment.into();
        let auction_id = auction_id.into();
        let discount_piconero = bps_amount(face_value_piconero, self.config.coupon_discount_bps);
        let clearing_id = record_id("coupon", &[coupon_commitment.as_str(), auction_id.as_str()]);
        let clearing = CouponClearing {
            clearing_id: clearing_id.clone(),
            coupon_commitment,
            auction_id,
            discount_piconero,
            status: CouponStatus::Reserved,
            expires_at_height: self.height.saturating_add(self.config.coupon_ttl_blocks),
        };
        self.coupon_clearings.insert(clearing_id.clone(), clearing);
        self.counters.coupon_clearings = self.counters.coupon_clearings.saturating_add(1);
        self.counters.coupon_discount_piconero = self
            .counters
            .coupon_discount_piconero
            .saturating_add(discount_piconero);
        self.note_event("coupon_clearing_reserved", &clearing_id);
        self.refresh_roots();
        Ok(self.state_root())
    }

    pub fn reserve_gas_swap(
        &mut self,
        wallet_commitment: impl Into<String>,
        source_asset_id: impl Into<String>,
        source_amount: u128,
        gas_amount_piconero: u128,
        price_commitment: impl Into<String>,
    ) -> Result<String> {
        ensure!(
            self.gas_swaps.len() < MAX_GAS_SWAPS,
            "gas swap capacity reached"
        );
        let wallet_commitment = wallet_commitment.into();
        let source_asset_id = source_asset_id.into();
        let price_commitment = price_commitment.into();
        let swap_id = record_id(
            "gas-swap",
            &[
                wallet_commitment.as_str(),
                source_asset_id.as_str(),
                price_commitment.as_str(),
            ],
        );
        let swap = GasTokenSwap {
            swap_id: swap_id.clone(),
            wallet_commitment,
            source_asset_id,
            gas_asset_id: self.config.gas_asset_id.clone(),
            source_amount,
            gas_amount_piconero,
            price_commitment,
            status: SwapStatus::Reserved,
            expires_at_height: self.height.saturating_add(self.config.swap_ttl_blocks),
        };
        self.gas_swaps.insert(swap_id.clone(), swap);
        self.counters.gas_swaps = self.counters.gas_swaps.saturating_add(1);
        self.note_event("gas_swap_reserved", &swap_id);
        self.refresh_roots();
        Ok(self.state_root())
    }

    pub fn issue_voucher(
        &mut self,
        kind: VoucherKind,
        lane: FeeLane,
        voucher_commitment: impl Into<String>,
        cover_piconero: u128,
    ) -> Result<String> {
        ensure!(
            self.vouchers.len() < MAX_VOUCHERS,
            "voucher capacity reached"
        );
        let voucher_commitment = voucher_commitment.into();
        let voucher_id = record_id("voucher", &[lane.as_str(), voucher_commitment.as_str()]);
        let cover_bps = match kind {
            VoucherKind::DataAvailability | VoucherKind::BlobInclusion => {
                self.config.da_voucher_cover_bps
            }
            VoucherKind::RecursiveProof => self.config.proof_voucher_cover_bps,
            VoucherKind::BridgeExit | VoucherKind::OperatorBackstop => {
                self.config.sponsor_cover_bps
            }
        };
        let voucher = DaProofVoucher {
            voucher_id: voucher_id.clone(),
            kind,
            lane,
            voucher_commitment,
            cover_piconero,
            cover_bps,
            status: VoucherStatus::Reserved,
            expires_at_height: self.height.saturating_add(self.config.voucher_ttl_blocks),
        };
        self.vouchers.insert(voucher_id.clone(), voucher);
        self.counters.vouchers = self.counters.vouchers.saturating_add(1);
        self.note_event("da_proof_voucher_reserved", &voucher_id);
        self.refresh_roots();
        Ok(self.state_root())
    }

    pub fn record_pq_attestation(
        &mut self,
        subject_id: impl Into<String>,
        attester_commitment: impl Into<String>,
        attestation_root: impl Into<String>,
    ) -> Result<String> {
        ensure!(
            self.pq_attestations.len() < MAX_ATTESTATIONS,
            "pq attestation capacity reached"
        );
        let subject_id = subject_id.into();
        let attester_commitment = attester_commitment.into();
        let attestation_root = attestation_root.into();
        let attestation_id = record_id(
            "pq-attestation",
            &[
                subject_id.as_str(),
                attester_commitment.as_str(),
                attestation_root.as_str(),
            ],
        );
        let attestation = PqAttestation {
            attestation_id: attestation_id.clone(),
            subject_id,
            attester_commitment,
            attestation_root,
            pq_security_bits: self.config.min_pq_security_bits,
            valid_from_height: self.height,
            expires_at_height: self
                .height
                .saturating_add(self.config.attestation_ttl_blocks),
        };
        self.pq_attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.pq_attestations = self.counters.pq_attestations.saturating_add(1);
        self.note_event("pq_attestation_recorded", &attestation_id);
        self.refresh_roots();
        Ok(self.state_root())
    }

    pub fn record_wallet_cap(
        &mut self,
        wallet_commitment: impl Into<String>,
        lane: FeeLane,
        spent_today_piconero: u128,
    ) -> Result<String> {
        ensure!(
            self.wallet_caps.len() < MAX_WALLET_CAPS,
            "wallet cap capacity reached"
        );
        let wallet_commitment = wallet_commitment.into();
        ensure!(
            spent_today_piconero <= self.config.wallet_daily_cap_piconero,
            "wallet daily cap exceeded"
        );
        ensure!(
            spent_today_piconero <= self.config.wallet_batch_cap_piconero,
            "wallet batch cap exceeded"
        );
        let wallet_cap_id = record_id(
            "wallet-cap",
            &[
                wallet_commitment.as_str(),
                lane.as_str(),
                &self.epoch.to_string(),
            ],
        );
        let cap_root = record_id(
            "wallet-cap-root",
            &[wallet_cap_id.as_str(), ANTI_ABUSE_SCHEME],
        );
        let cap = WalletCap {
            wallet_cap_id: wallet_cap_id.clone(),
            wallet_commitment,
            lane,
            daily_cap_piconero: self.config.wallet_daily_cap_piconero,
            batch_cap_piconero: self.config.wallet_batch_cap_piconero,
            spent_today_piconero,
            epoch: self.epoch,
            cap_root,
        };
        self.wallet_caps.insert(wallet_cap_id.clone(), cap);
        self.counters.wallet_caps = self.counters.wallet_caps.saturating_add(1);
        self.note_event("wallet_cap_recorded", &wallet_cap_id);
        self.refresh_roots();
        Ok(self.state_root())
    }

    pub fn quarantine_subject(
        &mut self,
        subject_id: impl Into<String>,
        reason: QuarantineReason,
        evidence_root: impl Into<String>,
    ) -> Result<String> {
        ensure!(
            self.quarantines.len() < MAX_QUARANTINES,
            "quarantine capacity reached"
        );
        let subject_id = subject_id.into();
        let evidence_root = evidence_root.into();
        let quarantine_id = record_id("quarantine", &[subject_id.as_str(), evidence_root.as_str()]);
        let quarantine = QuarantineRecord {
            quarantine_id: quarantine_id.clone(),
            subject_id: subject_id.clone(),
            reason,
            evidence_root,
            release_height: self
                .height
                .saturating_add(self.config.quarantine_ttl_blocks),
        };
        if let Some(intent) = self.fee_intents.get_mut(&subject_id) {
            intent.status = IntentStatus::Quarantined;
        }
        self.quarantines.insert(quarantine_id.clone(), quarantine);
        self.counters.quarantines = self.counters.quarantines.saturating_add(1);
        self.note_event("anti_abuse_quarantine_recorded", &quarantine_id);
        self.refresh_roots();
        Ok(self.state_root())
    }

    pub fn net_and_clear_auction(&mut self, auction_id: &str) -> Result<String> {
        let auction_snapshot = self
            .auctions
            .get(auction_id)
            .cloned()
            .ok_or_else(|| format!("unknown auction {auction_id}"))?;
        ensure!(auction_snapshot.status.can_clear(), "auction cannot clear");

        let matching_intents: Vec<String> = self
            .fee_intents
            .iter()
            .filter(|(_, intent)| intent.lane == auction_snapshot.lane && intent.status.live())
            .map(|(intent_id, _)| intent_id.clone())
            .collect();
        ensure!(!matching_intents.is_empty(), "auction has no live intents");

        let gross_fee = matching_intents
            .iter()
            .filter_map(|intent_id| self.fee_intents.get(intent_id))
            .fold(0u128, |acc, intent| {
                acc.saturating_add(intent.fee_budget_piconero)
            });
        let sponsor_cover = self.reserve_sponsor_credit(auction_snapshot.lane, gross_fee);
        let coupon_discount = self
            .coupon_clearings
            .values()
            .filter(|coupon| {
                coupon.auction_id == auction_id && coupon.status == CouponStatus::Reserved
            })
            .fold(0u128, |acc, coupon| {
                acc.saturating_add(coupon.discount_piconero)
            });
        let voucher_cover = self
            .vouchers
            .values()
            .filter(|voucher| {
                voucher.lane == auction_snapshot.lane && voucher.status == VoucherStatus::Reserved
            })
            .fold(0u128, |acc, voucher| {
                acc.saturating_add(voucher.cover_piconero)
            });
        let operator_fee = bps_amount(gross_fee, self.config.operator_fee_bps);
        let net_fee = gross_fee
            .saturating_sub(sponsor_cover)
            .saturating_sub(coupon_discount)
            .saturating_sub(voucher_cover)
            .saturating_add(operator_fee);

        for intent_id in &matching_intents {
            if let Some(intent) = self.fee_intents.get_mut(intent_id) {
                intent.status = IntentStatus::Cleared;
            }
        }
        for coupon in self.coupon_clearings.values_mut() {
            if coupon.auction_id == auction_id && coupon.status == CouponStatus::Reserved {
                coupon.status = CouponStatus::Applied;
            }
        }
        for voucher in self.vouchers.values_mut() {
            if voucher.lane == auction_snapshot.lane && voucher.status == VoucherStatus::Reserved {
                voucher.status = VoucherStatus::Applied;
            }
        }
        if let Some(auction) = self.auctions.get_mut(auction_id) {
            auction.status = AuctionStatus::Settled;
            auction.intent_count = matching_intents.len() as u64;
            auction.gross_fee_piconero = gross_fee;
            auction.net_fee_piconero = net_fee;
            auction.sponsor_credit_piconero = sponsor_cover;
            auction.coupon_discount_piconero = coupon_discount;
            auction.voucher_cover_piconero = voucher_cover;
            auction.operator_fee_piconero = operator_fee;
            auction.clearing_fee_bps = self.config.target_user_fee_bps;
        }
        self.counters.netted_intents = self
            .counters
            .netted_intents
            .saturating_add(matching_intents.len() as u64);
        self.counters.auctions_cleared = self.counters.auctions_cleared.saturating_add(1);
        self.note_event("batch_auction_cleared", auction_id);
        self.refresh_roots();
        Ok(self.state_root())
    }

    pub fn publish_operator_summary(
        &mut self,
        operator_id: impl Into<String>,
        lane: FeeLane,
    ) -> Result<String> {
        ensure!(
            self.operator_summaries.len() < MAX_OPERATOR_SUMMARIES,
            "operator summary capacity reached"
        );
        let operator_id = operator_id.into();
        let lane_auctions: Vec<&BatchAuction> = self
            .auctions
            .values()
            .filter(|auction| auction.lane == lane)
            .collect();
        let live_intents = self
            .fee_intents
            .values()
            .filter(|intent| intent.lane == lane && intent.status.live())
            .count() as u64;
        let cleared_auctions = lane_auctions
            .iter()
            .filter(|auction| auction.status == AuctionStatus::Settled)
            .count() as u64;
        let gross_fee_piconero = lane_auctions.iter().fold(0u128, |acc, auction| {
            acc.saturating_add(auction.gross_fee_piconero)
        });
        let net_fee_piconero = lane_auctions.iter().fold(0u128, |acc, auction| {
            acc.saturating_add(auction.net_fee_piconero)
        });
        let sponsor_credit_piconero = lane_auctions.iter().fold(0u128, |acc, auction| {
            acc.saturating_add(auction.sponsor_credit_piconero)
        });
        let coupon_discount_piconero = lane_auctions.iter().fold(0u128, |acc, auction| {
            acc.saturating_add(auction.coupon_discount_piconero)
        });
        let voucher_cover_piconero = lane_auctions.iter().fold(0u128, |acc, auction| {
            acc.saturating_add(auction.voucher_cover_piconero)
        });
        let quarantined_subjects = self.quarantines.len() as u64;
        let summary_id = record_id(
            "operator-summary",
            &[operator_id.as_str(), lane.as_str(), &self.epoch.to_string()],
        );
        let summary_root = self.record_root(
            "operator-summary",
            &json!({
                "operator_id": operator_id,
                "epoch": self.epoch,
                "lane": lane,
                "live_intents": live_intents,
                "cleared_auctions": cleared_auctions,
                "gross_fee_piconero": gross_fee_piconero,
                "net_fee_piconero": net_fee_piconero,
                "sponsor_credit_piconero": sponsor_credit_piconero,
                "coupon_discount_piconero": coupon_discount_piconero,
                "voucher_cover_piconero": voucher_cover_piconero,
                "quarantined_subjects": quarantined_subjects,
            }),
        );
        let summary = OperatorSummary {
            summary_id: summary_id.clone(),
            operator_id,
            epoch: self.epoch,
            lane,
            live_intents,
            cleared_auctions,
            gross_fee_piconero,
            net_fee_piconero,
            sponsor_credit_piconero,
            coupon_discount_piconero,
            voucher_cover_piconero,
            quarantined_subjects,
            summary_root,
        };
        self.operator_summaries.insert(summary_id.clone(), summary);
        self.note_event("operator_summary_published", &summary_id);
        self.refresh_roots();
        Ok(self.state_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "scheme": PUBLIC_RECORD_SCHEME,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_attestation_suite": PQ_ATTESTATION_SUITE,
            "schemes": {
                "confidential_intent": CONFIDENTIAL_INTENT_SCHEME,
                "batch_auction": BATCH_AUCTION_SCHEME,
                "coupon_clearing": COUPON_CLEARING_SCHEME,
                "gas_swap": GAS_SWAP_SCHEME,
                "voucher": VOUCHER_SCHEME,
                "anti_abuse": ANTI_ABUSE_SCHEME,
                "operator_summary": OPERATOR_SUMMARY_SCHEME,
            },
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn refresh_roots(&mut self) {
        self.roots.fee_intents_root = map_root("fee_intents", &self.fee_intents);
        self.roots.auctions_root = map_root("auctions", &self.auctions);
        self.roots.sponsor_credits_root = map_root("sponsor_credits", &self.sponsor_credits);
        self.roots.coupon_clearings_root = map_root("coupon_clearings", &self.coupon_clearings);
        self.roots.gas_swaps_root = map_root("gas_swaps", &self.gas_swaps);
        self.roots.vouchers_root = map_root("vouchers", &self.vouchers);
        self.roots.pq_attestations_root = map_root("pq_attestations", &self.pq_attestations);
        self.roots.quarantines_root = map_root("quarantines", &self.quarantines);
        self.roots.wallet_caps_root = map_root("wallet_caps", &self.wallet_caps);
        self.roots.nullifier_fences_root = set_root("nullifier_fences", &self.nullifier_fences);
        self.roots.operator_summaries_root =
            map_root("operator_summaries", &self.operator_summaries);
        self.roots.public_events_root = vec_root("public_events", &self.public_events);
        self.roots.state_root = domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-INTENT-NETTING-BATCH-AUCTION:STATE",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(SCHEMA_VERSION),
                HashPart::U64(self.config.chain_id),
                HashPart::U64(self.height),
                HashPart::U64(self.epoch),
                HashPart::Str(&self.roots.fee_intents_root),
                HashPart::Str(&self.roots.auctions_root),
                HashPart::Str(&self.roots.sponsor_credits_root),
                HashPart::Str(&self.roots.coupon_clearings_root),
                HashPart::Str(&self.roots.gas_swaps_root),
                HashPart::Str(&self.roots.vouchers_root),
                HashPart::Str(&self.roots.pq_attestations_root),
                HashPart::Str(&self.roots.quarantines_root),
                HashPart::Str(&self.roots.wallet_caps_root),
                HashPart::Str(&self.roots.nullifier_fences_root),
                HashPart::Str(&self.roots.operator_summaries_root),
                HashPart::Str(&self.roots.public_events_root),
            ],
            32,
        );
    }

    fn reserve_sponsor_credit(&mut self, lane: FeeLane, gross_fee: u128) -> u128 {
        let target_cover = bps_amount(gross_fee, self.config.sponsor_cover_bps);
        let mut remaining = target_cover;
        let mut reserved = 0u128;
        for sponsor in self
            .sponsor_credits
            .values_mut()
            .filter(|sponsor| sponsor.lane == lane && sponsor.status.usable())
        {
            if remaining == 0 {
                break;
            }
            let spendable = sponsor
                .available_piconero
                .saturating_sub(sponsor.reserved_piconero);
            let take = spendable.min(remaining);
            sponsor.reserved_piconero = sponsor.reserved_piconero.saturating_add(take);
            remaining = remaining.saturating_sub(take);
            reserved = reserved.saturating_add(take);
            sponsor.status = SponsorStatus::Reserving;
        }
        reserved
    }

    fn record_root(&self, domain: &str, value: &Value) -> String {
        domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-INTENT-NETTING-BATCH-AUCTION:RECORD",
            &[
                HashPart::Str(domain),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(self.config.chain_id),
                HashPart::U64(self.height),
                HashPart::U64(self.epoch),
                HashPart::Str(&canonical_value(value)),
            ],
            32,
        )
    }

    fn note_event(&mut self, kind: &str, subject_id: &str) {
        if self.public_events.len() >= MAX_PUBLIC_EVENTS {
            return;
        }
        let subject_root = self.record_root(kind, &json!({ "subject_id": subject_id }));
        let event_id = record_id(
            "event",
            &[kind, subject_id, &self.public_events.len().to_string()],
        );
        let event = PublicEvent {
            event_id,
            kind: kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root,
            state_root: self.state_root(),
            sequence: self.public_events.len() as u64,
        };
        self.public_events.push(event);
        self.counters.public_events = self.counters.public_events.saturating_add(1);
    }
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

pub fn devnet() -> Runtime {
    State::devnet()
}

pub fn demo() -> Runtime {
    State::demo()
}

pub fn state_root() -> String {
    demo().state_root()
}

fn bps_amount(amount: u128, bps: u64) -> u128 {
    amount.saturating_mul(bps as u128) / MAX_BPS as u128
}

fn record_id(domain: &str, parts: &[&str]) -> String {
    let leaves = parts
        .iter()
        .enumerate()
        .map(|(index, part)| {
            domain_hash(
                "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-INTENT-NETTING-BATCH-AUCTION:ID-PART",
                &[
                    HashPart::Str(domain),
                    HashPart::U64(index as u64),
                    HashPart::Str(part),
                ],
                16,
            )
        })
        .collect::<Vec<_>>();
    let leaves = leaves.into_iter().map(Value::String).collect::<Vec<_>>();
    let root = merkle_root(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-INTENT-NETTING-BATCH-AUCTION:ID",
        &leaves,
    );
    format!("{domain}-{}", &root[..16])
}

fn map_root<T: Serialize>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| {
            domain_hash(
                "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-INTENT-NETTING-BATCH-AUCTION:MAP",
                &[
                    HashPart::Str(domain),
                    HashPart::Str(key),
                    HashPart::Str(&canonical(value)),
                ],
                32,
            )
        })
        .collect::<Vec<_>>();
    let leaves = leaves.into_iter().map(Value::String).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| {
            domain_hash(
                "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-INTENT-NETTING-BATCH-AUCTION:SET",
                &[HashPart::Str(domain), HashPart::Str(value)],
                32,
            )
        })
        .collect::<Vec<_>>();
    let leaves = leaves.into_iter().map(Value::String).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn vec_root<T: Serialize>(domain: &str, values: &[T]) -> String {
    let leaves = values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            domain_hash(
                "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-INTENT-NETTING-BATCH-AUCTION:VEC",
                &[
                    HashPart::Str(domain),
                    HashPart::U64(index as u64),
                    HashPart::Str(&canonical(value)),
                ],
                32,
            )
        })
        .collect::<Vec<_>>();
    let leaves = leaves.into_iter().map(Value::String).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn canonical<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".to_string())
}

fn canonical_value(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".to_string())
}
