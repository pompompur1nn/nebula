use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_FEE_TOKEN_SWAP_PAYMASTER_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-low-fee-pq-confidential-fee-token-swap-paymaster-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_FEE_TOKEN_SWAP_PAYMASTER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_APPROVAL_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-fee-token-paymaster-v1";
pub const CONFIDENTIAL_FEE_COMMITMENT_SUITE: &str =
    "private-l2-confidential-fee-token-commitment-v1";
pub const PAYMASTER_POLICY_SUITE: &str = "private-l2-paymaster-route-policy-root-v1";
pub const SWAP_QUOTE_SUITE: &str = "low-fee-confidential-fee-token-piconero-swap-quote-v1";
pub const HEDGE_NOTE_SUITE: &str = "paymaster-private-fee-token-hedge-note-v1";
pub const REBATE_COUPON_SUITE: &str = "sponsor-private-fee-rebate-coupon-v1";
pub const VOUCHER_SUITE: &str = "da-proof-fee-voucher-root-v1";
pub const PRIVACY_FENCE_SUITE: &str = "roots-only-nullifier-fence-v1";
pub const PUBLIC_RECORD_SUITE: &str = "roots-only-public-record-v1";
pub const DEFAULT_NATIVE_FEE_ASSET: &str = "piconero-devnet";
pub const DEFAULT_PRIVATE_STABLE_ASSET: &str = "pdusd-devnet";
pub const DEFAULT_PRIVATE_FEE_TOKEN: &str = "pfee-devnet";
pub const DEFAULT_REBATE_ASSET: &str = "rebate-credit-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_044_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_742_000;
pub const DEVNET_EPOCH: u64 = 9_601;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 16;
pub const DEFAULT_MAX_SLIPPAGE_BPS: u64 = 35;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 8;
pub const DEFAULT_PAYMASTER_SPREAD_BPS: u64 = 10;
pub const DEFAULT_HEDGE_RESERVE_BPS: u64 = 1_500;
pub const DEFAULT_MIN_PAYMASTER_LIQUIDITY_PICONERO: u128 = 25_000_000_000;
pub const DEFAULT_INTENT_TTL_BLOCKS: u64 = 36;
pub const DEFAULT_QUOTE_TTL_BLOCKS: u64 = 18;
pub const DEFAULT_APPROVAL_TTL_BLOCKS: u64 = 64;
pub const DEFAULT_VOUCHER_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_HEDGE_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 4_320;
pub const DEFAULT_MAX_ROUTE_HOPS: usize = 4;
pub const DEFAULT_MAX_BATCH_ITEMS: usize = 2_048;
pub const DEFAULT_PROOF_FEE_SHARE_BPS: u64 = 3_000;
pub const DEFAULT_DA_FEE_SHARE_BPS: u64 = 2_500;
pub const DEFAULT_SPONSOR_REBATE_SHARE_BPS: u64 = 2_000;
pub const DEFAULT_PAYMASTER_RETAINED_SHARE_BPS: u64 = 2_500;
pub const MAX_FEE_TOKENS: usize = 1_048_576;
pub const MAX_PAYMASTERS: usize = 1_048_576;
pub const MAX_SWAP_QUOTES: usize = 4_194_304;
pub const MAX_FEE_INTENTS: usize = 8_388_608;
pub const MAX_ROUTE_PLANS: usize = 8_388_608;
pub const MAX_PQ_APPROVALS: usize = 8_388_608;
pub const MAX_EXECUTION_RECEIPTS: usize = 8_388_608;
pub const MAX_REBATE_COUPONS: usize = 8_388_608;
pub const MAX_VOUCHERS: usize = 8_388_608;
pub const MAX_HEDGE_POSITIONS: usize = 4_194_304;
pub const MAX_SETTLEMENT_BATCHES: usize = 4_194_304;
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
pub enum FeeAssetKind {
    NativePiconero,
    PrivateFeeToken,
    PrivateStable,
    ConfidentialLpShare,
    SponsorCredit,
    RebateCoupon,
    DaProofVoucher,
}

impl FeeAssetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NativePiconero => "native_piconero",
            Self::PrivateFeeToken => "private_fee_token",
            Self::PrivateStable => "private_stable",
            Self::ConfidentialLpShare => "confidential_lp_share",
            Self::SponsorCredit => "sponsor_credit",
            Self::RebateCoupon => "rebate_coupon",
            Self::DaProofVoucher => "da_proof_voucher",
        }
    }

    pub fn is_private_payment(self) -> bool {
        matches!(
            self,
            Self::PrivateFeeToken
                | Self::PrivateStable
                | Self::ConfidentialLpShare
                | Self::SponsorCredit
                | Self::RebateCoupon
                | Self::DaProofVoucher
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteLane {
    WalletTransfer,
    ContractCall,
    DefiBundle,
    BridgeExit,
    RecursiveProof,
    BlobDa,
    FastSync,
    EmergencyEscape,
}

impl RouteLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletTransfer => "wallet_transfer",
            Self::ContractCall => "contract_call",
            Self::DefiBundle => "defi_bundle",
            Self::BridgeExit => "bridge_exit",
            Self::RecursiveProof => "recursive_proof",
            Self::BlobDa => "blob_da",
            Self::FastSync => "fast_sync",
            Self::EmergencyEscape => "emergency_escape",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::WalletTransfer => 2,
            Self::ContractCall => 4,
            Self::DefiBundle => 7,
            Self::BridgeExit => 8,
            Self::RecursiveProof => 6,
            Self::BlobDa => 5,
            Self::FastSync => 3,
            Self::EmergencyEscape => 10,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymasterStatus {
    Registered,
    Active,
    Routing,
    Hedging,
    Settling,
    Exhausted,
    Paused,
    Retired,
    Slashed,
}

impl PaymasterStatus {
    pub fn usable(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Routing | Self::Hedging | Self::Settling
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Open,
    Reserved,
    Filled,
    Expired,
    Cancelled,
    SlippageRejected,
}

impl QuoteStatus {
    pub fn live(self) -> bool {
        matches!(self, Self::Open | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Submitted,
    Quoted,
    Approved,
    Routed,
    Executed,
    Rebated,
    Settled,
    Expired,
    Rejected,
}

impl IntentStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::Quoted | Self::Approved | Self::Routed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Proposed,
    Verified,
    Consumed,
    Expired,
    Revoked,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VoucherKind {
    DataAvailability,
    RecursiveProof,
    BlobFee,
    WitnessCache,
    FastSync,
    BridgeExitProof,
}

impl VoucherKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DataAvailability => "data_availability",
            Self::RecursiveProof => "recursive_proof",
            Self::BlobFee => "blob_fee",
            Self::WitnessCache => "witness_cache",
            Self::FastSync => "fast_sync",
            Self::BridgeExitProof => "bridge_exit_proof",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VoucherStatus {
    Minted,
    Reserved,
    Applied,
    Settled,
    Expired,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HedgeKind {
    InventoryNetting,
    AmmSwap,
    RfqFill,
    BridgeReserve,
    FuturesOffset,
    SponsoredBackstop,
}

impl HedgeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InventoryNetting => "inventory_netting",
            Self::AmmSwap => "amm_swap",
            Self::RfqFill => "rfq_fill",
            Self::BridgeReserve => "bridge_reserve",
            Self::FuturesOffset => "futures_offset",
            Self::SponsoredBackstop => "sponsored_backstop",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HedgeStatus {
    Planned,
    Reserved,
    Executed,
    Settled,
    Expired,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Open,
    Netting,
    Proving,
    Anchored,
    Settled,
    Disputed,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceStatus {
    Armed,
    Consumed,
    Challenged,
    Released,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub native_fee_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub max_slippage_bps: u64,
    pub target_rebate_bps: u64,
    pub paymaster_spread_bps: u64,
    pub hedge_reserve_bps: u64,
    pub min_paymaster_liquidity_piconero: u128,
    pub intent_ttl_blocks: u64,
    pub quote_ttl_blocks: u64,
    pub approval_ttl_blocks: u64,
    pub voucher_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub hedge_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub max_route_hops: usize,
    pub max_batch_items: usize,
    pub proof_fee_share_bps: u64,
    pub da_fee_share_bps: u64,
    pub sponsor_rebate_share_bps: u64,
    pub paymaster_retained_share_bps: u64,
    pub accepted_private_fee_assets: BTreeSet<String>,
    pub paymaster_allowlist_root: String,
    pub oracle_committee_root: String,
    pub route_policy_root: String,
}

impl Config {
    pub fn devnet() -> Self {
        let mut accepted_private_fee_assets = BTreeSet::new();
        accepted_private_fee_assets.insert(DEFAULT_PRIVATE_FEE_TOKEN.to_string());
        accepted_private_fee_assets.insert(DEFAULT_PRIVATE_STABLE_ASSET.to_string());
        accepted_private_fee_assets.insert(DEFAULT_REBATE_ASSET.to_string());
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            epoch: DEVNET_EPOCH,
            native_fee_asset_id: DEFAULT_NATIVE_FEE_ASSET.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_slippage_bps: DEFAULT_MAX_SLIPPAGE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            paymaster_spread_bps: DEFAULT_PAYMASTER_SPREAD_BPS,
            hedge_reserve_bps: DEFAULT_HEDGE_RESERVE_BPS,
            min_paymaster_liquidity_piconero: DEFAULT_MIN_PAYMASTER_LIQUIDITY_PICONERO,
            intent_ttl_blocks: DEFAULT_INTENT_TTL_BLOCKS,
            quote_ttl_blocks: DEFAULT_QUOTE_TTL_BLOCKS,
            approval_ttl_blocks: DEFAULT_APPROVAL_TTL_BLOCKS,
            voucher_ttl_blocks: DEFAULT_VOUCHER_TTL_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            hedge_ttl_blocks: DEFAULT_HEDGE_TTL_BLOCKS,
            settlement_ttl_blocks: DEFAULT_SETTLEMENT_TTL_BLOCKS,
            max_route_hops: DEFAULT_MAX_ROUTE_HOPS,
            max_batch_items: DEFAULT_MAX_BATCH_ITEMS,
            proof_fee_share_bps: DEFAULT_PROOF_FEE_SHARE_BPS,
            da_fee_share_bps: DEFAULT_DA_FEE_SHARE_BPS,
            sponsor_rebate_share_bps: DEFAULT_SPONSOR_REBATE_SHARE_BPS,
            paymaster_retained_share_bps: DEFAULT_PAYMASTER_RETAINED_SHARE_BPS,
            accepted_private_fee_assets,
            paymaster_allowlist_root: empty_root("paymaster-allowlist"),
            oracle_committee_root: empty_root("oracle-committee"),
            route_policy_root: empty_root("route-policy"),
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(self.chain_id == CHAIN_ID, "config chain id mismatch");
        ensure!(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "pq security below policy"
        );
        ensure!(
            self.min_privacy_set_size >= DEFAULT_MIN_PRIVACY_SET_SIZE,
            "privacy set below policy"
        );
        ensure!(
            self.max_user_fee_bps <= MAX_BPS,
            "max user fee above bps range"
        );
        ensure!(
            self.max_slippage_bps <= MAX_BPS,
            "max slippage above bps range"
        );
        ensure!(
            self.target_rebate_bps <= self.max_user_fee_bps,
            "rebate target above user fee cap"
        );
        ensure!(
            !self.accepted_private_fee_assets.is_empty(),
            "no accepted private fee assets"
        );
        let shares = self
            .proof_fee_share_bps
            .saturating_add(self.da_fee_share_bps)
            .saturating_add(self.sponsor_rebate_share_bps)
            .saturating_add(self.paymaster_retained_share_bps);
        ensure!(shares == MAX_BPS, "fee share bps must sum to 10000");
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
            "native_fee_asset_id": self.native_fee_asset_id,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_slippage_bps": self.max_slippage_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "paymaster_spread_bps": self.paymaster_spread_bps,
            "hedge_reserve_bps": self.hedge_reserve_bps,
            "min_paymaster_liquidity_piconero": self.min_paymaster_liquidity_piconero.to_string(),
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "approval_ttl_blocks": self.approval_ttl_blocks,
            "voucher_ttl_blocks": self.voucher_ttl_blocks,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "hedge_ttl_blocks": self.hedge_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "max_route_hops": self.max_route_hops,
            "max_batch_items": self.max_batch_items,
            "proof_fee_share_bps": self.proof_fee_share_bps,
            "da_fee_share_bps": self.da_fee_share_bps,
            "sponsor_rebate_share_bps": self.sponsor_rebate_share_bps,
            "paymaster_retained_share_bps": self.paymaster_retained_share_bps,
            "accepted_private_fee_assets_root": root_from_set(
                "fee-token-swap-paymaster-accepted-assets",
                &self.accepted_private_fee_assets
            ),
            "paymaster_allowlist_root": self.paymaster_allowlist_root,
            "oracle_committee_root": self.oracle_committee_root,
            "route_policy_root": self.route_policy_root,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub fee_tokens: u64,
    pub paymasters: u64,
    pub swap_quotes: u64,
    pub fee_intents: u64,
    pub route_plans: u64,
    pub pq_approvals: u64,
    pub execution_receipts: u64,
    pub rebate_coupons: u64,
    pub vouchers: u64,
    pub hedge_positions: u64,
    pub settlement_batches: u64,
    pub privacy_fences: u64,
    pub risk_snapshots: u64,
    pub public_events: u64,
    pub piconero_sponsored: u128,
    pub private_token_collected: u128,
    pub rebates_reserved: u128,
    pub voucher_value_reserved: u128,
    pub hedge_notional_piconero: u128,
    pub slippage_rejections: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "fee_tokens": self.fee_tokens,
            "paymasters": self.paymasters,
            "swap_quotes": self.swap_quotes,
            "fee_intents": self.fee_intents,
            "route_plans": self.route_plans,
            "pq_approvals": self.pq_approvals,
            "execution_receipts": self.execution_receipts,
            "rebate_coupons": self.rebate_coupons,
            "vouchers": self.vouchers,
            "hedge_positions": self.hedge_positions,
            "settlement_batches": self.settlement_batches,
            "privacy_fences": self.privacy_fences,
            "risk_snapshots": self.risk_snapshots,
            "public_events": self.public_events,
            "piconero_sponsored": self.piconero_sponsored.to_string(),
            "private_token_collected": self.private_token_collected.to_string(),
            "rebates_reserved": self.rebates_reserved.to_string(),
            "voucher_value_reserved": self.voucher_value_reserved.to_string(),
            "hedge_notional_piconero": self.hedge_notional_piconero.to_string(),
            "slippage_rejections": self.slippage_rejections,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub fee_token_root: String,
    pub paymaster_root: String,
    pub swap_quote_root: String,
    pub fee_intent_root: String,
    pub route_plan_root: String,
    pub pq_approval_root: String,
    pub execution_receipt_root: String,
    pub rebate_root: String,
    pub voucher_root: String,
    pub hedge_root: String,
    pub settlement_root: String,
    pub privacy_fence_root: String,
    pub risk_root: String,
    pub public_event_root: String,
    pub liquidity_index_root: String,
    pub paymaster_asset_index_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "fee_token_root": self.fee_token_root,
            "paymaster_root": self.paymaster_root,
            "swap_quote_root": self.swap_quote_root,
            "fee_intent_root": self.fee_intent_root,
            "route_plan_root": self.route_plan_root,
            "pq_approval_root": self.pq_approval_root,
            "execution_receipt_root": self.execution_receipt_root,
            "rebate_root": self.rebate_root,
            "voucher_root": self.voucher_root,
            "hedge_root": self.hedge_root,
            "settlement_root": self.settlement_root,
            "privacy_fence_root": self.privacy_fence_root,
            "risk_root": self.risk_root,
            "public_event_root": self.public_event_root,
            "liquidity_index_root": self.liquidity_index_root,
            "paymaster_asset_index_root": self.paymaster_asset_index_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeToken {
    pub asset_id: String,
    pub kind: FeeAssetKind,
    pub issuer_commitment: String,
    pub token_policy_root: String,
    pub oracle_price_root: String,
    pub reserve_attestation_root: String,
    pub decimals: u8,
    pub max_fee_payment_micro_units: u128,
    pub max_slippage_bps: u64,
    pub min_privacy_set_size: u64,
    pub enabled: bool,
}

impl FeeToken {
    pub fn new(
        config: &Config,
        asset_id: impl Into<String>,
        kind: FeeAssetKind,
        issuer_commitment: impl Into<String>,
        decimals: u8,
    ) -> Self {
        let asset_id = asset_id.into();
        let issuer_commitment = issuer_commitment.into();
        let token_policy_root = domain_hash(
            "FEE-TOKEN-SWAP-PAYMASTER:TOKEN-POLICY",
            &[
                HashPart::Str(&asset_id),
                HashPart::Str(kind.as_str()),
                HashPart::Str(&issuer_commitment),
                HashPart::U64(decimals as u64),
            ],
            32,
        );
        Self {
            asset_id,
            kind,
            issuer_commitment,
            token_policy_root,
            oracle_price_root: empty_root("fee-token-oracle-price"),
            reserve_attestation_root: empty_root("fee-token-reserve-attestation"),
            decimals,
            max_fee_payment_micro_units: 500_000_000_000,
            max_slippage_bps: config.max_slippage_bps,
            min_privacy_set_size: config.min_privacy_set_size,
            enabled: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "asset_id": self.asset_id,
            "kind": self.kind.as_str(),
            "issuer_commitment": self.issuer_commitment,
            "token_policy_root": self.token_policy_root,
            "oracle_price_root": self.oracle_price_root,
            "reserve_attestation_root": self.reserve_attestation_root,
            "decimals": self.decimals,
            "max_fee_payment_micro_units": self.max_fee_payment_micro_units.to_string(),
            "max_slippage_bps": self.max_slippage_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "enabled": self.enabled,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Paymaster {
    pub paymaster_id: String,
    pub operator_commitment: String,
    pub status: PaymasterStatus,
    pub supported_assets: BTreeSet<String>,
    pub supported_lanes: BTreeSet<RouteLane>,
    pub piconero_liquidity: u128,
    pub private_token_inventory_root: String,
    pub hedge_policy_root: String,
    pub route_policy_root: String,
    pub rebate_policy_root: String,
    pub max_sponsor_fee_bps: u64,
    pub max_slippage_bps: u64,
    pub min_pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub registered_l2_height: u64,
    pub expires_l2_height: u64,
}

impl Paymaster {
    pub fn new(
        config: &Config,
        operator_commitment: impl Into<String>,
        supported_assets: BTreeSet<String>,
        supported_lanes: BTreeSet<RouteLane>,
        piconero_liquidity: u128,
        nonce: u64,
    ) -> Self {
        let operator_commitment = operator_commitment.into();
        let supported_asset_root = root_from_set("paymaster-supported-assets", &supported_assets);
        let supported_lane_root =
            route_lane_set_root("paymaster-supported-lanes", &supported_lanes);
        let paymaster_id = domain_hash(
            "FEE-TOKEN-SWAP-PAYMASTER:PAYMASTER-ID",
            &[
                HashPart::Str(&operator_commitment),
                HashPart::Str(&supported_asset_root),
                HashPart::Str(&supported_lane_root),
                HashPart::U64(nonce),
            ],
            20,
        );
        let hedge_policy_root = domain_hash(
            "FEE-TOKEN-SWAP-PAYMASTER:HEDGE-POLICY",
            &[
                HashPart::Str(&paymaster_id),
                HashPart::Str(HEDGE_NOTE_SUITE),
                HashPart::U64(config.hedge_reserve_bps),
            ],
            32,
        );
        Self {
            paymaster_id,
            operator_commitment,
            status: PaymasterStatus::Active,
            supported_assets,
            supported_lanes,
            piconero_liquidity,
            private_token_inventory_root: empty_root("paymaster-private-token-inventory"),
            hedge_policy_root,
            route_policy_root: config.route_policy_root.clone(),
            rebate_policy_root: empty_root("paymaster-rebate-policy"),
            max_sponsor_fee_bps: config.max_user_fee_bps,
            max_slippage_bps: config.max_slippage_bps,
            min_pq_security_bits: config.min_pq_security_bits,
            privacy_set_size: config.min_privacy_set_size,
            registered_l2_height: config.l2_height,
            expires_l2_height: config
                .l2_height
                .saturating_add(config.settlement_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "paymaster_id": self.paymaster_id,
            "operator_commitment": self.operator_commitment,
            "status": self.status,
            "supported_assets_root": root_from_set(
                "paymaster-public-supported-assets",
                &self.supported_assets
            ),
            "supported_lanes_root": route_lane_set_root(
                "paymaster-public-supported-lanes",
                &self.supported_lanes
            ),
            "piconero_liquidity": self.piconero_liquidity.to_string(),
            "private_token_inventory_root": self.private_token_inventory_root,
            "hedge_policy_root": self.hedge_policy_root,
            "route_policy_root": self.route_policy_root,
            "rebate_policy_root": self.rebate_policy_root,
            "max_sponsor_fee_bps": self.max_sponsor_fee_bps,
            "max_slippage_bps": self.max_slippage_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "privacy_set_size": self.privacy_set_size,
            "registered_l2_height": self.registered_l2_height,
            "expires_l2_height": self.expires_l2_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SwapQuote {
    pub quote_id: String,
    pub paymaster_id: String,
    pub fee_asset_id: String,
    pub lane: RouteLane,
    pub private_fee_amount_micro_units: u128,
    pub piconero_fee_amount: u128,
    pub min_piconero_out: u128,
    pub max_slippage_bps: u64,
    pub paymaster_spread_bps: u64,
    pub oracle_price_root: String,
    pub route_commitment_root: String,
    pub liquidity_bucket_root: String,
    pub status: QuoteStatus,
    pub quoted_l2_height: u64,
    pub expires_l2_height: u64,
}

impl SwapQuote {
    pub fn new(
        config: &Config,
        paymaster_id: &str,
        fee_asset_id: &str,
        lane: RouteLane,
        private_fee_amount_micro_units: u128,
        piconero_fee_amount: u128,
        max_slippage_bps: u64,
        nonce: u64,
    ) -> Self {
        let min_piconero_out = apply_bps_floor(piconero_fee_amount, max_slippage_bps);
        let quote_id = domain_hash(
            "FEE-TOKEN-SWAP-PAYMASTER:QUOTE-ID",
            &[
                HashPart::Str(paymaster_id),
                HashPart::Str(fee_asset_id),
                HashPart::Str(lane.as_str()),
                HashPart::Str(&private_fee_amount_micro_units.to_string()),
                HashPart::Str(&piconero_fee_amount.to_string()),
                HashPart::U64(nonce),
            ],
            20,
        );
        let route_commitment_root = domain_hash(
            "FEE-TOKEN-SWAP-PAYMASTER:QUOTE-ROUTE",
            &[
                HashPart::Str(&quote_id),
                HashPart::Str(SWAP_QUOTE_SUITE),
                HashPart::U64(lane.priority_weight()),
            ],
            32,
        );
        Self {
            quote_id,
            paymaster_id: paymaster_id.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            lane,
            private_fee_amount_micro_units,
            piconero_fee_amount,
            min_piconero_out,
            max_slippage_bps,
            paymaster_spread_bps: config.paymaster_spread_bps,
            oracle_price_root: empty_root("swap-quote-oracle-price"),
            route_commitment_root,
            liquidity_bucket_root: empty_root("swap-quote-liquidity-bucket"),
            status: QuoteStatus::Open,
            quoted_l2_height: config.l2_height,
            expires_l2_height: config.l2_height.saturating_add(config.quote_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "paymaster_id": self.paymaster_id,
            "fee_asset_id": self.fee_asset_id,
            "lane": self.lane.as_str(),
            "private_fee_amount_commitment": amount_commitment(
                "quote-private-fee",
                &self.quote_id,
                self.private_fee_amount_micro_units
            ),
            "piconero_fee_amount_commitment": amount_commitment(
                "quote-piconero-fee",
                &self.quote_id,
                self.piconero_fee_amount
            ),
            "min_piconero_out_commitment": amount_commitment(
                "quote-min-piconero-out",
                &self.quote_id,
                self.min_piconero_out
            ),
            "max_slippage_bps": self.max_slippage_bps,
            "paymaster_spread_bps": self.paymaster_spread_bps,
            "oracle_price_root": self.oracle_price_root,
            "route_commitment_root": self.route_commitment_root,
            "liquidity_bucket_root": self.liquidity_bucket_root,
            "status": self.status,
            "quoted_l2_height": self.quoted_l2_height,
            "expires_l2_height": self.expires_l2_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeIntent {
    pub intent_id: String,
    pub payer_commitment: String,
    pub fee_asset_id: String,
    pub lane: RouteLane,
    pub requested_fee_token_commitment: String,
    pub max_fee_token_micro_units: u128,
    pub max_piconero_fee: u128,
    pub max_slippage_bps: u64,
    pub call_bundle_root: String,
    pub nullifier_root: String,
    pub encrypted_metadata_root: String,
    pub voucher_ids: BTreeSet<String>,
    pub status: IntentStatus,
    pub submitted_l2_height: u64,
    pub expires_l2_height: u64,
}

impl FeeIntent {
    pub fn new(
        config: &Config,
        payer_commitment: impl Into<String>,
        fee_asset_id: impl Into<String>,
        lane: RouteLane,
        max_fee_token_micro_units: u128,
        max_piconero_fee: u128,
        nonce: u64,
    ) -> Self {
        let payer_commitment = payer_commitment.into();
        let fee_asset_id = fee_asset_id.into();
        let intent_id = domain_hash(
            "FEE-TOKEN-SWAP-PAYMASTER:INTENT-ID",
            &[
                HashPart::Str(&payer_commitment),
                HashPart::Str(&fee_asset_id),
                HashPart::Str(lane.as_str()),
                HashPart::Str(&max_fee_token_micro_units.to_string()),
                HashPart::U64(nonce),
            ],
            20,
        );
        let requested_fee_token_commitment = amount_commitment(
            "intent-requested-fee-token",
            &intent_id,
            max_fee_token_micro_units,
        );
        Self {
            intent_id,
            payer_commitment,
            fee_asset_id,
            lane,
            requested_fee_token_commitment,
            max_fee_token_micro_units,
            max_piconero_fee,
            max_slippage_bps: config.max_slippage_bps,
            call_bundle_root: empty_root("intent-call-bundle"),
            nullifier_root: empty_root("intent-nullifier"),
            encrypted_metadata_root: empty_root("intent-encrypted-metadata"),
            voucher_ids: BTreeSet::new(),
            status: IntentStatus::Submitted,
            submitted_l2_height: config.l2_height,
            expires_l2_height: config.l2_height.saturating_add(config.intent_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "payer_commitment": self.payer_commitment,
            "fee_asset_id": self.fee_asset_id,
            "lane": self.lane.as_str(),
            "requested_fee_token_commitment": self.requested_fee_token_commitment,
            "max_piconero_fee_commitment": amount_commitment(
                "intent-max-piconero-fee",
                &self.intent_id,
                self.max_piconero_fee
            ),
            "max_slippage_bps": self.max_slippage_bps,
            "call_bundle_root": self.call_bundle_root,
            "nullifier_root": self.nullifier_root,
            "encrypted_metadata_root": self.encrypted_metadata_root,
            "voucher_root": root_from_set("intent-vouchers", &self.voucher_ids),
            "status": self.status,
            "submitted_l2_height": self.submitted_l2_height,
            "expires_l2_height": self.expires_l2_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqApproval {
    pub approval_id: String,
    pub intent_id: String,
    pub quote_id: String,
    pub signer_commitment: String,
    pub pq_key_root: String,
    pub transcript_root: String,
    pub signature_root: String,
    pub authorization_scope_root: String,
    pub min_pq_security_bits: u16,
    pub status: ApprovalStatus,
    pub approved_l2_height: u64,
    pub expires_l2_height: u64,
}

impl PqApproval {
    pub fn new(
        config: &Config,
        intent_id: &str,
        quote_id: &str,
        signer_commitment: impl Into<String>,
        nonce: u64,
    ) -> Self {
        let signer_commitment = signer_commitment.into();
        let transcript_root = domain_hash(
            "FEE-TOKEN-SWAP-PAYMASTER:PQ-APPROVAL-TRANSCRIPT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(intent_id),
                HashPart::Str(quote_id),
                HashPart::Str(&signer_commitment),
                HashPart::U64(nonce),
            ],
            32,
        );
        let approval_id = domain_hash(
            "FEE-TOKEN-SWAP-PAYMASTER:PQ-APPROVAL-ID",
            &[
                HashPart::Str(&transcript_root),
                HashPart::Str(PQ_APPROVAL_SUITE),
            ],
            20,
        );
        Self {
            approval_id,
            intent_id: intent_id.to_string(),
            quote_id: quote_id.to_string(),
            signer_commitment,
            pq_key_root: empty_root("pq-approval-key"),
            transcript_root,
            signature_root: empty_root("pq-approval-signature"),
            authorization_scope_root: empty_root("pq-approval-scope"),
            min_pq_security_bits: config.min_pq_security_bits,
            status: ApprovalStatus::Verified,
            approved_l2_height: config.l2_height,
            expires_l2_height: config.l2_height.saturating_add(config.approval_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "approval_id": self.approval_id,
            "intent_id": self.intent_id,
            "quote_id": self.quote_id,
            "signer_commitment": self.signer_commitment,
            "pq_key_root": self.pq_key_root,
            "transcript_root": self.transcript_root,
            "signature_root": self.signature_root,
            "authorization_scope_root": self.authorization_scope_root,
            "min_pq_security_bits": self.min_pq_security_bits,
            "status": self.status,
            "approved_l2_height": self.approved_l2_height,
            "expires_l2_height": self.expires_l2_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoutePlan {
    pub plan_id: String,
    pub intent_id: String,
    pub quote_id: String,
    pub paymaster_id: String,
    pub approval_id: String,
    pub lane: RouteLane,
    pub hop_roots: Vec<String>,
    pub voucher_ids: BTreeSet<String>,
    pub expected_piconero_fee: u128,
    pub expected_private_fee_token: u128,
    pub expected_rebate_micro_units: u128,
    pub proof_fee_commitment: String,
    pub da_fee_commitment: String,
    pub sponsor_rebate_commitment: String,
    pub paymaster_retained_commitment: String,
    pub route_risk_root: String,
    pub planned_l2_height: u64,
    pub expires_l2_height: u64,
}

impl RoutePlan {
    pub fn from_parts(
        config: &Config,
        intent: &FeeIntent,
        quote: &SwapQuote,
        approval_id: &str,
        voucher_ids: BTreeSet<String>,
    ) -> Self {
        let hop_roots = vec![
            deterministic_root("route-hop-intent", &[&intent.intent_id]),
            deterministic_root("route-hop-quote", &[&quote.quote_id]),
            deterministic_root("route-hop-paymaster", &[&quote.paymaster_id]),
        ];
        let hop_root = root_from_strings(
            "route-plan-hop-roots",
            &hop_roots.iter().map(String::as_str).collect::<Vec<_>>(),
        );
        let voucher_root = root_from_set("route-plan-vouchers", &voucher_ids);
        let plan_id = domain_hash(
            "FEE-TOKEN-SWAP-PAYMASTER:ROUTE-PLAN-ID",
            &[
                HashPart::Str(&intent.intent_id),
                HashPart::Str(&quote.quote_id),
                HashPart::Str(approval_id),
                HashPart::Str(&hop_root),
                HashPart::Str(&voucher_root),
            ],
            20,
        );
        let expected_rebate_micro_units = quote
            .piconero_fee_amount
            .saturating_mul(config.target_rebate_bps as u128)
            / MAX_BPS as u128;
        Self {
            plan_id: plan_id.clone(),
            intent_id: intent.intent_id.clone(),
            quote_id: quote.quote_id.clone(),
            paymaster_id: quote.paymaster_id.clone(),
            approval_id: approval_id.to_string(),
            lane: intent.lane,
            hop_roots,
            voucher_ids,
            expected_piconero_fee: quote.piconero_fee_amount,
            expected_private_fee_token: quote.private_fee_amount_micro_units,
            expected_rebate_micro_units,
            proof_fee_commitment: share_commitment(
                "route-proof-fee",
                &plan_id,
                quote.piconero_fee_amount,
                config.proof_fee_share_bps,
            ),
            da_fee_commitment: share_commitment(
                "route-da-fee",
                &plan_id,
                quote.piconero_fee_amount,
                config.da_fee_share_bps,
            ),
            sponsor_rebate_commitment: share_commitment(
                "route-sponsor-rebate",
                &plan_id,
                quote.piconero_fee_amount,
                config.sponsor_rebate_share_bps,
            ),
            paymaster_retained_commitment: share_commitment(
                "route-paymaster-retained",
                &plan_id,
                quote.piconero_fee_amount,
                config.paymaster_retained_share_bps,
            ),
            route_risk_root: empty_root("route-plan-risk"),
            planned_l2_height: config.l2_height,
            expires_l2_height: config.l2_height.saturating_add(config.approval_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "plan_id": self.plan_id,
            "intent_id": self.intent_id,
            "quote_id": self.quote_id,
            "paymaster_id": self.paymaster_id,
            "approval_id": self.approval_id,
            "lane": self.lane.as_str(),
            "hop_root": root_from_strings(
                "route-plan-public-hop-roots",
                &self.hop_roots.iter().map(String::as_str).collect::<Vec<_>>()
            ),
            "voucher_root": root_from_set("route-plan-public-vouchers", &self.voucher_ids),
            "expected_piconero_fee_commitment": amount_commitment(
                "route-expected-piconero",
                &self.plan_id,
                self.expected_piconero_fee
            ),
            "expected_private_fee_token_commitment": amount_commitment(
                "route-expected-private-fee-token",
                &self.plan_id,
                self.expected_private_fee_token
            ),
            "expected_rebate_commitment": amount_commitment(
                "route-expected-rebate",
                &self.plan_id,
                self.expected_rebate_micro_units
            ),
            "proof_fee_commitment": self.proof_fee_commitment,
            "da_fee_commitment": self.da_fee_commitment,
            "sponsor_rebate_commitment": self.sponsor_rebate_commitment,
            "paymaster_retained_commitment": self.paymaster_retained_commitment,
            "route_risk_root": self.route_risk_root,
            "planned_l2_height": self.planned_l2_height,
            "expires_l2_height": self.expires_l2_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionReceipt {
    pub receipt_id: String,
    pub plan_id: String,
    pub intent_id: String,
    pub paymaster_id: String,
    pub actual_piconero_paid: u128,
    pub actual_private_fee_collected: u128,
    pub slippage_bps: u64,
    pub execution_root: String,
    pub proof_root: String,
    pub da_root: String,
    pub rebate_id: Option<String>,
    pub voucher_root: String,
    pub executed_l2_height: u64,
}

impl ExecutionReceipt {
    pub fn new(
        config: &Config,
        plan: &RoutePlan,
        actual_piconero_paid: u128,
        actual_private_fee_collected: u128,
        slippage_bps: u64,
    ) -> Self {
        let receipt_id = domain_hash(
            "FEE-TOKEN-SWAP-PAYMASTER:EXECUTION-RECEIPT-ID",
            &[
                HashPart::Str(&plan.plan_id),
                HashPart::Str(&actual_piconero_paid.to_string()),
                HashPart::Str(&actual_private_fee_collected.to_string()),
                HashPart::U64(slippage_bps),
            ],
            20,
        );
        Self {
            receipt_id,
            plan_id: plan.plan_id.clone(),
            intent_id: plan.intent_id.clone(),
            paymaster_id: plan.paymaster_id.clone(),
            actual_piconero_paid,
            actual_private_fee_collected,
            slippage_bps,
            execution_root: deterministic_root("execution-receipt-execution", &[&plan.plan_id]),
            proof_root: empty_root("execution-receipt-proof"),
            da_root: empty_root("execution-receipt-da"),
            rebate_id: None,
            voucher_root: root_from_set("execution-receipt-vouchers", &plan.voucher_ids),
            executed_l2_height: config.l2_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "plan_id": self.plan_id,
            "intent_id": self.intent_id,
            "paymaster_id": self.paymaster_id,
            "actual_piconero_paid_commitment": amount_commitment(
                "receipt-actual-piconero-paid",
                &self.receipt_id,
                self.actual_piconero_paid
            ),
            "actual_private_fee_collected_commitment": amount_commitment(
                "receipt-actual-private-fee-collected",
                &self.receipt_id,
                self.actual_private_fee_collected
            ),
            "slippage_bps": self.slippage_bps,
            "execution_root": self.execution_root,
            "proof_root": self.proof_root,
            "da_root": self.da_root,
            "rebate_id": self.rebate_id,
            "voucher_root": self.voucher_root,
            "executed_l2_height": self.executed_l2_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateCoupon {
    pub rebate_id: String,
    pub receipt_id: String,
    pub payer_commitment: String,
    pub sponsor_commitment: String,
    pub rebate_asset_id: String,
    pub rebate_amount_micro_units: u128,
    pub rebate_note_root: String,
    pub nullifier_root: String,
    pub status: VoucherStatus,
    pub minted_l2_height: u64,
    pub expires_l2_height: u64,
}

impl RebateCoupon {
    pub fn new(
        config: &Config,
        receipt: &ExecutionReceipt,
        payer_commitment: &str,
        sponsor_commitment: &str,
        rebate_amount_micro_units: u128,
    ) -> Self {
        let rebate_id = domain_hash(
            "FEE-TOKEN-SWAP-PAYMASTER:REBATE-ID",
            &[
                HashPart::Str(&receipt.receipt_id),
                HashPart::Str(payer_commitment),
                HashPart::Str(sponsor_commitment),
                HashPart::Str(&rebate_amount_micro_units.to_string()),
            ],
            20,
        );
        Self {
            rebate_id: rebate_id.clone(),
            receipt_id: receipt.receipt_id.clone(),
            payer_commitment: payer_commitment.to_string(),
            sponsor_commitment: sponsor_commitment.to_string(),
            rebate_asset_id: DEFAULT_REBATE_ASSET.to_string(),
            rebate_amount_micro_units,
            rebate_note_root: deterministic_root(
                "rebate-note",
                &[&rebate_id, &receipt.receipt_id, REBATE_COUPON_SUITE],
            ),
            nullifier_root: empty_root("rebate-nullifier"),
            status: VoucherStatus::Minted,
            minted_l2_height: config.l2_height,
            expires_l2_height: config.l2_height.saturating_add(config.rebate_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "receipt_id": self.receipt_id,
            "payer_commitment": self.payer_commitment,
            "sponsor_commitment": self.sponsor_commitment,
            "rebate_asset_id": self.rebate_asset_id,
            "rebate_amount_commitment": amount_commitment(
                "rebate-amount",
                &self.rebate_id,
                self.rebate_amount_micro_units
            ),
            "rebate_note_root": self.rebate_note_root,
            "nullifier_root": self.nullifier_root,
            "status": self.status,
            "minted_l2_height": self.minted_l2_height,
            "expires_l2_height": self.expires_l2_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeVoucher {
    pub voucher_id: String,
    pub kind: VoucherKind,
    pub sponsor_commitment: String,
    pub beneficiary_commitment: String,
    pub asset_id: String,
    pub value_piconero: u128,
    pub fee_component_root: String,
    pub proof_claim_root: String,
    pub da_claim_root: String,
    pub nullifier_root: String,
    pub status: VoucherStatus,
    pub minted_l2_height: u64,
    pub expires_l2_height: u64,
}

impl FeeVoucher {
    pub fn new(
        config: &Config,
        kind: VoucherKind,
        sponsor_commitment: impl Into<String>,
        beneficiary_commitment: impl Into<String>,
        value_piconero: u128,
        nonce: u64,
    ) -> Self {
        let sponsor_commitment = sponsor_commitment.into();
        let beneficiary_commitment = beneficiary_commitment.into();
        let voucher_id = domain_hash(
            "FEE-TOKEN-SWAP-PAYMASTER:VOUCHER-ID",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(&sponsor_commitment),
                HashPart::Str(&beneficiary_commitment),
                HashPart::Str(&value_piconero.to_string()),
                HashPart::U64(nonce),
            ],
            20,
        );
        Self {
            voucher_id: voucher_id.clone(),
            kind,
            sponsor_commitment,
            beneficiary_commitment,
            asset_id: config.native_fee_asset_id.clone(),
            value_piconero,
            fee_component_root: deterministic_root("voucher-fee-component", &[&voucher_id]),
            proof_claim_root: empty_root("voucher-proof-claim"),
            da_claim_root: empty_root("voucher-da-claim"),
            nullifier_root: empty_root("voucher-nullifier"),
            status: VoucherStatus::Minted,
            minted_l2_height: config.l2_height,
            expires_l2_height: config.l2_height.saturating_add(config.voucher_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "voucher_id": self.voucher_id,
            "kind": self.kind.as_str(),
            "sponsor_commitment": self.sponsor_commitment,
            "beneficiary_commitment": self.beneficiary_commitment,
            "asset_id": self.asset_id,
            "value_piconero_commitment": amount_commitment(
                "voucher-value-piconero",
                &self.voucher_id,
                self.value_piconero
            ),
            "fee_component_root": self.fee_component_root,
            "proof_claim_root": self.proof_claim_root,
            "da_claim_root": self.da_claim_root,
            "nullifier_root": self.nullifier_root,
            "status": self.status,
            "minted_l2_height": self.minted_l2_height,
            "expires_l2_height": self.expires_l2_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HedgePosition {
    pub hedge_id: String,
    pub paymaster_id: String,
    pub kind: HedgeKind,
    pub source_asset_id: String,
    pub target_asset_id: String,
    pub source_amount_commitment: String,
    pub target_piconero_commitment: String,
    pub notional_piconero: u128,
    pub hedge_ratio_bps: u64,
    pub route_root: String,
    pub settlement_root: String,
    pub status: HedgeStatus,
    pub opened_l2_height: u64,
    pub expires_l2_height: u64,
}

impl HedgePosition {
    pub fn new(
        config: &Config,
        paymaster_id: &str,
        kind: HedgeKind,
        source_asset_id: &str,
        source_amount: u128,
        notional_piconero: u128,
        nonce: u64,
    ) -> Self {
        let hedge_id = domain_hash(
            "FEE-TOKEN-SWAP-PAYMASTER:HEDGE-ID",
            &[
                HashPart::Str(paymaster_id),
                HashPart::Str(kind.as_str()),
                HashPart::Str(source_asset_id),
                HashPart::Str(&source_amount.to_string()),
                HashPart::Str(&notional_piconero.to_string()),
                HashPart::U64(nonce),
            ],
            20,
        );
        Self {
            hedge_id: hedge_id.clone(),
            paymaster_id: paymaster_id.to_string(),
            kind,
            source_asset_id: source_asset_id.to_string(),
            target_asset_id: config.native_fee_asset_id.clone(),
            source_amount_commitment: amount_commitment(
                "hedge-source-amount",
                &hedge_id,
                source_amount,
            ),
            target_piconero_commitment: amount_commitment(
                "hedge-target-piconero",
                &hedge_id,
                notional_piconero,
            ),
            notional_piconero,
            hedge_ratio_bps: config.hedge_reserve_bps,
            route_root: deterministic_root("hedge-route", &[&hedge_id, HEDGE_NOTE_SUITE]),
            settlement_root: empty_root("hedge-settlement"),
            status: HedgeStatus::Planned,
            opened_l2_height: config.l2_height,
            expires_l2_height: config.l2_height.saturating_add(config.hedge_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "hedge_id": self.hedge_id,
            "paymaster_id": self.paymaster_id,
            "kind": self.kind.as_str(),
            "source_asset_id": self.source_asset_id,
            "target_asset_id": self.target_asset_id,
            "source_amount_commitment": self.source_amount_commitment,
            "target_piconero_commitment": self.target_piconero_commitment,
            "notional_piconero_commitment": amount_commitment(
                "hedge-notional-piconero",
                &self.hedge_id,
                self.notional_piconero
            ),
            "hedge_ratio_bps": self.hedge_ratio_bps,
            "route_root": self.route_root,
            "settlement_root": self.settlement_root,
            "status": self.status,
            "opened_l2_height": self.opened_l2_height,
            "expires_l2_height": self.expires_l2_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementBatch {
    pub batch_id: String,
    pub paymaster_id: String,
    pub receipt_ids: BTreeSet<String>,
    pub hedge_ids: BTreeSet<String>,
    pub voucher_ids: BTreeSet<String>,
    pub rebate_ids: BTreeSet<String>,
    pub gross_piconero_commitment: String,
    pub private_token_net_commitment: String,
    pub voucher_net_commitment: String,
    pub rebate_net_commitment: String,
    pub proof_root: String,
    pub da_root: String,
    pub anchor_root: String,
    pub status: SettlementStatus,
    pub opened_l2_height: u64,
    pub expires_l2_height: u64,
}

impl SettlementBatch {
    pub fn new(
        config: &Config,
        paymaster_id: &str,
        receipt_ids: BTreeSet<String>,
        hedge_ids: BTreeSet<String>,
        voucher_ids: BTreeSet<String>,
        rebate_ids: BTreeSet<String>,
        nonce: u64,
    ) -> Self {
        let receipt_root = root_from_set("settlement-receipts", &receipt_ids);
        let hedge_root = root_from_set("settlement-hedges", &hedge_ids);
        let voucher_root = root_from_set("settlement-vouchers", &voucher_ids);
        let rebate_root = root_from_set("settlement-rebates", &rebate_ids);
        let batch_id = domain_hash(
            "FEE-TOKEN-SWAP-PAYMASTER:SETTLEMENT-BATCH-ID",
            &[
                HashPart::Str(paymaster_id),
                HashPart::Str(&receipt_root),
                HashPart::Str(&hedge_root),
                HashPart::Str(&voucher_root),
                HashPart::Str(&rebate_root),
                HashPart::U64(nonce),
            ],
            20,
        );
        Self {
            batch_id: batch_id.clone(),
            paymaster_id: paymaster_id.to_string(),
            receipt_ids,
            hedge_ids,
            voucher_ids,
            rebate_ids,
            gross_piconero_commitment: deterministic_root(
                "settlement-gross-piconero",
                &[&batch_id],
            ),
            private_token_net_commitment: deterministic_root(
                "settlement-private-token-net",
                &[&batch_id],
            ),
            voucher_net_commitment: deterministic_root("settlement-voucher-net", &[&batch_id]),
            rebate_net_commitment: deterministic_root("settlement-rebate-net", &[&batch_id]),
            proof_root: empty_root("settlement-proof"),
            da_root: empty_root("settlement-da"),
            anchor_root: empty_root("settlement-anchor"),
            status: SettlementStatus::Open,
            opened_l2_height: config.l2_height,
            expires_l2_height: config
                .l2_height
                .saturating_add(config.settlement_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "paymaster_id": self.paymaster_id,
            "receipt_root": root_from_set("settlement-public-receipts", &self.receipt_ids),
            "hedge_root": root_from_set("settlement-public-hedges", &self.hedge_ids),
            "voucher_root": root_from_set("settlement-public-vouchers", &self.voucher_ids),
            "rebate_root": root_from_set("settlement-public-rebates", &self.rebate_ids),
            "gross_piconero_commitment": self.gross_piconero_commitment,
            "private_token_net_commitment": self.private_token_net_commitment,
            "voucher_net_commitment": self.voucher_net_commitment,
            "rebate_net_commitment": self.rebate_net_commitment,
            "proof_root": self.proof_root,
            "da_root": self.da_root,
            "anchor_root": self.anchor_root,
            "status": self.status,
            "opened_l2_height": self.opened_l2_height,
            "expires_l2_height": self.expires_l2_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub kind: String,
    pub subject_id: String,
    pub nullifier_root: String,
    pub commitment_root: String,
    pub abuse_score_commitment: String,
    pub status: FenceStatus,
    pub armed_l2_height: u64,
    pub expires_l2_height: u64,
}

impl PrivacyFence {
    pub fn new(
        config: &Config,
        kind: impl Into<String>,
        subject_id: impl Into<String>,
        nullifier_root: impl Into<String>,
        commitment_root: impl Into<String>,
    ) -> Self {
        let kind = kind.into();
        let subject_id = subject_id.into();
        let nullifier_root = nullifier_root.into();
        let commitment_root = commitment_root.into();
        let fence_id = domain_hash(
            "FEE-TOKEN-SWAP-PAYMASTER:PRIVACY-FENCE-ID",
            &[
                HashPart::Str(&kind),
                HashPart::Str(&subject_id),
                HashPart::Str(&nullifier_root),
                HashPart::Str(&commitment_root),
            ],
            20,
        );
        Self {
            fence_id: fence_id.clone(),
            kind,
            subject_id,
            nullifier_root,
            commitment_root,
            abuse_score_commitment: deterministic_root("privacy-fence-abuse-score", &[&fence_id]),
            status: FenceStatus::Armed,
            armed_l2_height: config.l2_height,
            expires_l2_height: config.l2_height.saturating_add(config.intent_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "nullifier_root": self.nullifier_root,
            "commitment_root": self.commitment_root,
            "abuse_score_commitment": self.abuse_score_commitment,
            "status": self.status,
            "armed_l2_height": self.armed_l2_height,
            "expires_l2_height": self.expires_l2_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskSnapshot {
    pub snapshot_id: String,
    pub paymaster_id: String,
    pub exposure_root: String,
    pub inventory_root: String,
    pub hedge_root: String,
    pub slippage_bucket_root: String,
    pub liquidity_ratio_bps: u64,
    pub route_health_bps: u64,
    pub observed_l2_height: u64,
}

impl RiskSnapshot {
    pub fn new(config: &Config, paymaster_id: &str, liquidity_ratio_bps: u64) -> Self {
        let snapshot_id = domain_hash(
            "FEE-TOKEN-SWAP-PAYMASTER:RISK-SNAPSHOT-ID",
            &[
                HashPart::Str(paymaster_id),
                HashPart::U64(liquidity_ratio_bps),
                HashPart::U64(config.l2_height),
            ],
            20,
        );
        Self {
            snapshot_id: snapshot_id.clone(),
            paymaster_id: paymaster_id.to_string(),
            exposure_root: deterministic_root("risk-exposure", &[&snapshot_id]),
            inventory_root: deterministic_root("risk-inventory", &[&snapshot_id]),
            hedge_root: deterministic_root("risk-hedge", &[&snapshot_id]),
            slippage_bucket_root: deterministic_root("risk-slippage-bucket", &[&snapshot_id]),
            liquidity_ratio_bps,
            route_health_bps: MAX_BPS.saturating_sub(liquidity_ratio_bps.min(MAX_BPS) / 10),
            observed_l2_height: config.l2_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "paymaster_id": self.paymaster_id,
            "exposure_root": self.exposure_root,
            "inventory_root": self.inventory_root,
            "hedge_root": self.hedge_root,
            "slippage_bucket_root": self.slippage_bucket_root,
            "liquidity_ratio_bps": self.liquidity_ratio_bps,
            "route_health_bps": self.route_health_bps,
            "observed_l2_height": self.observed_l2_height,
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
    pub l2_height: u64,
    pub sequence: u64,
}

impl PublicEvent {
    pub fn new(
        kind: impl Into<String>,
        subject_id: impl Into<String>,
        subject_root: impl Into<String>,
        state_root: impl Into<String>,
        l2_height: u64,
        sequence: u64,
    ) -> Self {
        let kind = kind.into();
        let subject_id = subject_id.into();
        let subject_root = subject_root.into();
        let state_root = state_root.into();
        let event_id = domain_hash(
            "FEE-TOKEN-SWAP-PAYMASTER:PUBLIC-EVENT-ID",
            &[
                HashPart::Str(&kind),
                HashPart::Str(&subject_id),
                HashPart::Str(&subject_root),
                HashPart::Str(&state_root),
                HashPart::U64(l2_height),
                HashPart::U64(sequence),
            ],
            20,
        );
        Self {
            event_id,
            kind,
            subject_id,
            subject_root,
            state_root,
            l2_height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "state_root": self.state_root,
            "l2_height": self.l2_height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub fee_tokens: BTreeMap<String, FeeToken>,
    pub paymasters: BTreeMap<String, Paymaster>,
    pub swap_quotes: BTreeMap<String, SwapQuote>,
    pub fee_intents: BTreeMap<String, FeeIntent>,
    pub route_plans: BTreeMap<String, RoutePlan>,
    pub pq_approvals: BTreeMap<String, PqApproval>,
    pub execution_receipts: BTreeMap<String, ExecutionReceipt>,
    pub rebate_coupons: BTreeMap<String, RebateCoupon>,
    pub vouchers: BTreeMap<String, FeeVoucher>,
    pub hedge_positions: BTreeMap<String, HedgePosition>,
    pub settlement_batches: BTreeMap<String, SettlementBatch>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub risk_snapshots: BTreeMap<String, RiskSnapshot>,
    pub public_events: Vec<PublicEvent>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            fee_tokens: BTreeMap::new(),
            paymasters: BTreeMap::new(),
            swap_quotes: BTreeMap::new(),
            fee_intents: BTreeMap::new(),
            route_plans: BTreeMap::new(),
            pq_approvals: BTreeMap::new(),
            execution_receipts: BTreeMap::new(),
            rebate_coupons: BTreeMap::new(),
            vouchers: BTreeMap::new(),
            hedge_positions: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            risk_snapshots: BTreeMap::new(),
            public_events: Vec::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let pfee = FeeToken::new(
            &state.config,
            DEFAULT_PRIVATE_FEE_TOKEN,
            FeeAssetKind::PrivateFeeToken,
            "issuer:pfee-devnet",
            12,
        );
        let pdusd = FeeToken::new(
            &state.config,
            DEFAULT_PRIVATE_STABLE_ASSET,
            FeeAssetKind::PrivateStable,
            "issuer:pdusd-devnet",
            6,
        );
        let _ = state.register_fee_token(pfee);
        let _ = state.register_fee_token(pdusd);

        let mut assets = BTreeSet::new();
        assets.insert(DEFAULT_PRIVATE_FEE_TOKEN.to_string());
        assets.insert(DEFAULT_PRIVATE_STABLE_ASSET.to_string());
        let mut lanes = BTreeSet::new();
        lanes.insert(RouteLane::WalletTransfer);
        lanes.insert(RouteLane::ContractCall);
        lanes.insert(RouteLane::RecursiveProof);
        lanes.insert(RouteLane::BlobDa);
        let paymaster_id = state
            .register_paymaster(
                "paymaster:alpha-operator",
                assets,
                lanes,
                125_000_000_000,
                1,
            )
            .unwrap_or_else(|_| "demo-paymaster".to_string());
        let voucher_id = state
            .mint_voucher(
                VoucherKind::RecursiveProof,
                "sponsor:proof-pool",
                "payer:demo-wallet",
                12_000_000,
                2,
            )
            .unwrap_or_else(|_| "demo-voucher".to_string());
        let quote_id = state
            .quote_swap(
                &paymaster_id,
                DEFAULT_PRIVATE_FEE_TOKEN,
                RouteLane::ContractCall,
                50_000_000,
                9_500_000,
                25,
                3,
            )
            .unwrap_or_else(|_| "demo-quote".to_string());
        let mut vouchers = BTreeSet::new();
        vouchers.insert(voucher_id);
        let intent_id = state
            .submit_fee_intent(
                "payer:demo-wallet",
                DEFAULT_PRIVATE_FEE_TOKEN,
                RouteLane::ContractCall,
                50_000_000,
                10_000_000,
                vouchers,
                4,
            )
            .unwrap_or_else(|_| "demo-intent".to_string());
        let approval_id = state
            .approve_intent(&intent_id, &quote_id, "payer:pq-signer", 5)
            .unwrap_or_else(|_| "demo-approval".to_string());
        let plan_id = state
            .build_route_plan(&intent_id, &quote_id, &approval_id)
            .unwrap_or_else(|_| "demo-plan".to_string());
        let receipt_id = state
            .execute_route(&plan_id, 9_450_000, 49_750_000, 18)
            .unwrap_or_else(|_| "demo-receipt".to_string());
        let _ = state.issue_rebate(&receipt_id, "payer:demo-wallet", "sponsor:rebate-pool");
        let _ = state.open_hedge_position(
            &paymaster_id,
            HedgeKind::AmmSwap,
            DEFAULT_PRIVATE_FEE_TOKEN,
            49_750_000,
            9_450_000,
            6,
        );
        let _ = state.record_risk_snapshot(&paymaster_id, 2_400);
        state.refresh_roots();
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_approval_suite": PQ_APPROVAL_SUITE,
            "public_record_suite": PUBLIC_RECORD_SUITE,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        ensure!(
            self.fee_tokens.len() <= MAX_FEE_TOKENS,
            "fee token table exceeds limit"
        );
        ensure!(
            self.paymasters.len() <= MAX_PAYMASTERS,
            "paymaster table exceeds limit"
        );
        ensure!(
            self.swap_quotes.len() <= MAX_SWAP_QUOTES,
            "swap quote table exceeds limit"
        );
        ensure!(
            self.fee_intents.len() <= MAX_FEE_INTENTS,
            "fee intent table exceeds limit"
        );
        ensure!(
            self.route_plans.len() <= MAX_ROUTE_PLANS,
            "route plan table exceeds limit"
        );
        ensure!(
            self.pq_approvals.len() <= MAX_PQ_APPROVALS,
            "pq approval table exceeds limit"
        );
        ensure!(
            self.execution_receipts.len() <= MAX_EXECUTION_RECEIPTS,
            "execution receipt table exceeds limit"
        );
        ensure!(
            self.rebate_coupons.len() <= MAX_REBATE_COUPONS,
            "rebate coupon table exceeds limit"
        );
        ensure!(
            self.vouchers.len() <= MAX_VOUCHERS,
            "voucher table exceeds limit"
        );
        ensure!(
            self.hedge_positions.len() <= MAX_HEDGE_POSITIONS,
            "hedge table exceeds limit"
        );
        ensure!(
            self.settlement_batches.len() <= MAX_SETTLEMENT_BATCHES,
            "settlement table exceeds limit"
        );
        ensure!(
            self.privacy_fences.len() <= MAX_PRIVACY_FENCES,
            "privacy fence table exceeds limit"
        );
        ensure!(
            self.public_events.len() <= MAX_PUBLIC_EVENTS,
            "public event table exceeds limit"
        );
        Ok(())
    }

    pub fn refresh_roots(&mut self) {
        self.counters.fee_tokens = self.fee_tokens.len() as u64;
        self.counters.paymasters = self.paymasters.len() as u64;
        self.counters.swap_quotes = self.swap_quotes.len() as u64;
        self.counters.fee_intents = self.fee_intents.len() as u64;
        self.counters.route_plans = self.route_plans.len() as u64;
        self.counters.pq_approvals = self.pq_approvals.len() as u64;
        self.counters.execution_receipts = self.execution_receipts.len() as u64;
        self.counters.rebate_coupons = self.rebate_coupons.len() as u64;
        self.counters.vouchers = self.vouchers.len() as u64;
        self.counters.hedge_positions = self.hedge_positions.len() as u64;
        self.counters.settlement_batches = self.settlement_batches.len() as u64;
        self.counters.privacy_fences = self.privacy_fences.len() as u64;
        self.counters.risk_snapshots = self.risk_snapshots.len() as u64;
        self.counters.public_events = self.public_events.len() as u64;
        self.roots.fee_token_root =
            map_root("fee-token-swap-paymaster-fee-tokens", &self.fee_tokens);
        self.roots.paymaster_root =
            map_root("fee-token-swap-paymaster-paymasters", &self.paymasters);
        self.roots.swap_quote_root =
            map_root("fee-token-swap-paymaster-swap-quotes", &self.swap_quotes);
        self.roots.fee_intent_root =
            map_root("fee-token-swap-paymaster-fee-intents", &self.fee_intents);
        self.roots.route_plan_root =
            map_root("fee-token-swap-paymaster-route-plans", &self.route_plans);
        self.roots.pq_approval_root =
            map_root("fee-token-swap-paymaster-pq-approvals", &self.pq_approvals);
        self.roots.execution_receipt_root = map_root(
            "fee-token-swap-paymaster-execution-receipts",
            &self.execution_receipts,
        );
        self.roots.rebate_root = map_root("fee-token-swap-paymaster-rebates", &self.rebate_coupons);
        self.roots.voucher_root = map_root("fee-token-swap-paymaster-vouchers", &self.vouchers);
        self.roots.hedge_root = map_root("fee-token-swap-paymaster-hedges", &self.hedge_positions);
        self.roots.settlement_root = map_root(
            "fee-token-swap-paymaster-settlement-batches",
            &self.settlement_batches,
        );
        self.roots.privacy_fence_root = map_root(
            "fee-token-swap-paymaster-privacy-fences",
            &self.privacy_fences,
        );
        self.roots.risk_root = map_root(
            "fee-token-swap-paymaster-risk-snapshots",
            &self.risk_snapshots,
        );
        self.roots.public_event_root = vec_root(
            "fee-token-swap-paymaster-public-events",
            &self.public_events,
        );
        self.roots.liquidity_index_root = self.liquidity_index_root();
        self.roots.paymaster_asset_index_root = self.paymaster_asset_index_root();
        self.roots.state_root = state_root_from_roots(&self.roots, &self.counters, &self.config);
    }

    pub fn register_fee_token(&mut self, token: FeeToken) -> Result<String> {
        self.validate()?;
        ensure!(token.kind.is_private_payment(), "fee token must be private");
        ensure!(
            self.config
                .accepted_private_fee_assets
                .contains(&token.asset_id),
            "fee token not accepted by config"
        );
        ensure!(
            token.min_privacy_set_size >= self.config.min_privacy_set_size,
            "token privacy set below policy"
        );
        let asset_id = token.asset_id.clone();
        self.fee_tokens.insert(asset_id.clone(), token);
        self.refresh_roots();
        self.append_public_event("register_fee_token", &asset_id);
        Ok(asset_id)
    }

    pub fn register_paymaster(
        &mut self,
        operator_commitment: impl Into<String>,
        supported_assets: BTreeSet<String>,
        supported_lanes: BTreeSet<RouteLane>,
        piconero_liquidity: u128,
        nonce: u64,
    ) -> Result<String> {
        self.validate()?;
        ensure!(!supported_assets.is_empty(), "paymaster supports no assets");
        ensure!(!supported_lanes.is_empty(), "paymaster supports no lanes");
        ensure!(
            piconero_liquidity >= self.config.min_paymaster_liquidity_piconero,
            "paymaster liquidity below minimum"
        );
        for asset_id in &supported_assets {
            ensure!(
                self.config.accepted_private_fee_assets.contains(asset_id),
                "paymaster asset is not accepted"
            );
        }
        let paymaster = Paymaster::new(
            &self.config,
            operator_commitment,
            supported_assets,
            supported_lanes,
            piconero_liquidity,
            nonce,
        );
        let paymaster_id = paymaster.paymaster_id.clone();
        self.paymasters.insert(paymaster_id.clone(), paymaster);
        self.refresh_roots();
        self.append_public_event("register_paymaster", &paymaster_id);
        Ok(paymaster_id)
    }

    pub fn quote_swap(
        &mut self,
        paymaster_id: &str,
        fee_asset_id: &str,
        lane: RouteLane,
        private_fee_amount_micro_units: u128,
        piconero_fee_amount: u128,
        max_slippage_bps: u64,
        nonce: u64,
    ) -> Result<String> {
        self.validate()?;
        let paymaster = self
            .paymasters
            .get(paymaster_id)
            .ok_or_else(|| "unknown paymaster".to_string())?;
        ensure!(paymaster.status.usable(), "paymaster not usable");
        ensure!(
            paymaster.supported_assets.contains(fee_asset_id),
            "paymaster does not support fee asset"
        );
        ensure!(
            paymaster.supported_lanes.contains(&lane),
            "paymaster does not support route lane"
        );
        ensure!(
            self.fee_tokens
                .get(fee_asset_id)
                .map(|token| token.enabled)
                .unwrap_or(false),
            "fee token is not enabled"
        );
        ensure!(
            max_slippage_bps <= self.config.max_slippage_bps,
            "quote slippage above configured cap"
        );
        ensure!(
            piconero_fee_amount <= paymaster.piconero_liquidity,
            "paymaster has insufficient piconero liquidity"
        );
        let quote = SwapQuote::new(
            &self.config,
            paymaster_id,
            fee_asset_id,
            lane,
            private_fee_amount_micro_units,
            piconero_fee_amount,
            max_slippage_bps,
            nonce,
        );
        let quote_id = quote.quote_id.clone();
        self.swap_quotes.insert(quote_id.clone(), quote);
        self.refresh_roots();
        self.append_public_event("quote_swap", &quote_id);
        Ok(quote_id)
    }

    pub fn mint_voucher(
        &mut self,
        kind: VoucherKind,
        sponsor_commitment: impl Into<String>,
        beneficiary_commitment: impl Into<String>,
        value_piconero: u128,
        nonce: u64,
    ) -> Result<String> {
        self.validate()?;
        ensure!(value_piconero > 0, "voucher value must be positive");
        let voucher = FeeVoucher::new(
            &self.config,
            kind,
            sponsor_commitment,
            beneficiary_commitment,
            value_piconero,
            nonce,
        );
        let voucher_id = voucher.voucher_id.clone();
        self.counters.voucher_value_reserved = self
            .counters
            .voucher_value_reserved
            .saturating_add(value_piconero);
        self.vouchers.insert(voucher_id.clone(), voucher);
        self.refresh_roots();
        self.append_public_event("mint_voucher", &voucher_id);
        Ok(voucher_id)
    }

    pub fn submit_fee_intent(
        &mut self,
        payer_commitment: impl Into<String>,
        fee_asset_id: impl Into<String>,
        lane: RouteLane,
        max_fee_token_micro_units: u128,
        max_piconero_fee: u128,
        voucher_ids: BTreeSet<String>,
        nonce: u64,
    ) -> Result<String> {
        self.validate()?;
        let fee_asset_id = fee_asset_id.into();
        ensure!(
            self.fee_tokens.contains_key(&fee_asset_id),
            "unknown fee token"
        );
        ensure!(
            max_fee_token_micro_units > 0,
            "max fee token amount must be positive"
        );
        ensure!(max_piconero_fee > 0, "max piconero fee must be positive");
        for voucher_id in &voucher_ids {
            let voucher = self
                .vouchers
                .get(voucher_id)
                .ok_or_else(|| "unknown voucher in intent".to_string())?;
            ensure!(
                matches!(
                    voucher.status,
                    VoucherStatus::Minted | VoucherStatus::Reserved
                ),
                "voucher is not usable"
            );
        }
        let mut intent = FeeIntent::new(
            &self.config,
            payer_commitment,
            fee_asset_id,
            lane,
            max_fee_token_micro_units,
            max_piconero_fee,
            nonce,
        );
        intent.voucher_ids = voucher_ids;
        let intent_id = intent.intent_id.clone();
        self.fee_intents.insert(intent_id.clone(), intent);
        self.refresh_roots();
        self.append_public_event("submit_fee_intent", &intent_id);
        Ok(intent_id)
    }

    pub fn approve_intent(
        &mut self,
        intent_id: &str,
        quote_id: &str,
        signer_commitment: impl Into<String>,
        nonce: u64,
    ) -> Result<String> {
        self.validate()?;
        let intent = self
            .fee_intents
            .get(intent_id)
            .ok_or_else(|| "unknown fee intent".to_string())?;
        let quote = self
            .swap_quotes
            .get(quote_id)
            .ok_or_else(|| "unknown swap quote".to_string())?;
        ensure!(intent.status.live(), "intent not live");
        ensure!(quote.status.live(), "quote not live");
        ensure!(
            intent.fee_asset_id == quote.fee_asset_id,
            "intent and quote asset mismatch"
        );
        ensure!(intent.lane == quote.lane, "intent and quote lane mismatch");
        ensure!(
            quote.private_fee_amount_micro_units <= intent.max_fee_token_micro_units,
            "quote exceeds user private fee cap"
        );
        ensure!(
            quote.piconero_fee_amount <= intent.max_piconero_fee,
            "quote exceeds user piconero fee cap"
        );
        ensure!(
            quote.max_slippage_bps <= intent.max_slippage_bps,
            "quote exceeds user slippage cap"
        );
        let approval = PqApproval::new(&self.config, intent_id, quote_id, signer_commitment, nonce);
        let approval_id = approval.approval_id.clone();
        self.pq_approvals.insert(approval_id.clone(), approval);
        if let Some(intent) = self.fee_intents.get_mut(intent_id) {
            intent.status = IntentStatus::Approved;
        }
        if let Some(quote) = self.swap_quotes.get_mut(quote_id) {
            quote.status = QuoteStatus::Reserved;
        }
        self.refresh_roots();
        self.append_public_event("approve_intent", &approval_id);
        Ok(approval_id)
    }

    pub fn build_route_plan(
        &mut self,
        intent_id: &str,
        quote_id: &str,
        approval_id: &str,
    ) -> Result<String> {
        self.validate()?;
        let intent = self
            .fee_intents
            .get(intent_id)
            .ok_or_else(|| "unknown fee intent".to_string())?;
        let quote = self
            .swap_quotes
            .get(quote_id)
            .ok_or_else(|| "unknown swap quote".to_string())?;
        let approval = self
            .pq_approvals
            .get(approval_id)
            .ok_or_else(|| "unknown pq approval".to_string())?;
        ensure!(
            approval.status == ApprovalStatus::Verified,
            "pq approval not verified"
        );
        ensure!(
            approval.intent_id == intent.intent_id && approval.quote_id == quote.quote_id,
            "approval does not bind intent and quote"
        );
        ensure!(
            intent.voucher_ids.len().saturating_add(3) <= self.config.max_route_hops,
            "route exceeds max hop count"
        );
        let plan = RoutePlan::from_parts(
            &self.config,
            intent,
            quote,
            approval_id,
            intent.voucher_ids.clone(),
        );
        let plan_id = plan.plan_id.clone();
        self.route_plans.insert(plan_id.clone(), plan);
        if let Some(intent) = self.fee_intents.get_mut(intent_id) {
            intent.status = IntentStatus::Routed;
        }
        self.refresh_roots();
        self.append_public_event("build_route_plan", &plan_id);
        Ok(plan_id)
    }

    pub fn execute_route(
        &mut self,
        plan_id: &str,
        actual_piconero_paid: u128,
        actual_private_fee_collected: u128,
        slippage_bps: u64,
    ) -> Result<String> {
        self.validate()?;
        let plan = self
            .route_plans
            .get(plan_id)
            .ok_or_else(|| "unknown route plan".to_string())?;
        ensure!(
            slippage_bps <= self.config.max_slippage_bps,
            "execution slippage above configured cap"
        );
        ensure!(
            actual_piconero_paid <= plan.expected_piconero_fee,
            "actual piconero exceeds expected fee"
        );
        ensure!(
            actual_private_fee_collected <= plan.expected_private_fee_token,
            "actual private fee exceeds expected"
        );
        let paymaster = self
            .paymasters
            .get_mut(&plan.paymaster_id)
            .ok_or_else(|| "unknown paymaster for route".to_string())?;
        ensure!(
            paymaster.piconero_liquidity >= actual_piconero_paid,
            "paymaster liquidity below execution amount"
        );
        paymaster.piconero_liquidity = paymaster
            .piconero_liquidity
            .saturating_sub(actual_piconero_paid);
        paymaster.status = PaymasterStatus::Routing;
        let receipt = ExecutionReceipt::new(
            &self.config,
            plan,
            actual_piconero_paid,
            actual_private_fee_collected,
            slippage_bps,
        );
        let receipt_id = receipt.receipt_id.clone();
        let intent_id = receipt.intent_id.clone();
        let quote_id = plan.quote_id.clone();
        let approval_id = plan.approval_id.clone();
        self.counters.piconero_sponsored = self
            .counters
            .piconero_sponsored
            .saturating_add(actual_piconero_paid);
        self.counters.private_token_collected = self
            .counters
            .private_token_collected
            .saturating_add(actual_private_fee_collected);
        self.execution_receipts.insert(receipt_id.clone(), receipt);
        if let Some(intent) = self.fee_intents.get_mut(&intent_id) {
            intent.status = IntentStatus::Executed;
        }
        if let Some(quote) = self.swap_quotes.get_mut(&quote_id) {
            quote.status = QuoteStatus::Filled;
        }
        if let Some(approval) = self.pq_approvals.get_mut(&approval_id) {
            approval.status = ApprovalStatus::Consumed;
        }
        self.refresh_roots();
        self.append_public_event("execute_route", &receipt_id);
        Ok(receipt_id)
    }

    pub fn reject_for_slippage(
        &mut self,
        quote_id: &str,
        observed_slippage_bps: u64,
    ) -> Result<()> {
        let quote = self
            .swap_quotes
            .get_mut(quote_id)
            .ok_or_else(|| "unknown quote".to_string())?;
        ensure!(
            observed_slippage_bps > quote.max_slippage_bps,
            "observed slippage does not exceed quote cap"
        );
        quote.status = QuoteStatus::SlippageRejected;
        self.counters.slippage_rejections = self.counters.slippage_rejections.saturating_add(1);
        self.refresh_roots();
        self.append_public_event("reject_for_slippage", quote_id);
        Ok(())
    }

    pub fn issue_rebate(
        &mut self,
        receipt_id: &str,
        payer_commitment: &str,
        sponsor_commitment: &str,
    ) -> Result<String> {
        self.validate()?;
        let receipt = self
            .execution_receipts
            .get(receipt_id)
            .ok_or_else(|| "unknown execution receipt".to_string())?;
        let rebate_amount = receipt
            .actual_piconero_paid
            .saturating_mul(self.config.target_rebate_bps as u128)
            / MAX_BPS as u128;
        ensure!(rebate_amount > 0, "rebate amount is zero");
        let rebate = RebateCoupon::new(
            &self.config,
            receipt,
            payer_commitment,
            sponsor_commitment,
            rebate_amount,
        );
        let rebate_id = rebate.rebate_id.clone();
        let intent_id = receipt.intent_id.clone();
        self.rebate_coupons.insert(rebate_id.clone(), rebate);
        self.counters.rebates_reserved =
            self.counters.rebates_reserved.saturating_add(rebate_amount);
        if let Some(receipt) = self.execution_receipts.get_mut(receipt_id) {
            receipt.rebate_id = Some(rebate_id.clone());
        }
        if let Some(intent) = self.fee_intents.get_mut(&intent_id) {
            intent.status = IntentStatus::Rebated;
        }
        self.refresh_roots();
        self.append_public_event("issue_rebate", &rebate_id);
        Ok(rebate_id)
    }

    pub fn open_hedge_position(
        &mut self,
        paymaster_id: &str,
        kind: HedgeKind,
        source_asset_id: &str,
        source_amount: u128,
        notional_piconero: u128,
        nonce: u64,
    ) -> Result<String> {
        self.validate()?;
        let paymaster = self
            .paymasters
            .get_mut(paymaster_id)
            .ok_or_else(|| "unknown paymaster".to_string())?;
        ensure!(paymaster.status.usable(), "paymaster not usable for hedge");
        ensure!(
            paymaster.supported_assets.contains(source_asset_id),
            "paymaster cannot hedge unsupported source asset"
        );
        let hedge = HedgePosition::new(
            &self.config,
            paymaster_id,
            kind,
            source_asset_id,
            source_amount,
            notional_piconero,
            nonce,
        );
        let hedge_id = hedge.hedge_id.clone();
        paymaster.status = PaymasterStatus::Hedging;
        self.counters.hedge_notional_piconero = self
            .counters
            .hedge_notional_piconero
            .saturating_add(notional_piconero);
        self.hedge_positions.insert(hedge_id.clone(), hedge);
        self.refresh_roots();
        self.append_public_event("open_hedge_position", &hedge_id);
        Ok(hedge_id)
    }

    pub fn settle_hedge(
        &mut self,
        hedge_id: &str,
        settlement_root: impl Into<String>,
    ) -> Result<()> {
        let hedge = self
            .hedge_positions
            .get_mut(hedge_id)
            .ok_or_else(|| "unknown hedge".to_string())?;
        ensure!(
            matches!(
                hedge.status,
                HedgeStatus::Planned | HedgeStatus::Reserved | HedgeStatus::Executed
            ),
            "hedge is not settleable"
        );
        hedge.status = HedgeStatus::Settled;
        hedge.settlement_root = settlement_root.into();
        self.refresh_roots();
        self.append_public_event("settle_hedge", hedge_id);
        Ok(())
    }

    pub fn open_settlement_batch(
        &mut self,
        paymaster_id: &str,
        receipt_ids: BTreeSet<String>,
        hedge_ids: BTreeSet<String>,
        voucher_ids: BTreeSet<String>,
        rebate_ids: BTreeSet<String>,
        nonce: u64,
    ) -> Result<String> {
        self.validate()?;
        ensure!(
            self.paymasters.contains_key(paymaster_id),
            "unknown paymaster"
        );
        let item_count = receipt_ids
            .len()
            .saturating_add(hedge_ids.len())
            .saturating_add(voucher_ids.len())
            .saturating_add(rebate_ids.len());
        ensure!(
            item_count <= self.config.max_batch_items,
            "settlement batch too large"
        );
        for receipt_id in &receipt_ids {
            ensure!(
                self.execution_receipts.contains_key(receipt_id),
                "unknown receipt in settlement"
            );
        }
        for hedge_id in &hedge_ids {
            ensure!(
                self.hedge_positions.contains_key(hedge_id),
                "unknown hedge in settlement"
            );
        }
        for voucher_id in &voucher_ids {
            ensure!(
                self.vouchers.contains_key(voucher_id),
                "unknown voucher in settlement"
            );
        }
        for rebate_id in &rebate_ids {
            ensure!(
                self.rebate_coupons.contains_key(rebate_id),
                "unknown rebate in settlement"
            );
        }
        let batch = SettlementBatch::new(
            &self.config,
            paymaster_id,
            receipt_ids,
            hedge_ids,
            voucher_ids,
            rebate_ids,
            nonce,
        );
        let batch_id = batch.batch_id.clone();
        self.settlement_batches.insert(batch_id.clone(), batch);
        if let Some(paymaster) = self.paymasters.get_mut(paymaster_id) {
            paymaster.status = PaymasterStatus::Settling;
        }
        self.refresh_roots();
        self.append_public_event("open_settlement_batch", &batch_id);
        Ok(batch_id)
    }

    pub fn anchor_settlement_batch(
        &mut self,
        batch_id: &str,
        proof_root: impl Into<String>,
        da_root: impl Into<String>,
        anchor_root: impl Into<String>,
    ) -> Result<()> {
        let batch = self
            .settlement_batches
            .get_mut(batch_id)
            .ok_or_else(|| "unknown settlement batch".to_string())?;
        ensure!(
            matches!(
                batch.status,
                SettlementStatus::Open | SettlementStatus::Netting | SettlementStatus::Proving
            ),
            "settlement batch cannot be anchored"
        );
        batch.proof_root = proof_root.into();
        batch.da_root = da_root.into();
        batch.anchor_root = anchor_root.into();
        batch.status = SettlementStatus::Anchored;
        self.refresh_roots();
        self.append_public_event("anchor_settlement_batch", batch_id);
        Ok(())
    }

    pub fn settle_batch(&mut self, batch_id: &str) -> Result<()> {
        let paymaster_id = {
            let batch = self
                .settlement_batches
                .get_mut(batch_id)
                .ok_or_else(|| "unknown settlement batch".to_string())?;
            ensure!(
                matches!(
                    batch.status,
                    SettlementStatus::Anchored | SettlementStatus::Proving
                ),
                "batch must be anchored before settlement"
            );
            batch.status = SettlementStatus::Settled;
            batch.paymaster_id.clone()
        };
        if let Some(paymaster) = self.paymasters.get_mut(&paymaster_id) {
            paymaster.status = PaymasterStatus::Active;
        }
        self.refresh_roots();
        self.append_public_event("settle_batch", batch_id);
        Ok(())
    }

    pub fn arm_privacy_fence(
        &mut self,
        kind: impl Into<String>,
        subject_id: impl Into<String>,
        nullifier_root: impl Into<String>,
        commitment_root: impl Into<String>,
    ) -> Result<String> {
        self.validate()?;
        let fence = PrivacyFence::new(
            &self.config,
            kind,
            subject_id,
            nullifier_root,
            commitment_root,
        );
        let fence_id = fence.fence_id.clone();
        self.privacy_fences.insert(fence_id.clone(), fence);
        self.refresh_roots();
        self.append_public_event("arm_privacy_fence", &fence_id);
        Ok(fence_id)
    }

    pub fn record_risk_snapshot(
        &mut self,
        paymaster_id: &str,
        liquidity_ratio_bps: u64,
    ) -> Result<String> {
        ensure!(
            self.paymasters.contains_key(paymaster_id),
            "unknown paymaster"
        );
        ensure!(
            liquidity_ratio_bps <= MAX_BPS,
            "liquidity ratio outside bps range"
        );
        let snapshot = RiskSnapshot::new(&self.config, paymaster_id, liquidity_ratio_bps);
        let snapshot_id = snapshot.snapshot_id.clone();
        self.risk_snapshots.insert(snapshot_id.clone(), snapshot);
        self.refresh_roots();
        self.append_public_event("record_risk_snapshot", &snapshot_id);
        Ok(snapshot_id)
    }

    fn append_public_event(&mut self, kind: &str, subject_id: &str) {
        let subject_root = deterministic_root("public-event-subject", &[kind, subject_id]);
        let sequence = self.public_events.len() as u64;
        let event = PublicEvent::new(
            kind,
            subject_id,
            subject_root,
            self.roots.state_root.clone(),
            self.config.l2_height,
            sequence,
        );
        self.public_events.push(event);
        self.counters.public_events = self.public_events.len() as u64;
        self.roots.public_event_root = vec_root(
            "fee-token-swap-paymaster-public-events",
            &self.public_events,
        );
        self.roots.state_root = state_root_from_roots(&self.roots, &self.counters, &self.config);
    }

    fn liquidity_index_root(&self) -> String {
        let leaves = self
            .paymasters
            .values()
            .map(|paymaster| {
                json!({
                    "paymaster_id": paymaster.paymaster_id,
                    "status": paymaster.status,
                    "piconero_liquidity_commitment": amount_commitment(
                        "liquidity-index-piconero",
                        &paymaster.paymaster_id,
                        paymaster.piconero_liquidity
                    ),
                    "asset_root": root_from_set(
                        "liquidity-index-supported-assets",
                        &paymaster.supported_assets
                    ),
                    "lane_root": route_lane_set_root(
                        "liquidity-index-supported-lanes",
                        &paymaster.supported_lanes
                    )
                })
            })
            .collect::<Vec<_>>();
        merkle_root("fee-token-swap-paymaster-liquidity-index", &leaves)
    }

    fn paymaster_asset_index_root(&self) -> String {
        let mut index: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for paymaster in self.paymasters.values() {
            for asset_id in &paymaster.supported_assets {
                index
                    .entry(asset_id.clone())
                    .or_default()
                    .insert(paymaster.paymaster_id.clone());
            }
        }
        let leaves = index
            .iter()
            .map(|(asset_id, paymaster_ids)| {
                json!({
                    "asset_id": asset_id,
                    "paymaster_root": root_from_set(
                        "asset-index-paymasters",
                        paymaster_ids
                    )
                })
            })
            .collect::<Vec<_>>();
        merkle_root("fee-token-swap-paymaster-asset-index", &leaves)
    }
}

pub fn devnet() -> Runtime {
    State::devnet()
}

pub fn demo() -> Runtime {
    State::demo()
}

pub fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

pub fn root_from_values(domain: &str, values: &[Value]) -> String {
    merkle_root(domain, values)
}

pub fn root_from_strings(domain: &str, values: &[&str]) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn root_from_set(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn route_lane_set_root(domain: &str, values: &BTreeSet<RouteLane>) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({ "lane": value.as_str(), "weight": value.priority_weight() }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

pub fn deterministic_root(domain: &str, parts: &[&str]) -> String {
    let hash_parts = parts
        .iter()
        .map(|part| HashPart::Str(*part))
        .collect::<Vec<_>>();
    domain_hash(domain, &hash_parts, 32)
}

pub fn deterministic_id(domain: &str, parts: &[&str]) -> String {
    let hash_parts = parts
        .iter()
        .map(|part| HashPart::Str(*part))
        .collect::<Vec<_>>();
    domain_hash(domain, &hash_parts, 20)
}

pub fn amount_commitment(domain: &str, subject_id: &str, amount: u128) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(subject_id),
            HashPart::Str(&amount.to_string()),
        ],
        32,
    )
}

pub fn share_commitment(domain: &str, subject_id: &str, amount: u128, share_bps: u64) -> String {
    let share = amount.saturating_mul(share_bps as u128) / MAX_BPS as u128;
    domain_hash(
        domain,
        &[
            HashPart::Str(subject_id),
            HashPart::Str(&share.to_string()),
            HashPart::U64(share_bps),
        ],
        32,
    )
}

pub fn apply_bps_floor(amount: u128, bps: u64) -> u128 {
    let clipped = bps.min(MAX_BPS);
    amount.saturating_mul((MAX_BPS - clipped) as u128) / MAX_BPS as u128
}

pub fn json_commitment<T: Serialize>(domain: &str, value: &T) -> String {
    let encoded = serde_json::to_value(value).unwrap_or_else(|_| json!({"encoding": "failed"}));
    domain_hash(domain, &[HashPart::Json(&encoded)], 32)
}

pub fn map_root<T: Serialize>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| {
            let encoded = serde_json::to_value(value).unwrap_or_else(|_| json!({}));
            json!({ "key": key, "value": encoded })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn vec_root<T: Serialize>(domain: &str, values: &[T]) -> String {
    let leaves = values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let encoded = serde_json::to_value(value).unwrap_or_else(|_| json!({}));
            json!({ "index": index, "value": encoded })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn state_root_from_roots(roots: &Roots, counters: &Counters, config: &Config) -> String {
    let payload = json!({
        "protocol_version": PROTOCOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "chain_id": config.chain_id,
        "l2_height": config.l2_height,
        "monero_height": config.monero_height,
        "epoch": config.epoch,
        "fee_token_root": roots.fee_token_root,
        "paymaster_root": roots.paymaster_root,
        "swap_quote_root": roots.swap_quote_root,
        "fee_intent_root": roots.fee_intent_root,
        "route_plan_root": roots.route_plan_root,
        "pq_approval_root": roots.pq_approval_root,
        "execution_receipt_root": roots.execution_receipt_root,
        "rebate_root": roots.rebate_root,
        "voucher_root": roots.voucher_root,
        "hedge_root": roots.hedge_root,
        "settlement_root": roots.settlement_root,
        "privacy_fence_root": roots.privacy_fence_root,
        "risk_root": roots.risk_root,
        "public_event_root": roots.public_event_root,
        "liquidity_index_root": roots.liquidity_index_root,
        "paymaster_asset_index_root": roots.paymaster_asset_index_root,
        "counters": counters.public_record(),
    });
    domain_hash(
        "fee-token-swap-paymaster-state-root",
        &[HashPart::Json(&payload)],
        32,
    )
}
