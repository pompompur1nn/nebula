use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type RuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_DYNAMIC_FEE_COUPON_ROUTER_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-low-fee-pq-confidential-dynamic-fee-coupon-router-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_DYNAMIC_FEE_COUPON_ROUTER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const PQ_COUPON_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-dynamic-fee-coupon-v1";
pub const CONFIDENTIAL_COUPON_SUITE: &str =
    "private-l2-low-fee-confidential-dynamic-coupon-note-v1";
pub const SPONSOR_POOL_SUITE: &str = "private-l2-low-fee-sponsor-pool-nullifier-fence-v1";
pub const CROSS_ASSET_COUPON_SUITE: &str = "private-l2-low-fee-cross-asset-confidential-coupon-v1";
pub const TOKEN_GAS_DISCOUNT_SUITE: &str = "private-l2-low-fee-token-gas-discount-private-defi-v1";
pub const REBATE_SETTLEMENT_SUITE: &str = "private-l2-confidential-rebate-settlement-v1";
pub const REDACTION_BUDGET_SUITE: &str = "monero-private-l2-redaction-budget-root-v1";
pub const OPERATOR_SUMMARY_SUITE: &str = "operator-safe-roots-only-summary-v1";
pub const DEVNET_L2_HEIGHT: u64 = 2_420_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_760_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 4_096;
pub const DEFAULT_TARGET_USER_FEE_BPS: u64 = 9;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const DEFAULT_MIN_SPONSOR_RESERVE_MICRO: u64 = 50_000_000;
pub const DEFAULT_COUPON_TTL_BLOCKS: u64 = 72;
pub const DEFAULT_SPONSOR_POOL_TTL_BLOCKS: u64 = 21_600;
pub const DEFAULT_WALLET_CAP_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_REDACTION_WINDOW_BLOCKS: u64 = 1_440;
pub const DEFAULT_MAX_WALLET_CAP_MICRO: u64 = 2_500_000;
pub const DEFAULT_MAX_REDACTIONS_PER_WINDOW: u32 = 12;
pub const DEFAULT_OPERATOR_SUMMARY_LIMIT: usize = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeLane {
    MoneroPrivateTransfer,
    PrivateContractCall,
    DefiSwap,
    DefiLending,
    ConfidentialTokenTransfer,
    BridgeExit,
    WalletSession,
    MerchantPayment,
}

impl FeeLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroPrivateTransfer => "monero_private_transfer",
            Self::PrivateContractCall => "private_contract_call",
            Self::DefiSwap => "defi_swap",
            Self::DefiLending => "defi_lending",
            Self::ConfidentialTokenTransfer => "confidential_token_transfer",
            Self::BridgeExit => "bridge_exit",
            Self::WalletSession => "wallet_session",
            Self::MerchantPayment => "merchant_payment",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Quoted,
    Minted,
    Reserved,
    Applied,
    Rebated,
    Settled,
    Revoked,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorPoolStatus {
    Open,
    Throttled,
    Draining,
    Paused,
    Slashed,
    Closed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Queued,
    Netting,
    Settled,
    Disputed,
    Refunded,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AbuseSeverity {
    Watch,
    SoftLimit,
    Slashable,
    Critical,
}

impl AbuseSeverity {
    pub fn slash_bps(self) -> u64 {
        match self {
            Self::Watch => 0,
            Self::SoftLimit => 250,
            Self::Slashable => 1_500,
            Self::Critical => 4_000,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_user_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub min_sponsor_reserve_micro: u64,
    pub coupon_ttl_blocks: u64,
    pub sponsor_pool_ttl_blocks: u64,
    pub wallet_cap_window_blocks: u64,
    pub redaction_window_blocks: u64,
    pub max_wallet_cap_micro: u64,
    pub max_redactions_per_window: u32,
    pub operator_summary_limit: usize,
    pub accepted_fee_assets: BTreeSet<String>,
    pub accepted_discount_tokens: BTreeSet<String>,
    pub sponsor_allowlist_root: String,
    pub private_l2_ux_profile: String,
}

impl Config {
    pub fn devnet() -> Self {
        let mut accepted_fee_assets = BTreeSet::new();
        accepted_fee_assets.insert("piconero-devnet".to_string());
        accepted_fee_assets.insert("pdusd-devnet".to_string());
        accepted_fee_assets.insert("pxmr-l2-devnet".to_string());
        accepted_fee_assets.insert("defi-basket-lowfee-devnet".to_string());

        let mut accepted_discount_tokens = BTreeSet::new();
        accepted_discount_tokens.insert("NEBULA".to_string());
        accepted_discount_tokens.insert("pDUSD".to_string());
        accepted_discount_tokens.insert("pXMR".to_string());
        accepted_discount_tokens.insert("LP-LOWFEE".to_string());

        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            min_sponsor_reserve_micro: DEFAULT_MIN_SPONSOR_RESERVE_MICRO,
            coupon_ttl_blocks: DEFAULT_COUPON_TTL_BLOCKS,
            sponsor_pool_ttl_blocks: DEFAULT_SPONSOR_POOL_TTL_BLOCKS,
            wallet_cap_window_blocks: DEFAULT_WALLET_CAP_WINDOW_BLOCKS,
            redaction_window_blocks: DEFAULT_REDACTION_WINDOW_BLOCKS,
            max_wallet_cap_micro: DEFAULT_MAX_WALLET_CAP_MICRO,
            max_redactions_per_window: DEFAULT_MAX_REDACTIONS_PER_WINDOW,
            operator_summary_limit: DEFAULT_OPERATOR_SUMMARY_LIMIT,
            accepted_fee_assets,
            accepted_discount_tokens,
            sponsor_allowlist_root: root_from_values("devnet-sponsor-allowlist", &[]),
            private_l2_ux_profile: "monero-private-l2-low-fee-wallet-v1".to_string(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        require(self.chain_id == CHAIN_ID, "config chain id mismatch")?;
        require(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "pq security below policy",
        )?;
        require(
            self.min_privacy_set_size >= DEFAULT_MIN_PRIVACY_SET_SIZE,
            "privacy set below policy",
        )?;
        require(
            self.target_user_fee_bps <= self.max_user_fee_bps,
            "target fee above max",
        )?;
        require(self.max_user_fee_bps <= MAX_BPS, "max fee above bps range")?;
        require(
            !self.accepted_fee_assets.is_empty(),
            "no accepted fee assets",
        )?;
        require(
            !self.accepted_discount_tokens.is_empty(),
            "no accepted discount tokens",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub dynamic_fee_coupons: u64,
    pub sponsor_pools: u64,
    pub wallet_caps: u64,
    pub cross_asset_coupons: u64,
    pub token_gas_discounts: u64,
    pub pq_coupon_attestations: u64,
    pub rebate_settlements: u64,
    pub abuse_slashing_records: u64,
    pub redaction_budgets: u64,
    pub operator_summaries: u64,
    pub applied_coupons: u64,
    pub total_fee_saved_micro: u64,
    pub total_sponsor_reserved_micro: u64,
    pub total_rebated_micro: u64,
    pub total_slashed_micro: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub dynamic_fee_coupons_root: String,
    pub sponsor_pools_root: String,
    pub wallet_caps_root: String,
    pub cross_asset_coupons_root: String,
    pub token_gas_discounts_root: String,
    pub pq_coupon_attestations_root: String,
    pub rebate_settlements_root: String,
    pub abuse_slashing_root: String,
    pub redaction_budgets_root: String,
    pub operator_summaries_root: String,
    pub nullifier_fences_root: String,
    pub wallet_indexes_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CouponQuoteRequest {
    pub wallet_commitment: String,
    pub sponsor_pool_id: String,
    pub fee_asset: String,
    pub lane: FeeLane,
    pub base_fee_micro: u64,
    pub congestion_bps: u64,
    pub privacy_set_size: u64,
    pub nullifier: String,
    pub valid_until_height: Option<u64>,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorPoolRequest {
    pub sponsor_commitment: String,
    pub fee_asset: String,
    pub reserve_micro: u64,
    pub max_discount_bps: u64,
    pub lanes: BTreeSet<FeeLane>,
    pub policy_root: String,
    pub valid_until_height: Option<u64>,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletCapRequest {
    pub wallet_commitment: String,
    pub cap_micro: u64,
    pub window_blocks: Option<u64>,
    pub redaction_budget_hint: u32,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CrossAssetCouponRequest {
    pub source_coupon_id: String,
    pub source_asset: String,
    pub target_asset: String,
    pub quoted_exchange_rate_ppm: u64,
    pub max_slippage_bps: u64,
    pub private_swap_root: String,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TokenGasDiscountRequest {
    pub wallet_commitment: String,
    pub token_symbol: String,
    pub token_balance_commitment: String,
    pub discount_bps: u64,
    pub max_discount_micro: u64,
    pub defi_context_root: String,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqCouponAttestationRequest {
    pub coupon_id: String,
    pub attestor_committee_root: String,
    pub pq_signature_root: String,
    pub kem_ciphertext_root: String,
    pub security_bits: u16,
    pub transcript_root: String,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateSettlementRequest {
    pub coupon_id: String,
    pub sponsor_pool_id: String,
    pub wallet_commitment: String,
    pub rebate_asset: String,
    pub rebate_micro: u64,
    pub settlement_batch_root: String,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AbuseReportRequest {
    pub subject_id: String,
    pub sponsor_pool_id: Option<String>,
    pub nullifier: String,
    pub evidence_root: String,
    pub severity: AbuseSeverity,
    pub reporter_commitment: String,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudgetRequest {
    pub wallet_commitment: String,
    pub reason_root: String,
    pub requested_redactions: u32,
    pub window_blocks: Option<u64>,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DynamicFeeCoupon {
    pub coupon_id: String,
    pub wallet_commitment: String,
    pub sponsor_pool_id: String,
    pub fee_asset: String,
    pub lane: FeeLane,
    pub base_fee_micro: u64,
    pub dynamic_fee_micro: u64,
    pub discount_bps: u64,
    pub discount_micro: u64,
    pub user_fee_micro: u64,
    pub privacy_set_size: u64,
    pub nullifier: String,
    pub status: CouponStatus,
    pub minted_at_height: u64,
    pub valid_until_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorPool {
    pub sponsor_pool_id: String,
    pub sponsor_commitment: String,
    pub fee_asset: String,
    pub reserve_micro: u64,
    pub reserved_micro: u64,
    pub settled_micro: u64,
    pub slashed_micro: u64,
    pub max_discount_bps: u64,
    pub lanes: BTreeSet<FeeLane>,
    pub policy_root: String,
    pub status: SponsorPoolStatus,
    pub opened_at_height: u64,
    pub valid_until_height: u64,
}

impl SponsorPool {
    pub fn available_micro(&self) -> u64 {
        self.reserve_micro
            .saturating_sub(self.reserved_micro)
            .saturating_sub(self.settled_micro)
            .saturating_sub(self.slashed_micro)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletCap {
    pub wallet_cap_id: String,
    pub wallet_commitment: String,
    pub cap_micro: u64,
    pub spent_micro: u64,
    pub remaining_micro: u64,
    pub redaction_budget_hint: u32,
    pub window_start_height: u64,
    pub window_end_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CrossAssetCoupon {
    pub cross_asset_coupon_id: String,
    pub source_coupon_id: String,
    pub source_asset: String,
    pub target_asset: String,
    pub quoted_exchange_rate_ppm: u64,
    pub max_slippage_bps: u64,
    pub converted_discount_micro: u64,
    pub private_swap_root: String,
    pub created_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TokenGasDiscount {
    pub discount_id: String,
    pub wallet_commitment: String,
    pub token_symbol: String,
    pub token_balance_commitment: String,
    pub discount_bps: u64,
    pub max_discount_micro: u64,
    pub applied_discount_micro: u64,
    pub defi_context_root: String,
    pub issued_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqCouponAttestation {
    pub attestation_id: String,
    pub coupon_id: String,
    pub attestor_committee_root: String,
    pub pq_signature_root: String,
    pub kem_ciphertext_root: String,
    pub security_bits: u16,
    pub transcript_root: String,
    pub attested_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateSettlement {
    pub settlement_id: String,
    pub coupon_id: String,
    pub sponsor_pool_id: String,
    pub wallet_commitment: String,
    pub rebate_asset: String,
    pub rebate_micro: u64,
    pub settlement_batch_root: String,
    pub status: RebateStatus,
    pub settled_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AbuseSlashRecord {
    pub slash_id: String,
    pub subject_id: String,
    pub sponsor_pool_id: Option<String>,
    pub nullifier: String,
    pub evidence_root: String,
    pub severity: AbuseSeverity,
    pub reporter_commitment: String,
    pub slashed_micro: u64,
    pub recorded_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub wallet_commitment: String,
    pub reason_root: String,
    pub allowed_redactions: u32,
    pub used_redactions: u32,
    pub window_start_height: u64,
    pub window_end_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSafeSummary {
    pub summary_id: String,
    pub height: u64,
    pub state_root: String,
    pub coupon_count: u64,
    pub sponsor_pool_count: u64,
    pub live_sponsor_liquidity_micro: u64,
    pub total_fee_saved_micro: u64,
    pub total_rebated_micro: u64,
    pub total_slashed_micro: u64,
    pub roots: Roots,
    pub redacted_wallet_sample_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FlowReceipt {
    pub receipt_id: String,
    pub kind: String,
    pub subject_id: String,
    pub state_root: String,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub dynamic_fee_coupons: BTreeMap<String, DynamicFeeCoupon>,
    pub sponsor_pools: BTreeMap<String, SponsorPool>,
    pub wallet_caps: BTreeMap<String, WalletCap>,
    pub cross_asset_coupons: BTreeMap<String, CrossAssetCoupon>,
    pub token_gas_discounts: BTreeMap<String, TokenGasDiscount>,
    pub pq_coupon_attestations: BTreeMap<String, PqCouponAttestation>,
    pub rebate_settlements: BTreeMap<String, RebateSettlement>,
    pub abuse_slashing_records: BTreeMap<String, AbuseSlashRecord>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: Vec<OperatorSafeSummary>,
    pub nullifier_fences: BTreeSet<String>,
    pub wallet_indexes: BTreeMap<String, BTreeSet<String>>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            dynamic_fee_coupons: BTreeMap::new(),
            sponsor_pools: BTreeMap::new(),
            wallet_caps: BTreeMap::new(),
            cross_asset_coupons: BTreeMap::new(),
            token_gas_discounts: BTreeMap::new(),
            pq_coupon_attestations: BTreeMap::new(),
            rebate_settlements: BTreeMap::new(),
            abuse_slashing_records: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: Vec::new(),
            nullifier_fences: BTreeSet::new(),
            wallet_indexes: BTreeMap::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet()).expect("valid devnet dynamic fee coupon router config")
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let mut lanes = BTreeSet::new();
        lanes.insert(FeeLane::MoneroPrivateTransfer);
        lanes.insert(FeeLane::DefiSwap);
        lanes.insert(FeeLane::ConfidentialTokenTransfer);

        let pool = state
            .register_sponsor_pool(SponsorPoolRequest {
                sponsor_commitment: demo_commitment("sponsor", 1),
                fee_asset: "piconero-devnet".to_string(),
                reserve_micro: 250_000_000,
                max_discount_bps: 7_500,
                lanes,
                policy_root: demo_root("sponsor-policy", 1),
                valid_until_height: None,
                nonce: 1,
            })
            .expect("demo sponsor pool");

        state
            .set_wallet_cap(WalletCapRequest {
                wallet_commitment: demo_commitment("wallet", 1),
                cap_micro: 1_500_000,
                window_blocks: None,
                redaction_budget_hint: 4,
                nonce: 2,
            })
            .expect("demo wallet cap");

        let coupon = state
            .issue_dynamic_fee_coupon(CouponQuoteRequest {
                wallet_commitment: demo_commitment("wallet", 1),
                sponsor_pool_id: pool.subject_id,
                fee_asset: "piconero-devnet".to_string(),
                lane: FeeLane::MoneroPrivateTransfer,
                base_fee_micro: 42_000,
                congestion_bps: 1_200,
                privacy_set_size: 16_384,
                nullifier: demo_root("coupon-nullifier", 1),
                valid_until_height: None,
                nonce: 3,
            })
            .expect("demo dynamic fee coupon");

        state
            .attest_coupon_pq(PqCouponAttestationRequest {
                coupon_id: coupon.subject_id.clone(),
                attestor_committee_root: demo_root("pq-committee", 1),
                pq_signature_root: demo_root("pq-signature", 1),
                kem_ciphertext_root: demo_root("kem-ciphertext", 1),
                security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                transcript_root: demo_root("attestation-transcript", 1),
                nonce: 4,
            })
            .expect("demo pq attestation");

        state
            .issue_cross_asset_coupon(CrossAssetCouponRequest {
                source_coupon_id: coupon.subject_id.clone(),
                source_asset: "piconero-devnet".to_string(),
                target_asset: "pdusd-devnet".to_string(),
                quoted_exchange_rate_ppm: 1_000_000,
                max_slippage_bps: 25,
                private_swap_root: demo_root("private-swap", 1),
                nonce: 5,
            })
            .expect("demo cross asset coupon");

        state
            .apply_token_gas_discount(TokenGasDiscountRequest {
                wallet_commitment: demo_commitment("wallet", 1),
                token_symbol: "NEBULA".to_string(),
                token_balance_commitment: demo_root("token-balance", 1),
                discount_bps: 1_000,
                max_discount_micro: 8_000,
                defi_context_root: demo_root("defi-context", 1),
                nonce: 6,
            })
            .expect("demo token gas discount");

        state
            .settle_rebate(RebateSettlementRequest {
                coupon_id: coupon.subject_id,
                sponsor_pool_id: pool.subject_id,
                wallet_commitment: demo_commitment("wallet", 1),
                rebate_asset: "piconero-devnet".to_string(),
                rebate_micro: 5_000,
                settlement_batch_root: demo_root("settlement-batch", 1),
                nonce: 7,
            })
            .expect("demo rebate settlement");

        state
            .reserve_redaction_budget(RedactionBudgetRequest {
                wallet_commitment: demo_commitment("wallet", 1),
                reason_root: demo_root("redaction-reason", 1),
                requested_redactions: 3,
                window_blocks: None,
                nonce: 8,
            })
            .expect("demo redaction budget");

        state.operator_safe_summary();
        state
    }

    pub fn issue_dynamic_fee_coupon(
        &mut self,
        request: CouponQuoteRequest,
    ) -> RuntimeResult<FlowReceipt> {
        self.config.validate()?;
        require(
            self.config.accepted_fee_assets.contains(&request.fee_asset),
            "unsupported fee asset",
        )?;
        require(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set below policy",
        )?;
        require(
            !self.nullifier_fences.contains(&request.nullifier),
            "coupon nullifier already consumed",
        )?;

        let pool = self
            .sponsor_pools
            .get_mut(&request.sponsor_pool_id)
            .ok_or_else(|| "sponsor pool missing".to_string())?;
        require(
            pool.status == SponsorPoolStatus::Open,
            "sponsor pool not open",
        )?;
        require(
            pool.fee_asset == request.fee_asset,
            "sponsor pool asset mismatch",
        )?;
        require(
            pool.lanes.contains(&request.lane),
            "sponsor pool lane mismatch",
        )?;

        let dynamic_fee_micro = dynamic_fee_quote(request.base_fee_micro, request.congestion_bps);
        let discount_bps = pool
            .max_discount_bps
            .min(self.config.max_user_fee_bps.saturating_mul(100))
            .min(MAX_BPS);
        let discount_micro = bps_amount(dynamic_fee_micro, discount_bps);
        require(
            pool.available_micro() >= discount_micro,
            "sponsor liquidity exhausted",
        )?;

        let wallet_cap_id = wallet_cap_id(&request.wallet_commitment, self.config.l2_height);
        if let Some(cap) = self.wallet_caps.get_mut(&wallet_cap_id) {
            require(
                cap.remaining_micro >= dynamic_fee_micro.saturating_sub(discount_micro),
                "wallet fee cap exceeded",
            )?;
            let charged = dynamic_fee_micro.saturating_sub(discount_micro);
            cap.spent_micro = cap.spent_micro.saturating_add(charged);
            cap.remaining_micro = cap.cap_micro.saturating_sub(cap.spent_micro);
        }

        let coupon_id = dynamic_coupon_id(&request, dynamic_fee_micro, discount_micro);
        let coupon = DynamicFeeCoupon {
            coupon_id: coupon_id.clone(),
            wallet_commitment: request.wallet_commitment.clone(),
            sponsor_pool_id: request.sponsor_pool_id.clone(),
            fee_asset: request.fee_asset,
            lane: request.lane,
            base_fee_micro: request.base_fee_micro,
            dynamic_fee_micro,
            discount_bps,
            discount_micro,
            user_fee_micro: dynamic_fee_micro.saturating_sub(discount_micro),
            privacy_set_size: request.privacy_set_size,
            nullifier: request.nullifier.clone(),
            status: CouponStatus::Minted,
            minted_at_height: self.config.l2_height,
            valid_until_height: request.valid_until_height.unwrap_or_else(|| {
                self.config
                    .l2_height
                    .saturating_add(self.config.coupon_ttl_blocks)
            }),
        };

        pool.reserved_micro = pool.reserved_micro.saturating_add(discount_micro);
        self.nullifier_fences.insert(request.nullifier);
        self.wallet_indexes
            .entry(request.wallet_commitment)
            .or_default()
            .insert(coupon_id.clone());
        self.dynamic_fee_coupons.insert(coupon_id.clone(), coupon);
        self.counters.dynamic_fee_coupons = self.counters.dynamic_fee_coupons.saturating_add(1);
        self.counters.applied_coupons = self.counters.applied_coupons.saturating_add(1);
        self.counters.total_fee_saved_micro = self
            .counters
            .total_fee_saved_micro
            .saturating_add(discount_micro);
        self.counters.total_sponsor_reserved_micro = self
            .counters
            .total_sponsor_reserved_micro
            .saturating_add(discount_micro);
        self.refresh_roots();
        Ok(self.receipt("dynamic_fee_coupon", &coupon_id))
    }

    pub fn register_sponsor_pool(
        &mut self,
        request: SponsorPoolRequest,
    ) -> RuntimeResult<FlowReceipt> {
        require(
            self.config.accepted_fee_assets.contains(&request.fee_asset),
            "unsupported sponsor asset",
        )?;
        require(
            request.reserve_micro >= self.config.min_sponsor_reserve_micro,
            "sponsor reserve below policy",
        )?;
        require(
            request.max_discount_bps <= MAX_BPS,
            "discount bps above range",
        )?;
        require(!request.lanes.is_empty(), "sponsor pool has no lanes")?;
        let sponsor_pool_id = sponsor_pool_id(&request);
        let pool = SponsorPool {
            sponsor_pool_id: sponsor_pool_id.clone(),
            sponsor_commitment: request.sponsor_commitment,
            fee_asset: request.fee_asset,
            reserve_micro: request.reserve_micro,
            reserved_micro: 0,
            settled_micro: 0,
            slashed_micro: 0,
            max_discount_bps: request.max_discount_bps,
            lanes: request.lanes,
            policy_root: request.policy_root,
            status: SponsorPoolStatus::Open,
            opened_at_height: self.config.l2_height,
            valid_until_height: request.valid_until_height.unwrap_or_else(|| {
                self.config
                    .l2_height
                    .saturating_add(self.config.sponsor_pool_ttl_blocks)
            }),
        };
        self.sponsor_pools.insert(sponsor_pool_id.clone(), pool);
        self.counters.sponsor_pools = self.counters.sponsor_pools.saturating_add(1);
        self.refresh_roots();
        Ok(self.receipt("sponsor_pool", &sponsor_pool_id))
    }

    pub fn set_wallet_cap(&mut self, request: WalletCapRequest) -> RuntimeResult<FlowReceipt> {
        require(
            request.cap_micro <= self.config.max_wallet_cap_micro,
            "wallet cap too high",
        )?;
        let window_blocks = request
            .window_blocks
            .unwrap_or(self.config.wallet_cap_window_blocks);
        let wallet_cap_id = wallet_cap_id(&request.wallet_commitment, self.config.l2_height);
        let cap = WalletCap {
            wallet_cap_id: wallet_cap_id.clone(),
            wallet_commitment: request.wallet_commitment,
            cap_micro: request.cap_micro,
            spent_micro: 0,
            remaining_micro: request.cap_micro,
            redaction_budget_hint: request.redaction_budget_hint,
            window_start_height: self.config.l2_height,
            window_end_height: self.config.l2_height.saturating_add(window_blocks),
        };
        self.wallet_caps.insert(wallet_cap_id.clone(), cap);
        self.counters.wallet_caps = self.counters.wallet_caps.saturating_add(1);
        self.refresh_roots();
        Ok(self.receipt("wallet_cap", &wallet_cap_id))
    }

    pub fn issue_cross_asset_coupon(
        &mut self,
        request: CrossAssetCouponRequest,
    ) -> RuntimeResult<FlowReceipt> {
        require(
            self.config
                .accepted_fee_assets
                .contains(&request.source_asset),
            "unsupported source asset",
        )?;
        require(
            self.config
                .accepted_fee_assets
                .contains(&request.target_asset),
            "unsupported target asset",
        )?;
        require(
            request.max_slippage_bps <= 500,
            "slippage above coupon policy",
        )?;
        let source = self
            .dynamic_fee_coupons
            .get(&request.source_coupon_id)
            .ok_or_else(|| "source coupon missing".to_string())?;
        let converted_discount_micro = source
            .discount_micro
            .saturating_mul(request.quoted_exchange_rate_ppm)
            / 1_000_000;
        let cross_asset_coupon_id = cross_asset_coupon_id(&request, converted_discount_micro);
        let record = CrossAssetCoupon {
            cross_asset_coupon_id: cross_asset_coupon_id.clone(),
            source_coupon_id: request.source_coupon_id,
            source_asset: request.source_asset,
            target_asset: request.target_asset,
            quoted_exchange_rate_ppm: request.quoted_exchange_rate_ppm,
            max_slippage_bps: request.max_slippage_bps,
            converted_discount_micro,
            private_swap_root: request.private_swap_root,
            created_at_height: self.config.l2_height,
        };
        self.cross_asset_coupons
            .insert(cross_asset_coupon_id.clone(), record);
        self.counters.cross_asset_coupons = self.counters.cross_asset_coupons.saturating_add(1);
        self.refresh_roots();
        Ok(self.receipt("cross_asset_coupon", &cross_asset_coupon_id))
    }

    pub fn apply_token_gas_discount(
        &mut self,
        request: TokenGasDiscountRequest,
    ) -> RuntimeResult<FlowReceipt> {
        require(
            self.config
                .accepted_discount_tokens
                .contains(&request.token_symbol),
            "unsupported discount token",
        )?;
        require(
            request.discount_bps <= MAX_BPS,
            "token discount bps above range",
        )?;
        let applied_discount_micro = bps_amount(request.max_discount_micro, request.discount_bps)
            .min(request.max_discount_micro);
        let discount_id = token_gas_discount_id(&request, applied_discount_micro);
        let record = TokenGasDiscount {
            discount_id: discount_id.clone(),
            wallet_commitment: request.wallet_commitment,
            token_symbol: request.token_symbol,
            token_balance_commitment: request.token_balance_commitment,
            discount_bps: request.discount_bps,
            max_discount_micro: request.max_discount_micro,
            applied_discount_micro,
            defi_context_root: request.defi_context_root,
            issued_at_height: self.config.l2_height,
        };
        self.token_gas_discounts.insert(discount_id.clone(), record);
        self.counters.token_gas_discounts = self.counters.token_gas_discounts.saturating_add(1);
        self.counters.total_fee_saved_micro = self
            .counters
            .total_fee_saved_micro
            .saturating_add(applied_discount_micro);
        self.refresh_roots();
        Ok(self.receipt("token_gas_discount", &discount_id))
    }

    pub fn attest_coupon_pq(
        &mut self,
        request: PqCouponAttestationRequest,
    ) -> RuntimeResult<FlowReceipt> {
        require(
            self.dynamic_fee_coupons.contains_key(&request.coupon_id),
            "coupon missing for pq attestation",
        )?;
        require(
            request.security_bits >= self.config.min_pq_security_bits,
            "pq attestation security below policy",
        )?;
        let attestation_id = pq_attestation_id(&request);
        let record = PqCouponAttestation {
            attestation_id: attestation_id.clone(),
            coupon_id: request.coupon_id,
            attestor_committee_root: request.attestor_committee_root,
            pq_signature_root: request.pq_signature_root,
            kem_ciphertext_root: request.kem_ciphertext_root,
            security_bits: request.security_bits,
            transcript_root: request.transcript_root,
            attested_at_height: self.config.l2_height,
        };
        self.pq_coupon_attestations
            .insert(attestation_id.clone(), record);
        self.counters.pq_coupon_attestations =
            self.counters.pq_coupon_attestations.saturating_add(1);
        self.refresh_roots();
        Ok(self.receipt("pq_coupon_attestation", &attestation_id))
    }

    pub fn settle_rebate(
        &mut self,
        request: RebateSettlementRequest,
    ) -> RuntimeResult<FlowReceipt> {
        require(
            self.config
                .accepted_fee_assets
                .contains(&request.rebate_asset),
            "unsupported rebate asset",
        )?;
        let coupon = self
            .dynamic_fee_coupons
            .get_mut(&request.coupon_id)
            .ok_or_else(|| "coupon missing for rebate".to_string())?;
        let pool = self
            .sponsor_pools
            .get_mut(&request.sponsor_pool_id)
            .ok_or_else(|| "sponsor pool missing for rebate".to_string())?;
        require(
            coupon.sponsor_pool_id == request.sponsor_pool_id,
            "coupon sponsor pool mismatch",
        )?;
        require(
            request.rebate_micro <= coupon.discount_micro,
            "rebate above coupon discount",
        )?;
        require(
            pool.reserved_micro >= request.rebate_micro,
            "pool reserved below rebate",
        )?;
        let settlement_id = rebate_settlement_id(&request);
        coupon.status = CouponStatus::Rebated;
        pool.reserved_micro = pool.reserved_micro.saturating_sub(request.rebate_micro);
        pool.settled_micro = pool.settled_micro.saturating_add(request.rebate_micro);
        let record = RebateSettlement {
            settlement_id: settlement_id.clone(),
            coupon_id: request.coupon_id,
            sponsor_pool_id: request.sponsor_pool_id,
            wallet_commitment: request.wallet_commitment,
            rebate_asset: request.rebate_asset,
            rebate_micro: request.rebate_micro,
            settlement_batch_root: request.settlement_batch_root,
            status: RebateStatus::Settled,
            settled_at_height: self.config.l2_height,
        };
        self.rebate_settlements
            .insert(settlement_id.clone(), record);
        self.counters.rebate_settlements = self.counters.rebate_settlements.saturating_add(1);
        self.counters.total_rebated_micro = self
            .counters
            .total_rebated_micro
            .saturating_add(request.rebate_micro);
        self.refresh_roots();
        Ok(self.receipt("rebate_settlement", &settlement_id))
    }

    pub fn report_abuse_and_slash(
        &mut self,
        request: AbuseReportRequest,
    ) -> RuntimeResult<FlowReceipt> {
        require(
            !self.nullifier_fences.contains(&request.nullifier),
            "abuse nullifier already recorded",
        )?;
        let mut slashed_micro = 0;
        if let Some(pool_id) = &request.sponsor_pool_id {
            let pool = self
                .sponsor_pools
                .get_mut(pool_id)
                .ok_or_else(|| "sponsor pool missing for abuse report".to_string())?;
            slashed_micro = bps_amount(pool.available_micro(), request.severity.slash_bps());
            pool.slashed_micro = pool.slashed_micro.saturating_add(slashed_micro);
            if request.severity >= AbuseSeverity::Slashable {
                pool.status = SponsorPoolStatus::Slashed;
            }
        }
        let slash_id = abuse_slash_id(&request, slashed_micro);
        let record = AbuseSlashRecord {
            slash_id: slash_id.clone(),
            subject_id: request.subject_id,
            sponsor_pool_id: request.sponsor_pool_id,
            nullifier: request.nullifier.clone(),
            evidence_root: request.evidence_root,
            severity: request.severity,
            reporter_commitment: request.reporter_commitment,
            slashed_micro,
            recorded_at_height: self.config.l2_height,
        };
        self.nullifier_fences.insert(request.nullifier);
        self.abuse_slashing_records.insert(slash_id.clone(), record);
        self.counters.abuse_slashing_records =
            self.counters.abuse_slashing_records.saturating_add(1);
        self.counters.total_slashed_micro = self
            .counters
            .total_slashed_micro
            .saturating_add(slashed_micro);
        self.refresh_roots();
        Ok(self.receipt("abuse_slashing", &slash_id))
    }

    pub fn reserve_redaction_budget(
        &mut self,
        request: RedactionBudgetRequest,
    ) -> RuntimeResult<FlowReceipt> {
        require(
            request.requested_redactions <= self.config.max_redactions_per_window,
            "redaction request above policy",
        )?;
        let window_blocks = request
            .window_blocks
            .unwrap_or(self.config.redaction_window_blocks);
        let budget_id = redaction_budget_id(&request, self.config.l2_height);
        let record = RedactionBudget {
            budget_id: budget_id.clone(),
            wallet_commitment: request.wallet_commitment,
            reason_root: request.reason_root,
            allowed_redactions: request.requested_redactions,
            used_redactions: 0,
            window_start_height: self.config.l2_height,
            window_end_height: self.config.l2_height.saturating_add(window_blocks),
        };
        self.redaction_budgets.insert(budget_id.clone(), record);
        self.counters.redaction_budgets = self.counters.redaction_budgets.saturating_add(1);
        self.refresh_roots();
        Ok(self.receipt("redaction_budget", &budget_id))
    }

    pub fn operator_safe_summary(&mut self) -> OperatorSafeSummary {
        self.refresh_roots();
        let live_sponsor_liquidity_micro = self
            .sponsor_pools
            .values()
            .filter(|pool| pool.status == SponsorPoolStatus::Open)
            .map(SponsorPool::available_micro)
            .sum();
        let redacted_wallet_sample_root = root_from_values(
            "operator-redacted-wallet-sample",
            &self
                .wallet_indexes
                .keys()
                .take(self.config.operator_summary_limit)
                .map(|wallet| json!({"wallet_commitment_root": string_root("wallet", wallet)}))
                .collect::<Vec<_>>(),
        );
        let summary_id = domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DYNAMIC-FEE-COUPON:OPERATOR-SUMMARY-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::U64(self.config.l2_height),
                HashPart::Str(&self.roots.dynamic_fee_coupons_root),
            ],
            32,
        );
        let summary = OperatorSafeSummary {
            summary_id,
            height: self.config.l2_height,
            state_root: self.state_root(),
            coupon_count: self.counters.dynamic_fee_coupons,
            sponsor_pool_count: self.counters.sponsor_pools,
            live_sponsor_liquidity_micro,
            total_fee_saved_micro: self.counters.total_fee_saved_micro,
            total_rebated_micro: self.counters.total_rebated_micro,
            total_slashed_micro: self.counters.total_slashed_micro,
            roots: self.roots.clone(),
            redacted_wallet_sample_root,
        };
        self.operator_summaries.push(summary.clone());
        self.counters.operator_summaries = self.counters.operator_summaries.saturating_add(1);
        self.refresh_roots();
        summary
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record
            .as_object_mut()
            .expect("state public record is object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "pq_coupon_attestation_suite": PQ_COUPON_ATTESTATION_SUITE,
            "confidential_coupon_suite": CONFIDENTIAL_COUPON_SUITE,
            "sponsor_pool_suite": SPONSOR_POOL_SUITE,
            "cross_asset_coupon_suite": CROSS_ASSET_COUPON_SUITE,
            "token_gas_discount_suite": TOKEN_GAS_DISCOUNT_SUITE,
            "rebate_settlement_suite": REBATE_SETTLEMENT_SUITE,
            "redaction_budget_suite": REDACTION_BUDGET_SUITE,
            "operator_summary_suite": OPERATOR_SUMMARY_SUITE,
            "chain_id": CHAIN_ID,
            "config": record_value(&self.config),
            "counters": record_value(&self.counters),
            "roots": record_value(&self.roots),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DYNAMIC-FEE-COUPON:STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Json(&self.public_record_without_state_root()),
            ],
            32,
        )
    }

    pub fn refresh_roots(&mut self) {
        self.roots = Roots {
            dynamic_fee_coupons_root: map_root(
                "dynamic-fee-coupons",
                self.dynamic_fee_coupons
                    .values()
                    .map(record_value)
                    .collect::<Vec<_>>(),
            ),
            sponsor_pools_root: map_root(
                "sponsor-pools",
                self.sponsor_pools
                    .values()
                    .map(record_value)
                    .collect::<Vec<_>>(),
            ),
            wallet_caps_root: map_root(
                "wallet-caps",
                self.wallet_caps
                    .values()
                    .map(record_value)
                    .collect::<Vec<_>>(),
            ),
            cross_asset_coupons_root: map_root(
                "cross-asset-coupons",
                self.cross_asset_coupons
                    .values()
                    .map(record_value)
                    .collect::<Vec<_>>(),
            ),
            token_gas_discounts_root: map_root(
                "token-gas-discounts",
                self.token_gas_discounts
                    .values()
                    .map(record_value)
                    .collect::<Vec<_>>(),
            ),
            pq_coupon_attestations_root: map_root(
                "pq-coupon-attestations",
                self.pq_coupon_attestations
                    .values()
                    .map(record_value)
                    .collect::<Vec<_>>(),
            ),
            rebate_settlements_root: map_root(
                "rebate-settlements",
                self.rebate_settlements
                    .values()
                    .map(record_value)
                    .collect::<Vec<_>>(),
            ),
            abuse_slashing_root: map_root(
                "abuse-slashing",
                self.abuse_slashing_records
                    .values()
                    .map(record_value)
                    .collect::<Vec<_>>(),
            ),
            redaction_budgets_root: map_root(
                "redaction-budgets",
                self.redaction_budgets
                    .values()
                    .map(record_value)
                    .collect::<Vec<_>>(),
            ),
            operator_summaries_root: map_root(
                "operator-summaries",
                self.operator_summaries
                    .iter()
                    .map(record_value)
                    .collect::<Vec<_>>(),
            ),
            nullifier_fences_root: map_root(
                "nullifier-fences",
                self.nullifier_fences
                    .iter()
                    .map(|nullifier| json!({"nullifier": nullifier}))
                    .collect::<Vec<_>>(),
            ),
            wallet_indexes_root: map_root(
                "wallet-indexes",
                self.wallet_indexes
                    .iter()
                    .map(|(wallet, coupons)| {
                        json!({
                            "wallet_commitment": wallet,
                            "coupon_ids": coupons,
                        })
                    })
                    .collect::<Vec<_>>(),
            ),
        };
    }

    fn receipt(&self, kind: &str, subject_id: &str) -> FlowReceipt {
        let state_root = self.state_root();
        FlowReceipt {
            receipt_id: domain_hash(
                "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DYNAMIC-FEE-COUPON:RECEIPT",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(kind),
                    HashPart::Str(subject_id),
                    HashPart::Str(&state_root),
                ],
                32,
            ),
            kind: kind.to_string(),
            subject_id: subject_id.to_string(),
            state_root,
            height: self.config.l2_height,
        }
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn record_value<T: Serialize>(record: &T) -> Value {
    serde_json::to_value(record).expect("runtime record serializes")
}

fn dynamic_fee_quote(base_fee_micro: u64, congestion_bps: u64) -> u64 {
    let congestion_bps = congestion_bps.min(MAX_BPS);
    base_fee_micro.saturating_add(bps_amount(base_fee_micro, congestion_bps))
}

fn bps_amount(amount: u64, bps: u64) -> u64 {
    amount.saturating_mul(bps.min(MAX_BPS)) / MAX_BPS
}

fn map_root(domain: &str, leaves: Vec<Value>) -> String {
    let domain = format!("PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DYNAMIC-FEE-COUPON:{domain}");
    merkle_root(&domain, &leaves)
}

fn root_from_values(domain: &str, leaves: &[Value]) -> String {
    let domain = format!("PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DYNAMIC-FEE-COUPON:{domain}");
    merkle_root(&domain, leaves)
}

fn string_root(domain: &str, value: &str) -> String {
    domain_hash(
        &format!("PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DYNAMIC-FEE-COUPON:{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Str(value)],
        32,
    )
}

fn demo_root(label: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DYNAMIC-FEE-COUPON:DEMO-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::U64(nonce),
        ],
        32,
    )
}

fn demo_commitment(label: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DYNAMIC-FEE-COUPON:DEMO-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::U64(nonce),
        ],
        32,
    )
}

fn sponsor_pool_id(request: &SponsorPoolRequest) -> String {
    let lanes = request
        .lanes
        .iter()
        .map(|lane| lane.as_str())
        .collect::<Vec<_>>()
        .join(",");
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DYNAMIC-FEE-COUPON:SPONSOR-POOL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.fee_asset),
            HashPart::U64(request.reserve_micro),
            HashPart::U64(request.max_discount_bps),
            HashPart::Str(&lanes),
            HashPart::Str(&request.policy_root),
            HashPart::U64(request.nonce),
        ],
        32,
    )
}

fn wallet_cap_id(wallet_commitment: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DYNAMIC-FEE-COUPON:WALLET-CAP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(wallet_commitment),
            HashPart::U64(height),
        ],
        32,
    )
}

fn dynamic_coupon_id(
    request: &CouponQuoteRequest,
    dynamic_fee_micro: u64,
    discount_micro: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DYNAMIC-FEE-COUPON:COUPON-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.wallet_commitment),
            HashPart::Str(&request.sponsor_pool_id),
            HashPart::Str(&request.fee_asset),
            HashPart::Str(request.lane.as_str()),
            HashPart::U64(dynamic_fee_micro),
            HashPart::U64(discount_micro),
            HashPart::Str(&request.nullifier),
            HashPart::U64(request.nonce),
        ],
        32,
    )
}

fn cross_asset_coupon_id(
    request: &CrossAssetCouponRequest,
    converted_discount_micro: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DYNAMIC-FEE-COUPON:CROSS-ASSET-COUPON-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.source_coupon_id),
            HashPart::Str(&request.source_asset),
            HashPart::Str(&request.target_asset),
            HashPart::U64(request.quoted_exchange_rate_ppm),
            HashPart::U64(converted_discount_micro),
            HashPart::Str(&request.private_swap_root),
            HashPart::U64(request.nonce),
        ],
        32,
    )
}

fn token_gas_discount_id(request: &TokenGasDiscountRequest, applied_discount_micro: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DYNAMIC-FEE-COUPON:TOKEN-GAS-DISCOUNT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.wallet_commitment),
            HashPart::Str(&request.token_symbol),
            HashPart::Str(&request.token_balance_commitment),
            HashPart::U64(request.discount_bps),
            HashPart::U64(applied_discount_micro),
            HashPart::Str(&request.defi_context_root),
            HashPart::U64(request.nonce),
        ],
        32,
    )
}

fn pq_attestation_id(request: &PqCouponAttestationRequest) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DYNAMIC-FEE-COUPON:PQ-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.coupon_id),
            HashPart::Str(&request.attestor_committee_root),
            HashPart::Str(&request.pq_signature_root),
            HashPart::Str(&request.kem_ciphertext_root),
            HashPart::U64(request.security_bits as u64),
            HashPart::Str(&request.transcript_root),
            HashPart::U64(request.nonce),
        ],
        32,
    )
}

fn rebate_settlement_id(request: &RebateSettlementRequest) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DYNAMIC-FEE-COUPON:REBATE-SETTLEMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.coupon_id),
            HashPart::Str(&request.sponsor_pool_id),
            HashPart::Str(&request.wallet_commitment),
            HashPart::Str(&request.rebate_asset),
            HashPart::U64(request.rebate_micro),
            HashPart::Str(&request.settlement_batch_root),
            HashPart::U64(request.nonce),
        ],
        32,
    )
}

fn abuse_slash_id(request: &AbuseReportRequest, slashed_micro: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DYNAMIC-FEE-COUPON:ABUSE-SLASH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.subject_id),
            HashPart::Str(request.sponsor_pool_id.as_deref().unwrap_or("none")),
            HashPart::Str(&request.nullifier),
            HashPart::Str(&request.evidence_root),
            HashPart::U64(request.severity.slash_bps()),
            HashPart::U64(slashed_micro),
            HashPart::U64(request.nonce),
        ],
        32,
    )
}

fn redaction_budget_id(request: &RedactionBudgetRequest, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DYNAMIC-FEE-COUPON:REDACTION-BUDGET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.wallet_commitment),
            HashPart::Str(&request.reason_root),
            HashPart::U64(request.requested_redactions as u64),
            HashPart::U64(height),
            HashPart::U64(request.nonce),
        ],
        32,
    )
}
