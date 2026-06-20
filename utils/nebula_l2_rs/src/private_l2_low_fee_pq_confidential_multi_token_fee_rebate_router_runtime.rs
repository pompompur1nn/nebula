use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_MULTI_TOKEN_FEE_REBATE_ROUTER_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-low-fee-pq-confidential-multi-token-fee-rebate-router-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_MULTI_TOKEN_FEE_REBATE_ROUTER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const COMMITMENT_SUITE: &str = "confidential-multi-token-fee-commitment-v1";
pub const PAYMASTER_SUITE: &str = "private-paymaster-approval-root-v1";
pub const REBATE_SUITE: &str = "low-fee-confidential-rebate-coupon-root-v1";
pub const SETTLEMENT_SUITE: &str = "sponsor-settlement-lane-root-v1";
pub const CONVERSION_SUITE: &str = "token-basket-fee-conversion-root-v1";
pub const NETTING_SUITE: &str = "batch-fee-netting-root-v1";
pub const COHORT_SUITE: &str = "encrypted-payer-cohort-root-v1";
pub const QUOTE_SUITE: &str = "route-level-fee-quote-root-v1";
pub const PROOF_SUITE: &str = "recursive-proof-amortization-root-v1";
pub const FENCE_SUITE: &str = "anti-abuse-nullifier-fence-root-v1";
pub const SLASHING_SUITE: &str = "settlement-slashing-evidence-root-v1";
pub const PUBLIC_RECORD_SUITE: &str = "roots-only-public-record-v1";
pub const DEVNET_L2_HEIGHT: u64 = 1_884_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_680_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 1_024;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_REBATE_TARGET_BPS: u64 = 7;
pub const DEFAULT_PAYMASTER_TTL_BLOCKS: u64 = 64;
pub const DEFAULT_QUOTE_TTL_BLOCKS: u64 = 20;
pub const DEFAULT_FENCE_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_BATCH_MAX_ITEMS: usize = 2_048;
pub const DEFAULT_RECURSIVE_PROOF_BATCH_SIZE: u64 = 256;
pub const DEFAULT_SLASHING_ESCROW_MICRO_UNITS: u64 = 250_000_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeAssetKind {
    NativePiconero,
    ConfidentialToken,
    StablePrivateToken,
    BasketShare,
    SponsoredCredit,
    RebateCoupon,
    BridgeVoucher,
}

impl FeeAssetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NativePiconero => "native_piconero",
            Self::ConfidentialToken => "confidential_token",
            Self::StablePrivateToken => "stable_private_token",
            Self::BasketShare => "basket_share",
            Self::SponsoredCredit => "sponsored_credit",
            Self::RebateCoupon => "rebate_coupon",
            Self::BridgeVoucher => "bridge_voucher",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Throttled,
    Settling,
    Settled,
    Slashed,
    Paused,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Throttled => "throttled",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Slashed => "slashed",
            Self::Paused => "paused",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Minted,
    Reserved,
    Applied,
    Settled,
    Revoked,
    Expired,
}

impl CouponStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Minted => "minted",
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Settled => "settled",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
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

impl FenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Armed => "armed",
            Self::Consumed => "consumed",
            Self::Challenged => "challenged",
            Self::Released => "released",
            Self::Expired => "expired",
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
    pub max_user_fee_bps: u64,
    pub rebate_target_bps: u64,
    pub paymaster_ttl_blocks: u64,
    pub quote_ttl_blocks: u64,
    pub fence_ttl_blocks: u64,
    pub batch_max_items: usize,
    pub recursive_proof_batch_size: u64,
    pub slashing_escrow_micro_units: u64,
    pub accepted_fee_assets: BTreeSet<String>,
    pub sponsor_allowlist_root: String,
    pub compliance_epoch: u64,
}

impl Config {
    pub fn devnet() -> Self {
        let mut accepted_fee_assets = BTreeSet::new();
        accepted_fee_assets.insert("piconero-devnet".to_string());
        accepted_fee_assets.insert("pdusd-devnet".to_string());
        accepted_fee_assets.insert("basket-lowfee-devnet".to_string());
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            rebate_target_bps: DEFAULT_REBATE_TARGET_BPS,
            paymaster_ttl_blocks: DEFAULT_PAYMASTER_TTL_BLOCKS,
            quote_ttl_blocks: DEFAULT_QUOTE_TTL_BLOCKS,
            fence_ttl_blocks: DEFAULT_FENCE_TTL_BLOCKS,
            batch_max_items: DEFAULT_BATCH_MAX_ITEMS,
            recursive_proof_batch_size: DEFAULT_RECURSIVE_PROOF_BATCH_SIZE,
            slashing_escrow_micro_units: DEFAULT_SLASHING_ESCROW_MICRO_UNITS,
            accepted_fee_assets,
            sponsor_allowlist_root: root_from_values("devnet-sponsor-allowlist", &[]),
            compliance_epoch: 1,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require(self.chain_id == CHAIN_ID, "config chain id mismatch")?;
        require(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "pq security below policy",
        )?;
        require(
            self.max_user_fee_bps <= MAX_BPS,
            "max user fee above bps range",
        )?;
        require(
            self.rebate_target_bps <= self.max_user_fee_bps,
            "rebate target above max fee",
        )?;
        require(
            !self.accepted_fee_assets.is_empty(),
            "no accepted fee assets",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub commitments: u64,
    pub paymaster_approvals: u64,
    pub rebate_coupons: u64,
    pub settlement_lanes: u64,
    pub conversion_quotes: u64,
    pub netting_batches: u64,
    pub encrypted_cohorts: u64,
    pub fee_quotes: u64,
    pub proof_plans: u64,
    pub nullifier_fences: u64,
    pub slashing_records: u64,
    pub public_records: u64,
}

impl Counters {
    pub fn empty() -> Self {
        Self {
            commitments: 0,
            paymaster_approvals: 0,
            rebate_coupons: 0,
            settlement_lanes: 0,
            conversion_quotes: 0,
            netting_batches: 0,
            encrypted_cohorts: 0,
            fee_quotes: 0,
            proof_plans: 0,
            nullifier_fences: 0,
            slashing_records: 0,
            public_records: 0,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub commitment_root: String,
    pub paymaster_root: String,
    pub rebate_root: String,
    pub settlement_lane_root: String,
    pub conversion_root: String,
    pub netting_root: String,
    pub cohort_root: String,
    pub quote_root: String,
    pub proof_root: String,
    pub fence_root: String,
    pub slashing_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            commitment_root: root_from_values(COMMITMENT_SUITE, &[]),
            paymaster_root: root_from_values(PAYMASTER_SUITE, &[]),
            rebate_root: root_from_values(REBATE_SUITE, &[]),
            settlement_lane_root: root_from_values(SETTLEMENT_SUITE, &[]),
            conversion_root: root_from_values(CONVERSION_SUITE, &[]),
            netting_root: root_from_values(NETTING_SUITE, &[]),
            cohort_root: root_from_values(COHORT_SUITE, &[]),
            quote_root: root_from_values(QUOTE_SUITE, &[]),
            proof_root: root_from_values(PROOF_SUITE, &[]),
            fence_root: root_from_values(FENCE_SUITE, &[]),
            slashing_root: root_from_values(SLASHING_SUITE, &[]),
            state_root: domain_hash("empty-private-fee-rebate-router-state", &[], 32),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TokenFeeCommitment {
    pub commitment_id: String,
    pub payer_account_root: String,
    pub fee_asset_id: String,
    pub fee_asset_kind: FeeAssetKind,
    pub amount_commitment: String,
    pub blinding_commitment: String,
    pub payer_nullifier: String,
    pub route_id: String,
    pub cohort_id: String,
    pub max_fee_bps: u64,
    pub pq_auth_root: String,
    pub created_l2_height: u64,
}

impl TokenFeeCommitment {
    pub fn public_leaf(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "payer_account_root": self.payer_account_root,
            "fee_asset_id": self.fee_asset_id,
            "fee_asset_kind": self.fee_asset_kind.as_str(),
            "amount_commitment": self.amount_commitment,
            "payer_nullifier": self.payer_nullifier,
            "route_id": self.route_id,
            "cohort_id": self.cohort_id,
            "max_fee_bps": self.max_fee_bps,
            "pq_auth_root": self.pq_auth_root,
            "created_l2_height": self.created_l2_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PaymasterApproval {
    pub approval_id: String,
    pub sponsor_id: String,
    pub payer_cohort_id: String,
    pub lane_id: String,
    pub approved_assets: BTreeSet<String>,
    pub max_private_fee_micro_units: u64,
    pub max_rebate_bps: u64,
    pub policy_root: String,
    pub pq_signature_commitment: String,
    pub valid_from_l2_height: u64,
    pub valid_until_l2_height: u64,
}

impl PaymasterApproval {
    pub fn active_at(&self, height: u64) -> bool {
        self.valid_from_l2_height <= height && height <= self.valid_until_l2_height
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateCoupon {
    pub coupon_id: String,
    pub sponsor_id: String,
    pub payer_cohort_id: String,
    pub fee_asset_id: String,
    pub face_value_commitment: String,
    pub rebate_bps: u64,
    pub coupon_nullifier: String,
    pub settlement_lane_id: String,
    pub status: CouponStatus,
    pub minted_l2_height: u64,
    pub expires_l2_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorSettlementLane {
    pub lane_id: String,
    pub sponsor_id: String,
    pub settlement_asset_id: String,
    pub lane_commitment_root: String,
    pub escrow_commitment: String,
    pub capacity_micro_units: u64,
    pub pending_net_micro_units: i128,
    pub settled_micro_units: u64,
    pub status: LaneStatus,
    pub slashing_escrow_micro_units: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BasketLeg {
    pub asset_id: String,
    pub weight_ppm: u64,
    pub oracle_price_micro_units: u64,
    pub haircut_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TokenBasketConversion {
    pub conversion_id: String,
    pub source_asset_id: String,
    pub target_asset_id: String,
    pub route_id: String,
    pub basket_legs: Vec<BasketLeg>,
    pub source_amount_commitment: String,
    pub target_amount_commitment: String,
    pub conversion_rate_micro_units: u64,
    pub max_slippage_bps: u64,
    pub oracle_attestation_root: String,
    pub quoted_l2_height: u64,
}

impl TokenBasketConversion {
    pub fn effective_fee_bps(&self) -> u64 {
        self.basket_legs
            .iter()
            .map(|leg| leg.haircut_bps.saturating_mul(leg.weight_ppm) / 1_000_000)
            .sum::<u64>()
            .saturating_add(self.max_slippage_bps)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BatchFeeNetting {
    pub batch_id: String,
    pub lane_id: String,
    pub commitment_ids: BTreeSet<String>,
    pub coupon_ids: BTreeSet<String>,
    pub net_by_asset_micro_units: BTreeMap<String, i128>,
    pub gross_fee_commitment_root: String,
    pub rebate_commitment_root: String,
    pub net_settlement_commitment: String,
    pub proof_plan_id: String,
    pub closed_l2_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedPayerCohort {
    pub cohort_id: String,
    pub encrypted_membership_root: String,
    pub payer_count_commitment: String,
    pub min_privacy_set_size: u64,
    pub encryption_suite: String,
    pub view_key_policy_root: String,
    pub nullifier_domain: String,
    pub created_l2_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteFeeQuote {
    pub quote_id: String,
    pub route_id: String,
    pub payer_cohort_id: String,
    pub preferred_fee_asset_id: String,
    pub accepted_fee_assets: BTreeSet<String>,
    pub quoted_fee_commitment: String,
    pub user_fee_bps: u64,
    pub sponsor_rebate_bps: u64,
    pub paymaster_approval_id: Option<String>,
    pub conversion_id: Option<String>,
    pub proof_plan_id: String,
    pub quote_l2_height: u64,
    pub expires_l2_height: u64,
}

impl RouteFeeQuote {
    pub fn active_at(&self, height: u64) -> bool {
        self.quote_l2_height <= height && height <= self.expires_l2_height
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecursiveProofAmortization {
    pub proof_plan_id: String,
    pub aggregation_root: String,
    pub route_ids: BTreeSet<String>,
    pub batch_ids: BTreeSet<String>,
    pub proof_count: u64,
    pub amortized_fee_micro_units: u64,
    pub recursive_depth: u16,
    pub pq_verifier_key_root: String,
    pub compression_ratio_ppm: u64,
    pub scheduled_l2_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NullifierFence {
    pub fence_id: String,
    pub nullifier: String,
    pub account_set_root: String,
    pub route_id: String,
    pub cohort_id: String,
    pub abuse_score_commitment: String,
    pub status: FenceStatus,
    pub armed_l2_height: u64,
    pub expires_l2_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub slash_id: String,
    pub lane_id: String,
    pub sponsor_id: String,
    pub accused_actor_id: String,
    pub evidence_root: String,
    pub violated_policy_root: String,
    pub disputed_commitment_ids: BTreeSet<String>,
    pub slash_amount_micro_units: u64,
    pub pq_attestation_root: String,
    pub recorded_l2_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterCommitmentRequest {
    pub payer_account_root: String,
    pub fee_asset_id: String,
    pub fee_asset_kind: FeeAssetKind,
    pub amount_commitment: String,
    pub blinding_commitment: String,
    pub payer_nullifier: String,
    pub route_id: String,
    pub cohort_id: String,
    pub max_fee_bps: u64,
    pub pq_auth_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ApprovePaymasterRequest {
    pub sponsor_id: String,
    pub payer_cohort_id: String,
    pub lane_id: String,
    pub approved_assets: BTreeSet<String>,
    pub max_private_fee_micro_units: u64,
    pub max_rebate_bps: u64,
    pub policy_root: String,
    pub pq_signature_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MintRebateRequest {
    pub sponsor_id: String,
    pub payer_cohort_id: String,
    pub fee_asset_id: String,
    pub face_value_commitment: String,
    pub rebate_bps: u64,
    pub coupon_nullifier: String,
    pub settlement_lane_id: String,
    pub ttl_blocks: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuoteRouteFeeRequest {
    pub route_id: String,
    pub payer_cohort_id: String,
    pub preferred_fee_asset_id: String,
    pub accepted_fee_assets: BTreeSet<String>,
    pub quoted_fee_commitment: String,
    pub user_fee_bps: u64,
    pub sponsor_rebate_bps: u64,
    pub paymaster_approval_id: Option<String>,
    pub conversion_id: Option<String>,
    pub proof_plan_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub commitments: BTreeMap<String, TokenFeeCommitment>,
    pub paymaster_approvals: BTreeMap<String, PaymasterApproval>,
    pub rebate_coupons: BTreeMap<String, RebateCoupon>,
    pub settlement_lanes: BTreeMap<String, SponsorSettlementLane>,
    pub conversions: BTreeMap<String, TokenBasketConversion>,
    pub netting_batches: BTreeMap<String, BatchFeeNetting>,
    pub encrypted_cohorts: BTreeMap<String, EncryptedPayerCohort>,
    pub fee_quotes: BTreeMap<String, RouteFeeQuote>,
    pub proof_plans: BTreeMap<String, RecursiveProofAmortization>,
    pub nullifier_fences: BTreeMap<String, NullifierFence>,
    pub slashing_records: BTreeMap<String, SlashingEvidence>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub public_journal: Vec<Value>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self {
            config,
            counters: Counters::empty(),
            roots: Roots::empty(),
            commitments: BTreeMap::new(),
            paymaster_approvals: BTreeMap::new(),
            rebate_coupons: BTreeMap::new(),
            settlement_lanes: BTreeMap::new(),
            conversions: BTreeMap::new(),
            netting_batches: BTreeMap::new(),
            encrypted_cohorts: BTreeMap::new(),
            fee_quotes: BTreeMap::new(),
            proof_plans: BTreeMap::new(),
            nullifier_fences: BTreeMap::new(),
            slashing_records: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            public_journal: Vec::new(),
        };
        let cohort = EncryptedPayerCohort {
            cohort_id: deterministic_id("cohort", &["devnet-payer-cohort"]),
            encrypted_membership_root: root_from_strings(
                COHORT_SUITE,
                &["payer-a", "payer-b", "payer-c", "payer-d"],
            ),
            payer_count_commitment: commitment_id("cohort-count", "devnet", 4096),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            encryption_suite: "ML-KEM-1024-sealed-payer-cohort".to_string(),
            view_key_policy_root: root_from_strings("view-key-policy", &["auditor", "payer"]),
            nullifier_domain: deterministic_id("nullifier-domain", &["devnet"]),
            created_l2_height: DEVNET_L2_HEIGHT,
        };
        state
            .encrypted_cohorts
            .insert(cohort.cohort_id.clone(), cohort);
        let lane = SponsorSettlementLane {
            lane_id: deterministic_id("lane", &["devnet-sponsor", "piconero-devnet"]),
            sponsor_id: "devnet-sponsor".to_string(),
            settlement_asset_id: "piconero-devnet".to_string(),
            lane_commitment_root: root_from_strings(SETTLEMENT_SUITE, &["devnet-lane"]),
            escrow_commitment: commitment_id("lane-escrow", "devnet-sponsor", 500_000_000),
            capacity_micro_units: 500_000_000,
            pending_net_micro_units: 0,
            settled_micro_units: 0,
            status: LaneStatus::Open,
            slashing_escrow_micro_units: DEFAULT_SLASHING_ESCROW_MICRO_UNITS,
        };
        state.settlement_lanes.insert(lane.lane_id.clone(), lane);
        state.counters.encrypted_cohorts = 1;
        state.counters.settlement_lanes = 1;
        state.recompute_roots();
        state
    }

    pub fn state_root(&self) -> String {
        state_root_from_roots(&self.roots, &self.counters, &self.config)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": self.config.chain_id,
            "l2_height": self.config.l2_height,
            "monero_height": self.config.monero_height,
            "hash_suite": HASH_SUITE,
            "pq_auth_suite": PQ_AUTH_SUITE,
            "roots": self.roots,
            "counters": self.counters,
            "state_root": self.state_root()
        })
    }

    pub fn recompute_roots(&mut self) {
        self.roots.commitment_root = map_root(COMMITMENT_SUITE, &self.commitments);
        self.roots.paymaster_root = map_root(PAYMASTER_SUITE, &self.paymaster_approvals);
        self.roots.rebate_root = map_root(REBATE_SUITE, &self.rebate_coupons);
        self.roots.settlement_lane_root = map_root(SETTLEMENT_SUITE, &self.settlement_lanes);
        self.roots.conversion_root = map_root(CONVERSION_SUITE, &self.conversions);
        self.roots.netting_root = map_root(NETTING_SUITE, &self.netting_batches);
        self.roots.cohort_root = map_root(COHORT_SUITE, &self.encrypted_cohorts);
        self.roots.quote_root = map_root(QUOTE_SUITE, &self.fee_quotes);
        self.roots.proof_root = map_root(PROOF_SUITE, &self.proof_plans);
        self.roots.fence_root = map_root(FENCE_SUITE, &self.nullifier_fences);
        self.roots.slashing_root = map_root(SLASHING_SUITE, &self.slashing_records);
        self.roots.state_root = self.state_root();
    }

    pub fn register_commitment(&mut self, request: RegisterCommitmentRequest) -> Result<String> {
        self.config.validate()?;
        require(
            self.config
                .accepted_fee_assets
                .contains(&request.fee_asset_id),
            "fee asset is not accepted",
        )?;
        require(
            request.max_fee_bps <= self.config.max_user_fee_bps,
            "commitment max fee exceeds config",
        )?;
        require(
            !self.consumed_nullifiers.contains(&request.payer_nullifier),
            "payer nullifier already consumed",
        )?;
        require(
            self.encrypted_cohorts.contains_key(&request.cohort_id),
            "unknown payer cohort",
        )?;
        let commitment_id = deterministic_id(
            "fee-commitment",
            &[
                request.payer_account_root.as_str(),
                request.fee_asset_id.as_str(),
                request.amount_commitment.as_str(),
                request.payer_nullifier.as_str(),
                request.route_id.as_str(),
            ],
        );
        require(
            !self.commitments.contains_key(&commitment_id),
            "commitment already exists",
        )?;
        let commitment = TokenFeeCommitment {
            commitment_id: commitment_id.clone(),
            payer_account_root: request.payer_account_root,
            fee_asset_id: request.fee_asset_id,
            fee_asset_kind: request.fee_asset_kind,
            amount_commitment: request.amount_commitment,
            blinding_commitment: request.blinding_commitment,
            payer_nullifier: request.payer_nullifier,
            route_id: request.route_id,
            cohort_id: request.cohort_id,
            max_fee_bps: request.max_fee_bps,
            pq_auth_root: request.pq_auth_root,
            created_l2_height: self.config.l2_height,
        };
        self.consumed_nullifiers
            .insert(commitment.payer_nullifier.clone());
        self.commitments.insert(commitment_id.clone(), commitment);
        self.counters.commitments = self.counters.commitments.saturating_add(1);
        self.recompute_roots();
        self.append_record("register_commitment", &commitment_id);
        Ok(commitment_id)
    }

    pub fn open_settlement_lane(
        &mut self,
        sponsor_id: &str,
        settlement_asset_id: &str,
        capacity_micro_units: u64,
    ) -> Result<String> {
        require(!sponsor_id.is_empty(), "empty sponsor id")?;
        require(
            self.config
                .accepted_fee_assets
                .contains(settlement_asset_id),
            "settlement asset is not accepted",
        )?;
        let lane_id = deterministic_id("lane", &[sponsor_id, settlement_asset_id]);
        let lane = SponsorSettlementLane {
            lane_id: lane_id.clone(),
            sponsor_id: sponsor_id.to_string(),
            settlement_asset_id: settlement_asset_id.to_string(),
            lane_commitment_root: root_from_strings(SETTLEMENT_SUITE, &[sponsor_id]),
            escrow_commitment: commitment_id("lane-escrow", sponsor_id, capacity_micro_units),
            capacity_micro_units,
            pending_net_micro_units: 0,
            settled_micro_units: 0,
            status: LaneStatus::Open,
            slashing_escrow_micro_units: self.config.slashing_escrow_micro_units,
        };
        self.settlement_lanes.insert(lane_id.clone(), lane);
        self.counters.settlement_lanes = self.settlement_lanes.len() as u64;
        self.recompute_roots();
        self.append_record("open_settlement_lane", &lane_id);
        Ok(lane_id)
    }

    pub fn approve_paymaster(&mut self, request: ApprovePaymasterRequest) -> Result<String> {
        require(
            self.settlement_lanes.contains_key(&request.lane_id),
            "unknown settlement lane",
        )?;
        require(
            self.encrypted_cohorts
                .contains_key(&request.payer_cohort_id),
            "unknown payer cohort",
        )?;
        require(
            request.max_rebate_bps <= self.config.max_user_fee_bps,
            "paymaster rebate above max user fee",
        )?;
        for asset in &request.approved_assets {
            require(
                self.config.accepted_fee_assets.contains(asset),
                "paymaster asset is not accepted",
            )?;
        }
        let approval_id = deterministic_id(
            "paymaster-approval",
            &[
                request.sponsor_id.as_str(),
                request.payer_cohort_id.as_str(),
                request.lane_id.as_str(),
                request.policy_root.as_str(),
            ],
        );
        let approval = PaymasterApproval {
            approval_id: approval_id.clone(),
            sponsor_id: request.sponsor_id,
            payer_cohort_id: request.payer_cohort_id,
            lane_id: request.lane_id,
            approved_assets: request.approved_assets,
            max_private_fee_micro_units: request.max_private_fee_micro_units,
            max_rebate_bps: request.max_rebate_bps,
            policy_root: request.policy_root,
            pq_signature_commitment: request.pq_signature_commitment,
            valid_from_l2_height: self.config.l2_height,
            valid_until_l2_height: self
                .config
                .l2_height
                .saturating_add(self.config.paymaster_ttl_blocks),
        };
        self.paymaster_approvals
            .insert(approval_id.clone(), approval);
        self.counters.paymaster_approvals = self.paymaster_approvals.len() as u64;
        self.recompute_roots();
        self.append_record("approve_paymaster", &approval_id);
        Ok(approval_id)
    }

    pub fn mint_rebate_coupon(&mut self, request: MintRebateRequest) -> Result<String> {
        require(
            self.settlement_lanes
                .contains_key(&request.settlement_lane_id),
            "unknown settlement lane",
        )?;
        require(
            self.encrypted_cohorts
                .contains_key(&request.payer_cohort_id),
            "unknown payer cohort",
        )?;
        require(
            request.rebate_bps <= self.config.max_user_fee_bps,
            "rebate above max user fee",
        )?;
        require(
            !self.consumed_nullifiers.contains(&request.coupon_nullifier),
            "coupon nullifier already consumed",
        )?;
        let coupon_id = deterministic_id(
            "rebate-coupon",
            &[
                request.sponsor_id.as_str(),
                request.payer_cohort_id.as_str(),
                request.fee_asset_id.as_str(),
                request.coupon_nullifier.as_str(),
            ],
        );
        let coupon = RebateCoupon {
            coupon_id: coupon_id.clone(),
            sponsor_id: request.sponsor_id,
            payer_cohort_id: request.payer_cohort_id,
            fee_asset_id: request.fee_asset_id,
            face_value_commitment: request.face_value_commitment,
            rebate_bps: request.rebate_bps,
            coupon_nullifier: request.coupon_nullifier,
            settlement_lane_id: request.settlement_lane_id,
            status: CouponStatus::Minted,
            minted_l2_height: self.config.l2_height,
            expires_l2_height: self.config.l2_height.saturating_add(request.ttl_blocks),
        };
        self.consumed_nullifiers
            .insert(coupon.coupon_nullifier.clone());
        self.rebate_coupons.insert(coupon_id.clone(), coupon);
        self.counters.rebate_coupons = self.rebate_coupons.len() as u64;
        self.recompute_roots();
        self.append_record("mint_rebate_coupon", &coupon_id);
        Ok(coupon_id)
    }

    pub fn create_encrypted_cohort(
        &mut self,
        encrypted_membership_root: &str,
        payer_count_commitment: &str,
        view_key_policy_root: &str,
    ) -> Result<String> {
        require(
            !encrypted_membership_root.is_empty(),
            "empty encrypted membership root",
        )?;
        let cohort_id = deterministic_id(
            "cohort",
            &[
                encrypted_membership_root,
                payer_count_commitment,
                view_key_policy_root,
            ],
        );
        let cohort = EncryptedPayerCohort {
            cohort_id: cohort_id.clone(),
            encrypted_membership_root: encrypted_membership_root.to_string(),
            payer_count_commitment: payer_count_commitment.to_string(),
            min_privacy_set_size: self.config.min_privacy_set_size,
            encryption_suite: "ML-KEM-1024+private-view-key-policy".to_string(),
            view_key_policy_root: view_key_policy_root.to_string(),
            nullifier_domain: deterministic_id("nullifier-domain", &[encrypted_membership_root]),
            created_l2_height: self.config.l2_height,
        };
        self.encrypted_cohorts.insert(cohort_id.clone(), cohort);
        self.counters.encrypted_cohorts = self.encrypted_cohorts.len() as u64;
        self.recompute_roots();
        self.append_record("create_encrypted_cohort", &cohort_id);
        Ok(cohort_id)
    }

    pub fn add_conversion(&mut self, mut conversion: TokenBasketConversion) -> Result<String> {
        require(
            self.config
                .accepted_fee_assets
                .contains(&conversion.source_asset_id),
            "source asset is not accepted",
        )?;
        require(
            self.config
                .accepted_fee_assets
                .contains(&conversion.target_asset_id),
            "target asset is not accepted",
        )?;
        require(!conversion.basket_legs.is_empty(), "empty basket legs")?;
        let weight_sum = conversion
            .basket_legs
            .iter()
            .map(|leg| leg.weight_ppm)
            .sum::<u64>();
        require(
            weight_sum == 1_000_000,
            "basket weights must sum to ppm one",
        )?;
        conversion.conversion_id = deterministic_id(
            "basket-conversion",
            &[
                conversion.source_asset_id.as_str(),
                conversion.target_asset_id.as_str(),
                conversion.route_id.as_str(),
                conversion.oracle_attestation_root.as_str(),
            ],
        );
        let conversion_id = conversion.conversion_id.clone();
        self.conversions.insert(conversion_id.clone(), conversion);
        self.counters.conversion_quotes = self.conversions.len() as u64;
        self.recompute_roots();
        self.append_record("add_conversion", &conversion_id);
        Ok(conversion_id)
    }

    pub fn schedule_proof_amortization(
        &mut self,
        route_ids: BTreeSet<String>,
        batch_ids: BTreeSet<String>,
        pq_verifier_key_root: &str,
    ) -> Result<String> {
        require(!route_ids.is_empty(), "proof plan needs a route")?;
        let proof_plan_id = deterministic_id(
            "proof-plan",
            &[
                root_from_set("proof-routes", &route_ids).as_str(),
                root_from_set("proof-batches", &batch_ids).as_str(),
                pq_verifier_key_root,
            ],
        );
        let proof_count = route_ids.len().saturating_add(batch_ids.len()) as u64;
        let plan = RecursiveProofAmortization {
            proof_plan_id: proof_plan_id.clone(),
            aggregation_root: root_from_strings(PROOF_SUITE, &[proof_plan_id.as_str()]),
            route_ids,
            batch_ids,
            proof_count,
            amortized_fee_micro_units: proof_count
                .saturating_mul(1_000)
                .saturating_div(self.config.recursive_proof_batch_size.max(1)),
            recursive_depth: depth_for_count(proof_count),
            pq_verifier_key_root: pq_verifier_key_root.to_string(),
            compression_ratio_ppm: compression_ratio_ppm(proof_count),
            scheduled_l2_height: self.config.l2_height,
        };
        self.proof_plans.insert(proof_plan_id.clone(), plan);
        self.counters.proof_plans = self.proof_plans.len() as u64;
        self.recompute_roots();
        self.append_record("schedule_proof_amortization", &proof_plan_id);
        Ok(proof_plan_id)
    }

    pub fn quote_route_fee(&mut self, request: QuoteRouteFeeRequest) -> Result<String> {
        require(
            self.encrypted_cohorts
                .contains_key(&request.payer_cohort_id),
            "unknown payer cohort",
        )?;
        require(
            request.user_fee_bps <= self.config.max_user_fee_bps,
            "quote user fee exceeds config",
        )?;
        require(
            request.sponsor_rebate_bps <= request.user_fee_bps,
            "rebate exceeds quoted user fee",
        )?;
        require(
            self.proof_plans.contains_key(&request.proof_plan_id),
            "unknown proof plan",
        )?;
        if let Some(approval_id) = &request.paymaster_approval_id {
            let approval = self
                .paymaster_approvals
                .get(approval_id)
                .ok_or_else(|| "unknown paymaster approval".to_string())?;
            require(
                approval.active_at(self.config.l2_height),
                "paymaster approval is not active",
            )?;
            require(
                approval
                    .approved_assets
                    .contains(&request.preferred_fee_asset_id),
                "preferred fee asset not approved",
            )?;
        }
        if let Some(conversion_id) = &request.conversion_id {
            require(
                self.conversions.contains_key(conversion_id),
                "unknown conversion quote",
            )?;
        }
        let quote_id = deterministic_id(
            "route-fee-quote",
            &[
                request.route_id.as_str(),
                request.payer_cohort_id.as_str(),
                request.preferred_fee_asset_id.as_str(),
                request.quoted_fee_commitment.as_str(),
            ],
        );
        let quote = RouteFeeQuote {
            quote_id: quote_id.clone(),
            route_id: request.route_id,
            payer_cohort_id: request.payer_cohort_id,
            preferred_fee_asset_id: request.preferred_fee_asset_id,
            accepted_fee_assets: request.accepted_fee_assets,
            quoted_fee_commitment: request.quoted_fee_commitment,
            user_fee_bps: request.user_fee_bps,
            sponsor_rebate_bps: request.sponsor_rebate_bps,
            paymaster_approval_id: request.paymaster_approval_id,
            conversion_id: request.conversion_id,
            proof_plan_id: request.proof_plan_id,
            quote_l2_height: self.config.l2_height,
            expires_l2_height: self
                .config
                .l2_height
                .saturating_add(self.config.quote_ttl_blocks),
        };
        self.fee_quotes.insert(quote_id.clone(), quote);
        self.counters.fee_quotes = self.fee_quotes.len() as u64;
        self.recompute_roots();
        self.append_record("quote_route_fee", &quote_id);
        Ok(quote_id)
    }

    pub fn arm_nullifier_fence(
        &mut self,
        nullifier: &str,
        account_set_root: &str,
        route_id: &str,
        cohort_id: &str,
        abuse_score_commitment: &str,
    ) -> Result<String> {
        require(
            self.encrypted_cohorts.contains_key(cohort_id),
            "unknown payer cohort",
        )?;
        let fence_id = deterministic_id("nullifier-fence", &[nullifier, route_id, cohort_id]);
        let fence = NullifierFence {
            fence_id: fence_id.clone(),
            nullifier: nullifier.to_string(),
            account_set_root: account_set_root.to_string(),
            route_id: route_id.to_string(),
            cohort_id: cohort_id.to_string(),
            abuse_score_commitment: abuse_score_commitment.to_string(),
            status: FenceStatus::Armed,
            armed_l2_height: self.config.l2_height,
            expires_l2_height: self
                .config
                .l2_height
                .saturating_add(self.config.fence_ttl_blocks),
        };
        self.nullifier_fences.insert(fence_id.clone(), fence);
        self.counters.nullifier_fences = self.nullifier_fences.len() as u64;
        self.recompute_roots();
        self.append_record("arm_nullifier_fence", &fence_id);
        Ok(fence_id)
    }

    pub fn net_batch(
        &mut self,
        lane_id: &str,
        commitment_ids: BTreeSet<String>,
        coupon_ids: BTreeSet<String>,
        net_by_asset_micro_units: BTreeMap<String, i128>,
        proof_plan_id: &str,
    ) -> Result<String> {
        require(
            self.settlement_lanes.contains_key(lane_id),
            "unknown settlement lane",
        )?;
        require(
            commitment_ids.len().saturating_add(coupon_ids.len()) <= self.config.batch_max_items,
            "netting batch too large",
        )?;
        require(
            self.proof_plans.contains_key(proof_plan_id),
            "unknown proof plan",
        )?;
        for id in &commitment_ids {
            require(
                self.commitments.contains_key(id),
                "unknown commitment in batch",
            )?;
        }
        for id in &coupon_ids {
            require(
                self.rebate_coupons.contains_key(id),
                "unknown coupon in batch",
            )?;
        }
        let batch_id = deterministic_id(
            "netting-batch",
            &[
                lane_id,
                root_from_set("batch-commitments", &commitment_ids).as_str(),
                root_from_set("batch-coupons", &coupon_ids).as_str(),
                proof_plan_id,
            ],
        );
        let gross_fee_commitment_root = root_from_set("batch-gross-fees", &commitment_ids);
        let rebate_commitment_root = root_from_set("batch-rebates", &coupon_ids);
        let net_settlement_commitment =
            json_commitment("batch-net-settlement", &net_by_asset_micro_units);
        let batch = BatchFeeNetting {
            batch_id: batch_id.clone(),
            lane_id: lane_id.to_string(),
            commitment_ids,
            coupon_ids,
            net_by_asset_micro_units,
            gross_fee_commitment_root,
            rebate_commitment_root,
            net_settlement_commitment,
            proof_plan_id: proof_plan_id.to_string(),
            closed_l2_height: self.config.l2_height,
        };
        let net_delta = batch
            .net_by_asset_micro_units
            .values()
            .copied()
            .fold(0_i128, |acc, value| acc.saturating_add(value));
        if let Some(lane) = self.settlement_lanes.get_mut(lane_id) {
            lane.pending_net_micro_units = lane.pending_net_micro_units.saturating_add(net_delta);
        }
        self.netting_batches.insert(batch_id.clone(), batch);
        self.counters.netting_batches = self.netting_batches.len() as u64;
        self.recompute_roots();
        self.append_record("net_batch", &batch_id);
        Ok(batch_id)
    }

    pub fn settle_lane(&mut self, lane_id: &str, settled_micro_units: u64) -> Result<()> {
        let lane = self
            .settlement_lanes
            .get_mut(lane_id)
            .ok_or_else(|| "unknown settlement lane".to_string())?;
        require(lane.status != LaneStatus::Slashed, "lane is slashed")?;
        lane.settled_micro_units = lane.settled_micro_units.saturating_add(settled_micro_units);
        lane.pending_net_micro_units = lane
            .pending_net_micro_units
            .saturating_sub(settled_micro_units as i128);
        lane.status = LaneStatus::Settled;
        self.recompute_roots();
        self.append_record("settle_lane", lane_id);
        Ok(())
    }

    pub fn record_slashing(&mut self, evidence: SlashingEvidence) -> Result<String> {
        require(
            self.settlement_lanes.contains_key(&evidence.lane_id),
            "unknown settlement lane",
        )?;
        let slash_id = deterministic_id(
            "slash",
            &[
                evidence.lane_id.as_str(),
                evidence.sponsor_id.as_str(),
                evidence.accused_actor_id.as_str(),
                evidence.evidence_root.as_str(),
            ],
        );
        let mut stored = evidence;
        stored.slash_id = slash_id.clone();
        if let Some(lane) = self.settlement_lanes.get_mut(&stored.lane_id) {
            lane.status = LaneStatus::Slashed;
            lane.slashing_escrow_micro_units = lane
                .slashing_escrow_micro_units
                .saturating_sub(stored.slash_amount_micro_units);
        }
        self.slashing_records.insert(slash_id.clone(), stored);
        self.counters.slashing_records = self.slashing_records.len() as u64;
        self.recompute_roots();
        self.append_record("record_slashing", &slash_id);
        Ok(slash_id)
    }

    fn append_record(&mut self, action: &str, object_id: &str) {
        self.public_journal.push(json!({
            "action": action,
            "object_id": object_id,
            "state_root": self.roots.state_root,
            "l2_height": self.config.l2_height
        }));
        self.counters.public_records = self.public_journal.len() as u64;
    }
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

pub fn deterministic_id(domain: &str, parts: &[&str]) -> String {
    let mut hash_parts = Vec::with_capacity(parts.len());
    for part in parts {
        hash_parts.push(HashPart::Str(part));
    }
    domain_hash(domain, &hash_parts, 20)
}

pub fn commitment_id(domain: &str, owner: &str, amount_micro_units: u64) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(owner), HashPart::U64(amount_micro_units)],
        32,
    )
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

pub fn state_root_from_roots(roots: &Roots, counters: &Counters, config: &Config) -> String {
    let payload = json!({
        "protocol_version": PROTOCOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "chain_id": config.chain_id,
        "l2_height": config.l2_height,
        "monero_height": config.monero_height,
        "commitment_root": roots.commitment_root,
        "paymaster_root": roots.paymaster_root,
        "rebate_root": roots.rebate_root,
        "settlement_lane_root": roots.settlement_lane_root,
        "conversion_root": roots.conversion_root,
        "netting_root": roots.netting_root,
        "cohort_root": roots.cohort_root,
        "quote_root": roots.quote_root,
        "proof_root": roots.proof_root,
        "fence_root": roots.fence_root,
        "slashing_root": roots.slashing_root,
        "counters": counters
    });
    domain_hash(
        "private-fee-rebate-router-state-root",
        &[HashPart::Json(&payload)],
        32,
    )
}

pub fn depth_for_count(count: u64) -> u16 {
    let mut remaining = count.max(1);
    let mut depth = 0_u16;
    while remaining > 1 {
        remaining = remaining.div_ceil(2);
        depth = depth.saturating_add(1);
    }
    depth
}

pub fn compression_ratio_ppm(proof_count: u64) -> u64 {
    if proof_count <= 1 {
        1_000_000
    } else {
        1_000_000_u64.saturating_div(depth_for_count(proof_count) as u64 + 1)
    }
}
