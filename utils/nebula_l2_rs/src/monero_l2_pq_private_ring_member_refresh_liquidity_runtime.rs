use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateRingMemberRefreshLiquidityRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_RING_MEMBER_REFRESH_LIQUIDITY_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-ring-member-refresh-liquidity-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_RING_MEMBER_REFRESH_LIQUIDITY_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-ring-refresh-liquidity-v1";
pub const RING_POOL_SCHEME: &str = "monero-l2-ring-member-refresh-pool-root-v1";
pub const DECOY_QUALITY_SCHEME: &str = "monero-l2-decoy-quality-commitment-root-v1";
pub const CURATOR_ATTESTATION_SCHEME: &str = "pq-curator-ring-member-attestation-root-v1";
pub const SPONSOR_LANE_SCHEME: &str = "private-liquidity-sponsor-lane-root-v1";
pub const WITHDRAWAL_FLOOR_SCHEME: &str = "withdrawal-privacy-floor-root-v1";
pub const QUARANTINE_SCHEME: &str = "stale-linked-ring-member-quarantine-root-v1";
pub const REFRESH_CREDIT_SCHEME: &str = "low-fee-ring-refresh-credit-root-v1";
pub const REDACTION_BUDGET_SCHEME: &str = "ring-member-refresh-redaction-budget-root-v1";
pub const DEFAULT_MIN_POOL_MEMBERS: u64 = 16_384;
pub const DEFAULT_TARGET_POOL_MEMBERS: u64 = 65_536;
pub const DEFAULT_MIN_DECOY_QUALITY_BPS: u64 = 8_500;
pub const DEFAULT_WITHDRAWAL_PRIVACY_FLOOR: u64 = 262_144;
pub const DEFAULT_MAX_LINKAGE_BPS: u64 = 40;
pub const DEFAULT_QUARANTINE_TTL_BLOCKS: u64 = 7_200;
pub const DEFAULT_REFRESH_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_CREDIT_TTL_BLOCKS: u64 = 43_200;
pub const DEFAULT_MAX_REDACTIONS_PER_EPOCH: u64 = 512;
pub const DEFAULT_LOW_FEE_CREDIT_MICRO_UNITS: u64 = 3_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_POOLS: usize = 262_144;
pub const DEFAULT_MAX_QUALITY_COMMITMENTS: usize = 1_048_576;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 1_048_576;
pub const DEFAULT_MAX_SPONSOR_LANES: usize = 262_144;
pub const DEFAULT_MAX_WITHDRAWAL_FLOORS: usize = 524_288;
pub const DEFAULT_MAX_QUARANTINES: usize = 1_048_576;
pub const DEFAULT_MAX_CREDITS: usize = 1_048_576;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 262_144;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolKind {
    WalletRefresh,
    WithdrawalCover,
    LiquidityRebalance,
    MerchantSettlement,
    AtomicSwap,
    DevnetDemo,
}

impl PoolKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletRefresh => "wallet_refresh",
            Self::WithdrawalCover => "withdrawal_cover",
            Self::LiquidityRebalance => "liquidity_rebalance",
            Self::MerchantSettlement => "merchant_settlement",
            Self::AtomicSwap => "atomic_swap",
            Self::DevnetDemo => "devnet_demo",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Draft,
    Active,
    Saturated,
    Draining,
    Frozen,
    Retired,
}

impl PoolStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Saturated => "saturated",
            Self::Draining => "draining",
            Self::Frozen => "frozen",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QualityStatus {
    Pending,
    Accepted,
    BelowFloor,
    Superseded,
    Disputed,
}

impl QualityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::BelowFloor => "below_floor",
            Self::Superseded => "superseded",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    PoolCurated,
    QualityAudited,
    PqSignatureRotated,
    LiquidityAvailable,
    WithdrawalFloorMet,
    QuarantineObserved,
    RedactionBudgetObserved,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PoolCurated => "pool_curated",
            Self::QualityAudited => "quality_audited",
            Self::PqSignatureRotated => "pq_signature_rotated",
            Self::LiquidityAvailable => "liquidity_available",
            Self::WithdrawalFloorMet => "withdrawal_floor_met",
            Self::QuarantineObserved => "quarantine_observed",
            Self::RedactionBudgetObserved => "redaction_budget_observed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorLaneStatus {
    Open,
    Throttled,
    Exhausted,
    Settling,
    Closed,
}

impl SponsorLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Throttled => "throttled",
            Self::Exhausted => "exhausted",
            Self::Settling => "settling",
            Self::Closed => "closed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FloorStatus {
    Proposed,
    Active,
    Breached,
    Retired,
}

impl FloorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Active => "active",
            Self::Breached => "breached",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineKind {
    StaleAge,
    LinkedKeyImage,
    DecoyCluster,
    CuratorDispute,
    WithdrawalCorrelation,
}

impl QuarantineKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaleAge => "stale_age",
            Self::LinkedKeyImage => "linked_key_image",
            Self::DecoyCluster => "decoy_cluster",
            Self::CuratorDispute => "curator_dispute",
            Self::WithdrawalCorrelation => "withdrawal_correlation",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CreditStatus {
    Minted,
    Reserved,
    Redeemed,
    Expired,
    Revoked,
}

impl CreditStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Minted => "minted",
            Self::Reserved => "reserved",
            Self::Redeemed => "redeemed",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionScope {
    PoolMembership,
    CuratorMetadata,
    SponsorLane,
    WithdrawalBatch,
    DemoFixture,
}

impl RedactionScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PoolMembership => "pool_membership",
            Self::CuratorMetadata => "curator_metadata",
            Self::SponsorLane => "sponsor_lane",
            Self::WithdrawalBatch => "withdrawal_batch",
            Self::DemoFixture => "demo_fixture",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub l2_network: String,
    pub monero_network: String,
    pub asset_id: String,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub ring_pool_scheme: String,
    pub decoy_quality_scheme: String,
    pub curator_attestation_scheme: String,
    pub sponsor_lane_scheme: String,
    pub withdrawal_floor_scheme: String,
    pub quarantine_scheme: String,
    pub refresh_credit_scheme: String,
    pub redaction_budget_scheme: String,
    pub min_pool_members: u64,
    pub target_pool_members: u64,
    pub min_decoy_quality_bps: u64,
    pub withdrawal_privacy_floor: u64,
    pub max_linkage_bps: u64,
    pub quarantine_ttl_blocks: u64,
    pub refresh_ttl_blocks: u64,
    pub credit_ttl_blocks: u64,
    pub max_redactions_per_epoch: u64,
    pub low_fee_credit_micro_units: u64,
    pub min_pq_security_bits: u16,
    pub max_pools: usize,
    pub max_quality_commitments: usize,
    pub max_attestations: usize,
    pub max_sponsor_lanes: usize,
    pub max_withdrawal_floors: usize,
    pub max_quarantines: usize,
    pub max_credits: usize,
    pub max_redaction_budgets: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            asset_id: DEVNET_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_auth_suite: PQ_AUTH_SUITE.to_string(),
            ring_pool_scheme: RING_POOL_SCHEME.to_string(),
            decoy_quality_scheme: DECOY_QUALITY_SCHEME.to_string(),
            curator_attestation_scheme: CURATOR_ATTESTATION_SCHEME.to_string(),
            sponsor_lane_scheme: SPONSOR_LANE_SCHEME.to_string(),
            withdrawal_floor_scheme: WITHDRAWAL_FLOOR_SCHEME.to_string(),
            quarantine_scheme: QUARANTINE_SCHEME.to_string(),
            refresh_credit_scheme: REFRESH_CREDIT_SCHEME.to_string(),
            redaction_budget_scheme: REDACTION_BUDGET_SCHEME.to_string(),
            min_pool_members: DEFAULT_MIN_POOL_MEMBERS,
            target_pool_members: DEFAULT_TARGET_POOL_MEMBERS,
            min_decoy_quality_bps: DEFAULT_MIN_DECOY_QUALITY_BPS,
            withdrawal_privacy_floor: DEFAULT_WITHDRAWAL_PRIVACY_FLOOR,
            max_linkage_bps: DEFAULT_MAX_LINKAGE_BPS,
            quarantine_ttl_blocks: DEFAULT_QUARANTINE_TTL_BLOCKS,
            refresh_ttl_blocks: DEFAULT_REFRESH_TTL_BLOCKS,
            credit_ttl_blocks: DEFAULT_CREDIT_TTL_BLOCKS,
            max_redactions_per_epoch: DEFAULT_MAX_REDACTIONS_PER_EPOCH,
            low_fee_credit_micro_units: DEFAULT_LOW_FEE_CREDIT_MICRO_UNITS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_pools: DEFAULT_MAX_POOLS,
            max_quality_commitments: DEFAULT_MAX_QUALITY_COMMITMENTS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_sponsor_lanes: DEFAULT_MAX_SPONSOR_LANES,
            max_withdrawal_floors: DEFAULT_MAX_WITHDRAWAL_FLOORS,
            max_quarantines: DEFAULT_MAX_QUARANTINES,
            max_credits: DEFAULT_MAX_CREDITS,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "hash_suite": self.hash_suite,
            "pq_auth_suite": self.pq_auth_suite,
            "ring_pool_scheme": self.ring_pool_scheme,
            "decoy_quality_scheme": self.decoy_quality_scheme,
            "curator_attestation_scheme": self.curator_attestation_scheme,
            "sponsor_lane_scheme": self.sponsor_lane_scheme,
            "withdrawal_floor_scheme": self.withdrawal_floor_scheme,
            "quarantine_scheme": self.quarantine_scheme,
            "refresh_credit_scheme": self.refresh_credit_scheme,
            "redaction_budget_scheme": self.redaction_budget_scheme,
            "min_pool_members": self.min_pool_members,
            "target_pool_members": self.target_pool_members,
            "min_decoy_quality_bps": self.min_decoy_quality_bps,
            "withdrawal_privacy_floor": self.withdrawal_privacy_floor,
            "max_linkage_bps": self.max_linkage_bps,
            "quarantine_ttl_blocks": self.quarantine_ttl_blocks,
            "refresh_ttl_blocks": self.refresh_ttl_blocks,
            "credit_ttl_blocks": self.credit_ttl_blocks,
            "max_redactions_per_epoch": self.max_redactions_per_epoch,
            "low_fee_credit_micro_units": self.low_fee_credit_micro_units,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_pools": self.max_pools,
            "max_quality_commitments": self.max_quality_commitments,
            "max_attestations": self.max_attestations,
            "max_sponsor_lanes": self.max_sponsor_lanes,
            "max_withdrawal_floors": self.max_withdrawal_floors,
            "max_quarantines": self.max_quarantines,
            "max_credits": self.max_credits,
            "max_redaction_budgets": self.max_redaction_budgets,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub pools: u64,
    pub quality_commitments: u64,
    pub curator_attestations: u64,
    pub sponsor_lanes: u64,
    pub withdrawal_floors: u64,
    pub quarantines: u64,
    pub refresh_credits: u64,
    pub redaction_budgets: u64,
    pub public_records: u64,
    pub events: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "pools": self.pools,
            "quality_commitments": self.quality_commitments,
            "curator_attestations": self.curator_attestations,
            "sponsor_lanes": self.sponsor_lanes,
            "withdrawal_floors": self.withdrawal_floors,
            "quarantines": self.quarantines,
            "refresh_credits": self.refresh_credits,
            "redaction_budgets": self.redaction_budgets,
            "public_records": self.public_records,
            "events": self.events,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub pools_root: String,
    pub quality_commitments_root: String,
    pub curator_attestations_root: String,
    pub sponsor_lanes_root: String,
    pub withdrawal_floors_root: String,
    pub quarantines_root: String,
    pub refresh_credits_root: String,
    pub redaction_budgets_root: String,
    pub quarantined_members_root: String,
    pub refreshed_members_root: String,
    pub public_records_root: String,
    pub events_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "pools_root": self.pools_root,
            "quality_commitments_root": self.quality_commitments_root,
            "curator_attestations_root": self.curator_attestations_root,
            "sponsor_lanes_root": self.sponsor_lanes_root,
            "withdrawal_floors_root": self.withdrawal_floors_root,
            "quarantines_root": self.quarantines_root,
            "refresh_credits_root": self.refresh_credits_root,
            "redaction_budgets_root": self.redaction_budgets_root,
            "quarantined_members_root": self.quarantined_members_root,
            "refreshed_members_root": self.refreshed_members_root,
            "public_records_root": self.public_records_root,
            "events_root": self.events_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RingMemberRefreshPool {
    pub pool_id: String,
    pub curator_id: String,
    pub kind: PoolKind,
    pub status: PoolStatus,
    pub epoch: u64,
    pub member_commitment_root: String,
    pub decoy_distribution_root: String,
    pub liquidity_bucket_root: String,
    pub min_member_age_blocks: u64,
    pub member_count: u64,
    pub eligible_member_count: u64,
    pub reserved_refresh_slots: u64,
    pub liquidity_micro_units: u64,
    pub sponsor_lane_id: String,
    pub withdrawal_floor_id: String,
    pub created_height: u64,
    pub expires_height: u64,
}

impl RingMemberRefreshPool {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "curator_id": self.curator_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "epoch": self.epoch,
            "member_commitment_root": self.member_commitment_root,
            "decoy_distribution_root": self.decoy_distribution_root,
            "liquidity_bucket_root": self.liquidity_bucket_root,
            "min_member_age_blocks": self.min_member_age_blocks,
            "member_count": self.member_count,
            "eligible_member_count": self.eligible_member_count,
            "reserved_refresh_slots": self.reserved_refresh_slots,
            "liquidity_micro_units": self.liquidity_micro_units,
            "sponsor_lane_id": self.sponsor_lane_id,
            "withdrawal_floor_id": self.withdrawal_floor_id,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DecoyQualityCommitment {
    pub commitment_id: String,
    pub pool_id: String,
    pub curator_id: String,
    pub status: QualityStatus,
    pub decoy_quality_bps: u64,
    pub linkage_risk_bps: u64,
    pub age_histogram_root: String,
    pub output_amount_bucket_root: String,
    pub ring_member_entropy_root: String,
    pub excluded_member_root: String,
    pub sample_audit_root: String,
    pub committed_height: u64,
}

impl DecoyQualityCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "pool_id": self.pool_id,
            "curator_id": self.curator_id,
            "status": self.status.as_str(),
            "decoy_quality_bps": self.decoy_quality_bps,
            "linkage_risk_bps": self.linkage_risk_bps,
            "age_histogram_root": self.age_histogram_root,
            "output_amount_bucket_root": self.output_amount_bucket_root,
            "ring_member_entropy_root": self.ring_member_entropy_root,
            "excluded_member_root": self.excluded_member_root,
            "sample_audit_root": self.sample_audit_root,
            "committed_height": self.committed_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqCuratorAttestation {
    pub attestation_id: String,
    pub curator_id: String,
    pub subject_id: String,
    pub kind: AttestationKind,
    pub pq_public_key_root: String,
    pub attestation_root: String,
    pub signature_root: String,
    pub security_bits: u16,
    pub observed_height: u64,
}

impl PqCuratorAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "curator_id": self.curator_id,
            "subject_id": self.subject_id,
            "kind": self.kind.as_str(),
            "pq_public_key_root": self.pq_public_key_root,
            "attestation_root": self.attestation_root,
            "signature_root": self.signature_root,
            "security_bits": self.security_bits,
            "observed_height": self.observed_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquiditySponsorLane {
    pub lane_id: String,
    pub sponsor_id: String,
    pub status: SponsorLaneStatus,
    pub asset_id: String,
    pub committed_liquidity_micro_units: u64,
    pub remaining_liquidity_micro_units: u64,
    pub max_refreshes_per_epoch: u64,
    pub fee_cap_micro_units: u64,
    pub eligible_pool_root: String,
    pub sponsor_policy_root: String,
    pub opened_height: u64,
    pub expires_height: u64,
}

impl LiquiditySponsorLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "sponsor_id": self.sponsor_id,
            "status": self.status.as_str(),
            "asset_id": self.asset_id,
            "committed_liquidity_micro_units": self.committed_liquidity_micro_units,
            "remaining_liquidity_micro_units": self.remaining_liquidity_micro_units,
            "max_refreshes_per_epoch": self.max_refreshes_per_epoch,
            "fee_cap_micro_units": self.fee_cap_micro_units,
            "eligible_pool_root": self.eligible_pool_root,
            "sponsor_policy_root": self.sponsor_policy_root,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WithdrawalPrivacyFloor {
    pub floor_id: String,
    pub pool_id: String,
    pub status: FloorStatus,
    pub min_ring_members: u64,
    pub min_decoy_quality_bps: u64,
    pub min_sponsor_liquidity_micro_units: u64,
    pub enforced_for_withdrawal_root: String,
    pub breach_oracle_root: String,
    pub activated_height: u64,
}

impl WithdrawalPrivacyFloor {
    pub fn public_record(&self) -> Value {
        json!({
            "floor_id": self.floor_id,
            "pool_id": self.pool_id,
            "status": self.status.as_str(),
            "min_ring_members": self.min_ring_members,
            "min_decoy_quality_bps": self.min_decoy_quality_bps,
            "min_sponsor_liquidity_micro_units": self.min_sponsor_liquidity_micro_units,
            "enforced_for_withdrawal_root": self.enforced_for_withdrawal_root,
            "breach_oracle_root": self.breach_oracle_root,
            "activated_height": self.activated_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StaleLinkedMemberQuarantine {
    pub quarantine_id: String,
    pub pool_id: String,
    pub member_commitment: String,
    pub kind: QuarantineKind,
    pub evidence_root: String,
    pub linked_member_root: String,
    pub release_condition_root: String,
    pub linkage_risk_bps: u64,
    pub quarantined_height: u64,
    pub release_height: u64,
}

impl StaleLinkedMemberQuarantine {
    pub fn public_record(&self) -> Value {
        json!({
            "quarantine_id": self.quarantine_id,
            "pool_id": self.pool_id,
            "member_commitment": self.member_commitment,
            "kind": self.kind.as_str(),
            "evidence_root": self.evidence_root,
            "linked_member_root": self.linked_member_root,
            "release_condition_root": self.release_condition_root,
            "linkage_risk_bps": self.linkage_risk_bps,
            "quarantined_height": self.quarantined_height,
            "release_height": self.release_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRefreshCredit {
    pub credit_id: String,
    pub owner_commitment: String,
    pub pool_id: String,
    pub sponsor_lane_id: String,
    pub status: CreditStatus,
    pub credit_micro_units: u64,
    pub fee_reduction_bps: u64,
    pub nullifier: String,
    pub redemption_policy_root: String,
    pub minted_height: u64,
    pub expires_height: u64,
}

impl LowFeeRefreshCredit {
    pub fn public_record(&self) -> Value {
        json!({
            "credit_id": self.credit_id,
            "owner_commitment": self.owner_commitment,
            "pool_id": self.pool_id,
            "sponsor_lane_id": self.sponsor_lane_id,
            "status": self.status.as_str(),
            "credit_micro_units": self.credit_micro_units,
            "fee_reduction_bps": self.fee_reduction_bps,
            "nullifier": self.nullifier,
            "redemption_policy_root": self.redemption_policy_root,
            "minted_height": self.minted_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub owner_id: String,
    pub scope: RedactionScope,
    pub epoch: u64,
    pub redaction_allowance: u64,
    pub redactions_used: u64,
    pub redacted_field_root: String,
    pub audit_commitment_root: String,
    pub pq_authorization_root: String,
}

impl PrivacyRedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "owner_id": self.owner_id,
            "scope": self.scope.as_str(),
            "epoch": self.epoch,
            "redaction_allowance": self.redaction_allowance,
            "redactions_used": self.redactions_used,
            "redacted_field_root": self.redacted_field_root,
            "audit_commitment_root": self.audit_commitment_root,
            "pq_authorization_root": self.pq_authorization_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub height: u64,
}

impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "height": self.height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PoolRequest {
    pub curator_id: String,
    pub kind: PoolKind,
    pub epoch: u64,
    pub member_commitment_root: String,
    pub decoy_distribution_root: String,
    pub liquidity_bucket_root: String,
    pub min_member_age_blocks: u64,
    pub member_count: u64,
    pub eligible_member_count: u64,
    pub liquidity_micro_units: u64,
    pub sponsor_lane_id: String,
    pub withdrawal_floor_id: String,
    pub created_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QualityRequest {
    pub pool_id: String,
    pub curator_id: String,
    pub decoy_quality_bps: u64,
    pub linkage_risk_bps: u64,
    pub age_histogram_root: String,
    pub output_amount_bucket_root: String,
    pub ring_member_entropy_root: String,
    pub excluded_member_root: String,
    pub sample_audit_root: String,
    pub committed_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttestationRequest {
    pub curator_id: String,
    pub subject_id: String,
    pub kind: AttestationKind,
    pub pq_public_key_root: String,
    pub attestation_root: String,
    pub signature_root: String,
    pub security_bits: u16,
    pub observed_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorLaneRequest {
    pub sponsor_id: String,
    pub asset_id: String,
    pub committed_liquidity_micro_units: u64,
    pub max_refreshes_per_epoch: u64,
    pub fee_cap_micro_units: u64,
    pub eligible_pool_root: String,
    pub sponsor_policy_root: String,
    pub opened_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WithdrawalFloorRequest {
    pub pool_id: String,
    pub min_ring_members: u64,
    pub min_decoy_quality_bps: u64,
    pub min_sponsor_liquidity_micro_units: u64,
    pub enforced_for_withdrawal_root: String,
    pub breach_oracle_root: String,
    pub activated_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuarantineRequest {
    pub pool_id: String,
    pub member_commitment: String,
    pub kind: QuarantineKind,
    pub evidence_root: String,
    pub linked_member_root: String,
    pub release_condition_root: String,
    pub linkage_risk_bps: u64,
    pub quarantined_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RefreshCreditRequest {
    pub owner_commitment: String,
    pub pool_id: String,
    pub sponsor_lane_id: String,
    pub credit_micro_units: u64,
    pub fee_reduction_bps: u64,
    pub nullifier: String,
    pub redemption_policy_root: String,
    pub minted_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudgetRequest {
    pub owner_id: String,
    pub scope: RedactionScope,
    pub epoch: u64,
    pub redaction_allowance: u64,
    pub redactions_used: u64,
    pub redacted_field_root: String,
    pub audit_commitment_root: String,
    pub pq_authorization_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub pools: BTreeMap<String, RingMemberRefreshPool>,
    pub quality_commitments: BTreeMap<String, DecoyQualityCommitment>,
    pub curator_attestations: BTreeMap<String, PqCuratorAttestation>,
    pub sponsor_lanes: BTreeMap<String, LiquiditySponsorLane>,
    pub withdrawal_floors: BTreeMap<String, WithdrawalPrivacyFloor>,
    pub quarantines: BTreeMap<String, StaleLinkedMemberQuarantine>,
    pub refresh_credits: BTreeMap<String, LowFeeRefreshCredit>,
    pub redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub quarantined_members: BTreeSet<String>,
    pub refreshed_members: BTreeSet<String>,
    pub public_records: BTreeMap<String, Value>,
    pub events: Vec<RuntimeEvent>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::devnet())
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            pools: BTreeMap::new(),
            quality_commitments: BTreeMap::new(),
            curator_attestations: BTreeMap::new(),
            sponsor_lanes: BTreeMap::new(),
            withdrawal_floors: BTreeMap::new(),
            quarantines: BTreeMap::new(),
            refresh_credits: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            quarantined_members: BTreeSet::new(),
            refreshed_members: BTreeSet::new(),
            public_records: BTreeMap::new(),
            events: Vec::new(),
        }
    }

    pub fn devnet() -> Self {
        devnet_state()
    }

    pub fn demo() -> Self {
        demo_state()
    }

    pub fn counters(&self) -> Counters {
        Counters {
            pools: self.pools.len() as u64,
            quality_commitments: self.quality_commitments.len() as u64,
            curator_attestations: self.curator_attestations.len() as u64,
            sponsor_lanes: self.sponsor_lanes.len() as u64,
            withdrawal_floors: self.withdrawal_floors.len() as u64,
            quarantines: self.quarantines.len() as u64,
            refresh_credits: self.refresh_credits.len() as u64,
            redaction_budgets: self.redaction_budgets.len() as u64,
            public_records: self.public_records.len() as u64,
            events: self.events.len() as u64,
        }
    }

    pub fn roots(&self) -> Roots {
        let mut roots = Roots {
            config_root: record_root(
                "RING-REFRESH-LIQUIDITY-CONFIG",
                &self.config.public_record(),
            ),
            counters_root: record_root(
                "RING-REFRESH-LIQUIDITY-COUNTERS",
                &self.counters().public_record(),
            ),
            pools_root: map_public_root("RING-REFRESH-LIQUIDITY-POOLS", &self.pools),
            quality_commitments_root: map_public_root(
                "RING-REFRESH-LIQUIDITY-QUALITY-COMMITMENTS",
                &self.quality_commitments,
            ),
            curator_attestations_root: map_public_root(
                "RING-REFRESH-LIQUIDITY-CURATOR-ATTESTATIONS",
                &self.curator_attestations,
            ),
            sponsor_lanes_root: map_public_root(
                "RING-REFRESH-LIQUIDITY-SPONSOR-LANES",
                &self.sponsor_lanes,
            ),
            withdrawal_floors_root: map_public_root(
                "RING-REFRESH-LIQUIDITY-WITHDRAWAL-FLOORS",
                &self.withdrawal_floors,
            ),
            quarantines_root: map_public_root(
                "RING-REFRESH-LIQUIDITY-QUARANTINES",
                &self.quarantines,
            ),
            refresh_credits_root: map_public_root(
                "RING-REFRESH-LIQUIDITY-REFRESH-CREDITS",
                &self.refresh_credits,
            ),
            redaction_budgets_root: map_public_root(
                "RING-REFRESH-LIQUIDITY-REDACTION-BUDGETS",
                &self.redaction_budgets,
            ),
            quarantined_members_root: set_root(
                "RING-REFRESH-LIQUIDITY-QUARANTINED-MEMBERS",
                &self.quarantined_members,
            ),
            refreshed_members_root: set_root(
                "RING-REFRESH-LIQUIDITY-REFRESHED-MEMBERS",
                &self.refreshed_members,
            ),
            public_records_root: public_records_root(&self.public_records),
            events_root: event_root(&self.events),
            state_root: String::new(),
        };
        roots.state_root = state_root_from_roots(&roots);
        roots
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "roots": roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn register_sponsor_lane(
        &mut self,
        request: SponsorLaneRequest,
    ) -> Result<LiquiditySponsorLane> {
        ensure_capacity(
            "sponsor lane",
            self.sponsor_lanes.len(),
            self.config.max_sponsor_lanes,
        )?;
        ensure_nonempty("sponsor_id", &request.sponsor_id)?;
        ensure_nonempty("asset_id", &request.asset_id)?;
        ensure_nonempty("eligible_pool_root", &request.eligible_pool_root)?;
        ensure_nonempty("sponsor_policy_root", &request.sponsor_policy_root)?;
        if request.committed_liquidity_micro_units == 0 {
            return Err("committed_liquidity_micro_units must be positive".to_string());
        }
        let lane_id = sponsor_lane_id(&request);
        ensure_absent("sponsor lane", &self.sponsor_lanes, &lane_id)?;
        let record = LiquiditySponsorLane {
            lane_id: lane_id.clone(),
            sponsor_id: request.sponsor_id,
            status: SponsorLaneStatus::Open,
            asset_id: request.asset_id,
            committed_liquidity_micro_units: request.committed_liquidity_micro_units,
            remaining_liquidity_micro_units: request.committed_liquidity_micro_units,
            max_refreshes_per_epoch: request.max_refreshes_per_epoch,
            fee_cap_micro_units: request.fee_cap_micro_units,
            eligible_pool_root: request.eligible_pool_root,
            sponsor_policy_root: request.sponsor_policy_root,
            opened_height: request.opened_height,
            expires_height: request
                .opened_height
                .saturating_add(self.config.credit_ttl_blocks),
        };
        self.record_public(format!("sponsor_lane:{lane_id}"), record.public_record())?;
        self.push_event(
            "sponsor_lane_registered",
            &lane_id,
            record.public_record(),
            record.opened_height,
        );
        self.sponsor_lanes.insert(lane_id, record.clone());
        Ok(record)
    }

    pub fn register_withdrawal_floor(
        &mut self,
        request: WithdrawalFloorRequest,
    ) -> Result<WithdrawalPrivacyFloor> {
        ensure_capacity(
            "withdrawal floor",
            self.withdrawal_floors.len(),
            self.config.max_withdrawal_floors,
        )?;
        ensure_nonempty(
            "enforced_for_withdrawal_root",
            &request.enforced_for_withdrawal_root,
        )?;
        ensure_nonempty("breach_oracle_root", &request.breach_oracle_root)?;
        if request.min_ring_members < self.config.withdrawal_privacy_floor {
            return Err("withdrawal floor below configured privacy floor".to_string());
        }
        if request.min_decoy_quality_bps < self.config.min_decoy_quality_bps {
            return Err("decoy quality floor below configured minimum".to_string());
        }
        let floor_id = withdrawal_floor_id(&request);
        ensure_absent("withdrawal floor", &self.withdrawal_floors, &floor_id)?;
        let record = WithdrawalPrivacyFloor {
            floor_id: floor_id.clone(),
            pool_id: request.pool_id,
            status: FloorStatus::Active,
            min_ring_members: request.min_ring_members,
            min_decoy_quality_bps: request.min_decoy_quality_bps,
            min_sponsor_liquidity_micro_units: request.min_sponsor_liquidity_micro_units,
            enforced_for_withdrawal_root: request.enforced_for_withdrawal_root,
            breach_oracle_root: request.breach_oracle_root,
            activated_height: request.activated_height,
        };
        self.record_public(
            format!("withdrawal_floor:{floor_id}"),
            record.public_record(),
        )?;
        self.push_event(
            "withdrawal_floor_registered",
            &floor_id,
            record.public_record(),
            record.activated_height,
        );
        self.withdrawal_floors.insert(floor_id, record.clone());
        Ok(record)
    }

    pub fn open_pool(&mut self, request: PoolRequest) -> Result<RingMemberRefreshPool> {
        ensure_capacity("ring refresh pool", self.pools.len(), self.config.max_pools)?;
        ensure_nonempty("curator_id", &request.curator_id)?;
        ensure_nonempty("member_commitment_root", &request.member_commitment_root)?;
        ensure_nonempty("decoy_distribution_root", &request.decoy_distribution_root)?;
        ensure_nonempty("liquidity_bucket_root", &request.liquidity_bucket_root)?;
        if request.member_count < self.config.min_pool_members {
            return Err("ring refresh pool has too few members".to_string());
        }
        if request.eligible_member_count < self.config.min_pool_members {
            return Err("ring refresh pool has too few eligible members".to_string());
        }
        if !request.sponsor_lane_id.is_empty() {
            ensure_known(
                "sponsor lane",
                &self.sponsor_lanes,
                &request.sponsor_lane_id,
            )?;
        }
        if !request.withdrawal_floor_id.is_empty() {
            ensure_known(
                "withdrawal floor",
                &self.withdrawal_floors,
                &request.withdrawal_floor_id,
            )?;
        }
        let pool_id = pool_id(&request);
        ensure_absent("ring refresh pool", &self.pools, &pool_id)?;
        let record = RingMemberRefreshPool {
            pool_id: pool_id.clone(),
            curator_id: request.curator_id,
            kind: request.kind,
            status: PoolStatus::Active,
            epoch: request.epoch,
            member_commitment_root: request.member_commitment_root,
            decoy_distribution_root: request.decoy_distribution_root,
            liquidity_bucket_root: request.liquidity_bucket_root,
            min_member_age_blocks: request.min_member_age_blocks,
            member_count: request.member_count,
            eligible_member_count: request.eligible_member_count,
            reserved_refresh_slots: 0,
            liquidity_micro_units: request.liquidity_micro_units,
            sponsor_lane_id: request.sponsor_lane_id,
            withdrawal_floor_id: request.withdrawal_floor_id,
            created_height: request.created_height,
            expires_height: request
                .created_height
                .saturating_add(self.config.refresh_ttl_blocks),
        };
        self.record_public(format!("pool:{pool_id}"), record.public_record())?;
        self.push_event(
            "ring_refresh_pool_opened",
            &pool_id,
            record.public_record(),
            record.created_height,
        );
        self.pools.insert(pool_id, record.clone());
        Ok(record)
    }

    pub fn commit_decoy_quality(
        &mut self,
        request: QualityRequest,
    ) -> Result<DecoyQualityCommitment> {
        ensure_capacity(
            "decoy quality commitment",
            self.quality_commitments.len(),
            self.config.max_quality_commitments,
        )?;
        ensure_known("ring refresh pool", &self.pools, &request.pool_id)?;
        ensure_nonempty("curator_id", &request.curator_id)?;
        ensure_nonempty("age_histogram_root", &request.age_histogram_root)?;
        ensure_nonempty(
            "output_amount_bucket_root",
            &request.output_amount_bucket_root,
        )?;
        ensure_nonempty(
            "ring_member_entropy_root",
            &request.ring_member_entropy_root,
        )?;
        ensure_nonempty("sample_audit_root", &request.sample_audit_root)?;
        if request.decoy_quality_bps > MAX_BPS || request.linkage_risk_bps > MAX_BPS {
            return Err("quality and linkage risk are expressed in basis points".to_string());
        }
        let commitment_id = quality_commitment_id(&request);
        ensure_absent(
            "decoy quality commitment",
            &self.quality_commitments,
            &commitment_id,
        )?;
        let status = if request.decoy_quality_bps >= self.config.min_decoy_quality_bps
            && request.linkage_risk_bps <= self.config.max_linkage_bps
        {
            QualityStatus::Accepted
        } else {
            QualityStatus::BelowFloor
        };
        let record = DecoyQualityCommitment {
            commitment_id: commitment_id.clone(),
            pool_id: request.pool_id,
            curator_id: request.curator_id,
            status,
            decoy_quality_bps: request.decoy_quality_bps,
            linkage_risk_bps: request.linkage_risk_bps,
            age_histogram_root: request.age_histogram_root,
            output_amount_bucket_root: request.output_amount_bucket_root,
            ring_member_entropy_root: request.ring_member_entropy_root,
            excluded_member_root: request.excluded_member_root,
            sample_audit_root: request.sample_audit_root,
            committed_height: request.committed_height,
        };
        self.record_public(format!("quality:{commitment_id}"), record.public_record())?;
        self.push_event(
            "decoy_quality_committed",
            &commitment_id,
            record.public_record(),
            record.committed_height,
        );
        self.quality_commitments
            .insert(commitment_id, record.clone());
        Ok(record)
    }

    pub fn attest_curator(&mut self, request: AttestationRequest) -> Result<PqCuratorAttestation> {
        ensure_capacity(
            "pq curator attestation",
            self.curator_attestations.len(),
            self.config.max_attestations,
        )?;
        ensure_nonempty("curator_id", &request.curator_id)?;
        ensure_nonempty("subject_id", &request.subject_id)?;
        ensure_nonempty("pq_public_key_root", &request.pq_public_key_root)?;
        ensure_nonempty("attestation_root", &request.attestation_root)?;
        ensure_nonempty("signature_root", &request.signature_root)?;
        if request.security_bits < self.config.min_pq_security_bits {
            return Err("curator attestation below configured pq security bits".to_string());
        }
        let attestation_id = curator_attestation_id(&request);
        ensure_absent(
            "pq curator attestation",
            &self.curator_attestations,
            &attestation_id,
        )?;
        let record = PqCuratorAttestation {
            attestation_id: attestation_id.clone(),
            curator_id: request.curator_id,
            subject_id: request.subject_id,
            kind: request.kind,
            pq_public_key_root: request.pq_public_key_root,
            attestation_root: request.attestation_root,
            signature_root: request.signature_root,
            security_bits: request.security_bits,
            observed_height: request.observed_height,
        };
        self.record_public(
            format!("attestation:{attestation_id}"),
            record.public_record(),
        )?;
        self.push_event(
            "pq_curator_attested",
            &attestation_id,
            record.public_record(),
            record.observed_height,
        );
        self.curator_attestations
            .insert(attestation_id, record.clone());
        Ok(record)
    }

    pub fn quarantine_member(
        &mut self,
        request: QuarantineRequest,
    ) -> Result<StaleLinkedMemberQuarantine> {
        ensure_capacity(
            "quarantine",
            self.quarantines.len(),
            self.config.max_quarantines,
        )?;
        ensure_known("ring refresh pool", &self.pools, &request.pool_id)?;
        ensure_nonempty("member_commitment", &request.member_commitment)?;
        ensure_nonempty("evidence_root", &request.evidence_root)?;
        ensure_nonempty("linked_member_root", &request.linked_member_root)?;
        ensure_nonempty("release_condition_root", &request.release_condition_root)?;
        if request.linkage_risk_bps > MAX_BPS {
            return Err("linkage_risk_bps exceeds MAX_BPS".to_string());
        }
        let quarantine_id = quarantine_id(&request);
        ensure_absent("quarantine", &self.quarantines, &quarantine_id)?;
        let record = StaleLinkedMemberQuarantine {
            quarantine_id: quarantine_id.clone(),
            pool_id: request.pool_id,
            member_commitment: request.member_commitment,
            kind: request.kind,
            evidence_root: request.evidence_root,
            linked_member_root: request.linked_member_root,
            release_condition_root: request.release_condition_root,
            linkage_risk_bps: request.linkage_risk_bps,
            quarantined_height: request.quarantined_height,
            release_height: request
                .quarantined_height
                .saturating_add(self.config.quarantine_ttl_blocks),
        };
        self.quarantined_members
            .insert(record.member_commitment.clone());
        self.record_public(
            format!("quarantine:{quarantine_id}"),
            record.public_record(),
        )?;
        self.push_event(
            "member_quarantined",
            &quarantine_id,
            record.public_record(),
            record.quarantined_height,
        );
        self.quarantines.insert(quarantine_id, record.clone());
        Ok(record)
    }

    pub fn mint_refresh_credit(
        &mut self,
        request: RefreshCreditRequest,
    ) -> Result<LowFeeRefreshCredit> {
        ensure_capacity(
            "refresh credit",
            self.refresh_credits.len(),
            self.config.max_credits,
        )?;
        ensure_known("ring refresh pool", &self.pools, &request.pool_id)?;
        ensure_known(
            "sponsor lane",
            &self.sponsor_lanes,
            &request.sponsor_lane_id,
        )?;
        ensure_nonempty("owner_commitment", &request.owner_commitment)?;
        ensure_nonempty("nullifier", &request.nullifier)?;
        ensure_nonempty("redemption_policy_root", &request.redemption_policy_root)?;
        if request.fee_reduction_bps > MAX_BPS {
            return Err("fee_reduction_bps exceeds MAX_BPS".to_string());
        }
        let credit_id = refresh_credit_id(&request);
        ensure_absent("refresh credit", &self.refresh_credits, &credit_id)?;
        let record = LowFeeRefreshCredit {
            credit_id: credit_id.clone(),
            owner_commitment: request.owner_commitment,
            pool_id: request.pool_id,
            sponsor_lane_id: request.sponsor_lane_id,
            status: CreditStatus::Minted,
            credit_micro_units: request.credit_micro_units,
            fee_reduction_bps: request.fee_reduction_bps,
            nullifier: request.nullifier,
            redemption_policy_root: request.redemption_policy_root,
            minted_height: request.minted_height,
            expires_height: request
                .minted_height
                .saturating_add(self.config.credit_ttl_blocks),
        };
        self.refreshed_members
            .insert(record.owner_commitment.clone());
        self.record_public(
            format!("refresh_credit:{credit_id}"),
            record.public_record(),
        )?;
        self.push_event(
            "refresh_credit_minted",
            &credit_id,
            record.public_record(),
            record.minted_height,
        );
        self.refresh_credits.insert(credit_id, record.clone());
        Ok(record)
    }

    pub fn reserve_redaction_budget(
        &mut self,
        request: RedactionBudgetRequest,
    ) -> Result<PrivacyRedactionBudget> {
        ensure_capacity(
            "redaction budget",
            self.redaction_budgets.len(),
            self.config.max_redaction_budgets,
        )?;
        ensure_nonempty("owner_id", &request.owner_id)?;
        ensure_nonempty("redacted_field_root", &request.redacted_field_root)?;
        ensure_nonempty("audit_commitment_root", &request.audit_commitment_root)?;
        ensure_nonempty("pq_authorization_root", &request.pq_authorization_root)?;
        if request.redaction_allowance > self.config.max_redactions_per_epoch {
            return Err("redaction allowance exceeds configured epoch budget".to_string());
        }
        if request.redactions_used > request.redaction_allowance {
            return Err("redactions used cannot exceed allowance".to_string());
        }
        let budget_id = redaction_budget_id(&request);
        ensure_absent("redaction budget", &self.redaction_budgets, &budget_id)?;
        let record = PrivacyRedactionBudget {
            budget_id: budget_id.clone(),
            owner_id: request.owner_id,
            scope: request.scope,
            epoch: request.epoch,
            redaction_allowance: request.redaction_allowance,
            redactions_used: request.redactions_used,
            redacted_field_root: request.redacted_field_root,
            audit_commitment_root: request.audit_commitment_root,
            pq_authorization_root: request.pq_authorization_root,
        };
        self.record_public(
            format!("redaction_budget:{budget_id}"),
            record.public_record(),
        )?;
        self.push_event(
            "redaction_budget_reserved",
            &budget_id,
            record.public_record(),
            request.epoch,
        );
        self.redaction_budgets.insert(budget_id, record.clone());
        Ok(record)
    }

    fn record_public(&mut self, key: String, value: Value) -> Result<()> {
        ensure_capacity(
            "public record",
            self.public_records.len(),
            self.config.max_quality_commitments
                + self.config.max_attestations
                + self.config.max_pools,
        )?;
        self.public_records.insert(key, value);
        Ok(())
    }

    fn push_event(&mut self, kind: &str, subject_id: &str, payload: Value, height: u64) {
        let event_id = event_id(kind, subject_id, &payload, height, self.events.len() as u64);
        self.events.push(RuntimeEvent {
            event_id,
            kind: kind.to_string(),
            subject_id: subject_id.to_string(),
            payload_root: record_root("RING-REFRESH-LIQUIDITY-EVENT-PAYLOAD", &payload),
            height,
        });
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

pub fn devnet_state() -> State {
    let mut state = State::new(Config::devnet());
    let sponsor = state
        .register_sponsor_lane(SponsorLaneRequest {
            sponsor_id: "devnet-refresh-sponsor-0".to_string(),
            asset_id: DEVNET_ASSET_ID.to_string(),
            committed_liquidity_micro_units: 50_000_000_000,
            max_refreshes_per_epoch: 25_000,
            fee_cap_micro_units: 4_000,
            eligible_pool_root: fixture_root("eligible-pools", 0),
            sponsor_policy_root: fixture_root("sponsor-policy", 0),
            opened_height: 10,
        })
        .expect("devnet sponsor lane");
    let floor = state
        .register_withdrawal_floor(WithdrawalFloorRequest {
            pool_id: "pending-devnet-pool".to_string(),
            min_ring_members: DEFAULT_WITHDRAWAL_PRIVACY_FLOOR,
            min_decoy_quality_bps: DEFAULT_MIN_DECOY_QUALITY_BPS,
            min_sponsor_liquidity_micro_units: 1_000_000_000,
            enforced_for_withdrawal_root: fixture_root("withdrawal-enforcement", 0),
            breach_oracle_root: fixture_root("withdrawal-breach-oracle", 0),
            activated_height: 11,
        })
        .expect("devnet withdrawal floor");
    let pool = state
        .open_pool(PoolRequest {
            curator_id: "devnet-pq-curator-0".to_string(),
            kind: PoolKind::WalletRefresh,
            epoch: 1,
            member_commitment_root: fixture_root("ring-members", 0),
            decoy_distribution_root: fixture_root("decoy-distribution", 0),
            liquidity_bucket_root: fixture_root("liquidity-buckets", 0),
            min_member_age_blocks: 720,
            member_count: 393_216,
            eligible_member_count: 327_680,
            liquidity_micro_units: 25_000_000_000,
            sponsor_lane_id: sponsor.lane_id.clone(),
            withdrawal_floor_id: floor.floor_id.clone(),
            created_height: 12,
        })
        .expect("devnet pool");
    state
        .commit_decoy_quality(QualityRequest {
            pool_id: pool.pool_id.clone(),
            curator_id: pool.curator_id.clone(),
            decoy_quality_bps: 9_240,
            linkage_risk_bps: 18,
            age_histogram_root: fixture_root("age-histogram", 0),
            output_amount_bucket_root: fixture_root("amount-buckets", 0),
            ring_member_entropy_root: fixture_root("member-entropy", 0),
            excluded_member_root: fixture_root("excluded-members", 0),
            sample_audit_root: fixture_root("sample-audit", 0),
            committed_height: 13,
        })
        .expect("devnet quality commitment");
    state
        .attest_curator(AttestationRequest {
            curator_id: pool.curator_id.clone(),
            subject_id: pool.pool_id.clone(),
            kind: AttestationKind::PoolCurated,
            pq_public_key_root: fixture_root("pq-public-key", 0),
            attestation_root: fixture_root("curator-attestation", 0),
            signature_root: fixture_root("curator-signature", 0),
            security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            observed_height: 14,
        })
        .expect("devnet attestation");
    state
}

pub fn demo_state() -> State {
    let mut state = devnet_state();
    let pool_id = state.pools.keys().next().cloned().expect("devnet pool id");
    let lane_id = state
        .sponsor_lanes
        .keys()
        .next()
        .cloned()
        .expect("devnet lane id");
    state
        .quarantine_member(QuarantineRequest {
            pool_id: pool_id.clone(),
            member_commitment: fixture_root("linked-member", 1),
            kind: QuarantineKind::LinkedKeyImage,
            evidence_root: fixture_root("linkage-evidence", 1),
            linked_member_root: fixture_root("linked-cluster", 1),
            release_condition_root: fixture_root("release-condition", 1),
            linkage_risk_bps: 250,
            quarantined_height: 21,
        })
        .expect("demo quarantine");
    state
        .mint_refresh_credit(RefreshCreditRequest {
            owner_commitment: fixture_root("refresh-owner", 1),
            pool_id: pool_id.clone(),
            sponsor_lane_id: lane_id,
            credit_micro_units: DEFAULT_LOW_FEE_CREDIT_MICRO_UNITS,
            fee_reduction_bps: 8_000,
            nullifier: fixture_root("refresh-credit-nullifier", 1),
            redemption_policy_root: fixture_root("refresh-credit-policy", 1),
            minted_height: 22,
        })
        .expect("demo refresh credit");
    state
        .reserve_redaction_budget(RedactionBudgetRequest {
            owner_id: "devnet-pq-curator-0".to_string(),
            scope: RedactionScope::PoolMembership,
            epoch: 1,
            redaction_allowance: 64,
            redactions_used: 3,
            redacted_field_root: fixture_root("redacted-fields", 1),
            audit_commitment_root: fixture_root("redaction-audit", 1),
            pq_authorization_root: fixture_root("redaction-pq-auth", 1),
        })
        .expect("demo redaction budget");
    state
}

pub fn pool_id(request: &PoolRequest) -> String {
    domain_hash(
        "RING-REFRESH-LIQUIDITY-POOL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.curator_id),
            HashPart::Str(request.kind.as_str()),
            HashPart::U64(request.epoch),
            HashPart::Str(&request.member_commitment_root),
            HashPart::Str(&request.decoy_distribution_root),
            HashPart::Str(&request.sponsor_lane_id),
            HashPart::U64(request.created_height),
        ],
        32,
    )
}

pub fn quality_commitment_id(request: &QualityRequest) -> String {
    domain_hash(
        "RING-REFRESH-LIQUIDITY-QUALITY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.pool_id),
            HashPart::Str(&request.curator_id),
            HashPart::U64(request.decoy_quality_bps),
            HashPart::U64(request.linkage_risk_bps),
            HashPart::Str(&request.ring_member_entropy_root),
            HashPart::U64(request.committed_height),
        ],
        32,
    )
}

pub fn curator_attestation_id(request: &AttestationRequest) -> String {
    domain_hash(
        "RING-REFRESH-LIQUIDITY-CURATOR-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.curator_id),
            HashPart::Str(&request.subject_id),
            HashPart::Str(request.kind.as_str()),
            HashPart::Str(&request.attestation_root),
            HashPart::Str(&request.signature_root),
            HashPart::U64(request.security_bits as u64),
            HashPart::U64(request.observed_height),
        ],
        32,
    )
}

pub fn sponsor_lane_id(request: &SponsorLaneRequest) -> String {
    domain_hash(
        "RING-REFRESH-LIQUIDITY-SPONSOR-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.sponsor_id),
            HashPart::Str(&request.asset_id),
            HashPart::U64(request.committed_liquidity_micro_units),
            HashPart::Str(&request.eligible_pool_root),
            HashPart::Str(&request.sponsor_policy_root),
            HashPart::U64(request.opened_height),
        ],
        32,
    )
}

pub fn withdrawal_floor_id(request: &WithdrawalFloorRequest) -> String {
    domain_hash(
        "RING-REFRESH-LIQUIDITY-WITHDRAWAL-FLOOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.pool_id),
            HashPart::U64(request.min_ring_members),
            HashPart::U64(request.min_decoy_quality_bps),
            HashPart::U64(request.min_sponsor_liquidity_micro_units),
            HashPart::Str(&request.enforced_for_withdrawal_root),
            HashPart::U64(request.activated_height),
        ],
        32,
    )
}

pub fn quarantine_id(request: &QuarantineRequest) -> String {
    domain_hash(
        "RING-REFRESH-LIQUIDITY-QUARANTINE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.pool_id),
            HashPart::Str(&request.member_commitment),
            HashPart::Str(request.kind.as_str()),
            HashPart::Str(&request.evidence_root),
            HashPart::U64(request.linkage_risk_bps),
            HashPart::U64(request.quarantined_height),
        ],
        32,
    )
}

pub fn refresh_credit_id(request: &RefreshCreditRequest) -> String {
    domain_hash(
        "RING-REFRESH-LIQUIDITY-REFRESH-CREDIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.owner_commitment),
            HashPart::Str(&request.pool_id),
            HashPart::Str(&request.sponsor_lane_id),
            HashPart::U64(request.credit_micro_units),
            HashPart::Str(&request.nullifier),
            HashPart::U64(request.minted_height),
        ],
        32,
    )
}

pub fn redaction_budget_id(request: &RedactionBudgetRequest) -> String {
    domain_hash(
        "RING-REFRESH-LIQUIDITY-REDACTION-BUDGET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.owner_id),
            HashPart::Str(request.scope.as_str()),
            HashPart::U64(request.epoch),
            HashPart::U64(request.redaction_allowance),
            HashPart::Str(&request.audit_commitment_root),
            HashPart::Str(&request.pq_authorization_root),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn record_root(domain: &str, record: &Value) -> String {
    payload_root(domain, record)
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn state_root_from_roots(roots: &Roots) -> String {
    record_root(
        "RING-REFRESH-LIQUIDITY-STATE-ROOT",
        &json!({
            "config_root": roots.config_root,
            "counters_root": roots.counters_root,
            "pools_root": roots.pools_root,
            "quality_commitments_root": roots.quality_commitments_root,
            "curator_attestations_root": roots.curator_attestations_root,
            "sponsor_lanes_root": roots.sponsor_lanes_root,
            "withdrawal_floors_root": roots.withdrawal_floors_root,
            "quarantines_root": roots.quarantines_root,
            "refresh_credits_root": roots.refresh_credits_root,
            "redaction_budgets_root": roots.redaction_budgets_root,
            "quarantined_members_root": roots.quarantined_members_root,
            "refreshed_members_root": roots.refreshed_members_root,
            "public_records_root": roots.public_records_root,
            "events_root": roots.events_root,
        }),
    )
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for RingMemberRefreshPool {
    fn public_record(&self) -> Value {
        RingMemberRefreshPool::public_record(self)
    }
}

impl PublicRecord for DecoyQualityCommitment {
    fn public_record(&self) -> Value {
        DecoyQualityCommitment::public_record(self)
    }
}

impl PublicRecord for PqCuratorAttestation {
    fn public_record(&self) -> Value {
        PqCuratorAttestation::public_record(self)
    }
}

impl PublicRecord for LiquiditySponsorLane {
    fn public_record(&self) -> Value {
        LiquiditySponsorLane::public_record(self)
    }
}

impl PublicRecord for WithdrawalPrivacyFloor {
    fn public_record(&self) -> Value {
        WithdrawalPrivacyFloor::public_record(self)
    }
}

impl PublicRecord for StaleLinkedMemberQuarantine {
    fn public_record(&self) -> Value {
        StaleLinkedMemberQuarantine::public_record(self)
    }
}

impl PublicRecord for LowFeeRefreshCredit {
    fn public_record(&self) -> Value {
        LowFeeRefreshCredit::public_record(self)
    }
}

impl PublicRecord for PrivacyRedactionBudget {
    fn public_record(&self) -> Value {
        PrivacyRedactionBudget::public_record(self)
    }
}

pub fn map_public_root<T: PublicRecord>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": value.public_record() }))
        .collect::<Vec<_>>();
    public_record_root(domain, &leaves)
}

pub fn public_records_root(records: &BTreeMap<String, Value>) -> String {
    let leaves = records
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": value }))
        .collect::<Vec<_>>();
    public_record_root("RING-REFRESH-LIQUIDITY-PUBLIC-RECORDS", &leaves)
}

pub fn event_root(events: &[RuntimeEvent]) -> String {
    let leaves = events
        .iter()
        .map(RuntimeEvent::public_record)
        .collect::<Vec<_>>();
    public_record_root("RING-REFRESH-LIQUIDITY-EVENTS", &leaves)
}

pub fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    public_record_root(domain, &leaves)
}

pub fn fixture_root(label: &str, index: u64) -> String {
    domain_hash(
        "RING-REFRESH-LIQUIDITY-DEVNET-FIXTURE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(index),
        ],
        32,
    )
}

pub fn event_id(
    kind: &str,
    subject_id: &str,
    payload: &Value,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "RING-REFRESH-LIQUIDITY-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(subject_id),
            HashPart::Json(payload),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn ensure_nonempty(field: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

pub fn ensure_capacity(label: &str, current: usize, max: usize) -> Result<()> {
    if current >= max {
        Err(format!("{label} capacity exhausted"))
    } else {
        Ok(())
    }
}

pub fn ensure_absent<T>(label: &str, map: &BTreeMap<String, T>, key: &str) -> Result<()> {
    if map.contains_key(key) {
        Err(format!("{label} {key} already exists"))
    } else {
        Ok(())
    }
}

pub fn ensure_known<T>(label: &str, map: &BTreeMap<String, T>, key: &str) -> Result<()> {
    if map.contains_key(key) {
        Ok(())
    } else {
        Err(format!("unknown {label} {key}"))
    }
}
