use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2LowFeePqConfidentialDaBatchReuseCouponRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2LowFeePqConfidentialDaBatchReuseCouponRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_DA_BATCH_REUSE_COUPON_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-da-batch-reuse-coupon-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_DA_BATCH_REUSE_COUPON_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-da-batch-reuse-coupon-v1";
pub const COUPON_BOOK_SCHEME: &str = "monero-private-l2-confidential-da-reuse-coupon-book-root-v1";
pub const DA_BATCH_SCHEME: &str = "monero-private-l2-low-fee-da-batch-root-v1";
pub const REUSE_CLAIM_SCHEME: &str = "monero-private-l2-confidential-da-batch-reuse-claim-root-v1";
pub const PQ_DA_ATTESTATION_SCHEME: &str =
    "monero-private-l2-pq-da-availability-attestation-root-v1";
pub const SETTLEMENT_FLOW_SCHEME: &str = "monero-private-l2-fast-da-batch-settlement-flow-root-v1";
pub const REBATE_FLOW_SCHEME: &str = "monero-private-l2-confidential-da-reuse-rebate-flow-root-v1";
pub const THROTTLE_SCHEME: &str = "monero-private-l2-da-reuse-abuse-throttle-root-v1";
pub const REDACTION_BUDGET_SCHEME: &str = "monero-private-l2-da-reuse-redaction-budget-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str =
    "roots-only-private-l2-da-batch-reuse-coupon-operator-summary-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "roots-only-private-l2-low-fee-pq-confidential-da-batch-reuse-coupon-public-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_COUPON_ASSET_ID: &str = "da-reuse-coupon-devnet";
pub const DEVNET_HEIGHT: u64 = 3_980_000;
pub const DEVNET_EPOCH: u64 = 24_100;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_USER_FEE_BPS: u64 = 4;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 8;
pub const DEFAULT_TARGET_DA_COST_REDUCTION_BPS: u64 = 7_500;
pub const DEFAULT_REUSE_REBATE_BPS: u64 = 1_800;
pub const DEFAULT_OPERATOR_FEE_SHARE_BPS: u64 = 700;
pub const DEFAULT_BATCH_TARGET_BLOCKS: u64 = 3;
pub const DEFAULT_BATCH_FINALITY_BLOCKS: u64 = 10;
pub const DEFAULT_COUPON_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_THROTTLE_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_REDACTION_WINDOW_BLOCKS: u64 = 1_440;
pub const DEFAULT_WALLET_DAILY_REUSE_CAP_BYTES: u64 = 2_097_152;
pub const DEFAULT_BATCH_MAX_PAYLOAD_BYTES: u64 = 33_554_432;
pub const DEFAULT_MAX_REUSES_PER_COUPON: u32 = 16;
pub const DEFAULT_MAX_CLAIMS_PER_BATCH: usize = 65_536;
pub const DEFAULT_OPERATOR_SUMMARY_LIMIT: usize = 128;
pub const MAX_COUPON_BOOKS: usize = 1_048_576;
pub const MAX_DA_BATCH_ROOTS: usize = 2_097_152;
pub const MAX_REUSE_CLAIMS: usize = 8_388_608;
pub const MAX_PQ_DA_ATTESTATIONS: usize = 8_388_608;
pub const MAX_SETTLEMENT_FLOWS: usize = 2_097_152;
pub const MAX_REBATE_FLOWS: usize = 4_194_304;
pub const MAX_THROTTLES: usize = 2_097_152;
pub const MAX_REDACTION_BUDGETS: usize = 1_048_576;
pub const MAX_OPERATOR_SUMMARIES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DaLane {
    MoneroPrivateTransfer,
    BridgeExit,
    SwapSettlement,
    MerchantBatch,
    PayrollBatch,
    WalletSync,
    ProofCarry,
    EmergencyDrain,
}

impl DaLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroPrivateTransfer => "monero_private_transfer",
            Self::BridgeExit => "bridge_exit",
            Self::SwapSettlement => "swap_settlement",
            Self::MerchantBatch => "merchant_batch",
            Self::PayrollBatch => "payroll_batch",
            Self::WalletSync => "wallet_sync",
            Self::ProofCarry => "proof_carry",
            Self::EmergencyDrain => "emergency_drain",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponBookStatus {
    Draft,
    Open,
    Issuing,
    Sealed,
    Reusing,
    Settled,
    Expired,
    Quarantined,
}

impl CouponBookStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Open => "open",
            Self::Issuing => "issuing",
            Self::Sealed => "sealed",
            Self::Reusing => "reusing",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn accepts_issuance(self) -> bool {
        matches!(self, Self::Open | Self::Issuing)
    }

    pub fn accepts_reuse(self) -> bool {
        matches!(self, Self::Sealed | Self::Reusing)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DaBatchStatus {
    Building,
    Rooted,
    Attested,
    Settling,
    Settled,
    Disputed,
    Expired,
}

impl DaBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Building => "building",
            Self::Rooted => "rooted",
            Self::Attested => "attested",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_claims(self) -> bool {
        matches!(self, Self::Rooted | Self::Attested | Self::Settling)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReuseClaimStatus {
    Proposed,
    Attested,
    Netting,
    Settled,
    Rebated,
    Rejected,
    Quarantined,
    Expired,
}

impl ReuseClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Attested => "attested",
            Self::Netting => "netting",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Rejected => "rejected",
            Self::Quarantined => "quarantined",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationPurpose {
    CouponBookIssue,
    DaRootAvailability,
    ReuseClaim,
    BatchSettlement,
    RebateRelease,
    ThrottleRelease,
    RedactionDisclosure,
}

impl AttestationPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CouponBookIssue => "coupon_book_issue",
            Self::DaRootAvailability => "da_root_availability",
            Self::ReuseClaim => "reuse_claim",
            Self::BatchSettlement => "batch_settlement",
            Self::RebateRelease => "rebate_release",
            Self::ThrottleRelease => "throttle_release",
            Self::RedactionDisclosure => "redaction_disclosure",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Approved,
    NeedsMoreShares,
    NeedsMorePrivacy,
    FeeCapExceeded,
    DuplicateNullifier,
    Throttled,
    Rejected,
}

impl AttestationVerdict {
    pub fn approves(self) -> bool {
        matches!(self, Self::Approved)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Proposed,
    Locked,
    FastFinalized,
    Finalized,
    PartiallyFinalized,
    Disputed,
    Reversed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accruing,
    Queued,
    Paid,
    ClawedBack,
    Forfeited,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ThrottleStatus {
    Clear,
    Watching,
    Limited,
    Frozen,
    Released,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionStatus {
    Available,
    Reserved,
    Spent,
    Exhausted,
    Frozen,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub coupon_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_user_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub target_da_cost_reduction_bps: u64,
    pub reuse_rebate_bps: u64,
    pub operator_fee_share_bps: u64,
    pub batch_target_blocks: u64,
    pub batch_finality_blocks: u64,
    pub coupon_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub throttle_window_blocks: u64,
    pub redaction_window_blocks: u64,
    pub wallet_daily_reuse_cap_bytes: u64,
    pub batch_max_payload_bytes: u64,
    pub max_reuses_per_coupon: u32,
    pub max_claims_per_batch: usize,
    pub operator_summary_limit: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            coupon_asset_id: DEVNET_COUPON_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_da_cost_reduction_bps: DEFAULT_TARGET_DA_COST_REDUCTION_BPS,
            reuse_rebate_bps: DEFAULT_REUSE_REBATE_BPS,
            operator_fee_share_bps: DEFAULT_OPERATOR_FEE_SHARE_BPS,
            batch_target_blocks: DEFAULT_BATCH_TARGET_BLOCKS,
            batch_finality_blocks: DEFAULT_BATCH_FINALITY_BLOCKS,
            coupon_ttl_blocks: DEFAULT_COUPON_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            throttle_window_blocks: DEFAULT_THROTTLE_WINDOW_BLOCKS,
            redaction_window_blocks: DEFAULT_REDACTION_WINDOW_BLOCKS,
            wallet_daily_reuse_cap_bytes: DEFAULT_WALLET_DAILY_REUSE_CAP_BYTES,
            batch_max_payload_bytes: DEFAULT_BATCH_MAX_PAYLOAD_BYTES,
            max_reuses_per_coupon: DEFAULT_MAX_REUSES_PER_COUPON,
            max_claims_per_batch: DEFAULT_MAX_CLAIMS_PER_BATCH,
            operator_summary_limit: DEFAULT_OPERATOR_SUMMARY_LIMIT,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> Result<()> {
        require(!self.chain_id.is_empty(), "chain_id is required")?;
        require(!self.l2_network.is_empty(), "l2_network is required")?;
        require(
            !self.monero_network.is_empty(),
            "monero_network is required",
        )?;
        require(!self.fee_asset_id.is_empty(), "fee_asset_id is required")?;
        require(
            !self.coupon_asset_id.is_empty(),
            "coupon_asset_id is required",
        )?;
        require(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "pq security below runtime minimum",
        )?;
        require(self.min_privacy_set_size > 0, "privacy set must be nonzero")?;
        require(
            self.target_user_fee_bps <= self.max_user_fee_bps,
            "target user fee exceeds max user fee",
        )?;
        require(self.max_user_fee_bps <= MAX_BPS, "max user fee exceeds bps")?;
        require(
            self.target_da_cost_reduction_bps <= MAX_BPS,
            "da cost reduction exceeds bps",
        )?;
        require(self.reuse_rebate_bps <= MAX_BPS, "reuse rebate exceeds bps")?;
        require(
            self.operator_fee_share_bps <= MAX_BPS,
            "operator share exceeds bps",
        )?;
        require(self.batch_target_blocks > 0, "batch target must be nonzero")?;
        require(self.batch_finality_blocks > 0, "finality must be nonzero")?;
        require(self.coupon_ttl_blocks > 0, "coupon ttl must be nonzero")?;
        require(
            self.attestation_ttl_blocks > 0,
            "attestation ttl must be nonzero",
        )?;
        require(self.max_reuses_per_coupon > 0, "reuse cap must be nonzero")?;
        require(
            self.max_claims_per_batch > 0,
            "batch claim cap must be nonzero",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "coupon_asset_id": self.coupon_asset_id,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_user_fee_bps": self.target_user_fee_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_da_cost_reduction_bps": self.target_da_cost_reduction_bps,
            "reuse_rebate_bps": self.reuse_rebate_bps,
            "operator_fee_share_bps": self.operator_fee_share_bps,
            "batch_target_blocks": self.batch_target_blocks,
            "batch_finality_blocks": self.batch_finality_blocks,
            "coupon_ttl_blocks": self.coupon_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "throttle_window_blocks": self.throttle_window_blocks,
            "redaction_window_blocks": self.redaction_window_blocks,
            "wallet_daily_reuse_cap_bytes": self.wallet_daily_reuse_cap_bytes,
            "batch_max_payload_bytes": self.batch_max_payload_bytes,
            "max_reuses_per_coupon": self.max_reuses_per_coupon,
            "max_claims_per_batch": self.max_claims_per_batch,
            "operator_summary_limit": self.operator_summary_limit,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub coupon_books_issued: u64,
    pub da_batches_rooted: u64,
    pub reuse_claims_opened: u64,
    pub reuse_claims_settled: u64,
    pub pq_da_attestations: u64,
    pub settlement_flows: u64,
    pub rebate_flows: u64,
    pub throttle_events: u64,
    pub redaction_budget_events: u64,
    pub operator_summaries: u64,
    pub total_payload_bytes: u64,
    pub reused_payload_bytes: u64,
    pub estimated_da_cost_saved_micro: u64,
    pub total_user_fee_micro: u64,
    pub total_rebate_micro: u64,
    pub total_operator_fee_micro: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub coupon_books_root: String,
    pub da_batch_roots_root: String,
    pub reuse_claims_root: String,
    pub pq_da_attestations_root: String,
    pub settlement_flows_root: String,
    pub rebate_flows_root: String,
    pub throttles_root: String,
    pub redaction_budgets_root: String,
    pub operator_summaries_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            config_root: empty_root("CONFIG"),
            counters_root: empty_root("COUNTERS"),
            coupon_books_root: empty_root(COUPON_BOOK_SCHEME),
            da_batch_roots_root: empty_root(DA_BATCH_SCHEME),
            reuse_claims_root: empty_root(REUSE_CLAIM_SCHEME),
            pq_da_attestations_root: empty_root(PQ_DA_ATTESTATION_SCHEME),
            settlement_flows_root: empty_root(SETTLEMENT_FLOW_SCHEME),
            rebate_flows_root: empty_root(REBATE_FLOW_SCHEME),
            throttles_root: empty_root(THROTTLE_SCHEME),
            redaction_budgets_root: empty_root(REDACTION_BUDGET_SCHEME),
            operator_summaries_root: empty_root(OPERATOR_SUMMARY_SCHEME),
            state_root: empty_root("STATE"),
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CouponBookRecord {
    pub book_id: String,
    pub issuer_id: String,
    pub lane: DaLane,
    pub status: CouponBookStatus,
    pub coupon_commitment_root: String,
    pub nullifier_root: String,
    pub eligible_da_root: String,
    pub issued_coupons: u64,
    pub remaining_coupons: u64,
    pub max_reuses_per_coupon: u32,
    pub face_value_micro: u64,
    pub fee_cap_micro: u64,
    pub privacy_set_size: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl CouponBookRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "book_id": self.book_id,
            "issuer_id": self.issuer_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "coupon_commitment_root": self.coupon_commitment_root,
            "nullifier_root": self.nullifier_root,
            "eligible_da_root": self.eligible_da_root,
            "issued_coupons": self.issued_coupons,
            "remaining_coupons": self.remaining_coupons,
            "max_reuses_per_coupon": self.max_reuses_per_coupon,
            "face_value_micro": self.face_value_micro,
            "fee_cap_micro": self.fee_cap_micro,
            "privacy_set_size": self.privacy_set_size,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DaBatchRootRecord {
    pub batch_id: String,
    pub operator_id: String,
    pub lane: DaLane,
    pub status: DaBatchStatus,
    pub da_root: String,
    pub erasure_root: String,
    pub availability_bitmap_root: String,
    pub payload_commitment_root: String,
    pub payload_bytes: u64,
    pub reused_payload_bytes: u64,
    pub claim_count: u64,
    pub privacy_set_size: u64,
    pub target_settlement_height: u64,
    pub rooted_at_height: u64,
}

impl DaBatchRootRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "operator_id": self.operator_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "da_root": self.da_root,
            "erasure_root": self.erasure_root,
            "availability_bitmap_root": self.availability_bitmap_root,
            "payload_commitment_root": self.payload_commitment_root,
            "payload_bytes": self.payload_bytes,
            "reused_payload_bytes": self.reused_payload_bytes,
            "claim_count": self.claim_count,
            "privacy_set_size": self.privacy_set_size,
            "target_settlement_height": self.target_settlement_height,
            "rooted_at_height": self.rooted_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReuseClaimRecord {
    pub claim_id: String,
    pub book_id: String,
    pub batch_id: String,
    pub wallet_tag: String,
    pub coupon_nullifier: String,
    pub status: ReuseClaimStatus,
    pub reused_bytes: u64,
    pub original_da_cost_micro: u64,
    pub discounted_da_cost_micro: u64,
    pub user_fee_micro: u64,
    pub rebate_micro: u64,
    pub confidential_accounting_root: String,
    pub reuse_witness_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl ReuseClaimRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "book_id": self.book_id,
            "batch_id": self.batch_id,
            "wallet_tag": self.wallet_tag,
            "coupon_nullifier": self.coupon_nullifier,
            "status": self.status.as_str(),
            "reused_bytes": self.reused_bytes,
            "original_da_cost_micro": self.original_da_cost_micro,
            "discounted_da_cost_micro": self.discounted_da_cost_micro,
            "user_fee_micro": self.user_fee_micro,
            "rebate_micro": self.rebate_micro,
            "confidential_accounting_root": self.confidential_accounting_root,
            "reuse_witness_root": self.reuse_witness_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqDaAttestationRecord {
    pub attestation_id: String,
    pub subject_id: String,
    pub operator_id: String,
    pub purpose: AttestationPurpose,
    pub verdict: AttestationVerdict,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub da_share_sample_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub measured_latency_ms: u64,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
}

impl PqDaAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "subject_id": self.subject_id,
            "operator_id": self.operator_id,
            "purpose": self.purpose.as_str(),
            "verdict": self.verdict,
            "pq_signature_root": self.pq_signature_root,
            "transcript_root": self.transcript_root,
            "da_share_sample_root": self.da_share_sample_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "measured_latency_ms": self.measured_latency_ms,
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementFlowRecord {
    pub settlement_id: String,
    pub batch_id: String,
    pub status: SettlementStatus,
    pub claim_count: u64,
    pub payload_bytes: u64,
    pub reused_payload_bytes: u64,
    pub settlement_commitment_root: String,
    pub monero_anchor_root: String,
    pub l2_state_root: String,
    pub operator_fee_micro: u64,
    pub proposed_at_height: u64,
    pub finalizes_at_height: u64,
}

impl SettlementFlowRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateFlowRecord {
    pub rebate_id: String,
    pub claim_id: String,
    pub book_id: String,
    pub wallet_tag: String,
    pub status: RebateStatus,
    pub rebate_micro: u64,
    pub confidential_rebate_root: String,
    pub paid_from_pool_root: String,
    pub queued_at_height: u64,
    pub paid_at_height: u64,
}

impl RebateFlowRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AbuseThrottleRecord {
    pub throttle_id: String,
    pub wallet_tag: String,
    pub status: ThrottleStatus,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub reused_bytes: u64,
    pub claim_count: u64,
    pub duplicate_nullifiers: u64,
    pub throttle_root: String,
}

impl AbuseThrottleRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudgetRecord {
    pub budget_id: String,
    pub operator_id: String,
    pub subject_id: String,
    pub status: RedactionStatus,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub redactions_allowed: u32,
    pub redactions_used: u32,
    pub disclosure_root: String,
}

impl RedactionBudgetRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummaryRecord {
    pub summary_id: String,
    pub operator_id: String,
    pub height: u64,
    pub epoch: u64,
    pub da_batch_roots_root: String,
    pub reuse_claims_root: String,
    pub pq_da_attestations_root: String,
    pub settlement_flows_root: String,
    pub rebate_flows_root: String,
    pub pending_batches: u64,
    pub open_claims: u64,
    pub settled_claims: u64,
    pub reused_payload_bytes: u64,
    pub estimated_da_cost_saved_micro: u64,
    pub average_settlement_blocks: u64,
}

impl OperatorSummaryRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssueCouponBookRequest {
    pub issuer_id: String,
    pub lane: DaLane,
    pub issued_coupons: u64,
    pub face_value_micro: u64,
    pub fee_cap_micro: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RootDaBatchRequest {
    pub operator_id: String,
    pub lane: DaLane,
    pub payload_bytes: u64,
    pub da_root: String,
    pub erasure_root: String,
    pub availability_bitmap_root: String,
    pub payload_commitment_root: String,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenReuseClaimRequest {
    pub book_id: String,
    pub batch_id: String,
    pub wallet_tag: String,
    pub coupon_nullifier: String,
    pub reused_bytes: u64,
    pub original_da_cost_micro: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttestDaRequest {
    pub subject_id: String,
    pub operator_id: String,
    pub purpose: AttestationPurpose,
    pub verdict: AttestationVerdict,
    pub privacy_set_size: u64,
    pub measured_latency_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub current_height: u64,
    pub current_epoch: u64,
    pub coupon_books: BTreeMap<String, CouponBookRecord>,
    pub da_batch_roots: BTreeMap<String, DaBatchRootRecord>,
    pub reuse_claims: BTreeMap<String, ReuseClaimRecord>,
    pub pq_da_attestations: BTreeMap<String, PqDaAttestationRecord>,
    pub settlement_flows: BTreeMap<String, SettlementFlowRecord>,
    pub rebate_flows: BTreeMap<String, RebateFlowRecord>,
    pub throttles: BTreeMap<String, AbuseThrottleRecord>,
    pub redaction_budgets: BTreeMap<String, RedactionBudgetRecord>,
    pub operator_summaries: BTreeMap<String, OperatorSummaryRecord>,
    pub spent_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            current_height: DEVNET_HEIGHT,
            current_epoch: DEVNET_EPOCH,
            coupon_books: BTreeMap::new(),
            da_batch_roots: BTreeMap::new(),
            reuse_claims: BTreeMap::new(),
            pq_da_attestations: BTreeMap::new(),
            settlement_flows: BTreeMap::new(),
            rebate_flows: BTreeMap::new(),
            throttles: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        devnet()
    }

    pub fn demo() -> Self {
        demo()
    }

    pub fn issue_coupon_book(&mut self, request: IssueCouponBookRequest) -> Result<String> {
        require(
            self.coupon_books.len() < MAX_COUPON_BOOKS,
            "coupon book limit",
        )?;
        require(!request.issuer_id.is_empty(), "issuer_id is required")?;
        require(request.issued_coupons > 0, "issued coupons must be nonzero")?;
        require(request.face_value_micro > 0, "face value must be nonzero")?;
        require(request.fee_cap_micro > 0, "fee cap must be nonzero")?;
        require(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set below minimum",
        )?;
        let book_id = record_id(
            "COUPON-BOOK",
            &request.issuer_id,
            self.counters.coupon_books_issued + 1,
        );
        let book = CouponBookRecord {
            book_id: book_id.clone(),
            issuer_id: request.issuer_id,
            lane: request.lane,
            status: CouponBookStatus::Issuing,
            coupon_commitment_root: sample_root("coupon-commitment", &book_id),
            nullifier_root: sample_root("coupon-nullifier", &book_id),
            eligible_da_root: sample_root("eligible-da", &book_id),
            issued_coupons: request.issued_coupons,
            remaining_coupons: request.issued_coupons,
            max_reuses_per_coupon: self.config.max_reuses_per_coupon,
            face_value_micro: request.face_value_micro,
            fee_cap_micro: request.fee_cap_micro,
            privacy_set_size: request.privacy_set_size,
            opened_at_height: self.current_height,
            expires_at_height: self.current_height + self.config.coupon_ttl_blocks,
        };
        self.counters.coupon_books_issued += 1;
        self.coupon_books.insert(book_id.clone(), book);
        self.refresh_roots();
        Ok(book_id)
    }

    pub fn root_da_batch(&mut self, request: RootDaBatchRequest) -> Result<String> {
        require(
            self.da_batch_roots.len() < MAX_DA_BATCH_ROOTS,
            "da batch limit",
        )?;
        require(!request.operator_id.is_empty(), "operator_id is required")?;
        require(request.payload_bytes > 0, "payload bytes must be nonzero")?;
        require(
            request.payload_bytes <= self.config.batch_max_payload_bytes,
            "payload exceeds batch cap",
        )?;
        require(!request.da_root.is_empty(), "da_root is required")?;
        require(!request.erasure_root.is_empty(), "erasure_root is required")?;
        require(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set below minimum",
        )?;
        let batch_id = record_id(
            "DA-BATCH",
            &request.operator_id,
            self.counters.da_batches_rooted + 1,
        );
        let batch = DaBatchRootRecord {
            batch_id: batch_id.clone(),
            operator_id: request.operator_id,
            lane: request.lane,
            status: DaBatchStatus::Rooted,
            da_root: request.da_root,
            erasure_root: request.erasure_root,
            availability_bitmap_root: request.availability_bitmap_root,
            payload_commitment_root: request.payload_commitment_root,
            payload_bytes: request.payload_bytes,
            reused_payload_bytes: 0,
            claim_count: 0,
            privacy_set_size: request.privacy_set_size,
            target_settlement_height: self.current_height + self.config.batch_target_blocks,
            rooted_at_height: self.current_height,
        };
        self.counters.da_batches_rooted += 1;
        self.counters.total_payload_bytes = self
            .counters
            .total_payload_bytes
            .saturating_add(batch.payload_bytes);
        self.da_batch_roots.insert(batch_id.clone(), batch);
        self.refresh_roots();
        Ok(batch_id)
    }

    pub fn open_reuse_claim(&mut self, request: OpenReuseClaimRequest) -> Result<String> {
        require(
            self.reuse_claims.len() < MAX_REUSE_CLAIMS,
            "reuse claim limit",
        )?;
        require(!request.wallet_tag.is_empty(), "wallet_tag is required")?;
        require(
            !request.coupon_nullifier.is_empty(),
            "coupon_nullifier is required",
        )?;
        require(
            !self.spent_nullifiers.contains(&request.coupon_nullifier),
            "duplicate nullifier",
        )?;
        require(request.reused_bytes > 0, "reused bytes must be nonzero")?;
        require(
            request.reused_bytes <= self.config.wallet_daily_reuse_cap_bytes,
            "wallet reuse cap exceeded",
        )?;
        let book = self
            .coupon_books
            .get_mut(&request.book_id)
            .ok_or_else(|| "coupon book not found".to_string())?;
        require(
            book.status.accepts_issuance() || book.status.accepts_reuse(),
            "book not reusable",
        )?;
        require(book.remaining_coupons > 0, "coupon book depleted")?;
        let batch = self
            .da_batch_roots
            .get_mut(&request.batch_id)
            .ok_or_else(|| "da batch not found".to_string())?;
        require(
            batch.status.accepts_claims(),
            "batch does not accept claims",
        )?;
        require(
            batch.claim_count < self.config.max_claims_per_batch as u64,
            "batch claim cap exceeded",
        )?;
        let discount = bps_amount(
            request.original_da_cost_micro,
            self.config.target_da_cost_reduction_bps,
        );
        let discounted_da_cost_micro = request.original_da_cost_micro.saturating_sub(discount);
        let user_fee_micro = bps_amount(discounted_da_cost_micro, self.config.target_user_fee_bps);
        require(user_fee_micro <= book.fee_cap_micro, "fee cap exceeded")?;
        let rebate_micro = bps_amount(discount, self.config.reuse_rebate_bps);
        let claim_id = record_id(
            "REUSE-CLAIM",
            &request.coupon_nullifier,
            self.counters.reuse_claims_opened + 1,
        );
        let claim = ReuseClaimRecord {
            claim_id: claim_id.clone(),
            book_id: request.book_id,
            batch_id: request.batch_id,
            wallet_tag: request.wallet_tag,
            coupon_nullifier: request.coupon_nullifier,
            status: ReuseClaimStatus::Proposed,
            reused_bytes: request.reused_bytes,
            original_da_cost_micro: request.original_da_cost_micro,
            discounted_da_cost_micro,
            user_fee_micro,
            rebate_micro,
            confidential_accounting_root: commitment_from_amount(
                "reuse-accounting",
                user_fee_micro,
            ),
            reuse_witness_root: sample_root("reuse-witness", &claim_id),
            opened_at_height: self.current_height,
            expires_at_height: self.current_height + self.config.coupon_ttl_blocks,
        };
        book.remaining_coupons -= 1;
        book.status = CouponBookStatus::Reusing;
        batch.claim_count += 1;
        batch.reused_payload_bytes = batch
            .reused_payload_bytes
            .saturating_add(claim.reused_bytes);
        self.spent_nullifiers.insert(claim.coupon_nullifier.clone());
        self.counters.reuse_claims_opened += 1;
        self.counters.reused_payload_bytes = self
            .counters
            .reused_payload_bytes
            .saturating_add(claim.reused_bytes);
        self.counters.estimated_da_cost_saved_micro = self
            .counters
            .estimated_da_cost_saved_micro
            .saturating_add(discount);
        self.counters.total_user_fee_micro = self
            .counters
            .total_user_fee_micro
            .saturating_add(user_fee_micro);
        self.reuse_claims.insert(claim_id.clone(), claim);
        self.upsert_throttle_after_claim()?;
        self.refresh_roots();
        Ok(claim_id)
    }

    pub fn attest_da(&mut self, request: AttestDaRequest) -> Result<String> {
        require(
            self.pq_da_attestations.len() < MAX_PQ_DA_ATTESTATIONS,
            "attestation limit",
        )?;
        require(!request.subject_id.is_empty(), "subject_id is required")?;
        require(!request.operator_id.is_empty(), "operator_id is required")?;
        require(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set below minimum",
        )?;
        let subject_root = subject_record_root(self, &request.subject_id);
        let attestation_id = record_id(
            "PQ-DA-ATTESTATION",
            &request.subject_id,
            self.counters.pq_da_attestations + 1,
        );
        let record = PqDaAttestationRecord {
            attestation_id: attestation_id.clone(),
            subject_id: request.subject_id.clone(),
            operator_id: request.operator_id,
            purpose: request.purpose,
            verdict: request.verdict,
            pq_signature_root: sample_root("pq-da-signature", &attestation_id),
            transcript_root: root_from_record(
                "PQ-DA-TRANSCRIPT",
                &json!({
                    "subject_id": request.subject_id,
                    "subject_root": subject_root,
                    "purpose": request.purpose.as_str(),
                    "verdict": request.verdict,
                }),
            ),
            da_share_sample_root: sample_root("da-share-sample", &attestation_id),
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
            measured_latency_ms: request.measured_latency_ms,
            attested_at_height: self.current_height,
            expires_at_height: self.current_height + self.config.attestation_ttl_blocks,
        };
        if record.verdict.approves() {
            if let Some(batch) = self.da_batch_roots.get_mut(&record.subject_id) {
                batch.status = DaBatchStatus::Attested;
            }
            if let Some(claim) = self.reuse_claims.get_mut(&record.subject_id) {
                claim.status = ReuseClaimStatus::Attested;
            }
        }
        self.counters.pq_da_attestations += 1;
        self.pq_da_attestations
            .insert(attestation_id.clone(), record);
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn settle_batch(&mut self, batch_id: &str, l2_state_root: String) -> Result<String> {
        require(
            self.settlement_flows.len() < MAX_SETTLEMENT_FLOWS,
            "settlement flow limit",
        )?;
        require(!l2_state_root.is_empty(), "l2_state_root is required")?;
        let batch = self
            .da_batch_roots
            .get_mut(batch_id)
            .ok_or_else(|| "da batch not found".to_string())?;
        require(
            matches!(
                batch.status,
                DaBatchStatus::Rooted | DaBatchStatus::Attested | DaBatchStatus::Settling
            ),
            "batch not settleable",
        )?;
        let settlement_id = record_id(
            "SETTLEMENT-FLOW",
            batch_id,
            self.counters.settlement_flows + 1,
        );
        let operator_fee_micro = bps_amount(
            self.counters.estimated_da_cost_saved_micro,
            self.config.operator_fee_share_bps,
        );
        let record = SettlementFlowRecord {
            settlement_id: settlement_id.clone(),
            batch_id: batch_id.to_string(),
            status: SettlementStatus::FastFinalized,
            claim_count: batch.claim_count,
            payload_bytes: batch.payload_bytes,
            reused_payload_bytes: batch.reused_payload_bytes,
            settlement_commitment_root: sample_root("settlement-commitment", &settlement_id),
            monero_anchor_root: sample_root("monero-anchor", &settlement_id),
            l2_state_root,
            operator_fee_micro,
            proposed_at_height: self.current_height,
            finalizes_at_height: self.current_height + self.config.batch_finality_blocks,
        };
        batch.status = DaBatchStatus::Settled;
        for claim in self.reuse_claims.values_mut() {
            if claim.batch_id == batch_id
                && matches!(
                    claim.status,
                    ReuseClaimStatus::Attested | ReuseClaimStatus::Proposed
                )
            {
                claim.status = ReuseClaimStatus::Settled;
                self.counters.reuse_claims_settled += 1;
            }
        }
        self.counters.settlement_flows += 1;
        self.counters.total_operator_fee_micro = self
            .counters
            .total_operator_fee_micro
            .saturating_add(operator_fee_micro);
        self.settlement_flows.insert(settlement_id.clone(), record);
        self.refresh_roots();
        Ok(settlement_id)
    }

    pub fn queue_rebate(&mut self, claim_id: &str) -> Result<String> {
        require(
            self.rebate_flows.len() < MAX_REBATE_FLOWS,
            "rebate flow limit",
        )?;
        let claim = self
            .reuse_claims
            .get_mut(claim_id)
            .ok_or_else(|| "reuse claim not found".to_string())?;
        require(
            matches!(
                claim.status,
                ReuseClaimStatus::Settled | ReuseClaimStatus::Rebated
            ),
            "claim is not settled",
        )?;
        let rebate_id = record_id("REBATE-FLOW", claim_id, self.counters.rebate_flows + 1);
        let record = RebateFlowRecord {
            rebate_id: rebate_id.clone(),
            claim_id: claim_id.to_string(),
            book_id: claim.book_id.clone(),
            wallet_tag: claim.wallet_tag.clone(),
            status: RebateStatus::Queued,
            rebate_micro: claim.rebate_micro,
            confidential_rebate_root: commitment_from_amount("rebate", claim.rebate_micro),
            paid_from_pool_root: sample_root("rebate-pool", &rebate_id),
            queued_at_height: self.current_height,
            paid_at_height: self.current_height + 1,
        };
        claim.status = ReuseClaimStatus::Rebated;
        self.counters.rebate_flows += 1;
        self.counters.total_rebate_micro = self
            .counters
            .total_rebate_micro
            .saturating_add(record.rebate_micro);
        self.rebate_flows.insert(rebate_id.clone(), record);
        self.refresh_roots();
        Ok(rebate_id)
    }

    pub fn reserve_redaction_budget(
        &mut self,
        operator_id: String,
        subject_id: String,
        redactions_allowed: u32,
    ) -> Result<String> {
        require(
            self.redaction_budgets.len() < MAX_REDACTION_BUDGETS,
            "redaction budget limit",
        )?;
        require(!operator_id.is_empty(), "operator_id is required")?;
        require(!subject_id.is_empty(), "subject_id is required")?;
        require(redactions_allowed > 0, "redactions_allowed must be nonzero")?;
        let budget_id = record_id(
            "REDACTION-BUDGET",
            &subject_id,
            self.counters.redaction_budget_events + 1,
        );
        let record = RedactionBudgetRecord {
            budget_id: budget_id.clone(),
            operator_id,
            subject_id,
            status: RedactionStatus::Reserved,
            window_start_height: self.current_height,
            window_end_height: self.current_height + self.config.redaction_window_blocks,
            redactions_allowed,
            redactions_used: 0,
            disclosure_root: sample_root("redaction-disclosure", &budget_id),
        };
        self.counters.redaction_budget_events += 1;
        self.redaction_budgets.insert(budget_id.clone(), record);
        self.refresh_roots();
        Ok(budget_id)
    }

    pub fn summarize_operator(&mut self, operator_id: String) -> Result<String> {
        require(
            self.operator_summaries.len() < MAX_OPERATOR_SUMMARIES,
            "operator summary limit",
        )?;
        require(!operator_id.is_empty(), "operator_id is required")?;
        let pending_batches = self
            .da_batch_roots
            .values()
            .filter(|batch| {
                matches!(
                    batch.status,
                    DaBatchStatus::Rooted | DaBatchStatus::Attested | DaBatchStatus::Settling
                )
            })
            .count() as u64;
        let open_claims = self
            .reuse_claims
            .values()
            .filter(|claim| {
                matches!(
                    claim.status,
                    ReuseClaimStatus::Proposed
                        | ReuseClaimStatus::Attested
                        | ReuseClaimStatus::Netting
                )
            })
            .count() as u64;
        let settled_claims = self
            .reuse_claims
            .values()
            .filter(|claim| {
                matches!(
                    claim.status,
                    ReuseClaimStatus::Settled | ReuseClaimStatus::Rebated
                )
            })
            .count() as u64;
        let average_settlement_blocks = if self.counters.settlement_flows == 0 {
            self.config.batch_target_blocks
        } else {
            self.config
                .batch_finality_blocks
                .min(self.config.batch_target_blocks)
        };
        let summary_id = record_id(
            "OPERATOR-SUMMARY",
            &operator_id,
            self.counters.operator_summaries + 1,
        );
        let record = OperatorSummaryRecord {
            summary_id: summary_id.clone(),
            operator_id,
            height: self.current_height,
            epoch: self.current_epoch,
            da_batch_roots_root: self.roots.da_batch_roots_root.clone(),
            reuse_claims_root: self.roots.reuse_claims_root.clone(),
            pq_da_attestations_root: self.roots.pq_da_attestations_root.clone(),
            settlement_flows_root: self.roots.settlement_flows_root.clone(),
            rebate_flows_root: self.roots.rebate_flows_root.clone(),
            pending_batches,
            open_claims,
            settled_claims,
            reused_payload_bytes: self.counters.reused_payload_bytes,
            estimated_da_cost_saved_micro: self.counters.estimated_da_cost_saved_micro,
            average_settlement_blocks,
        };
        self.counters.operator_summaries += 1;
        self.operator_summaries.insert(summary_id.clone(), record);
        self.prune_operator_summaries();
        self.refresh_roots();
        Ok(summary_id)
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_pq_confidential_da_batch_reuse_coupon_runtime",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_auth_suite": PQ_AUTH_SUITE,
            "chain_id": self.config.chain_id,
            "current_height": self.current_height,
            "current_epoch": self.current_epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut object) = record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn refresh_roots(&mut self) {
        self.roots.config_root = root_from_record("CONFIG", &self.config.public_record());
        self.roots.counters_root = root_from_record("COUNTERS", &self.counters.public_record());
        self.roots.coupon_books_root = map_root(
            COUPON_BOOK_SCHEME,
            self.coupon_books
                .values()
                .map(CouponBookRecord::public_record),
        );
        self.roots.da_batch_roots_root = map_root(
            DA_BATCH_SCHEME,
            self.da_batch_roots
                .values()
                .map(DaBatchRootRecord::public_record),
        );
        self.roots.reuse_claims_root = map_root(
            REUSE_CLAIM_SCHEME,
            self.reuse_claims
                .values()
                .map(ReuseClaimRecord::public_record),
        );
        self.roots.pq_da_attestations_root = map_root(
            PQ_DA_ATTESTATION_SCHEME,
            self.pq_da_attestations
                .values()
                .map(PqDaAttestationRecord::public_record),
        );
        self.roots.settlement_flows_root = map_root(
            SETTLEMENT_FLOW_SCHEME,
            self.settlement_flows
                .values()
                .map(SettlementFlowRecord::public_record),
        );
        self.roots.rebate_flows_root = map_root(
            REBATE_FLOW_SCHEME,
            self.rebate_flows
                .values()
                .map(RebateFlowRecord::public_record),
        );
        self.roots.throttles_root = map_root(
            THROTTLE_SCHEME,
            self.throttles
                .values()
                .map(AbuseThrottleRecord::public_record),
        );
        self.roots.redaction_budgets_root = map_root(
            REDACTION_BUDGET_SCHEME,
            self.redaction_budgets
                .values()
                .map(RedactionBudgetRecord::public_record),
        );
        self.roots.operator_summaries_root = map_root(
            OPERATOR_SUMMARY_SCHEME,
            self.operator_summaries
                .values()
                .map(OperatorSummaryRecord::public_record),
        );
        let record = json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": self.config.chain_id,
            "current_height": self.current_height,
            "current_epoch": self.current_epoch,
            "roots": {
                "config_root": self.roots.config_root,
                "counters_root": self.roots.counters_root,
                "coupon_books_root": self.roots.coupon_books_root,
                "da_batch_roots_root": self.roots.da_batch_roots_root,
                "reuse_claims_root": self.roots.reuse_claims_root,
                "pq_da_attestations_root": self.roots.pq_da_attestations_root,
                "settlement_flows_root": self.roots.settlement_flows_root,
                "rebate_flows_root": self.roots.rebate_flows_root,
                "throttles_root": self.roots.throttles_root,
                "redaction_budgets_root": self.roots.redaction_budgets_root,
                "operator_summaries_root": self.roots.operator_summaries_root,
            },
        });
        self.roots.state_root = root_from_record("STATE", &record);
    }

    fn upsert_throttle_after_claim(&mut self) -> Result<()> {
        let claim = self
            .reuse_claims
            .values()
            .next_back()
            .ok_or_else(|| "reuse claim not found".to_string())?;
        let throttle_id = record_id("THROTTLE", &claim.wallet_tag, 0);
        let wallet_tag = claim.wallet_tag.clone();
        let reused_bytes = claim.reused_bytes;
        let window_start_height = self.current_height;
        let window_end_height = self.current_height + self.config.throttle_window_blocks;
        let wallet_daily_reuse_cap_bytes = self.config.wallet_daily_reuse_cap_bytes;
        let max_reuses_per_coupon = self.config.max_reuses_per_coupon as u64;
        let record = self
            .throttles
            .entry(throttle_id.clone())
            .or_insert_with(|| AbuseThrottleRecord {
                throttle_id,
                wallet_tag: wallet_tag.clone(),
                status: ThrottleStatus::Clear,
                window_start_height,
                window_end_height,
                reused_bytes: 0,
                claim_count: 0,
                duplicate_nullifiers: 0,
                throttle_root: sample_root("throttle", &wallet_tag),
            });
        record.reused_bytes = record.reused_bytes.saturating_add(reused_bytes);
        record.claim_count += 1;
        record.status = if record.reused_bytes > wallet_daily_reuse_cap_bytes {
            ThrottleStatus::Limited
        } else if record.claim_count > max_reuses_per_coupon {
            ThrottleStatus::Watching
        } else {
            ThrottleStatus::Clear
        };
        self.counters.throttle_events += 1;
        Ok(())
    }

    fn prune_operator_summaries(&mut self) {
        while self.operator_summaries.len() > self.config.operator_summary_limit {
            if let Some(first_key) = self.operator_summaries.keys().next().cloned() {
                self.operator_summaries.remove(&first_key);
            } else {
                break;
            }
        }
    }
}

pub fn devnet() -> State {
    let mut state = State::new(Config::devnet()).expect("valid devnet config");
    let book_id = state
        .issue_coupon_book(IssueCouponBookRequest {
            issuer_id: "issuer:da-reuse-devnet-a".to_string(),
            lane: DaLane::MoneroPrivateTransfer,
            issued_coupons: 32_768,
            face_value_micro: 18_000,
            fee_cap_micro: 520,
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
        })
        .expect("devnet coupon book");
    if let Some(book) = state.coupon_books.get_mut(&book_id) {
        book.status = CouponBookStatus::Sealed;
    }
    let batch_id = state
        .root_da_batch(RootDaBatchRequest {
            operator_id: "operator:da-builder-01".to_string(),
            lane: DaLane::MoneroPrivateTransfer,
            payload_bytes: 8_388_608,
            da_root: sample_root("da-root", "batch:devnet:alpha"),
            erasure_root: sample_root("erasure-root", "batch:devnet:alpha"),
            availability_bitmap_root: sample_root("availability-bitmap", "batch:devnet:alpha"),
            payload_commitment_root: sample_root("payload-commitment", "batch:devnet:alpha"),
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
        })
        .expect("devnet da batch");
    let claim_id = state
        .open_reuse_claim(OpenReuseClaimRequest {
            book_id: book_id.clone(),
            batch_id: batch_id.clone(),
            wallet_tag: "wallet-tag:7b91-redacted".to_string(),
            coupon_nullifier: sample_root("coupon-nullifier", "wallet-tag:7b91:claim-1"),
            reused_bytes: 196_608,
            original_da_cost_micro: 18_400,
        })
        .expect("devnet reuse claim");
    state
        .attest_da(AttestDaRequest {
            subject_id: batch_id.clone(),
            operator_id: "operator:da-builder-01".to_string(),
            purpose: AttestationPurpose::DaRootAvailability,
            verdict: AttestationVerdict::Approved,
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            measured_latency_ms: 42,
        })
        .expect("devnet batch attestation");
    state
        .attest_da(AttestDaRequest {
            subject_id: claim_id.clone(),
            operator_id: "operator:da-builder-01".to_string(),
            purpose: AttestationPurpose::ReuseClaim,
            verdict: AttestationVerdict::Approved,
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            measured_latency_ms: 9,
        })
        .expect("devnet claim attestation");
    state
        .settle_batch(
            &batch_id,
            sample_root("l2-state", "devnet:settlement-alpha"),
        )
        .expect("devnet settlement");
    state.queue_rebate(&claim_id).expect("devnet rebate");
    state
        .reserve_redaction_budget("operator:da-builder-01".to_string(), claim_id, 8)
        .expect("devnet redaction budget");
    state
        .summarize_operator("operator:da-builder-01".to_string())
        .expect("devnet operator summary");
    state.refresh_roots();
    state
}

pub fn demo() -> State {
    devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn coupon_book_root(book: &CouponBookRecord) -> String {
    root_from_record("COUPON-BOOK", &book.public_record())
}

pub fn da_batch_root(batch: &DaBatchRootRecord) -> String {
    root_from_record("DA-BATCH", &batch.public_record())
}

pub fn reuse_claim_root(claim: &ReuseClaimRecord) -> String {
    root_from_record("REUSE-CLAIM", &claim.public_record())
}

pub fn pq_da_attestation_root(attestation: &PqDaAttestationRecord) -> String {
    root_from_record("PQ-DA-ATTESTATION", &attestation.public_record())
}

fn subject_record_root(state: &State, subject_id: &str) -> String {
    if let Some(book) = state.coupon_books.get(subject_id) {
        return coupon_book_root(book);
    }
    if let Some(batch) = state.da_batch_roots.get(subject_id) {
        return da_batch_root(batch);
    }
    if let Some(claim) = state.reuse_claims.get(subject_id) {
        return reuse_claim_root(claim);
    }
    root_from_record("UNKNOWN-SUBJECT", &json!({ "subject_id": subject_id }))
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn bps_amount(amount: u64, bps: u64) -> u64 {
    amount.saturating_mul(bps) / MAX_BPS
}

fn commitment_from_amount(domain: &str, amount: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-BATCH-REUSE-COUPON:AMOUNT-COMMITMENT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::U64(amount),
        ],
        32,
    )
}

fn record_id(kind: &str, subject: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-BATCH-REUSE-COUPON:RECORD-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(subject),
            HashPart::U64(sequence),
        ],
        32,
    )
}

fn map_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let values = records.into_iter().collect::<Vec<_>>();
    merkle_root(domain, &values)
}

fn empty_root(domain: &str) -> String {
    let domain = format!("PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-BATCH-REUSE-COUPON:{domain}");
    merkle_root(&domain, &Vec::<Value>::new())
}

fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-DA-BATCH-REUSE-COUPON:RECORD-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Json(record),
        ],
        32,
    )
}

fn sample_root(domain: &str, id: &str) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(id)],
        32,
    )
}
