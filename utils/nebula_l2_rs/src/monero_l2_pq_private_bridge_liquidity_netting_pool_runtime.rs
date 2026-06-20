use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_BRIDGE_LIQUIDITY_NETTING_POOL_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-bridge-liquidity-netting-pool-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_BRIDGE_LIQUIDITY_NETTING_POOL_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_POOL_ID: &str = "monero-l2-pq-private-bridge-liquidity-netting-pool-devnet";
pub const DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 1_244_000;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_PROOF_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-private-bridge-liquidity-netting-v1";
pub const ENCRYPTED_DEPOSIT_SCHEME: &str = "ml-kem-1024-sealed-bridge-liquidity-deposit-root-v1";
pub const NETTING_POOL_SCHEME: &str = "monero-l2-confidential-liquidity-netting-pool-root-v1";
pub const RESERVE_PROOF_SCHEME: &str = "pq-monero-reserve-proof-coverage-root-v1";
pub const WITHDRAWAL_BATCH_SCHEME: &str = "private-bridge-withdrawal-batch-netting-root-v1";
pub const MAKER_COMMITMENT_SCHEME: &str = "pq-private-bridge-market-maker-commitment-root-v1";
pub const FEE_COUPON_SCHEME: &str = "low-fee-private-bridge-coupon-root-v1";
pub const REORG_INSURANCE_SCHEME: &str = "monero-bridge-reorg-insurance-bond-root-v1";
pub const PRIVACY_FENCE_SCHEME: &str = "private-bridge-nullifier-fence-root-v1";
pub const SLASHING_EVIDENCE_SCHEME: &str = "private-bridge-liquidity-slashing-evidence-root-v1";
pub const REPLAY_DOMAIN: &str = "monero-l2-pq-private-bridge-liquidity-netting-pool-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_500;
pub const DEFAULT_TARGET_RESERVE_COVERAGE_BPS: u64 = 12_500;
pub const DEFAULT_LOW_FEE_BPS: u64 = 4;
pub const DEFAULT_STANDARD_FEE_BPS: u64 = 9;
pub const DEFAULT_FAST_FEE_BPS: u64 = 16;
pub const DEFAULT_MAKER_REBATE_BPS: u64 = 5;
pub const DEFAULT_INSURANCE_PREMIUM_BPS: u64 = 3;
pub const DEFAULT_NULLIFIER_TTL_BLOCKS: u64 = 7_200;
pub const DEFAULT_DEPOSIT_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_RESERVE_PROOF_TTL_BLOCKS: u64 = 64;
pub const DEFAULT_BATCH_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_MAKER_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_COUPON_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_INSURANCE_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_BATCH_ITEMS: usize = 768;
pub const DEFAULT_MAX_POOL_ITEMS: usize = 1_024;
pub const DEFAULT_SLASH_INVALID_PROOF_BPS: u64 = 2_500;
pub const DEFAULT_SLASH_DOUBLE_SPEND_BPS: u64 = 5_000;
pub const DEFAULT_SLASH_WITHHELD_LIQUIDITY_BPS: u64 = 1_500;
pub const MAX_DEPOSITS: usize = 4_194_304;
pub const MAX_NETTING_POOLS: usize = 262_144;
pub const MAX_RESERVE_PROOFS: usize = 2_097_152;
pub const MAX_WITHDRAWAL_BATCHES: usize = 1_048_576;
pub const MAX_MAKER_COMMITMENTS: usize = 2_097_152;
pub const MAX_FEE_COUPONS: usize = 2_097_152;
pub const MAX_REORG_INSURANCE_POLICIES: usize = 1_048_576;
pub const MAX_PRIVACY_FENCES: usize = 8_388_608;
pub const MAX_SLASHING_EVIDENCE: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeLane {
    LowFee,
    Standard,
    Fast,
    MakerRebalance,
    DefiSettlement,
    Emergency,
}
impl BridgeLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::Standard => "standard",
            Self::Fast => "fast",
            Self::MakerRebalance => "maker_rebalance",
            Self::DefiSettlement => "defi_settlement",
            Self::Emergency => "emergency",
        }
    }
    pub fn fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::LowFee => config.low_fee_bps,
            Self::Standard => config.standard_fee_bps,
            Self::Fast | Self::Emergency => config.fast_fee_bps,
            Self::MakerRebalance => config
                .standard_fee_bps
                .saturating_sub(config.maker_rebate_bps),
            Self::DefiSettlement => config.standard_fee_bps.saturating_mul(3) / 4,
        }
    }
    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Emergency => 1_000,
            Self::Fast => 940,
            Self::MakerRebalance => 900,
            Self::DefiSettlement => 840,
            Self::Standard => 720,
            Self::LowFee => 680,
        }
    }
}
macro_rules! status_enum { ($name:ident { $($variant:ident => $label:expr),+ $(,)? }) => { #[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)] #[serde(rename_all = "snake_case")] pub enum $name { $($variant),+ } impl $name { pub fn as_str(self) -> &'static str { match self { $(Self::$variant => $label),+ } } } }; }
status_enum!(DepositStatus { Sealed => "sealed", Admitted => "admitted", Netted => "netted", Reserved => "reserved", Withdrawn => "withdrawn", Expired => "expired", Rejected => "rejected", Slashed => "slashed" });
impl DepositStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::Admitted | Self::Netted | Self::Reserved
        )
    }
    pub fn nettable(self) -> bool {
        matches!(self, Self::Admitted | Self::Netted)
    }
}
status_enum!(PoolStatus { Open => "open", Sealed => "sealed", Settling => "settling", Settled => "settled", Paused => "paused", Cancelled => "cancelled", Slashed => "slashed" });
impl PoolStatus {
    pub fn accepts_liquidity(self) -> bool {
        matches!(self, Self::Open | Self::Sealed)
    }
}
status_enum!(ProofStatus { Submitted => "submitted", Accepted => "accepted", Superseded => "superseded", Expired => "expired", Invalid => "invalid", Slashed => "slashed" });
impl ProofStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Submitted | Self::Accepted)
    }
}
status_enum!(BatchStatus { Assembling => "assembling", Proved => "proved", Submitted => "submitted", Finalized => "finalized", Disputed => "disputed", Reorged => "reorged", Cancelled => "cancelled" });
status_enum!(MakerStatus { Pending => "pending", Active => "active", Throttled => "throttled", Exiting => "exiting", Exited => "exited", Slashed => "slashed" });
impl MakerStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Throttled)
    }
}
status_enum!(CouponStatus { Minted => "minted", Reserved => "reserved", Redeemed => "redeemed", Expired => "expired", Revoked => "revoked" });
impl CouponStatus {
    pub fn spendable(self) -> bool {
        matches!(self, Self::Minted | Self::Reserved)
    }
}
status_enum!(InsuranceStatus { Quoted => "quoted", Bound => "bound", ClaimPending => "claim_pending", Paid => "paid", Expired => "expired", Cancelled => "cancelled", Slashed => "slashed" });
status_enum!(FenceKind { DepositNullifier => "deposit_nullifier", WithdrawalNullifier => "withdrawal_nullifier", KeyImage => "key_image", ViewTagBucket => "view_tag_bucket", CouponNullifier => "coupon_nullifier", MakerSession => "maker_session", InsuranceClaim => "insurance_claim" });
status_enum!(SlashReason { InvalidReserveProof => "invalid_reserve_proof", DoubleSpendFence => "double_spend_fence", WithheldLiquidity => "withheld_liquidity", ExpiredBatch => "expired_batch", InvalidWithdrawalProof => "invalid_withdrawal_proof", MakerDefault => "maker_default", InsuranceFraud => "insurance_fraud" });

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_auth_proof_suite: String,
    pub encrypted_deposit_scheme: String,
    pub netting_pool_scheme: String,
    pub reserve_proof_scheme: String,
    pub withdrawal_batch_scheme: String,
    pub maker_commitment_scheme: String,
    pub fee_coupon_scheme: String,
    pub reorg_insurance_scheme: String,
    pub privacy_fence_scheme: String,
    pub slashing_evidence_scheme: String,
    pub replay_domain: String,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub min_reserve_coverage_bps: u64,
    pub target_reserve_coverage_bps: u64,
    pub low_fee_bps: u64,
    pub standard_fee_bps: u64,
    pub fast_fee_bps: u64,
    pub maker_rebate_bps: u64,
    pub insurance_premium_bps: u64,
    pub nullifier_ttl_blocks: u64,
    pub deposit_ttl_blocks: u64,
    pub reserve_proof_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub maker_ttl_blocks: u64,
    pub coupon_ttl_blocks: u64,
    pub insurance_ttl_blocks: u64,
    pub max_batch_items: usize,
    pub max_pool_items: usize,
    pub slash_invalid_proof_bps: u64,
    pub slash_double_spend_bps: u64,
    pub slash_withheld_liquidity_bps: u64,
}
impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            asset_id: DEVNET_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_auth_proof_suite: PQ_AUTH_PROOF_SUITE.to_string(),
            encrypted_deposit_scheme: ENCRYPTED_DEPOSIT_SCHEME.to_string(),
            netting_pool_scheme: NETTING_POOL_SCHEME.to_string(),
            reserve_proof_scheme: RESERVE_PROOF_SCHEME.to_string(),
            withdrawal_batch_scheme: WITHDRAWAL_BATCH_SCHEME.to_string(),
            maker_commitment_scheme: MAKER_COMMITMENT_SCHEME.to_string(),
            fee_coupon_scheme: FEE_COUPON_SCHEME.to_string(),
            reorg_insurance_scheme: REORG_INSURANCE_SCHEME.to_string(),
            privacy_fence_scheme: PRIVACY_FENCE_SCHEME.to_string(),
            slashing_evidence_scheme: SLASHING_EVIDENCE_SCHEME.to_string(),
            replay_domain: REPLAY_DOMAIN.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            target_reserve_coverage_bps: DEFAULT_TARGET_RESERVE_COVERAGE_BPS,
            low_fee_bps: DEFAULT_LOW_FEE_BPS,
            standard_fee_bps: DEFAULT_STANDARD_FEE_BPS,
            fast_fee_bps: DEFAULT_FAST_FEE_BPS,
            maker_rebate_bps: DEFAULT_MAKER_REBATE_BPS,
            insurance_premium_bps: DEFAULT_INSURANCE_PREMIUM_BPS,
            nullifier_ttl_blocks: DEFAULT_NULLIFIER_TTL_BLOCKS,
            deposit_ttl_blocks: DEFAULT_DEPOSIT_TTL_BLOCKS,
            reserve_proof_ttl_blocks: DEFAULT_RESERVE_PROOF_TTL_BLOCKS,
            batch_ttl_blocks: DEFAULT_BATCH_TTL_BLOCKS,
            maker_ttl_blocks: DEFAULT_MAKER_TTL_BLOCKS,
            coupon_ttl_blocks: DEFAULT_COUPON_TTL_BLOCKS,
            insurance_ttl_blocks: DEFAULT_INSURANCE_TTL_BLOCKS,
            max_batch_items: DEFAULT_MAX_BATCH_ITEMS,
            max_pool_items: DEFAULT_MAX_POOL_ITEMS,
            slash_invalid_proof_bps: DEFAULT_SLASH_INVALID_PROOF_BPS,
            slash_double_spend_bps: DEFAULT_SLASH_DOUBLE_SPEND_BPS,
            slash_withheld_liquidity_bps: DEFAULT_SLASH_WITHHELD_LIQUIDITY_BPS,
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("protocol version mismatch".to_string());
        }
        if self.low_fee_bps > self.standard_fee_bps || self.standard_fee_bps > self.fast_fee_bps {
            return Err("fee lanes must be ordered low <= standard <= fast".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq security bits below devnet floor".to_string());
        }
        if self.min_privacy_set_size == 0 || self.batch_privacy_set_size < self.min_privacy_set_size
        {
            return Err("privacy set sizes are inconsistent".to_string());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub encrypted_deposits: u64,
    pub active_deposits: u64,
    pub netted_deposits: u64,
    pub rejected_deposits: u64,
    pub netting_pools: u64,
    pub open_pools: u64,
    pub settled_pools: u64,
    pub reserve_proofs: u64,
    pub accepted_reserve_proofs: u64,
    pub reserve_failures: u64,
    pub withdrawal_batches: u64,
    pub finalized_batches: u64,
    pub reorged_batches: u64,
    pub maker_commitments: u64,
    pub active_makers: u64,
    pub maker_defaults: u64,
    pub fee_coupons: u64,
    pub redeemed_coupons: u64,
    pub coupon_savings_piconero: u64,
    pub insurance_policies: u64,
    pub insurance_claims: u64,
    pub insurance_payout_piconero: u64,
    pub privacy_fences: u64,
    pub nullifier_replays_blocked: u64,
    pub slashing_events: u64,
    pub slashed_piconero: u64,
    pub total_deposit_commitment_piconero: u64,
    pub total_withdrawal_commitment_piconero: u64,
    pub total_fee_commitment_piconero: u64,
    pub total_rebate_commitment_piconero: u64,
}
impl Counters {
    pub fn empty() -> Self {
        Self {
            encrypted_deposits: 0,
            active_deposits: 0,
            netted_deposits: 0,
            rejected_deposits: 0,
            netting_pools: 0,
            open_pools: 0,
            settled_pools: 0,
            reserve_proofs: 0,
            accepted_reserve_proofs: 0,
            reserve_failures: 0,
            withdrawal_batches: 0,
            finalized_batches: 0,
            reorged_batches: 0,
            maker_commitments: 0,
            active_makers: 0,
            maker_defaults: 0,
            fee_coupons: 0,
            redeemed_coupons: 0,
            coupon_savings_piconero: 0,
            insurance_policies: 0,
            insurance_claims: 0,
            insurance_payout_piconero: 0,
            privacy_fences: 0,
            nullifier_replays_blocked: 0,
            slashing_events: 0,
            slashed_piconero: 0,
            total_deposit_commitment_piconero: 0,
            total_withdrawal_commitment_piconero: 0,
            total_fee_commitment_piconero: 0,
            total_rebate_commitment_piconero: 0,
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub deposit_root: String,
    pub pool_root: String,
    pub reserve_proof_root: String,
    pub withdrawal_batch_root: String,
    pub maker_commitment_root: String,
    pub fee_coupon_root: String,
    pub reorg_insurance_root: String,
    pub privacy_fence_root: String,
    pub slashing_evidence_root: String,
    pub policy_root: String,
    pub counter_root: String,
}
impl Roots {
    pub fn empty() -> Self {
        Self {
            deposit_root: empty_root("DEPOSITS"),
            pool_root: empty_root("POOLS"),
            reserve_proof_root: empty_root("RESERVE-PROOFS"),
            withdrawal_batch_root: empty_root("WITHDRAWAL-BATCHES"),
            maker_commitment_root: empty_root("MAKERS"),
            fee_coupon_root: empty_root("COUPONS"),
            reorg_insurance_root: empty_root("INSURANCE"),
            privacy_fence_root: empty_root("FENCES"),
            slashing_evidence_root: empty_root("SLASHINGS"),
            policy_root: empty_root("POLICY"),
            counter_root: empty_root("COUNTERS"),
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-PRIVATE-BRIDGE-LIQUIDITY-NETTING-POOL-ROOTS",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedBridgeLiquidityDeposit {
    pub deposit_id: String,
    pub pool_id: String,
    pub maker_id: String,
    pub lane: BridgeLane,
    pub status: DepositStatus,
    pub amount_commitment: String,
    pub amount_bucket_piconero: u64,
    pub fee_commitment: String,
    pub encrypted_note_root: String,
    pub monero_txid_root: String,
    pub output_commitment_root: String,
    pub key_image_root: String,
    pub view_tag_root: String,
    pub deposit_nullifier: String,
    pub reserve_proof_id: String,
    pub coupon_id: Option<String>,
    pub insurance_policy_id: Option<String>,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub admitted_at_height: u64,
    pub expires_at_height: u64,
    pub transcript_hash: String,
}
impl EncryptedBridgeLiquidityDeposit {
    pub fn public_record(&self) -> Value {
        json!({
            "deposit_id": self.deposit_id,
            "pool_id": self.pool_id,
            "maker_id": self.maker_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "amount_commitment": self.amount_commitment,
            "amount_bucket_piconero": self.amount_bucket_piconero,
            "fee_commitment": self.fee_commitment,
            "encrypted_note_root": self.encrypted_note_root,
            "monero_txid_root": self.monero_txid_root,
            "output_commitment_root": self.output_commitment_root,
            "key_image_root": self.key_image_root,
            "view_tag_root": self.view_tag_root,
            "deposit_nullifier": self.deposit_nullifier,
            "reserve_proof_id": self.reserve_proof_id,
            "coupon_id": self.coupon_id,
            "insurance_policy_id": self.insurance_policy_id,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "admitted_at_height": self.admitted_at_height,
            "expires_at_height": self.expires_at_height,
            "transcript_hash": self.transcript_hash,
        })
    }
    pub fn root(&self) -> String {
        record_root("ENCRYPTED-BRIDGE-LIQUIDITY-DEPOSIT", &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NettingPool {
    pub pool_id: String,
    pub epoch: u64,
    pub lane: BridgeLane,
    pub status: PoolStatus,
    pub asset_id: String,
    pub maker_root: String,
    pub deposit_root: String,
    pub withdrawal_root: String,
    pub reserve_proof_root: String,
    pub fee_coupon_root: String,
    pub insurance_root: String,
    pub privacy_fence_root: String,
    pub total_input_bucket_piconero: u64,
    pub total_output_bucket_piconero: u64,
    pub fee_bucket_piconero: u64,
    pub min_privacy_set_size: u64,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
    pub settles_before_height: u64,
    pub transcript_hash: String,
}
impl NettingPool {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "epoch": self.epoch,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "asset_id": self.asset_id,
            "maker_root": self.maker_root,
            "deposit_root": self.deposit_root,
            "withdrawal_root": self.withdrawal_root,
            "reserve_proof_root": self.reserve_proof_root,
            "fee_coupon_root": self.fee_coupon_root,
            "insurance_root": self.insurance_root,
            "privacy_fence_root": self.privacy_fence_root,
            "total_input_bucket_piconero": self.total_input_bucket_piconero,
            "total_output_bucket_piconero": self.total_output_bucket_piconero,
            "fee_bucket_piconero": self.fee_bucket_piconero,
            "min_privacy_set_size": self.min_privacy_set_size,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "settles_before_height": self.settles_before_height,
            "transcript_hash": self.transcript_hash,
        })
    }
    pub fn root(&self) -> String {
        record_root("NETTING-POOL", &self.public_record())
    }
    pub fn imbalance_piconero(&self) -> u64 {
        self.total_input_bucket_piconero
            .abs_diff(self.total_output_bucket_piconero)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveProof {
    pub proof_id: String,
    pub maker_id: String,
    pub pool_id: String,
    pub status: ProofStatus,
    pub reserve_commitment_root: String,
    pub liabilities_commitment_root: String,
    pub coverage_bps: u64,
    pub monero_view_proof_root: String,
    pub pq_attestation_root: String,
    pub auditor_committee_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub transcript_hash: String,
}
impl ReserveProof {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "maker_id": self.maker_id,
            "pool_id": self.pool_id,
            "status": self.status.as_str(),
            "reserve_commitment_root": self.reserve_commitment_root,
            "liabilities_commitment_root": self.liabilities_commitment_root,
            "coverage_bps": self.coverage_bps,
            "monero_view_proof_root": self.monero_view_proof_root,
            "pq_attestation_root": self.pq_attestation_root,
            "auditor_committee_root": self.auditor_committee_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "transcript_hash": self.transcript_hash,
        })
    }
    pub fn root(&self) -> String {
        record_root("RESERVE-PROOF", &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WithdrawalBatch {
    pub batch_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub status: BatchStatus,
    pub withdrawal_note_root: String,
    pub deposit_spend_root: String,
    pub output_commitment_root: String,
    pub key_image_root: String,
    pub fee_coupon_root: String,
    pub proof_aggregate_root: String,
    pub monero_anchor_root: String,
    pub item_count: u64,
    pub amount_bucket_piconero: u64,
    pub fee_bucket_piconero: u64,
    pub privacy_set_size: u64,
    pub assembled_at_height: u64,
    pub finalizes_at_height: u64,
    pub transcript_hash: String,
}
impl WithdrawalBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "withdrawal_note_root": self.withdrawal_note_root,
            "deposit_spend_root": self.deposit_spend_root,
            "output_commitment_root": self.output_commitment_root,
            "key_image_root": self.key_image_root,
            "fee_coupon_root": self.fee_coupon_root,
            "proof_aggregate_root": self.proof_aggregate_root,
            "monero_anchor_root": self.monero_anchor_root,
            "item_count": self.item_count,
            "amount_bucket_piconero": self.amount_bucket_piconero,
            "fee_bucket_piconero": self.fee_bucket_piconero,
            "privacy_set_size": self.privacy_set_size,
            "assembled_at_height": self.assembled_at_height,
            "finalizes_at_height": self.finalizes_at_height,
            "transcript_hash": self.transcript_hash,
        })
    }
    pub fn root(&self) -> String {
        record_root("WITHDRAWAL-BATCH", &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MakerCommitment {
    pub maker_id: String,
    pub status: MakerStatus,
    pub lane: BridgeLane,
    pub capacity_commitment: String,
    pub stake_commitment: String,
    pub reserve_proof_id: String,
    pub fee_schedule_root: String,
    pub pq_public_key_root: String,
    pub session_nullifier: String,
    pub reputation_score: u64,
    pub max_fill_bucket_piconero: u64,
    pub active_from_height: u64,
    pub expires_at_height: u64,
    pub transcript_hash: String,
}
impl MakerCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "maker_id": self.maker_id,
            "status": self.status.as_str(),
            "lane": self.lane.as_str(),
            "capacity_commitment": self.capacity_commitment,
            "stake_commitment": self.stake_commitment,
            "reserve_proof_id": self.reserve_proof_id,
            "fee_schedule_root": self.fee_schedule_root,
            "pq_public_key_root": self.pq_public_key_root,
            "session_nullifier": self.session_nullifier,
            "reputation_score": self.reputation_score,
            "max_fill_bucket_piconero": self.max_fill_bucket_piconero,
            "active_from_height": self.active_from_height,
            "expires_at_height": self.expires_at_height,
            "transcript_hash": self.transcript_hash,
        })
    }
    pub fn root(&self) -> String {
        record_root("MAKER-COMMITMENT", &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCoupon {
    pub coupon_id: String,
    pub owner_commitment: String,
    pub pool_id: String,
    pub status: CouponStatus,
    pub lane: BridgeLane,
    pub discount_bps: u64,
    pub max_savings_piconero: u64,
    pub coupon_nullifier: String,
    pub sponsor_commitment: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub redeemed_batch_id: Option<String>,
    pub transcript_hash: String,
}
impl FeeCoupon {
    pub fn public_record(&self) -> Value {
        json!({
            "coupon_id": self.coupon_id,
            "owner_commitment": self.owner_commitment,
            "pool_id": self.pool_id,
            "status": self.status.as_str(),
            "lane": self.lane.as_str(),
            "discount_bps": self.discount_bps,
            "max_savings_piconero": self.max_savings_piconero,
            "coupon_nullifier": self.coupon_nullifier,
            "sponsor_commitment": self.sponsor_commitment,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "redeemed_batch_id": self.redeemed_batch_id,
            "transcript_hash": self.transcript_hash,
        })
    }
    pub fn root(&self) -> String {
        record_root("FEE-COUPON", &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReorgInsurancePolicy {
    pub policy_id: String,
    pub pool_id: String,
    pub maker_id: String,
    pub status: InsuranceStatus,
    pub insured_batch_root: String,
    pub premium_commitment: String,
    pub coverage_commitment: String,
    pub reorg_depth: u64,
    pub claim_nullifier: String,
    pub underwriter_root: String,
    pub bound_at_height: u64,
    pub expires_at_height: u64,
    pub transcript_hash: String,
}
impl ReorgInsurancePolicy {
    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "pool_id": self.pool_id,
            "maker_id": self.maker_id,
            "status": self.status.as_str(),
            "insured_batch_root": self.insured_batch_root,
            "premium_commitment": self.premium_commitment,
            "coverage_commitment": self.coverage_commitment,
            "reorg_depth": self.reorg_depth,
            "claim_nullifier": self.claim_nullifier,
            "underwriter_root": self.underwriter_root,
            "bound_at_height": self.bound_at_height,
            "expires_at_height": self.expires_at_height,
            "transcript_hash": self.transcript_hash,
        })
    }
    pub fn root(&self) -> String {
        record_root("REORG-INSURANCE-POLICY", &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub kind: FenceKind,
    pub scope_id: String,
    pub nullifier: String,
    pub commitment_root: String,
    pub first_seen_height: u64,
    pub expires_at_height: u64,
    pub spent: bool,
    pub transcript_hash: String,
}
impl PrivacyFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "kind": self.kind.as_str(),
            "scope_id": self.scope_id,
            "nullifier": self.nullifier,
            "commitment_root": self.commitment_root,
            "first_seen_height": self.first_seen_height,
            "expires_at_height": self.expires_at_height,
            "spent": self.spent,
            "transcript_hash": self.transcript_hash,
        })
    }
    pub fn root(&self) -> String {
        record_root("PRIVACY-FENCE", &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub reason: SlashReason,
    pub subject_id: String,
    pub pool_id: String,
    pub evidence_root: String,
    pub challenger_commitment: String,
    pub slash_bps: u64,
    pub slash_amount_piconero: u64,
    pub pq_signature_root: String,
    pub submitted_at_height: u64,
    pub resolved_at_height: u64,
    pub transcript_hash: String,
}
impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "reason": self.reason.as_str(),
            "subject_id": self.subject_id,
            "pool_id": self.pool_id,
            "evidence_root": self.evidence_root,
            "challenger_commitment": self.challenger_commitment,
            "slash_bps": self.slash_bps,
            "slash_amount_piconero": self.slash_amount_piconero,
            "pq_signature_root": self.pq_signature_root,
            "submitted_at_height": self.submitted_at_height,
            "resolved_at_height": self.resolved_at_height,
            "transcript_hash": self.transcript_hash,
        })
    }
    pub fn root(&self) -> String {
        record_root("SLASHING-EVIDENCE", &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub encrypted_deposits: BTreeMap<String, EncryptedBridgeLiquidityDeposit>,
    pub netting_pools: BTreeMap<String, NettingPool>,
    pub reserve_proofs: BTreeMap<String, ReserveProof>,
    pub withdrawal_batches: BTreeMap<String, WithdrawalBatch>,
    pub maker_commitments: BTreeMap<String, MakerCommitment>,
    pub fee_coupons: BTreeMap<String, FeeCoupon>,
    pub reorg_insurance: BTreeMap<String, ReorgInsurancePolicy>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub spent_nullifiers: BTreeSet<String>,
}
impl State {
    pub fn empty(config: Config) -> Self {
        Self {
            config,
            counters: Counters::empty(),
            roots: Roots::empty(),
            encrypted_deposits: BTreeMap::new(),
            netting_pools: BTreeMap::new(),
            reserve_proofs: BTreeMap::new(),
            withdrawal_batches: BTreeMap::new(),
            maker_commitments: BTreeMap::new(),
            fee_coupons: BTreeMap::new(),
            reorg_insurance: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        }
    }
    pub fn devnet() -> Self {
        let mut state = Self::empty(Config::devnet());
        state.seed_devnet();
        state.refresh_roots();
        state
    }
    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record_without_state_root())
    }
    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root());
        record
    }
    pub fn public_record_without_state_root(&self) -> Value {
        json!({ "protocol_version": PROTOCOL_VERSION, "chain_id": CHAIN_ID, "config": self.config.public_record(), "counters": self.counters.public_record(), "roots": self.roots.public_record(), "encrypted_deposits": self.encrypted_deposits.values().map(EncryptedBridgeLiquidityDeposit::public_record).collect::<Vec<_>>(), "netting_pools": self.netting_pools.values().map(NettingPool::public_record).collect::<Vec<_>>(), "reserve_proofs": self.reserve_proofs.values().map(ReserveProof::public_record).collect::<Vec<_>>(), "withdrawal_batches": self.withdrawal_batches.values().map(WithdrawalBatch::public_record).collect::<Vec<_>>(), "maker_commitments": self.maker_commitments.values().map(MakerCommitment::public_record).collect::<Vec<_>>(), "fee_coupons": self.fee_coupons.values().map(FeeCoupon::public_record).collect::<Vec<_>>(), "reorg_insurance": self.reorg_insurance.values().map(ReorgInsurancePolicy::public_record).collect::<Vec<_>>(), "privacy_fences": self.privacy_fences.values().map(PrivacyFence::public_record).collect::<Vec<_>>(), "slashing_evidence": self.slashing_evidence.values().map(SlashingEvidence::public_record).collect::<Vec<_>>(), "spent_nullifier_root": merkle_root("SPENT-NULLIFIERS", &self.spent_nullifiers.iter().map(|v| json!(v)).collect::<Vec<_>>()) })
    }
    pub fn refresh_roots(&mut self) {
        self.roots = Roots {
            deposit_root: merkle_root(
                "BRIDGE-LIQUIDITY-DEPOSITS",
                &self
                    .encrypted_deposits
                    .values()
                    .map(EncryptedBridgeLiquidityDeposit::public_record)
                    .collect::<Vec<_>>(),
            ),
            pool_root: merkle_root(
                "BRIDGE-LIQUIDITY-NETTING-POOLS",
                &self
                    .netting_pools
                    .values()
                    .map(NettingPool::public_record)
                    .collect::<Vec<_>>(),
            ),
            reserve_proof_root: merkle_root(
                "BRIDGE-LIQUIDITY-RESERVE-PROOFS",
                &self
                    .reserve_proofs
                    .values()
                    .map(ReserveProof::public_record)
                    .collect::<Vec<_>>(),
            ),
            withdrawal_batch_root: merkle_root(
                "BRIDGE-LIQUIDITY-WITHDRAWAL-BATCHES",
                &self
                    .withdrawal_batches
                    .values()
                    .map(WithdrawalBatch::public_record)
                    .collect::<Vec<_>>(),
            ),
            maker_commitment_root: merkle_root(
                "BRIDGE-LIQUIDITY-MAKERS",
                &self
                    .maker_commitments
                    .values()
                    .map(MakerCommitment::public_record)
                    .collect::<Vec<_>>(),
            ),
            fee_coupon_root: merkle_root(
                "BRIDGE-LIQUIDITY-FEE-COUPONS",
                &self
                    .fee_coupons
                    .values()
                    .map(FeeCoupon::public_record)
                    .collect::<Vec<_>>(),
            ),
            reorg_insurance_root: merkle_root(
                "BRIDGE-LIQUIDITY-REORG-INSURANCE",
                &self
                    .reorg_insurance
                    .values()
                    .map(ReorgInsurancePolicy::public_record)
                    .collect::<Vec<_>>(),
            ),
            privacy_fence_root: merkle_root(
                "BRIDGE-LIQUIDITY-PRIVACY-FENCES",
                &self
                    .privacy_fences
                    .values()
                    .map(PrivacyFence::public_record)
                    .collect::<Vec<_>>(),
            ),
            slashing_evidence_root: merkle_root(
                "BRIDGE-LIQUIDITY-SLASHING",
                &self
                    .slashing_evidence
                    .values()
                    .map(SlashingEvidence::public_record)
                    .collect::<Vec<_>>(),
            ),
            policy_root: record_root("BRIDGE-LIQUIDITY-POLICY", &self.config.public_record()),
            counter_root: record_root("BRIDGE-LIQUIDITY-COUNTERS", &self.counters.public_record()),
        };
    }
    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        self.validate_caps()?;
        for d in self.encrypted_deposits.values() {
            validate_deposit(d, &self.config)?;
        }
        for p in self.netting_pools.values() {
            validate_pool(p, &self.config)?;
        }
        for r in self.reserve_proofs.values() {
            validate_reserve_proof(r, &self.config)?;
        }
        for b in self.withdrawal_batches.values() {
            validate_batch(b, &self.config)?;
        }
        for m in self.maker_commitments.values() {
            validate_maker(m, &self.config)?;
        }
        for c in self.fee_coupons.values() {
            validate_coupon(c, &self.config)?;
        }
        for i in self.reorg_insurance.values() {
            validate_insurance(i, &self.config)?;
        }
        for f in self.privacy_fences.values() {
            validate_fence(f)?;
        }
        for s in self.slashing_evidence.values() {
            validate_slashing(s)?;
        }
        Ok(())
    }
    fn validate_caps(&self) -> Result<()> {
        if self.encrypted_deposits.len() > MAX_DEPOSITS {
            return Err("too many encrypted bridge liquidity deposits".to_string());
        }
        if self.netting_pools.len() > MAX_NETTING_POOLS {
            return Err("too many netting pools".to_string());
        }
        if self.reserve_proofs.len() > MAX_RESERVE_PROOFS {
            return Err("too many reserve proofs".to_string());
        }
        if self.withdrawal_batches.len() > MAX_WITHDRAWAL_BATCHES {
            return Err("too many withdrawal batches".to_string());
        }
        if self.maker_commitments.len() > MAX_MAKER_COMMITMENTS {
            return Err("too many maker commitments".to_string());
        }
        if self.fee_coupons.len() > MAX_FEE_COUPONS {
            return Err("too many fee coupons".to_string());
        }
        if self.reorg_insurance.len() > MAX_REORG_INSURANCE_POLICIES {
            return Err("too many reorg insurance policies".to_string());
        }
        if self.privacy_fences.len() > MAX_PRIVACY_FENCES {
            return Err("too many privacy fences".to_string());
        }
        if self.slashing_evidence.len() > MAX_SLASHING_EVIDENCE {
            return Err("too many slashing evidence records".to_string());
        }
        Ok(())
    }
    pub fn add_encrypted_deposit(
        &mut self,
        deposit: EncryptedBridgeLiquidityDeposit,
    ) -> Result<String> {
        validate_deposit(&deposit, &self.config)?;
        if self.spent_nullifiers.contains(&deposit.deposit_nullifier) {
            self.counters.nullifier_replays_blocked += 1;
            return Err("deposit nullifier already fenced".to_string());
        }
        let id = deposit.deposit_id.clone();
        self.spent_nullifiers
            .insert(deposit.deposit_nullifier.clone());
        self.counters.encrypted_deposits += 1;
        if deposit.status.live() {
            self.counters.active_deposits += 1;
        }
        self.counters.total_deposit_commitment_piconero = self
            .counters
            .total_deposit_commitment_piconero
            .saturating_add(deposit.amount_bucket_piconero);
        self.encrypted_deposits.insert(id.clone(), deposit);
        self.refresh_roots();
        Ok(id)
    }
    pub fn open_netting_pool(&mut self, pool: NettingPool) -> Result<String> {
        validate_pool(&pool, &self.config)?;
        let id = pool.pool_id.clone();
        self.counters.netting_pools += 1;
        if pool.status == PoolStatus::Open {
            self.counters.open_pools += 1;
        }
        self.netting_pools.insert(id.clone(), pool);
        self.refresh_roots();
        Ok(id)
    }
    pub fn submit_reserve_proof(&mut self, proof: ReserveProof) -> Result<String> {
        validate_reserve_proof(&proof, &self.config)?;
        let id = proof.proof_id.clone();
        self.counters.reserve_proofs += 1;
        if proof.status.usable() {
            self.counters.accepted_reserve_proofs += 1;
        }
        self.reserve_proofs.insert(id.clone(), proof);
        self.refresh_roots();
        Ok(id)
    }
    pub fn assemble_withdrawal_batch(&mut self, batch: WithdrawalBatch) -> Result<String> {
        validate_batch(&batch, &self.config)?;
        let id = batch.batch_id.clone();
        self.counters.withdrawal_batches += 1;
        self.counters.total_withdrawal_commitment_piconero = self
            .counters
            .total_withdrawal_commitment_piconero
            .saturating_add(batch.amount_bucket_piconero);
        self.counters.total_fee_commitment_piconero = self
            .counters
            .total_fee_commitment_piconero
            .saturating_add(batch.fee_bucket_piconero);
        self.withdrawal_batches.insert(id.clone(), batch);
        self.refresh_roots();
        Ok(id)
    }
    pub fn register_maker(&mut self, maker: MakerCommitment) -> Result<String> {
        validate_maker(&maker, &self.config)?;
        if self.spent_nullifiers.contains(&maker.session_nullifier) {
            return Err("maker session nullifier already used".to_string());
        }
        let id = maker.maker_id.clone();
        self.spent_nullifiers
            .insert(maker.session_nullifier.clone());
        self.counters.maker_commitments += 1;
        if maker.status.usable() {
            self.counters.active_makers += 1;
        }
        self.maker_commitments.insert(id.clone(), maker);
        self.refresh_roots();
        Ok(id)
    }
    pub fn mint_fee_coupon(&mut self, coupon: FeeCoupon) -> Result<String> {
        validate_coupon(&coupon, &self.config)?;
        if self.spent_nullifiers.contains(&coupon.coupon_nullifier) {
            return Err("coupon nullifier already used".to_string());
        }
        let id = coupon.coupon_id.clone();
        self.spent_nullifiers
            .insert(coupon.coupon_nullifier.clone());
        self.counters.fee_coupons += 1;
        self.fee_coupons.insert(id.clone(), coupon);
        self.refresh_roots();
        Ok(id)
    }
    pub fn bind_reorg_insurance(&mut self, policy: ReorgInsurancePolicy) -> Result<String> {
        validate_insurance(&policy, &self.config)?;
        if self.spent_nullifiers.contains(&policy.claim_nullifier) {
            return Err("insurance claim nullifier already used".to_string());
        }
        let id = policy.policy_id.clone();
        self.spent_nullifiers.insert(policy.claim_nullifier.clone());
        self.counters.insurance_policies += 1;
        self.reorg_insurance.insert(id.clone(), policy);
        self.refresh_roots();
        Ok(id)
    }
    pub fn insert_privacy_fence(&mut self, fence: PrivacyFence) -> Result<String> {
        validate_fence(&fence)?;
        if self.spent_nullifiers.contains(&fence.nullifier) {
            self.counters.nullifier_replays_blocked += 1;
            return Err("privacy fence nullifier replay".to_string());
        }
        let id = fence.fence_id.clone();
        self.spent_nullifiers.insert(fence.nullifier.clone());
        self.counters.privacy_fences += 1;
        self.privacy_fences.insert(id.clone(), fence);
        self.refresh_roots();
        Ok(id)
    }
    pub fn submit_slashing_evidence(&mut self, evidence: SlashingEvidence) -> Result<String> {
        validate_slashing(&evidence)?;
        let id = evidence.evidence_id.clone();
        self.counters.slashing_events += 1;
        self.counters.slashed_piconero = self
            .counters
            .slashed_piconero
            .saturating_add(evidence.slash_amount_piconero);
        self.slashing_evidence.insert(id.clone(), evidence);
        self.refresh_roots();
        Ok(id)
    }
    pub fn redeem_coupon(
        &mut self,
        coupon_id: &str,
        batch_id: &str,
        savings_piconero: u64,
    ) -> Result<()> {
        let coupon = self
            .fee_coupons
            .get_mut(coupon_id)
            .ok_or_else(|| "unknown coupon".to_string())?;
        if !coupon.status.spendable() {
            return Err("coupon is not spendable".to_string());
        }
        coupon.status = CouponStatus::Redeemed;
        coupon.redeemed_batch_id = Some(batch_id.to_string());
        self.counters.redeemed_coupons += 1;
        self.counters.coupon_savings_piconero = self
            .counters
            .coupon_savings_piconero
            .saturating_add(savings_piconero.min(coupon.max_savings_piconero));
        self.refresh_roots();
        Ok(())
    }
    pub fn finalize_batch(&mut self, batch_id: &str) -> Result<()> {
        let batch = self
            .withdrawal_batches
            .get_mut(batch_id)
            .ok_or_else(|| "unknown withdrawal batch".to_string())?;
        batch.status = BatchStatus::Finalized;
        self.counters.finalized_batches += 1;
        self.refresh_roots();
        Ok(())
    }
    pub fn mark_reorged_batch(&mut self, batch_id: &str) -> Result<()> {
        let batch = self
            .withdrawal_batches
            .get_mut(batch_id)
            .ok_or_else(|| "unknown withdrawal batch".to_string())?;
        batch.status = BatchStatus::Reorged;
        self.counters.reorged_batches += 1;
        self.refresh_roots();
        Ok(())
    }
    fn seed_devnet(&mut self) {
        let cfg = &self.config.clone();
        let pool_id = pool_id(BridgeLane::LowFee, 0, DEVNET_HEIGHT);
        let maker_id = maker_id("devnet-maker-alpha", BridgeLane::LowFee, DEVNET_HEIGHT);
        let proof_id = reserve_proof_id(&maker_id, &pool_id, DEVNET_HEIGHT);
        let deposit_id = deposit_id(&pool_id, &maker_id, "devnet-deposit-note", DEVNET_HEIGHT);
        let coupon_id = fee_coupon_id(&pool_id, "devnet-wallet", DEVNET_HEIGHT);
        let policy_id = insurance_policy_id(&pool_id, &maker_id, DEVNET_HEIGHT);
        let batch_id = withdrawal_batch_id(&pool_id, "devnet-withdrawals", DEVNET_HEIGHT);
        let fence_id = privacy_fence_id(
            FenceKind::DepositNullifier,
            &pool_id,
            "devnet-deposit-nullifier",
        );
        let maker = MakerCommitment {
            maker_id: maker_id.clone(),
            status: MakerStatus::Active,
            lane: BridgeLane::LowFee,
            capacity_commitment: commitment("maker-capacity", &maker_id, 50_000_000_000),
            stake_commitment: commitment("maker-stake", &maker_id, 5_000_000_000),
            reserve_proof_id: proof_id.clone(),
            fee_schedule_root: record_root(
                "DEVNET-FEE-SCHEDULE",
                &json!({"low_fee_bps": cfg.low_fee_bps}),
            ),
            pq_public_key_root: commitment("maker-pq-key", &maker_id, 1),
            session_nullifier: nullifier("maker-session", &maker_id),
            reputation_score: 980,
            max_fill_bucket_piconero: 25_000_000_000,
            active_from_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT + cfg.maker_ttl_blocks,
            transcript_hash: transcript("maker", &[&maker_id, &pool_id]),
        };
        let proof = ReserveProof {
            proof_id: proof_id.clone(),
            maker_id: maker_id.clone(),
            pool_id: pool_id.clone(),
            status: ProofStatus::Accepted,
            reserve_commitment_root: commitment("reserve", &maker_id, 64_000_000_000),
            liabilities_commitment_root: commitment("liability", &maker_id, 48_000_000_000),
            coverage_bps: 13_333,
            monero_view_proof_root: commitment("view-proof", &maker_id, 1),
            pq_attestation_root: commitment("pq-attestation", &maker_id, 1),
            auditor_committee_root: record_root(
                "DEVNET-AUDITORS",
                &json!(["auditor-a", "auditor-b"]),
            ),
            privacy_set_size: cfg.batch_privacy_set_size,
            pq_security_bits: cfg.min_pq_security_bits,
            submitted_at_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT + cfg.reserve_proof_ttl_blocks,
            transcript_hash: transcript("reserve-proof", &[&proof_id, &maker_id, &pool_id]),
        };
        let coupon = FeeCoupon {
            coupon_id: coupon_id.clone(),
            owner_commitment: commitment("coupon-owner", "devnet-wallet", 1),
            pool_id: pool_id.clone(),
            status: CouponStatus::Minted,
            lane: BridgeLane::LowFee,
            discount_bps: cfg.maker_rebate_bps,
            max_savings_piconero: 30_000,
            coupon_nullifier: nullifier("coupon", &coupon_id),
            sponsor_commitment: commitment("coupon-sponsor", "devnet-sponsor", 1),
            issued_at_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT + cfg.coupon_ttl_blocks,
            redeemed_batch_id: None,
            transcript_hash: transcript("coupon", &[&coupon_id, &pool_id]),
        };
        let policy = ReorgInsurancePolicy {
            policy_id: policy_id.clone(),
            pool_id: pool_id.clone(),
            maker_id: maker_id.clone(),
            status: InsuranceStatus::Bound,
            insured_batch_root: commitment("insured-batch", &pool_id, 1),
            premium_commitment: commitment("premium", &policy_id, 20_000),
            coverage_commitment: commitment("coverage", &policy_id, 2_000_000_000),
            reorg_depth: 12,
            claim_nullifier: nullifier("insurance-claim", &policy_id),
            underwriter_root: record_root(
                "DEVNET-UNDERWRITERS",
                &json!(["underwriter-a", "underwriter-b"]),
            ),
            bound_at_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT + cfg.insurance_ttl_blocks,
            transcript_hash: transcript("insurance", &[&policy_id, &pool_id]),
        };
        let deposit = EncryptedBridgeLiquidityDeposit {
            deposit_id: deposit_id.clone(),
            pool_id: pool_id.clone(),
            maker_id: maker_id.clone(),
            lane: BridgeLane::LowFee,
            status: DepositStatus::Admitted,
            amount_commitment: commitment("deposit-amount", &deposit_id, 1_500_000_000),
            amount_bucket_piconero: 1_500_000_000,
            fee_commitment: commitment("deposit-fee", &deposit_id, 6_000),
            encrypted_note_root: commitment("encrypted-note", &deposit_id, 1),
            monero_txid_root: commitment("monero-txid", &deposit_id, 1),
            output_commitment_root: commitment("output", &deposit_id, 1),
            key_image_root: commitment("key-image", &deposit_id, 1),
            view_tag_root: commitment("view-tag", &deposit_id, 1),
            deposit_nullifier: nullifier("deposit", &deposit_id),
            reserve_proof_id: proof_id.clone(),
            coupon_id: Some(coupon_id.clone()),
            insurance_policy_id: Some(policy_id.clone()),
            privacy_set_size: cfg.batch_privacy_set_size,
            pq_security_bits: cfg.min_pq_security_bits,
            admitted_at_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT + cfg.deposit_ttl_blocks,
            transcript_hash: transcript("deposit", &[&deposit_id, &pool_id, &maker_id]),
        };
        let batch = WithdrawalBatch {
            batch_id: batch_id.clone(),
            pool_id: pool_id.clone(),
            lane: BridgeLane::LowFee,
            status: BatchStatus::Proved,
            withdrawal_note_root: commitment("withdrawal-note", &batch_id, 1),
            deposit_spend_root: deposit.root(),
            output_commitment_root: commitment("batch-output", &batch_id, 1),
            key_image_root: commitment("batch-key-image", &batch_id, 1),
            fee_coupon_root: coupon.root(),
            proof_aggregate_root: commitment("aggregate-proof", &batch_id, 1),
            monero_anchor_root: commitment("monero-anchor", &batch_id, DEVNET_HEIGHT),
            item_count: 1,
            amount_bucket_piconero: 1_500_000_000,
            fee_bucket_piconero: 6_000,
            privacy_set_size: cfg.batch_privacy_set_size,
            assembled_at_height: DEVNET_HEIGHT + 2,
            finalizes_at_height: DEVNET_HEIGHT + cfg.batch_ttl_blocks,
            transcript_hash: transcript("batch", &[&batch_id, &pool_id]),
        };
        let fence = PrivacyFence {
            fence_id: fence_id.clone(),
            kind: FenceKind::DepositNullifier,
            scope_id: pool_id.clone(),
            nullifier: commitment("fence-nullifier", &deposit_id, 1),
            commitment_root: deposit.root(),
            first_seen_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT + cfg.nullifier_ttl_blocks,
            spent: false,
            transcript_hash: transcript("fence", &[&fence_id, &pool_id]),
        };
        let pool = NettingPool {
            pool_id: pool_id.clone(),
            epoch: 0,
            lane: BridgeLane::LowFee,
            status: PoolStatus::Open,
            asset_id: cfg.asset_id.clone(),
            maker_root: maker.root(),
            deposit_root: deposit.root(),
            withdrawal_root: batch.root(),
            reserve_proof_root: proof.root(),
            fee_coupon_root: coupon.root(),
            insurance_root: policy.root(),
            privacy_fence_root: fence.root(),
            total_input_bucket_piconero: 1_500_000_000,
            total_output_bucket_piconero: 1_500_000_000,
            fee_bucket_piconero: 6_000,
            min_privacy_set_size: cfg.min_privacy_set_size,
            opened_at_height: DEVNET_HEIGHT,
            sealed_at_height: 0,
            settles_before_height: DEVNET_HEIGHT + cfg.batch_ttl_blocks,
            transcript_hash: transcript("pool", &[&pool_id]),
        };
        let _ = self.register_maker(maker);
        let _ = self.submit_reserve_proof(proof);
        let _ = self.mint_fee_coupon(coupon);
        let _ = self.bind_reorg_insurance(policy);
        let _ = self.add_encrypted_deposit(deposit);
        let _ = self.assemble_withdrawal_batch(batch);
        let _ = self.open_netting_pool(pool);
        let _ = self.insert_privacy_fence(fence);
    }
}

pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}
pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}
pub fn state_root_from_public_record(record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-BRIDGE-LIQUIDITY-NETTING-POOL-STATE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}
fn empty_root(label: &str) -> String {
    merkle_root(
        &format!("MONERO-L2-PQ-PRIVATE-BRIDGE-LIQUIDITY-NETTING-POOL-{label}"),
        &[],
    )
}
fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}
fn transcript(domain: &str, parts: &[&str]) -> String {
    let mut hash_parts = vec![
        HashPart::Str(CHAIN_ID),
        HashPart::Str(PROTOCOL_VERSION),
        HashPart::Str(REPLAY_DOMAIN),
    ];
    for part in parts {
        hash_parts.push(HashPart::Str(part));
    }
    domain_hash(
        &format!("BRIDGE-LIQUIDITY-NETTING-TRANSCRIPT-{domain}"),
        &hash_parts,
        32,
    )
}
fn commitment(domain: &str, subject: &str, value: u64) -> String {
    domain_hash(
        &format!("BRIDGE-LIQUIDITY-COMMITMENT-{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject),
            HashPart::U64(value),
        ],
        32,
    )
}
fn nullifier(domain: &str, subject: &str) -> String {
    domain_hash(
        &format!("BRIDGE-LIQUIDITY-NULLIFIER-{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(REPLAY_DOMAIN),
            HashPart::Str(subject),
        ],
        32,
    )
}
pub fn pool_id(lane: BridgeLane, epoch: u64, height: u64) -> String {
    domain_hash(
        "BRIDGE-LIQUIDITY-POOL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::U64(epoch),
            HashPart::U64(height),
        ],
        32,
    )
}
pub fn maker_id(owner_commitment: &str, lane: BridgeLane, height: u64) -> String {
    domain_hash(
        "BRIDGE-LIQUIDITY-MAKER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_commitment),
            HashPart::Str(lane.as_str()),
            HashPart::U64(height),
        ],
        32,
    )
}
pub fn reserve_proof_id(maker_id: &str, pool_id: &str, height: u64) -> String {
    domain_hash(
        "BRIDGE-LIQUIDITY-RESERVE-PROOF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(maker_id),
            HashPart::Str(pool_id),
            HashPart::U64(height),
        ],
        32,
    )
}
pub fn deposit_id(pool_id: &str, maker_id: &str, note_commitment: &str, height: u64) -> String {
    domain_hash(
        "BRIDGE-LIQUIDITY-DEPOSIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Str(maker_id),
            HashPart::Str(note_commitment),
            HashPart::U64(height),
        ],
        32,
    )
}
pub fn withdrawal_batch_id(pool_id: &str, withdrawal_root: &str, height: u64) -> String {
    domain_hash(
        "BRIDGE-LIQUIDITY-WITHDRAWAL-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Str(withdrawal_root),
            HashPart::U64(height),
        ],
        32,
    )
}
pub fn fee_coupon_id(pool_id: &str, owner_commitment: &str, height: u64) -> String {
    domain_hash(
        "BRIDGE-LIQUIDITY-FEE-COUPON-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Str(owner_commitment),
            HashPart::U64(height),
        ],
        32,
    )
}
pub fn insurance_policy_id(pool_id: &str, maker_id: &str, height: u64) -> String {
    domain_hash(
        "BRIDGE-LIQUIDITY-INSURANCE-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Str(maker_id),
            HashPart::U64(height),
        ],
        32,
    )
}
pub fn privacy_fence_id(kind: FenceKind, scope_id: &str, nullifier: &str) -> String {
    domain_hash(
        "BRIDGE-LIQUIDITY-PRIVACY-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(scope_id),
            HashPart::Str(nullifier),
        ],
        32,
    )
}
pub fn slashing_evidence_id(
    reason: SlashReason,
    subject_id: &str,
    pool_id: &str,
    height: u64,
) -> String {
    domain_hash(
        "BRIDGE-LIQUIDITY-SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(reason.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(pool_id),
            HashPart::U64(height),
        ],
        32,
    )
}
fn validate_hash(label: &str, value: &str) -> Result<()> {
    if value.len() < 16 {
        return Err(format!("{label} must be a domain hash or commitment root"));
    }
    Ok(())
}
fn validate_height_window(label: &str, start: u64, end: u64) -> Result<()> {
    if end != 0 && end < start {
        return Err(format!("{label} has inverted height window"));
    }
    Ok(())
}
fn validate_deposit(d: &EncryptedBridgeLiquidityDeposit, c: &Config) -> Result<()> {
    validate_hash("deposit_id", &d.deposit_id)?;
    validate_hash("pool_id", &d.pool_id)?;
    validate_hash("maker_id", &d.maker_id)?;
    validate_hash("amount_commitment", &d.amount_commitment)?;
    validate_hash("deposit_nullifier", &d.deposit_nullifier)?;
    if d.privacy_set_size < c.min_privacy_set_size {
        return Err("deposit privacy set below minimum".to_string());
    }
    if d.pq_security_bits < c.min_pq_security_bits {
        return Err("deposit pq security below minimum".to_string());
    }
    validate_height_window("deposit", d.admitted_at_height, d.expires_at_height)
}
fn validate_pool(p: &NettingPool, c: &Config) -> Result<()> {
    validate_hash("pool_id", &p.pool_id)?;
    if p.min_privacy_set_size < c.min_privacy_set_size {
        return Err("pool privacy set below minimum".to_string());
    }
    if p.fee_bucket_piconero > p.total_input_bucket_piconero {
        return Err("pool fee exceeds input bucket".to_string());
    }
    validate_height_window("pool", p.opened_at_height, p.settles_before_height)
}
fn validate_reserve_proof(r: &ReserveProof, c: &Config) -> Result<()> {
    validate_hash("proof_id", &r.proof_id)?;
    if r.coverage_bps < c.min_reserve_coverage_bps {
        return Err("reserve proof coverage below minimum".to_string());
    }
    if r.privacy_set_size < c.min_privacy_set_size {
        return Err("reserve proof privacy set below minimum".to_string());
    }
    if r.pq_security_bits < c.min_pq_security_bits {
        return Err("reserve proof pq security below minimum".to_string());
    }
    validate_height_window("reserve proof", r.submitted_at_height, r.expires_at_height)
}
fn validate_batch(b: &WithdrawalBatch, c: &Config) -> Result<()> {
    validate_hash("batch_id", &b.batch_id)?;
    if b.item_count as usize > c.max_batch_items {
        return Err("withdrawal batch exceeds max items".to_string());
    }
    if b.privacy_set_size < c.min_privacy_set_size {
        return Err("withdrawal batch privacy set below minimum".to_string());
    }
    if b.fee_bucket_piconero > b.amount_bucket_piconero {
        return Err("withdrawal batch fee exceeds amount".to_string());
    }
    validate_height_window(
        "withdrawal batch",
        b.assembled_at_height,
        b.finalizes_at_height,
    )
}
fn validate_maker(m: &MakerCommitment, c: &Config) -> Result<()> {
    validate_hash("maker_id", &m.maker_id)?;
    validate_hash("session_nullifier", &m.session_nullifier)?;
    if m.max_fill_bucket_piconero == 0 {
        return Err("maker capacity must be nonzero".to_string());
    }
    validate_height_window("maker", m.active_from_height, m.expires_at_height)?;
    if m.expires_at_height.saturating_sub(m.active_from_height) > c.maker_ttl_blocks * 8 {
        return Err("maker ttl is too long".to_string());
    }
    Ok(())
}
fn validate_coupon(coupon: &FeeCoupon, c: &Config) -> Result<()> {
    validate_hash("coupon_id", &coupon.coupon_id)?;
    validate_hash("coupon_nullifier", &coupon.coupon_nullifier)?;
    if coupon.discount_bps > c.fast_fee_bps {
        return Err("coupon discount exceeds fast fee".to_string());
    }
    validate_height_window("coupon", coupon.issued_at_height, coupon.expires_at_height)
}
fn validate_insurance(i: &ReorgInsurancePolicy, c: &Config) -> Result<()> {
    validate_hash("policy_id", &i.policy_id)?;
    validate_hash("claim_nullifier", &i.claim_nullifier)?;
    if i.reorg_depth == 0 {
        return Err("insurance reorg depth must be nonzero".to_string());
    }
    validate_height_window("insurance", i.bound_at_height, i.expires_at_height)?;
    if i.expires_at_height.saturating_sub(i.bound_at_height) > c.insurance_ttl_blocks * 8 {
        return Err("insurance ttl is too long".to_string());
    }
    Ok(())
}
fn validate_fence(f: &PrivacyFence) -> Result<()> {
    validate_hash("fence_id", &f.fence_id)?;
    validate_hash("nullifier", &f.nullifier)?;
    validate_height_window("privacy fence", f.first_seen_height, f.expires_at_height)
}
fn validate_slashing(s: &SlashingEvidence) -> Result<()> {
    validate_hash("evidence_id", &s.evidence_id)?;
    validate_hash("subject_id", &s.subject_id)?;
    validate_hash("pool_id", &s.pool_id)?;
    if s.slash_bps > MAX_BPS {
        return Err("slash bps exceeds 100%".to_string());
    }
    validate_height_window("slashing", s.submitted_at_height, s.resolved_at_height)
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint01 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint01 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-01",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint02 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint02 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-02",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint03 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint03 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-03",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint04 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint04 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-04",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint05 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint05 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-05",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint06 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint06 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-06",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint07 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint07 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-07",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint08 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint08 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-08",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint09 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint09 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-09",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint10 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint10 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-10",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint11 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint11 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-11",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint12 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint12 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-12",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint13 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint13 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-13",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint14 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint14 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-14",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint15 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint15 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-15",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint16 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint16 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-16",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint17 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint17 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-17",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint18 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint18 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-18",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint19 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint19 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-19",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint20 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint20 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-20",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint21 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint21 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-21",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint22 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint22 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-22",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint23 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint23 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-23",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint24 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint24 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-24",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint25 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint25 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-25",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint26 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint26 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-26",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint27 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint27 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-27",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint28 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint28 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-28",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint29 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint29 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-29",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint30 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint30 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-30",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint31 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint31 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-31",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint32 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint32 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-32",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint33 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint33 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-33",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint34 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint34 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-34",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint35 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint35 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-35",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint36 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint36 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-36",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint37 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint37 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-37",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint38 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint38 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-38",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint39 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint39 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-39",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint40 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint40 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-40",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint41 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint41 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-41",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint42 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint42 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-42",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint43 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint43 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-43",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint44 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint44 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-44",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint45 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint45 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-45",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint46 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint46 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-46",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint47 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint47 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-47",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint48 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint48 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-48",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint49 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint49 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-49",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint50 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint50 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-50",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint51 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint51 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-51",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint52 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint52 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-52",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint53 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint53 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-53",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint54 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint54 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-54",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint55 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint55 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-55",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint56 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint56 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-56",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint57 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint57 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-57",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint58 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint58 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-58",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint59 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint59 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-59",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint60 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint60 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-60",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint61 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint61 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-61",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint62 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint62 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-62",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint63 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint63 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-63",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint64 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint64 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-64",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint65 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint65 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-65",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint66 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint66 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-66",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint67 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint67 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-67",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint68 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint68 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-68",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint69 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint69 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-69",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint70 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint70 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-70",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint71 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint71 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-71",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint72 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint72 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-72",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint73 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint73 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-73",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint74 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint74 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-74",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint75 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint75 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-75",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint76 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint76 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-76",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint77 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint77 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-77",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint78 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint78 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-78",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint79 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint79 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-79",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint80 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint80 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-80",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint81 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint81 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-81",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint82 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint82 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-82",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint83 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint83 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-83",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint84 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint84 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-84",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint85 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint85 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-85",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint86 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint86 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-86",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint87 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint87 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-87",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint88 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint88 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-88",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint89 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint89 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-89",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint90 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint90 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-90",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint91 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint91 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-91",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint92 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint92 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-92",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint93 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint93 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-93",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint94 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint94 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-94",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityNettingPolicyCheckpoint95 {
    pub checkpoint_id: String,
    pub pool_id: String,
    pub lane: BridgeLane,
    pub reserve_floor_bps: u64,
    pub fee_ceiling_bps: u64,
    pub privacy_floor: u64,
    pub pq_security_bits: u16,
    pub maker_commitment_root: String,
    pub withdrawal_batch_root: String,
    pub nullifier_fence_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}
impl LiquidityNettingPolicyCheckpoint95 {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "reserve_floor_bps": self.reserve_floor_bps,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "privacy_floor": self.privacy_floor,
            "pq_security_bits": self.pq_security_bits,
            "maker_commitment_root": self.maker_commitment_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn checkpoint_root(&self) -> String {
        record_root(
            "LIQUIDITY-NETTING-POLICY-CHECKPOINT-95",
            &self.public_record(),
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        validate_hash("checkpoint_id", &self.checkpoint_id)?;
        validate_hash("checkpoint_pool_id", &self.pool_id)?;
        if self.reserve_floor_bps < config.min_reserve_coverage_bps {
            return Err("checkpoint reserve floor below config minimum".to_string());
        }
        if self.fee_ceiling_bps > config.fast_fee_bps {
            return Err("checkpoint fee ceiling exceeds fast lane fee".to_string());
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err("checkpoint privacy floor below config minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("checkpoint pq security below config minimum".to_string());
        }
        validate_height_window(
            "policy checkpoint",
            self.effective_from_height,
            self.expires_at_height,
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_is_deterministic() {
        let a = State::devnet();
        let b = State::devnet();
        assert_eq!(a.state_root(), b.state_root());
        assert_eq!(devnet_state_root(), a.state_root());
    }

    #[test]
    fn public_record_round_trips_root_helper() {
        let state = State::devnet();
        let record = state.public_record_without_state_root();
        assert_eq!(state_root_from_public_record(&record), state.state_root());
    }
}
