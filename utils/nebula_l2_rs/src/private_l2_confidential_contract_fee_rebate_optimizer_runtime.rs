use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialContractFeeRebateOptimizerRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-contract-fee-rebate-optimizer-runtime-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-fee-rebate-optimizer-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEVNET_HEIGHT: u64 =
    1_044_000;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_MAX_POLICIES:
    usize = 2_097_152;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_MAX_QUOTES: usize =
    67_108_864;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_MAX_RESERVATIONS:
    usize = 16_777_216;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_MAX_BATCHES: usize =
    4_194_304;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_MAX_RECEIPTS:
    usize = 67_108_864;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_MAX_REBATES: usize =
    16_777_216;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_MAX_ATTESTATIONS:
    usize = 33_554_432;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_MAX_NULLIFIERS:
    usize = 134_217_728;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_MAX_BATCH_QUOTES:
    usize = 16_384;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_MIN_PRIVACY_SET:
    u64 = 32_768;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_BATCH_PRIVACY_SET:
    u64 = 524_288;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS:
    u16 = 256;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_MAX_OPTIMIZER_FEE_BPS:
    u64 = 7;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_MAX_SPONSOR_FEE_BPS:
    u64 = 6;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_TARGET_REBATE_BPS:
    u64 = 5;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_POLICY_TTL_BLOCKS:
    u64 = 86_400;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS:
    u64 = 72;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS:
    u64 = 48;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS:
    u64 = 96;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeLaneKind {
    ContractCall,
    TokenTransfer,
    Swap,
    Lending,
    Perpetuals,
    Bridge,
    Oracle,
    Governance,
    StateChannel,
}

impl FeeLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractCall => "contract_call",
            Self::TokenTransfer => "token_transfer",
            Self::Swap => "swap",
            Self::Lending => "lending",
            Self::Perpetuals => "perpetuals",
            Self::Bridge => "bridge",
            Self::Oracle => "oracle",
            Self::Governance => "governance",
            Self::StateChannel => "state_channel",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    Proposed,
    Active,
    Paused,
    Draining,
    Retired,
}

impl PolicyStatus {
    pub fn accepts_quotes(self) -> bool {
        matches!(self, Self::Active | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Encrypted,
    Scored,
    Sponsored,
    Batched,
    Settled,
    Disputed,
    Expired,
    Cancelled,
}

impl QuoteStatus {
    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Encrypted | Self::Scored | Self::Sponsored | Self::Batched
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OptimizationSignalKind {
    Congestion,
    ProofCacheHit,
    BatchDensity,
    SponsorInventory,
    OracleFreshness,
    ContractHeat,
    PrivacyFloor,
    MoneroExitDemand,
}

impl OptimizationSignalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Congestion => "congestion",
            Self::ProofCacheHit => "proof_cache_hit",
            Self::BatchDensity => "batch_density",
            Self::SponsorInventory => "sponsor_inventory",
            Self::OracleFreshness => "oracle_freshness",
            Self::ContractHeat => "contract_heat",
            Self::PrivacyFloor => "privacy_floor",
            Self::MoneroExitDemand => "monero_exit_demand",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    BoundToQuote,
    Consumed,
    RebateQueued,
    Released,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Sealed,
    Posted,
    Settled,
    PartiallySettled,
    Disputed,
    Expired,
}

impl BatchStatus {
    pub fn anchors_state(self) -> bool {
        matches!(self, Self::Sealed | Self::Posted | Self::Settled)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    QuoteSettlement,
    SponsorSettlement,
    RebateCredit,
    OptimizerCredit,
    BatchDiscount,
    DisputeResolution,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Pending,
    Claimable,
    Claimed,
    DonatedToLane,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    PqOptimizerKey,
    QuoteScore,
    SponsorSolvency,
    BatchDiscount,
    PrivacyFloor,
    ReplayFence,
    EmergencyPause,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Valid,
    ValidWithWarning,
    NeedsMoreWitnesses,
    Quarantined,
    Invalid,
    Revoked,
}

impl AttestationVerdict {
    pub fn contributes_to_quorum(self) -> bool {
        matches!(self, Self::Valid | Self::ValidWithWarning)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NullifierFenceStatus {
    Open,
    Locked,
    Spent,
    Disputed,
    Released,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub schema_version: u64,
    pub devnet_height: u64,
    pub fee_asset_id: String,
    pub max_policies: usize,
    pub max_quotes: usize,
    pub max_reservations: usize,
    pub max_batches: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub max_attestations: usize,
    pub max_nullifiers: usize,
    pub max_batch_quotes: usize,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_optimizer_fee_bps: u64,
    pub max_sponsor_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub policy_ttl_blocks: u64,
    pub quote_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub hash_suite: String,
    pub pq_auth_suite: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            schema_version:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_SCHEMA_VERSION,
            devnet_height:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEVNET_HEIGHT,
            fee_asset_id: "nebula-private-l2-fee-rebate-credit".to_string(),
            max_policies:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_MAX_POLICIES,
            max_quotes:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_MAX_QUOTES,
            max_reservations:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_batches:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_MAX_BATCHES,
            max_receipts:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_MAX_RECEIPTS,
            max_rebates:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_MAX_REBATES,
            max_attestations:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_MAX_ATTESTATIONS,
            max_nullifiers:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_MAX_NULLIFIERS,
            max_batch_quotes:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_MAX_BATCH_QUOTES,
            min_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
            batch_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_BATCH_PRIVACY_SET,
            min_pq_security_bits:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_optimizer_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_MAX_OPTIMIZER_FEE_BPS,
            max_sponsor_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_MAX_SPONSOR_FEE_BPS,
            target_rebate_bps:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            policy_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_POLICY_TTL_BLOCKS,
            quote_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS,
            batch_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS,
            reservation_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
            hash_suite: PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_HASH_SUITE
                .to_string(),
            pq_auth_suite:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_PQ_AUTH_SUITE
                    .to_string(),
        }
    }

    pub fn policy_record(&self) -> Value {
        json!({
            "schema_version": self.schema_version,
            "devnet_height": self.devnet_height,
            "fee_asset_id": self.fee_asset_id,
            "limits": {
                "max_policies": self.max_policies,
                "max_quotes": self.max_quotes,
                "max_reservations": self.max_reservations,
                "max_batches": self.max_batches,
                "max_receipts": self.max_receipts,
                "max_rebates": self.max_rebates,
                "max_attestations": self.max_attestations,
                "max_nullifiers": self.max_nullifiers,
                "max_batch_quotes": self.max_batch_quotes,
            },
            "privacy": {
                "min_privacy_set_size": self.min_privacy_set_size,
                "batch_privacy_set_size": self.batch_privacy_set_size,
                "min_pq_security_bits": self.min_pq_security_bits,
            },
            "fees": {
                "max_optimizer_fee_bps": self.max_optimizer_fee_bps,
                "max_sponsor_fee_bps": self.max_sponsor_fee_bps,
                "target_rebate_bps": self.target_rebate_bps,
            },
            "ttls": {
                "policy_ttl_blocks": self.policy_ttl_blocks,
                "quote_ttl_blocks": self.quote_ttl_blocks,
                "batch_ttl_blocks": self.batch_ttl_blocks,
                "reservation_ttl_blocks": self.reservation_ttl_blocks,
            },
            "suites": {
                "hash_suite": self.hash_suite,
                "pq_auth_suite": self.pq_auth_suite,
            },
        })
    }

    pub fn policy_root(&self) -> String {
        payload_root("fee-rebate-optimizer:config", &self.policy_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub policy_count: u64,
    pub quote_count: u64,
    pub reservation_count: u64,
    pub batch_count: u64,
    pub receipt_count: u64,
    pub rebate_count: u64,
    pub attestation_count: u64,
    pub nullifier_count: u64,
    pub lane_metric_count: u64,
    pub total_reserved_fee: u128,
    pub total_settled_fee: u128,
    pub total_rebate_amount: u128,
}

impl Counters {
    pub fn record(&self) -> Value {
        json!({
            "policy_count": self.policy_count,
            "quote_count": self.quote_count,
            "reservation_count": self.reservation_count,
            "batch_count": self.batch_count,
            "receipt_count": self.receipt_count,
            "rebate_count": self.rebate_count,
            "attestation_count": self.attestation_count,
            "nullifier_count": self.nullifier_count,
            "lane_metric_count": self.lane_metric_count,
            "total_reserved_fee": self.total_reserved_fee.to_string(),
            "total_settled_fee": self.total_settled_fee.to_string(),
            "total_rebate_amount": self.total_rebate_amount.to_string(),
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub policy_root: String,
    pub quote_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub attestation_root: String,
    pub nullifier_root: String,
    pub lane_metric_root: String,
    pub counter_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn without_state_root(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "policy_root": self.policy_root,
            "quote_root": self.quote_root,
            "reservation_root": self.reservation_root,
            "batch_root": self.batch_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
            "attestation_root": self.attestation_root,
            "nullifier_root": self.nullifier_root,
            "lane_metric_root": self.lane_metric_root,
            "counter_root": self.counter_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeePolicy {
    pub policy_id: String,
    pub lane_kind: FeeLaneKind,
    pub contract_family_commitment: String,
    pub sponsor_pool_root: String,
    pub optimizer_committee_root: String,
    pub discount_curve_commitment: String,
    pub min_privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub status: PolicyStatus,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl FeePolicy {
    pub fn record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "lane_kind": self.lane_kind,
            "contract_family_commitment": self.contract_family_commitment,
            "sponsor_pool_root": self.sponsor_pool_root,
            "optimizer_committee_root": self.optimizer_committee_root,
            "discount_curve_commitment": self.discount_curve_commitment,
            "min_privacy_set_size": self.min_privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "status": self.status,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedFeeQuote {
    pub quote_id: String,
    pub policy_id: String,
    pub requester_commitment: String,
    pub call_bundle_root: String,
    pub encrypted_fee_payload: String,
    pub signal_root: String,
    pub optimizer_score_commitment: String,
    pub nullifier: String,
    pub status: QuoteStatus,
    pub max_fee_amount: u128,
    pub quoted_fee_amount: u128,
    pub rebate_bps: u64,
    pub privacy_set_size: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl EncryptedFeeQuote {
    pub fn record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "policy_id": self.policy_id,
            "requester_commitment": self.requester_commitment,
            "call_bundle_root": self.call_bundle_root,
            "encrypted_fee_payload": self.encrypted_fee_payload,
            "signal_root": self.signal_root,
            "optimizer_score_commitment": self.optimizer_score_commitment,
            "nullifier": self.nullifier,
            "status": self.status,
            "max_fee_amount": self.max_fee_amount.to_string(),
            "quoted_fee_amount": self.quoted_fee_amount.to_string(),
            "rebate_bps": self.rebate_bps,
            "privacy_set_size": self.privacy_set_size,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorReservation {
    pub reservation_id: String,
    pub quote_id: String,
    pub sponsor_commitment: String,
    pub requester_commitment: String,
    pub reserved_fee_amount: u128,
    pub consumed_fee_amount: u128,
    pub rebate_bps: u64,
    pub status: ReservationStatus,
    pub sponsor_proof_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl SponsorReservation {
    pub fn record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "quote_id": self.quote_id,
            "sponsor_commitment": self.sponsor_commitment,
            "requester_commitment": self.requester_commitment,
            "reserved_fee_amount": self.reserved_fee_amount.to_string(),
            "consumed_fee_amount": self.consumed_fee_amount.to_string(),
            "rebate_bps": self.rebate_bps,
            "status": self.status,
            "sponsor_proof_root": self.sponsor_proof_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateBatch {
    pub batch_id: String,
    pub policy_root: String,
    pub quote_root: String,
    pub reservation_root: String,
    pub attestation_root: String,
    pub lane_metric_root: String,
    pub status: BatchStatus,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
    pub expires_at_height: u64,
    pub quote_count: u64,
    pub gross_fee_amount: u128,
    pub net_fee_amount: u128,
    pub rebate_amount: u128,
}

impl RebateBatch {
    pub fn record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "policy_root": self.policy_root,
            "quote_root": self.quote_root,
            "reservation_root": self.reservation_root,
            "attestation_root": self.attestation_root,
            "lane_metric_root": self.lane_metric_root,
            "status": self.status,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "expires_at_height": self.expires_at_height,
            "quote_count": self.quote_count,
            "gross_fee_amount": self.gross_fee_amount.to_string(),
            "net_fee_amount": self.net_fee_amount.to_string(),
            "rebate_amount": self.rebate_amount.to_string(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub quote_id: String,
    pub reservation_id: String,
    pub kind: ReceiptKind,
    pub fee_amount: u128,
    pub rebate_amount: u128,
    pub settlement_root: String,
    pub settled_at_height: u64,
}

impl FeeReceipt {
    pub fn record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "quote_id": self.quote_id,
            "reservation_id": self.reservation_id,
            "kind": self.kind,
            "fee_amount": self.fee_amount.to_string(),
            "rebate_amount": self.rebate_amount.to_string(),
            "settlement_root": self.settlement_root,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub receipt_id: String,
    pub claimant_commitment: String,
    pub rebate_amount: u128,
    pub rebate_bps: u64,
    pub status: RebateStatus,
    pub claim_after_height: u64,
    pub expires_at_height: u64,
}

impl FeeRebate {
    pub fn record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "receipt_id": self.receipt_id,
            "claimant_commitment": self.claimant_commitment,
            "rebate_amount": self.rebate_amount.to_string(),
            "rebate_bps": self.rebate_bps,
            "status": self.status,
            "claim_after_height": self.claim_after_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OptimizerAttestation {
    pub attestation_id: String,
    pub policy_id: String,
    pub quote_id: String,
    pub kind: AttestationKind,
    pub verdict: AttestationVerdict,
    pub attester_commitment: String,
    pub attestation_root: String,
    pub transcript_root: String,
    pub pq_signature_commitment: String,
    pub observed_at_height: u64,
}

impl OptimizerAttestation {
    pub fn record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "policy_id": self.policy_id,
            "quote_id": self.quote_id,
            "kind": self.kind,
            "verdict": self.verdict,
            "attester_commitment": self.attester_commitment,
            "attestation_root": self.attestation_root,
            "transcript_root": self.transcript_root,
            "pq_signature_commitment": self.pq_signature_commitment,
            "observed_at_height": self.observed_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NullifierFence {
    pub nullifier: String,
    pub quote_id: String,
    pub fence_root: String,
    pub status: NullifierFenceStatus,
    pub locked_at_height: u64,
    pub released_at_height: u64,
}

impl NullifierFence {
    pub fn record(&self) -> Value {
        json!({
            "nullifier": self.nullifier,
            "quote_id": self.quote_id,
            "fence_root": self.fence_root,
            "status": self.status,
            "locked_at_height": self.locked_at_height,
            "released_at_height": self.released_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LaneMetric {
    pub lane_id: String,
    pub lane_kind: FeeLaneKind,
    pub pending_quote_count: u64,
    pub settled_quote_count: u64,
    pub median_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub congestion_hint: u64,
    pub last_updated_height: u64,
}

impl LaneMetric {
    pub fn record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind,
            "pending_quote_count": self.pending_quote_count,
            "settled_quote_count": self.settled_quote_count,
            "median_fee_bps": self.median_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "congestion_hint": self.congestion_hint,
            "last_updated_height": self.last_updated_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub policies: BTreeMap<String, FeePolicy>,
    pub quotes: BTreeMap<String, EncryptedFeeQuote>,
    pub reservations: BTreeMap<String, SponsorReservation>,
    pub batches: BTreeMap<String, RebateBatch>,
    pub receipts: BTreeMap<String, FeeReceipt>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub attestations: BTreeMap<String, OptimizerAttestation>,
    pub nullifier_fences: BTreeMap<String, NullifierFence>,
    pub lane_metrics: BTreeMap<String, LaneMetric>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            policies: BTreeMap::new(),
            quotes: BTreeMap::new(),
            reservations: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            attestations: BTreeMap::new(),
            nullifier_fences: BTreeMap::new(),
            lane_metrics: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        };
        state.recompute_counters();
        state.recompute_roots();
        state
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        let height = state.config.devnet_height;
        let policy_id = fee_policy_id(FeeLaneKind::ContractCall, "devnet-contract-call-rebate", 0);
        let policy = FeePolicy {
            policy_id: policy_id.clone(),
            lane_kind: FeeLaneKind::ContractCall,
            contract_family_commitment: payload_root(
                "fee-rebate-optimizer:contract-family",
                &json!({"family": "private-contracts", "scope": "batch-call"}),
            ),
            sponsor_pool_root: root_from_values(
                "fee-rebate-optimizer:sponsor-pool",
                &["fee-vault-alpha", "fee-vault-beta", "proof-cache-sponsor"],
            ),
            optimizer_committee_root: root_from_values(
                "fee-rebate-optimizer:committee",
                &["aurora-optimizer", "cedar-optimizer", "sable-optimizer"],
            ),
            discount_curve_commitment: payload_root(
                "fee-rebate-optimizer:discount-curve",
                &json!({"target_batch_density": 4096, "max_discount_bps": 22}),
            ),
            min_privacy_set_size: state.config.min_privacy_set_size,
            pq_security_bits: state.config.min_pq_security_bits,
            max_fee_bps: state.config.max_optimizer_fee_bps,
            target_rebate_bps: state.config.target_rebate_bps,
            status: PolicyStatus::Active,
            created_at_height: height - 2_048,
            expires_at_height: height + state.config.policy_ttl_blocks,
        };
        state
            .register_policy(policy.clone())
            .expect("devnet policy");

        let requester_commitment = payload_root(
            "fee-rebate-optimizer:requester",
            &json!({"wallet": "devnet-private-smart-account", "purpose": "defi-call"}),
        );
        let quote_id = fee_quote_id(&policy_id, &requester_commitment, 7);
        let quote = EncryptedFeeQuote {
            quote_id: quote_id.clone(),
            policy_id: policy_id.clone(),
            requester_commitment: requester_commitment.clone(),
            call_bundle_root: payload_root(
                "fee-rebate-optimizer:call-bundle",
                &json!({"calls": ["swap", "deposit-lending"], "lane": "contract_call"}),
            ),
            encrypted_fee_payload: payload_root(
                "fee-rebate-optimizer:encrypted-fee-payload",
                &json!({"ciphertext": "devnet-fee-quote-alpha", "suite": "ml-kem-1024"}),
            ),
            signal_root: signal_root(
                &[
                    OptimizationSignalKind::Congestion,
                    OptimizationSignalKind::ProofCacheHit,
                    OptimizationSignalKind::BatchDensity,
                ],
                height - 4,
            ),
            optimizer_score_commitment: payload_root(
                "fee-rebate-optimizer:score",
                &json!({"score": "private-score-742", "discount_bps": 18}),
            ),
            nullifier: quote_nullifier(&policy_id, &requester_commitment, 7),
            status: QuoteStatus::Sponsored,
            max_fee_amount: 1_250_000,
            quoted_fee_amount: 920_000,
            rebate_bps: state.config.target_rebate_bps,
            privacy_set_size: state.config.min_privacy_set_size,
            created_at_height: height - 16,
            expires_at_height: height + state.config.quote_ttl_blocks,
        };
        state.submit_quote(quote.clone()).expect("devnet quote");

        let attestation = OptimizerAttestation {
            attestation_id: optimizer_attestation_id(&policy_id, &quote_id, "score-valid"),
            policy_id: policy_id.clone(),
            quote_id: quote_id.clone(),
            kind: AttestationKind::QuoteScore,
            verdict: AttestationVerdict::Valid,
            attester_commitment: payload_root(
                "fee-rebate-optimizer:attester",
                &json!({"committee": "devnet-optimizer-committee", "member": "aurora"}),
            ),
            attestation_root: payload_root(
                "fee-rebate-optimizer:attestation",
                &json!({"quote": quote_id.clone(), "fee": "920000", "rebate_bps": state.config.target_rebate_bps}),
            ),
            transcript_root: payload_root(
                "fee-rebate-optimizer:transcript",
                &json!({"height": height - 12, "signals": ["congestion", "proof_cache_hit"]}),
            ),
            pq_signature_commitment: payload_root(
                "fee-rebate-optimizer:pq-signature",
                &json!({"suite": "ml-dsa-87", "signature": "devnet-optimizer-signature"}),
            ),
            observed_at_height: height - 12,
        };
        state
            .record_attestation(attestation.clone())
            .expect("devnet attestation");

        let reservation = SponsorReservation {
            reservation_id: sponsor_reservation_id(&quote_id, "fee-vault-alpha", 0),
            quote_id: quote_id.clone(),
            sponsor_commitment: payload_root(
                "fee-rebate-optimizer:sponsor",
                &json!({"vault": "fee-vault-alpha", "strategy": "contract-call-low-fee"}),
            ),
            requester_commitment: requester_commitment.clone(),
            reserved_fee_amount: 1_250_000,
            consumed_fee_amount: 920_000,
            rebate_bps: state.config.target_rebate_bps,
            status: ReservationStatus::RebateQueued,
            sponsor_proof_root: payload_root(
                "fee-rebate-optimizer:sponsor-proof",
                &json!({"credit_root": "fee-vault-alpha-credit-root", "nonce": 55}),
            ),
            created_at_height: height - 14,
            expires_at_height: height + state.config.reservation_ttl_blocks,
        };
        state
            .reserve_sponsor_fee(reservation.clone())
            .expect("devnet reservation");

        let lane = LaneMetric {
            lane_id: rebate_lane_id(FeeLaneKind::ContractCall, "contract-call-fast-rebate"),
            lane_kind: FeeLaneKind::ContractCall,
            pending_quote_count: 12,
            settled_quote_count: 9_842,
            median_fee_bps: 4,
            target_rebate_bps: state.config.target_rebate_bps,
            congestion_hint: 19,
            last_updated_height: height,
        };
        state.record_lane_metric(lane.clone()).expect("devnet lane");

        let batch_id = rebate_batch_id(&policy_id, height - 2, 0);
        let batch = RebateBatch {
            batch_id: batch_id.clone(),
            policy_root: root_from_record("fee-rebate-optimizer:policy", &policy.record()),
            quote_root: root_from_record("fee-rebate-optimizer:quote", &quote.record()),
            reservation_root: root_from_record(
                "fee-rebate-optimizer:reservation",
                &reservation.record(),
            ),
            attestation_root: root_from_record(
                "fee-rebate-optimizer:attestation",
                &attestation.record(),
            ),
            lane_metric_root: root_from_record("fee-rebate-optimizer:lane", &lane.record()),
            status: BatchStatus::Settled,
            opened_at_height: height - 8,
            sealed_at_height: height - 2,
            expires_at_height: height + state.config.batch_ttl_blocks,
            quote_count: 1,
            gross_fee_amount: quote.max_fee_amount,
            net_fee_amount: quote.quoted_fee_amount,
            rebate_amount: 460,
        };
        state.record_batch(batch.clone()).expect("devnet batch");

        let receipt = FeeReceipt {
            receipt_id: fee_receipt_id(&batch_id, &quote_id, 0),
            batch_id: batch_id.clone(),
            quote_id: quote_id.clone(),
            reservation_id: reservation.reservation_id.clone(),
            kind: ReceiptKind::QuoteSettlement,
            fee_amount: quote.quoted_fee_amount,
            rebate_amount: batch.rebate_amount,
            settlement_root: payload_root(
                "fee-rebate-optimizer:settlement",
                &json!({"batch": batch_id, "quote": quote_id, "net_fee": quote.quoted_fee_amount.to_string()}),
            ),
            settled_at_height: height - 1,
        };
        state
            .record_receipt(receipt.clone())
            .expect("devnet receipt");

        let rebate = FeeRebate {
            rebate_id: rebate_id(&receipt.receipt_id, &requester_commitment, 0),
            receipt_id: receipt.receipt_id.clone(),
            claimant_commitment: requester_commitment,
            rebate_amount: receipt.rebate_amount,
            rebate_bps: state.config.target_rebate_bps,
            status: RebateStatus::Claimable,
            claim_after_height: height + 1,
            expires_at_height: height + 7_200,
        };
        state.record_rebate(rebate).expect("devnet rebate");

        state.recompute_counters();
        state.recompute_roots();
        state
    }

    pub fn register_policy(
        &mut self,
        policy: FeePolicy,
    ) -> PrivateL2ConfidentialContractFeeRebateOptimizerRuntimeResult<()> {
        if self.policies.len() >= self.config.max_policies {
            return Err("policy capacity exceeded".to_string());
        }
        if !policy.status.accepts_quotes() && policy.status != PolicyStatus::Proposed {
            return Err("policy status is not registerable".to_string());
        }
        if policy.pq_security_bits < self.config.min_pq_security_bits {
            return Err("policy pq security below runtime floor".to_string());
        }
        if policy.max_fee_bps > self.config.max_optimizer_fee_bps {
            return Err("policy fee above runtime ceiling".to_string());
        }
        self.policies.insert(policy.policy_id.clone(), policy);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn submit_quote(
        &mut self,
        quote: EncryptedFeeQuote,
    ) -> PrivateL2ConfidentialContractFeeRebateOptimizerRuntimeResult<()> {
        if self.quotes.len() >= self.config.max_quotes {
            return Err("quote capacity exceeded".to_string());
        }
        if !self.policies.contains_key(&quote.policy_id) {
            return Err("quote references unknown policy".to_string());
        }
        if self.consumed_nullifiers.contains(&quote.nullifier) {
            return Err("quote nullifier already consumed".to_string());
        }
        if !quote.status.is_open() {
            return Err("quote status is not open".to_string());
        }
        if quote.privacy_set_size < self.config.min_privacy_set_size {
            return Err("quote privacy set below runtime floor".to_string());
        }
        if quote.rebate_bps > self.config.target_rebate_bps {
            return Err("quote rebate above runtime target".to_string());
        }
        let fence = NullifierFence {
            nullifier: quote.nullifier.clone(),
            quote_id: quote.quote_id.clone(),
            fence_root: replay_fence_leaf(&quote.policy_id, &quote.nullifier),
            status: NullifierFenceStatus::Locked,
            locked_at_height: quote.created_at_height,
            released_at_height: 0,
        };
        self.consumed_nullifiers.insert(quote.nullifier.clone());
        self.nullifier_fences.insert(fence.nullifier.clone(), fence);
        self.quotes.insert(quote.quote_id.clone(), quote);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn reserve_sponsor_fee(
        &mut self,
        reservation: SponsorReservation,
    ) -> PrivateL2ConfidentialContractFeeRebateOptimizerRuntimeResult<()> {
        if self.reservations.len() >= self.config.max_reservations {
            return Err("reservation capacity exceeded".to_string());
        }
        if !self.quotes.contains_key(&reservation.quote_id) {
            return Err("reservation references unknown quote".to_string());
        }
        if reservation.rebate_bps > self.config.target_rebate_bps {
            return Err("reservation rebate above runtime target".to_string());
        }
        if reservation.consumed_fee_amount > reservation.reserved_fee_amount {
            return Err("reservation consumed fee exceeds reserved amount".to_string());
        }
        self.reservations
            .insert(reservation.reservation_id.clone(), reservation);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_batch(
        &mut self,
        batch: RebateBatch,
    ) -> PrivateL2ConfidentialContractFeeRebateOptimizerRuntimeResult<()> {
        if self.batches.len() >= self.config.max_batches {
            return Err("batch capacity exceeded".to_string());
        }
        if batch.quote_count as usize > self.config.max_batch_quotes {
            return Err("batch quote count exceeds runtime limit".to_string());
        }
        if !batch.status.anchors_state() && batch.status != BatchStatus::Open {
            return Err("batch status is not recordable".to_string());
        }
        self.batches.insert(batch.batch_id.clone(), batch);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_receipt(
        &mut self,
        receipt: FeeReceipt,
    ) -> PrivateL2ConfidentialContractFeeRebateOptimizerRuntimeResult<()> {
        if self.receipts.len() >= self.config.max_receipts {
            return Err("receipt capacity exceeded".to_string());
        }
        if !self.batches.contains_key(&receipt.batch_id) {
            return Err("receipt references unknown batch".to_string());
        }
        if !self.quotes.contains_key(&receipt.quote_id) {
            return Err("receipt references unknown quote".to_string());
        }
        if !self.reservations.contains_key(&receipt.reservation_id) {
            return Err("receipt references unknown reservation".to_string());
        }
        self.receipts.insert(receipt.receipt_id.clone(), receipt);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_rebate(
        &mut self,
        rebate: FeeRebate,
    ) -> PrivateL2ConfidentialContractFeeRebateOptimizerRuntimeResult<()> {
        if self.rebates.len() >= self.config.max_rebates {
            return Err("rebate capacity exceeded".to_string());
        }
        if !self.receipts.contains_key(&rebate.receipt_id) {
            return Err("rebate references unknown receipt".to_string());
        }
        self.rebates.insert(rebate.rebate_id.clone(), rebate);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_attestation(
        &mut self,
        attestation: OptimizerAttestation,
    ) -> PrivateL2ConfidentialContractFeeRebateOptimizerRuntimeResult<()> {
        if self.attestations.len() >= self.config.max_attestations {
            return Err("attestation capacity exceeded".to_string());
        }
        if !attestation.verdict.contributes_to_quorum() {
            return Err("attestation verdict does not contribute to quorum".to_string());
        }
        if !self.policies.contains_key(&attestation.policy_id) {
            return Err("attestation references unknown policy".to_string());
        }
        if !self.quotes.contains_key(&attestation.quote_id) {
            return Err("attestation references unknown quote".to_string());
        }
        self.attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_lane_metric(
        &mut self,
        metric: LaneMetric,
    ) -> PrivateL2ConfidentialContractFeeRebateOptimizerRuntimeResult<()> {
        if metric.median_fee_bps > self.config.max_optimizer_fee_bps {
            return Err("lane median fee above runtime ceiling".to_string());
        }
        self.lane_metrics.insert(metric.lane_id.clone(), metric);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn recompute_counters(&mut self) {
        self.counters.policy_count = self.policies.len() as u64;
        self.counters.quote_count = self.quotes.len() as u64;
        self.counters.reservation_count = self.reservations.len() as u64;
        self.counters.batch_count = self.batches.len() as u64;
        self.counters.receipt_count = self.receipts.len() as u64;
        self.counters.rebate_count = self.rebates.len() as u64;
        self.counters.attestation_count = self.attestations.len() as u64;
        self.counters.nullifier_count = self.nullifier_fences.len() as u64;
        self.counters.lane_metric_count = self.lane_metrics.len() as u64;
        self.counters.total_reserved_fee = self
            .reservations
            .values()
            .map(|reservation| reservation.reserved_fee_amount)
            .sum();
        self.counters.total_settled_fee = self
            .receipts
            .values()
            .map(|receipt| receipt.fee_amount)
            .sum();
        self.counters.total_rebate_amount = self
            .rebates
            .values()
            .map(|rebate| rebate.rebate_amount)
            .sum();
    }

    pub fn recompute_roots(&mut self) {
        let mut roots = Roots {
            config_root: self.config.policy_root(),
            policy_root: public_record_root(
                "fee-rebate-optimizer:policies",
                &map_records(&self.policies),
            ),
            quote_root: public_record_root(
                "fee-rebate-optimizer:quotes",
                &map_records(&self.quotes),
            ),
            reservation_root: public_record_root(
                "fee-rebate-optimizer:reservations",
                &map_records(&self.reservations),
            ),
            batch_root: public_record_root(
                "fee-rebate-optimizer:batches",
                &map_records(&self.batches),
            ),
            receipt_root: public_record_root(
                "fee-rebate-optimizer:receipts",
                &map_records(&self.receipts),
            ),
            rebate_root: public_record_root(
                "fee-rebate-optimizer:rebates",
                &map_records(&self.rebates),
            ),
            attestation_root: public_record_root(
                "fee-rebate-optimizer:attestations",
                &map_records(&self.attestations),
            ),
            nullifier_root: public_record_root(
                "fee-rebate-optimizer:nullifiers",
                &map_records(&self.nullifier_fences),
            ),
            lane_metric_root: public_record_root(
                "fee-rebate-optimizer:lane-metrics",
                &map_records(&self.lane_metrics),
            ),
            counter_root: payload_root("fee-rebate-optimizer:counters", &self.counters.record()),
            state_root: String::new(),
        };
        roots.state_root = state_root_from_record(&self.public_record_without_roots_state(&roots));
        self.roots = roots;
    }

    pub fn roots(&self) -> Roots {
        self.roots.clone()
    }

    pub fn public_record_without_state_root(&self) -> Value {
        self.public_record_without_roots_state(&self.roots)
    }

    fn public_record_without_roots_state(&self, roots: &Roots) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_CONFIDENTIAL_CONTRACT_FEE_REBATE_OPTIMIZER_RUNTIME_SCHEMA_VERSION,
            "config": self.config.policy_record(),
            "counters": self.counters.record(),
            "roots": roots.without_state_root(),
            "policies": map_records(&self.policies),
            "quotes": map_records(&self.quotes),
            "reservations": map_records(&self.reservations),
            "batches": map_records(&self.batches),
            "receipts": map_records(&self.receipts),
            "rebates": map_records(&self.rebates),
            "attestations": map_records(&self.attestations),
            "nullifier_fences": map_records(&self.nullifier_fences),
            "lane_metrics": map_records(&self.lane_metrics),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(map) = &mut record {
            map.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }
}

pub type Runtime = State;

pub fn devnet() -> State {
    State::devnet()
}

pub fn private_l2_confidential_contract_fee_rebate_optimizer_runtime_public_record() -> Value {
    State::devnet().public_record()
}

pub fn private_l2_confidential_contract_fee_rebate_optimizer_runtime_state_root() -> String {
    State::devnet().state_root()
}

pub fn fee_policy_id(lane_kind: FeeLaneKind, label: &str, sequence: u64) -> String {
    domain_hash(
        "fee-rebate-optimizer:policy-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_kind.as_str()),
            HashPart::Str(label),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn fee_quote_id(policy_id: &str, requester_commitment: &str, sequence: u64) -> String {
    domain_hash(
        "fee-rebate-optimizer:quote-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(policy_id),
            HashPart::Str(requester_commitment),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn sponsor_reservation_id(quote_id: &str, sponsor_label: &str, sequence: u64) -> String {
    domain_hash(
        "fee-rebate-optimizer:sponsor-reservation-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(quote_id),
            HashPart::Str(sponsor_label),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn rebate_batch_id(policy_id: &str, sealed_at_height: u64, sequence: u64) -> String {
    domain_hash(
        "fee-rebate-optimizer:rebate-batch-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(policy_id),
            HashPart::U64(sealed_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn fee_receipt_id(batch_id: &str, quote_id: &str, sequence: u64) -> String {
    domain_hash(
        "fee-rebate-optimizer:receipt-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(quote_id),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn rebate_id(receipt_id: &str, claimant_commitment: &str, sequence: u64) -> String {
    domain_hash(
        "fee-rebate-optimizer:rebate-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(receipt_id),
            HashPart::Str(claimant_commitment),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn optimizer_attestation_id(policy_id: &str, quote_id: &str, nonce: &str) -> String {
    domain_hash(
        "fee-rebate-optimizer:attestation-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(policy_id),
            HashPart::Str(quote_id),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn quote_nullifier(policy_id: &str, requester_commitment: &str, sequence: u64) -> String {
    domain_hash(
        "fee-rebate-optimizer:quote-nullifier",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(policy_id),
            HashPart::Str(requester_commitment),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn replay_fence_leaf(policy_id: &str, nullifier: &str) -> String {
    domain_hash(
        "fee-rebate-optimizer:replay-fence-leaf",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(policy_id),
            HashPart::Str(nullifier),
        ],
        32,
    )
}

pub fn rebate_lane_id(lane_kind: FeeLaneKind, label: &str) -> String {
    domain_hash(
        "fee-rebate-optimizer:lane-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_kind.as_str()),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn signal_root(signals: &[OptimizationSignalKind], observed_at_height: u64) -> String {
    let leaves = signals
        .iter()
        .map(|signal| {
            json!({
                "signal": signal.as_str(),
                "observed_at_height": observed_at_height,
            })
        })
        .collect::<Vec<_>>();
    merkle_root("fee-rebate-optimizer:signals", &leaves)
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("fee-rebate-optimizer:state-root", record)
}

pub fn root_from_values(domain: &str, values: &[&str]) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({"value": value}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn map_records<T: Serialize>(map: &BTreeMap<String, T>) -> Vec<Value> {
    map.values()
        .map(|value| serde_json::to_value(value).expect("serializable fee rebate optimizer state"))
        .collect()
}
