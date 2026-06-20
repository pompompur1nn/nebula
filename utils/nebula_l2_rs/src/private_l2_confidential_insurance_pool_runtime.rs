use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialInsurancePoolRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-insurance-pool-runtime-v1";
pub const PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s-insurance-pool-v1";
pub const PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_POOL_SCHEME: &str =
    "private-l2-confidential-insurance-pool-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_PREMIUM_SCHEME: &str =
    "confidential-insurance-premium-note-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_COVERAGE_SCHEME: &str =
    "shielded-insurance-coverage-vault-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_RISK_SCHEME: &str =
    "pq-confidential-insurance-risk-attestation-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_RESERVATION_SCHEME: &str =
    "low-fee-confidential-claim-reservation-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_CLAIM_BATCH_SCHEME: &str =
    "private-confidential-insurance-claim-batch-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_RECEIPT_SCHEME: &str =
    "private-confidential-insurance-settlement-receipt-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_REBATE_SCHEME: &str =
    "private-confidential-insurance-premium-rebate-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEVNET_HEIGHT: u64 = 734_000;
pub const PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_MAX_POOLS: usize = 131_072;
pub const PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_MAX_PREMIUM_NOTES: usize =
    4_194_304;
pub const PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_MAX_COVERAGES: usize = 2_097_152;
pub const PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_MAX_RISK_ATTESTATIONS: usize =
    1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize =
    2_097_152;
pub const PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_MAX_CLAIM_BATCHES: usize = 524_288;
pub const PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_MAX_RECEIPTS: usize = 1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_MAX_BATCH_CLAIMS: usize = 16_384;
pub const PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 8_192;
pub const PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 =
    131_072;
pub const PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 16;
pub const PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_MAX_PREMIUM_RATE_BPS: u64 = 1_500;
pub const PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_MIN_RESERVE_RATIO_BPS: u64 =
    12_500;
pub const PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_TARGET_REBATE_BPS: u64 = 6;
pub const PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_PREMIUM_NOTE_TTL_BLOCKS: u64 = 48;
pub const PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_CLAIM_TTL_BLOCKS: u64 = 24;
pub const PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 18;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InsurancePoolKind {
    SmartContractCover,
    BridgeCover,
    StablecoinDepeg,
    LiquidationBackstop,
    ValidatorSlashing,
    ParametricRisk,
    InstitutionalCover,
}

impl InsurancePoolKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SmartContractCover => "smart_contract_cover",
            Self::BridgeCover => "bridge_cover",
            Self::StablecoinDepeg => "stablecoin_depeg",
            Self::LiquidationBackstop => "liquidation_backstop",
            Self::ValidatorSlashing => "validator_slashing",
            Self::ParametricRisk => "parametric_risk",
            Self::InstitutionalCover => "institutional_cover",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Draft,
    Active,
    CoverageOnly,
    ClaimOnly,
    Paused,
    Retired,
}

impl PoolStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::CoverageOnly => "coverage_only",
            Self::ClaimOnly => "claim_only",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_premiums(self) -> bool {
        matches!(self, Self::Active | Self::CoverageOnly)
    }

    pub fn accepts_claims(self) -> bool {
        matches!(self, Self::Active | Self::ClaimOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PremiumNoteStatus {
    Submitted,
    Accepted,
    Encumbered,
    Refunded,
    Settled,
    Expired,
    Rejected,
}

impl PremiumNoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Encumbered => "encumbered",
            Self::Refunded => "refunded",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn can_open_coverage(self) -> bool {
        matches!(self, Self::Accepted | Self::Encumbered)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    Pending,
    Open,
    Reserved,
    ClaimPending,
    Settled,
    Expired,
    Cancelled,
    Rejected,
}

impl CoverageStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::ClaimPending => "claim_pending",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Rejected => "rejected",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Pending | Self::Open | Self::Reserved | Self::ClaimPending
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskVerdict {
    Pending,
    LowRisk,
    MediumRisk,
    HighRisk,
    Claimable,
    Halted,
    Rejected,
}

impl RiskVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::LowRisk => "low_risk",
            Self::MediumRisk => "medium_risk",
            Self::HighRisk => "high_risk",
            Self::Claimable => "claimable",
            Self::Halted => "halted",
            Self::Rejected => "rejected",
        }
    }

    pub fn allows_coverage(self) -> bool {
        matches!(self, Self::LowRisk | Self::MediumRisk)
    }

    pub fn allows_claim(self) -> bool {
        matches!(self, Self::Claimable | Self::HighRisk)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimReservationStatus {
    Reserved,
    Matched,
    Consumed,
    Rebated,
    Expired,
    Cancelled,
}

impl ClaimReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Matched => "matched",
            Self::Consumed => "consumed",
            Self::Rebated => "rebated",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimBatchStatus {
    Built,
    SettlementReady,
    Settled,
    Disputed,
    Expired,
}

impl ClaimBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }

    pub fn can_settle(self) -> bool {
        matches!(self, Self::SettlementReady)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    PoolOpened,
    PremiumAccepted,
    CoverageOpened,
    ClaimReserved,
    RiskAttested,
    ClaimSettled,
    RebatePublished,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PoolOpened => "pool_opened",
            Self::PremiumAccepted => "premium_accepted",
            Self::CoverageOpened => "coverage_opened",
            Self::ClaimReserved => "claim_reserved",
            Self::RiskAttested => "risk_attested",
            Self::ClaimSettled => "claim_settled",
            Self::RebatePublished => "rebate_published",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub coverage_asset_id: String,
    pub premium_asset_id: String,
    pub claim_asset_id: String,
    pub fee_asset_id: String,
    pub low_fee_lane: String,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub max_pools: usize,
    pub max_premium_notes: usize,
    pub max_coverages: usize,
    pub max_risk_attestations: usize,
    pub max_reservations: usize,
    pub max_claim_batches: usize,
    pub max_receipts: usize,
    pub max_batch_claims: usize,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_premium_rate_bps: u64,
    pub min_reserve_ratio_bps: u64,
    pub target_rebate_bps: u64,
    pub premium_note_ttl_blocks: u64,
    pub claim_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub require_low_fee_sponsor: bool,
    pub require_oracle_bound: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: "nebula-private-l2-devnet".to_string(),
            coverage_asset_id: "wxmr-insurance-capacity-devnet".to_string(),
            premium_asset_id: "zusd-premium-devnet".to_string(),
            claim_asset_id: "zusd-claim-devnet".to_string(),
            fee_asset_id: "piconero-devnet".to_string(),
            low_fee_lane: "devnet-private-l2-insurance-pool-low-fee".to_string(),
            hash_suite: PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_HASH_SUITE.to_string(),
            pq_auth_suite: PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_PQ_AUTH_SUITE.to_string(),
            max_pools: PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_MAX_POOLS,
            max_premium_notes:
                PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_MAX_PREMIUM_NOTES,
            max_coverages: PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_MAX_COVERAGES,
            max_risk_attestations:
                PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_MAX_RISK_ATTESTATIONS,
            max_reservations:
                PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_claim_batches:
                PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_MAX_CLAIM_BATCHES,
            max_receipts: PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_MAX_RECEIPTS,
            max_batch_claims:
                PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_MAX_BATCH_CLAIMS,
            min_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            max_premium_rate_bps:
                PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_MAX_PREMIUM_RATE_BPS,
            min_reserve_ratio_bps:
                PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_MIN_RESERVE_RATIO_BPS,
            target_rebate_bps:
                PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            premium_note_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_PREMIUM_NOTE_TTL_BLOCKS,
            claim_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_CLAIM_TTL_BLOCKS,
            settlement_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            require_low_fee_sponsor: true,
            require_oracle_bound: true,
        }
    }

    pub fn validate(&self) -> PrivateL2ConfidentialInsurancePoolRuntimeResult<()> {
        require(
            self.protocol_version
                == PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_PROTOCOL_VERSION,
            "unsupported confidential insurance pool protocol version",
        )?;
        require(self.schema_version > 0, "schema version must be positive")?;
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("l2_network", &self.l2_network)?;
        require_non_empty("coverage_asset_id", &self.coverage_asset_id)?;
        require_non_empty("premium_asset_id", &self.premium_asset_id)?;
        require_non_empty("claim_asset_id", &self.claim_asset_id)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_non_empty("low_fee_lane", &self.low_fee_lane)?;
        require_non_empty("hash_suite", &self.hash_suite)?;
        require_non_empty("pq_auth_suite", &self.pq_auth_suite)?;
        require(self.max_pools > 0, "max_pools must be positive")?;
        require(
            self.max_premium_notes > 0,
            "max_premium_notes must be positive",
        )?;
        require(self.max_coverages > 0, "max_coverages must be positive")?;
        require(
            self.max_risk_attestations > 0,
            "max_risk_attestations must be positive",
        )?;
        require(
            self.max_reservations > 0,
            "max_reservations must be positive",
        )?;
        require(
            self.max_claim_batches > 0,
            "max_claim_batches must be positive",
        )?;
        require(self.max_receipts > 0, "max_receipts must be positive")?;
        require(
            self.max_batch_claims > 0,
            "max_batch_claims must be positive",
        )?;
        require(
            self.batch_privacy_set_size >= self.min_privacy_set_size,
            "batch privacy set must cover individual privacy floor",
        )?;
        require(
            self.min_pq_security_bits
                >= PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            "PQ security floor is too low",
        )?;
        require_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        require_bps("max_premium_rate_bps", self.max_premium_rate_bps)?;
        require_bps("target_rebate_bps", self.target_rebate_bps)?;
        require(
            self.target_rebate_bps <= self.max_user_fee_bps,
            "rebate cannot exceed user fee cap",
        )?;
        require(
            self.min_reserve_ratio_bps > PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_MAX_BPS,
            "reserve ratio must exceed full claim coverage",
        )?;
        require(
            self.premium_note_ttl_blocks > 0
                && self.claim_ttl_blocks > 0
                && self.settlement_ttl_blocks > 0,
            "runtime TTLs must be positive",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "coverage_asset_id": self.coverage_asset_id,
            "premium_asset_id": self.premium_asset_id,
            "claim_asset_id": self.claim_asset_id,
            "fee_asset_id": self.fee_asset_id,
            "low_fee_lane": self.low_fee_lane,
            "hash_suite": self.hash_suite,
            "pq_auth_suite": self.pq_auth_suite,
            "max_pools": self.max_pools,
            "max_premium_notes": self.max_premium_notes,
            "max_coverages": self.max_coverages,
            "max_risk_attestations": self.max_risk_attestations,
            "max_reservations": self.max_reservations,
            "max_claim_batches": self.max_claim_batches,
            "max_receipts": self.max_receipts,
            "max_batch_claims": self.max_batch_claims,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_premium_rate_bps": self.max_premium_rate_bps,
            "min_reserve_ratio_bps": self.min_reserve_ratio_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "premium_note_ttl_blocks": self.premium_note_ttl_blocks,
            "claim_ttl_blocks": self.claim_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "require_low_fee_sponsor": self.require_low_fee_sponsor,
            "require_oracle_bound": self.require_oracle_bound,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub next_pool: u64,
    pub next_premium_note: u64,
    pub next_coverage: u64,
    pub next_risk_attestation: u64,
    pub next_reservation: u64,
    pub next_claim_batch: u64,
    pub next_receipt: u64,
    pub next_rebate: u64,
    pub consumed_nullifier_counter: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "next_pool": self.next_pool,
            "next_premium_note": self.next_premium_note,
            "next_coverage": self.next_coverage,
            "next_risk_attestation": self.next_risk_attestation,
            "next_reservation": self.next_reservation,
            "next_claim_batch": self.next_claim_batch,
            "next_receipt": self.next_receipt,
            "next_rebate": self.next_rebate,
            "consumed_nullifier_counter": self.consumed_nullifier_counter,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenShieldedCoveragePoolRequest {
    pub pool_kind: InsurancePoolKind,
    pub pool_commitment: String,
    pub operator_commitment: String,
    pub reserve_asset_root: String,
    pub coverage_policy_root: String,
    pub pool_nullifier: String,
    pub max_premium_rate_bps: u64,
    pub min_reserve_ratio_bps: u64,
    pub min_privacy_set_size: u64,
    pub pq_operator_key_root: String,
    pub metadata_root: String,
    pub opened_at_height: u64,
}

impl OpenShieldedCoveragePoolRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialInsurancePoolRuntimeResult<()> {
        require_root("pool_commitment", &self.pool_commitment)?;
        require_root("operator_commitment", &self.operator_commitment)?;
        require_root("reserve_asset_root", &self.reserve_asset_root)?;
        require_root("coverage_policy_root", &self.coverage_policy_root)?;
        require_root("pool_nullifier", &self.pool_nullifier)?;
        require_bps("max_premium_rate_bps", self.max_premium_rate_bps)?;
        require(
            self.max_premium_rate_bps <= config.max_premium_rate_bps,
            "pool premium rate exceeds configured cap",
        )?;
        require(
            self.min_reserve_ratio_bps >= config.min_reserve_ratio_bps,
            "pool reserve ratio below configured floor",
        )?;
        require(
            self.min_privacy_set_size >= config.min_privacy_set_size,
            "pool privacy set is too small",
        )?;
        require_root("pq_operator_key_root", &self.pq_operator_key_root)?;
        require_root("metadata_root", &self.metadata_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "pool_kind": self.pool_kind.as_str(),
            "pool_commitment": self.pool_commitment,
            "operator_commitment": self.operator_commitment,
            "reserve_asset_root": self.reserve_asset_root,
            "coverage_policy_root": self.coverage_policy_root,
            "pool_nullifier": self.pool_nullifier,
            "max_premium_rate_bps": self.max_premium_rate_bps,
            "min_reserve_ratio_bps": self.min_reserve_ratio_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "pq_operator_key_root": self.pq_operator_key_root,
            "metadata_root": self.metadata_root,
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitConfidentialPremiumNoteRequest {
    pub pool_id: String,
    pub payer_commitment: String,
    pub premium_note_root: String,
    pub premium_nullifier: String,
    pub encrypted_premium_root: String,
    pub coverage_commitment_root: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_authorization_root: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl SubmitConfidentialPremiumNoteRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialInsurancePoolRuntimeResult<()> {
        require_non_empty("pool_id", &self.pool_id)?;
        require_root("payer_commitment", &self.payer_commitment)?;
        require_root("premium_note_root", &self.premium_note_root)?;
        require_root("premium_nullifier", &self.premium_nullifier)?;
        require_root("encrypted_premium_root", &self.encrypted_premium_root)?;
        require_root("coverage_commitment_root", &self.coverage_commitment_root)?;
        require_bps("max_fee_bps", self.max_fee_bps)?;
        require(
            self.max_fee_bps <= config.max_user_fee_bps,
            "premium note fee exceeds low-fee cap",
        )?;
        require_privacy_and_pq(
            self.privacy_set_size,
            config.min_pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        require_root("pq_authorization_root", &self.pq_authorization_root)?;
        require(
            self.expires_at_height > self.submitted_at_height,
            "premium note must expire after submission",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "payer_commitment": self.payer_commitment,
            "premium_note_root": self.premium_note_root,
            "premium_nullifier": self.premium_nullifier,
            "encrypted_premium_root": self.encrypted_premium_root,
            "coverage_commitment_root": self.coverage_commitment_root,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_authorization_root": self.pq_authorization_root,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenShieldedCoverageRequest {
    pub pool_id: String,
    pub premium_note_id: String,
    pub insured_commitment: String,
    pub coverage_vault_root: String,
    pub coverage_nullifier: String,
    pub insured_asset_root: String,
    pub encrypted_limit_root: String,
    pub deductible_commitment_root: String,
    pub premium_rate_bps: u64,
    pub coverage_start_height: u64,
    pub coverage_end_height: u64,
    pub privacy_set_size: u64,
    pub pq_authorization_root: String,
}

impl OpenShieldedCoverageRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialInsurancePoolRuntimeResult<()> {
        require_non_empty("pool_id", &self.pool_id)?;
        require_non_empty("premium_note_id", &self.premium_note_id)?;
        require_root("insured_commitment", &self.insured_commitment)?;
        require_root("coverage_vault_root", &self.coverage_vault_root)?;
        require_root("coverage_nullifier", &self.coverage_nullifier)?;
        require_root("insured_asset_root", &self.insured_asset_root)?;
        require_root("encrypted_limit_root", &self.encrypted_limit_root)?;
        require_root(
            "deductible_commitment_root",
            &self.deductible_commitment_root,
        )?;
        require_bps("premium_rate_bps", self.premium_rate_bps)?;
        require(
            self.premium_rate_bps <= config.max_premium_rate_bps,
            "coverage premium rate exceeds configured cap",
        )?;
        require(
            self.coverage_end_height > self.coverage_start_height,
            "coverage must end after start",
        )?;
        require(
            self.privacy_set_size >= config.min_privacy_set_size,
            "coverage privacy set is too small",
        )?;
        require_root("pq_authorization_root", &self.pq_authorization_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "premium_note_id": self.premium_note_id,
            "insured_commitment": self.insured_commitment,
            "coverage_vault_root": self.coverage_vault_root,
            "coverage_nullifier": self.coverage_nullifier,
            "insured_asset_root": self.insured_asset_root,
            "encrypted_limit_root": self.encrypted_limit_root,
            "deductible_commitment_root": self.deductible_commitment_root,
            "premium_rate_bps": self.premium_rate_bps,
            "coverage_start_height": self.coverage_start_height,
            "coverage_end_height": self.coverage_end_height,
            "privacy_set_size": self.privacy_set_size,
            "pq_authorization_root": self.pq_authorization_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveLowFeeClaimExecutionRequest {
    pub pool_id: String,
    pub coverage_id: String,
    pub claimant_commitment: String,
    pub claim_note_root: String,
    pub reservation_nullifier: String,
    pub low_fee_sponsor_commitment: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_authorization_root: String,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl ReserveLowFeeClaimExecutionRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialInsurancePoolRuntimeResult<()> {
        require_non_empty("pool_id", &self.pool_id)?;
        require_non_empty("coverage_id", &self.coverage_id)?;
        require_root("claimant_commitment", &self.claimant_commitment)?;
        require_root("claim_note_root", &self.claim_note_root)?;
        require_root("reservation_nullifier", &self.reservation_nullifier)?;
        if config.require_low_fee_sponsor {
            require_root(
                "low_fee_sponsor_commitment",
                &self.low_fee_sponsor_commitment,
            )?;
        }
        require_bps("max_fee_bps", self.max_fee_bps)?;
        require(
            self.max_fee_bps <= config.max_user_fee_bps,
            "claim reservation fee exceeds low-fee cap",
        )?;
        require(
            self.privacy_set_size >= config.min_privacy_set_size,
            "claim reservation privacy set is too small",
        )?;
        require_root("pq_authorization_root", &self.pq_authorization_root)?;
        require(
            self.expires_at_height > self.reserved_at_height,
            "claim reservation must expire after reservation",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "coverage_id": self.coverage_id,
            "claimant_commitment": self.claimant_commitment,
            "claim_note_root": self.claim_note_root,
            "reservation_nullifier": self.reservation_nullifier,
            "low_fee_sponsor_commitment": self.low_fee_sponsor_commitment,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_authorization_root": self.pq_authorization_root,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestInsuranceRiskRequest {
    pub pool_id: String,
    pub coverage_id: String,
    pub exposure_root: String,
    pub oracle_observation_root: String,
    pub reserve_state_root: String,
    pub verdict: RiskVerdict,
    pub risk_score_commitment: String,
    pub pq_attestation_root: String,
    pub attestation_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub attested_at_height: u64,
}

impl AttestInsuranceRiskRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialInsurancePoolRuntimeResult<()> {
        require_non_empty("pool_id", &self.pool_id)?;
        require_non_empty("coverage_id", &self.coverage_id)?;
        require_root("exposure_root", &self.exposure_root)?;
        if config.require_oracle_bound {
            require_root("oracle_observation_root", &self.oracle_observation_root)?;
        }
        require_root("reserve_state_root", &self.reserve_state_root)?;
        require_root("risk_score_commitment", &self.risk_score_commitment)?;
        require_root("pq_attestation_root", &self.pq_attestation_root)?;
        require_root("attestation_nullifier", &self.attestation_nullifier)?;
        require_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "coverage_id": self.coverage_id,
            "exposure_root": self.exposure_root,
            "oracle_observation_root": self.oracle_observation_root,
            "reserve_state_root": self.reserve_state_root,
            "verdict": self.verdict.as_str(),
            "risk_score_commitment": self.risk_score_commitment,
            "pq_attestation_root": self.pq_attestation_root,
            "attestation_nullifier": self.attestation_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "attested_at_height": self.attested_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildPrivateClaimBatchRequest {
    pub pool_id: String,
    pub coverage_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub risk_attestation_ids: Vec<String>,
    pub claim_commitment_root: String,
    pub payout_note_root: String,
    pub reserve_delta_root: String,
    pub recursive_batch_proof_root: String,
    pub batch_privacy_set_size: u64,
    pub built_at_height: u64,
}

impl BuildPrivateClaimBatchRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialInsurancePoolRuntimeResult<()> {
        require_non_empty("pool_id", &self.pool_id)?;
        require(
            !self.coverage_ids.is_empty(),
            "claim batch must include at least one coverage",
        )?;
        require(
            self.coverage_ids.len() <= config.max_batch_claims,
            "claim batch exceeds configured coverage limit",
        )?;
        require_unique("coverage_ids", &self.coverage_ids)?;
        require_unique("reservation_ids", &self.reservation_ids)?;
        require_unique("risk_attestation_ids", &self.risk_attestation_ids)?;
        require_root("claim_commitment_root", &self.claim_commitment_root)?;
        require_root("payout_note_root", &self.payout_note_root)?;
        require_root("reserve_delta_root", &self.reserve_delta_root)?;
        require_root(
            "recursive_batch_proof_root",
            &self.recursive_batch_proof_root,
        )?;
        require(
            self.batch_privacy_set_size >= config.batch_privacy_set_size,
            "claim batch privacy set is too small",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "coverage_ids": self.coverage_ids,
            "reservation_ids": self.reservation_ids,
            "risk_attestation_ids": self.risk_attestation_ids,
            "claim_commitment_root": self.claim_commitment_root,
            "payout_note_root": self.payout_note_root,
            "reserve_delta_root": self.reserve_delta_root,
            "recursive_batch_proof_root": self.recursive_batch_proof_root,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "built_at_height": self.built_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishClaimSettlementReceiptRequest {
    pub receipt_kind: ReceiptKind,
    pub subject_id: String,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub payout_output_root: String,
    pub state_root_after: String,
    pub privacy_set_size: u64,
    pub settled_at_height: u64,
}

impl PublishClaimSettlementReceiptRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialInsurancePoolRuntimeResult<()> {
        require_non_empty("subject_id", &self.subject_id)?;
        require_root("settlement_tx_root", &self.settlement_tx_root)?;
        require_root("settlement_proof_root", &self.settlement_proof_root)?;
        require_root("payout_output_root", &self.payout_output_root)?;
        require_root("state_root_after", &self.state_root_after)?;
        require(
            self.privacy_set_size >= config.min_privacy_set_size,
            "settlement receipt privacy set is too small",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_kind": self.receipt_kind.as_str(),
            "subject_id": self.subject_id,
            "settlement_tx_root": self.settlement_tx_root,
            "settlement_proof_root": self.settlement_proof_root,
            "payout_output_root": self.payout_output_root,
            "state_root_after": self.state_root_after,
            "privacy_set_size": self.privacy_set_size,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishPremiumRebateRequest {
    pub receipt_id: String,
    pub reservation_ids: Vec<String>,
    pub rebate_pool_root: String,
    pub rebate_output_root: String,
    pub fee_asset_id: String,
    pub rebate_bps: u64,
    pub privacy_set_size: u64,
    pub published_at_height: u64,
}

impl PublishPremiumRebateRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialInsurancePoolRuntimeResult<()> {
        require_non_empty("receipt_id", &self.receipt_id)?;
        require_unique("reservation_ids", &self.reservation_ids)?;
        require_root("rebate_pool_root", &self.rebate_pool_root)?;
        require_root("rebate_output_root", &self.rebate_output_root)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_bps("rebate_bps", self.rebate_bps)?;
        require(
            self.rebate_bps <= config.target_rebate_bps,
            "rebate exceeds configured target",
        )?;
        require(
            self.privacy_set_size >= config.min_privacy_set_size,
            "rebate privacy set is too small",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "reservation_ids": self.reservation_ids,
            "rebate_pool_root": self.rebate_pool_root,
            "rebate_output_root": self.rebate_output_root,
            "fee_asset_id": self.fee_asset_id,
            "rebate_bps": self.rebate_bps,
            "privacy_set_size": self.privacy_set_size,
            "published_at_height": self.published_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedCoveragePoolRecord {
    pub pool_id: String,
    pub request: OpenShieldedCoveragePoolRequest,
    pub status: PoolStatus,
    pub opened_at_height: u64,
    pub latest_state_root: String,
    pub premium_note_ids: Vec<String>,
    pub coverage_ids: Vec<String>,
    pub claim_batch_ids: Vec<String>,
    pub pool_root: String,
}

impl ShieldedCoveragePoolRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "latest_state_root": self.latest_state_root,
            "premium_note_ids": self.premium_note_ids,
            "coverage_ids": self.coverage_ids,
            "claim_batch_ids": self.claim_batch_ids,
            "pool_root": self.pool_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialPremiumNoteRecord {
    pub premium_note_id: String,
    pub request: SubmitConfidentialPremiumNoteRequest,
    pub status: PremiumNoteStatus,
    pub accepted_at_height: u64,
    pub premium_root: String,
}

impl ConfidentialPremiumNoteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "premium_note_id": self.premium_note_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "accepted_at_height": self.accepted_at_height,
            "premium_root": self.premium_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedCoverageRecord {
    pub coverage_id: String,
    pub request: OpenShieldedCoverageRequest,
    pub status: CoverageStatus,
    pub opened_at_height: u64,
    pub coverage_root: String,
}

impl ShieldedCoverageRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "coverage_id": self.coverage_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "coverage_root": self.coverage_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InsuranceRiskAttestationRecord {
    pub risk_attestation_id: String,
    pub request: AttestInsuranceRiskRequest,
    pub risk_root: String,
}

impl InsuranceRiskAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "risk_attestation_id": self.risk_attestation_id,
            "request": self.request.public_record(),
            "risk_root": self.risk_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeClaimReservationRecord {
    pub reservation_id: String,
    pub request: ReserveLowFeeClaimExecutionRequest,
    pub status: ClaimReservationStatus,
    pub reservation_root: String,
}

impl LowFeeClaimReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "reservation_root": self.reservation_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateClaimBatchRecord {
    pub claim_batch_id: String,
    pub request: BuildPrivateClaimBatchRequest,
    pub status: ClaimBatchStatus,
    pub settlement_deadline_height: u64,
    pub claim_batch_root: String,
}

impl PrivateClaimBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "claim_batch_id": self.claim_batch_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "settlement_deadline_height": self.settlement_deadline_height,
            "claim_batch_root": self.claim_batch_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimSettlementReceiptRecord {
    pub receipt_id: String,
    pub request: PublishClaimSettlementReceiptRequest,
    pub receipt_root: String,
}

impl ClaimSettlementReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "request": self.request.public_record(),
            "receipt_root": self.receipt_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PremiumRebateRecord {
    pub rebate_id: String,
    pub request: PublishPremiumRebateRequest,
    pub rebate_root: String,
}

impl PremiumRebateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "request": self.request.public_record(),
            "rebate_root": self.rebate_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub pool_root: String,
    pub premium_note_root: String,
    pub coverage_root: String,
    pub risk_attestation_root: String,
    pub reservation_root: String,
    pub claim_batch_root: String,
    pub settlement_receipt_root: String,
    pub rebate_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_root": self.pool_root,
            "premium_note_root": self.premium_note_root,
            "coverage_root": self.coverage_root,
            "risk_attestation_root": self.risk_attestation_root,
            "reservation_root": self.reservation_root,
            "claim_batch_root": self.claim_batch_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "rebate_root": self.rebate_root,
            "nullifier_root": self.nullifier_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub pools: BTreeMap<String, ShieldedCoveragePoolRecord>,
    pub premium_notes: BTreeMap<String, ConfidentialPremiumNoteRecord>,
    pub coverages: BTreeMap<String, ShieldedCoverageRecord>,
    pub risk_attestations: BTreeMap<String, InsuranceRiskAttestationRecord>,
    pub reservations: BTreeMap<String, LowFeeClaimReservationRecord>,
    pub claim_batches: BTreeMap<String, PrivateClaimBatchRecord>,
    pub settlement_receipts: BTreeMap<String, ClaimSettlementReceiptRecord>,
    pub rebates: BTreeMap<String, PremiumRebateRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        Self::new(Config::devnet())
    }

    pub fn new(config: Config) -> Self {
        Self {
            config,
            counters: Counters::default(),
            current_height: PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_DEVNET_HEIGHT,
            pools: BTreeMap::new(),
            premium_notes: BTreeMap::new(),
            coverages: BTreeMap::new(),
            risk_attestations: BTreeMap::new(),
            reservations: BTreeMap::new(),
            claim_batches: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        }
    }

    pub fn open_pool(
        &mut self,
        request: OpenShieldedCoveragePoolRequest,
    ) -> PrivateL2ConfidentialInsurancePoolRuntimeResult<ShieldedCoveragePoolRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        require(
            self.pools.len() < self.config.max_pools,
            "insurance pool capacity exhausted",
        )?;
        self.consume_nullifier(&request.pool_nullifier)?;
        let sequence = self.counters.next_pool;
        self.counters.next_pool = self.counters.next_pool.saturating_add(1);
        self.current_height = self.current_height.max(request.opened_at_height);
        let pool_id = shielded_coverage_pool_id(&request, sequence);
        let pool_root = payload_root(
            PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_POOL_SCHEME,
            &json!({"pool_id": pool_id, "sequence": sequence, "request": request.public_record()}),
        );
        let record = ShieldedCoveragePoolRecord {
            pool_id: pool_id.clone(),
            request,
            status: PoolStatus::Active,
            opened_at_height: self.current_height,
            latest_state_root: pool_root.clone(),
            premium_note_ids: Vec::new(),
            coverage_ids: Vec::new(),
            claim_batch_ids: Vec::new(),
            pool_root,
        };
        self.pools.insert(pool_id, record.clone());
        Ok(record)
    }

    pub fn submit_premium_note(
        &mut self,
        request: SubmitConfidentialPremiumNoteRequest,
    ) -> PrivateL2ConfidentialInsurancePoolRuntimeResult<ConfidentialPremiumNoteRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        require(
            self.premium_notes.len() < self.config.max_premium_notes,
            "premium note capacity exhausted",
        )?;
        let pool = self
            .pools
            .get(&request.pool_id)
            .ok_or_else(|| "premium note references unknown insurance pool".to_string())?;
        require(
            pool.status.accepts_premiums(),
            "insurance pool does not accept premiums",
        )?;
        self.consume_nullifier(&request.premium_nullifier)?;
        let sequence = self.counters.next_premium_note;
        self.counters.next_premium_note = self.counters.next_premium_note.saturating_add(1);
        self.current_height = self.current_height.max(request.submitted_at_height);
        let premium_note_id = confidential_premium_note_id(&request, sequence);
        let premium_root = payload_root(
            PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_PREMIUM_SCHEME,
            &json!({"premium_note_id": premium_note_id, "sequence": sequence, "request": request.public_record()}),
        );
        if let Some(pool) = self.pools.get_mut(&request.pool_id) {
            pool.premium_note_ids.push(premium_note_id.clone());
        }
        let record = ConfidentialPremiumNoteRecord {
            premium_note_id: premium_note_id.clone(),
            request,
            status: PremiumNoteStatus::Accepted,
            accepted_at_height: self.current_height,
            premium_root,
        };
        self.premium_notes.insert(premium_note_id, record.clone());
        Ok(record)
    }

    pub fn open_coverage(
        &mut self,
        request: OpenShieldedCoverageRequest,
    ) -> PrivateL2ConfidentialInsurancePoolRuntimeResult<ShieldedCoverageRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        require(
            self.coverages.len() < self.config.max_coverages,
            "coverage capacity exhausted",
        )?;
        let pool = self
            .pools
            .get(&request.pool_id)
            .ok_or_else(|| "coverage references unknown insurance pool".to_string())?;
        require(
            pool.status.accepts_premiums(),
            "insurance pool does not accept new coverage",
        )?;
        let premium_note = self
            .premium_notes
            .get(&request.premium_note_id)
            .ok_or_else(|| "coverage references unknown premium note".to_string())?;
        require(
            premium_note.request.pool_id == request.pool_id,
            "premium note belongs to a different insurance pool",
        )?;
        require(
            premium_note.status.can_open_coverage(),
            "premium note cannot open coverage",
        )?;
        self.consume_nullifier(&request.coverage_nullifier)?;
        let sequence = self.counters.next_coverage;
        self.counters.next_coverage = self.counters.next_coverage.saturating_add(1);
        self.current_height = self.current_height.max(request.coverage_start_height);
        let coverage_id = shielded_coverage_id(&request, sequence);
        let coverage_root = payload_root(
            PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_COVERAGE_SCHEME,
            &json!({"coverage_id": coverage_id, "sequence": sequence, "request": request.public_record()}),
        );
        if let Some(premium_note) = self.premium_notes.get_mut(&request.premium_note_id) {
            premium_note.status = PremiumNoteStatus::Encumbered;
        }
        if let Some(pool) = self.pools.get_mut(&request.pool_id) {
            pool.coverage_ids.push(coverage_id.clone());
            pool.latest_state_root = coverage_root.clone();
        }
        let record = ShieldedCoverageRecord {
            coverage_id: coverage_id.clone(),
            request,
            status: CoverageStatus::Open,
            opened_at_height: self.current_height,
            coverage_root,
        };
        self.coverages.insert(coverage_id, record.clone());
        Ok(record)
    }

    pub fn reserve_claim_execution(
        &mut self,
        request: ReserveLowFeeClaimExecutionRequest,
    ) -> PrivateL2ConfidentialInsurancePoolRuntimeResult<LowFeeClaimReservationRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        require(
            self.reservations.len() < self.config.max_reservations,
            "claim reservation capacity exhausted",
        )?;
        let pool = self
            .pools
            .get(&request.pool_id)
            .ok_or_else(|| "claim reservation references unknown insurance pool".to_string())?;
        require(
            pool.status.accepts_claims(),
            "insurance pool does not accept claim reservations",
        )?;
        let coverage = self
            .coverages
            .get(&request.coverage_id)
            .ok_or_else(|| "claim reservation references unknown coverage".to_string())?;
        require(
            coverage.request.pool_id == request.pool_id,
            "coverage belongs to a different insurance pool",
        )?;
        require(coverage.status.live(), "coverage is not live")?;
        self.consume_nullifier(&request.reservation_nullifier)?;
        let sequence = self.counters.next_reservation;
        self.counters.next_reservation = self.counters.next_reservation.saturating_add(1);
        self.current_height = self.current_height.max(request.reserved_at_height);
        let reservation_id = low_fee_claim_reservation_id(&request, sequence);
        let reservation_root = payload_root(
            PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_RESERVATION_SCHEME,
            &json!({"reservation_id": reservation_id, "sequence": sequence, "request": request.public_record()}),
        );
        if let Some(coverage) = self.coverages.get_mut(&request.coverage_id) {
            coverage.status = CoverageStatus::Reserved;
        }
        let record = LowFeeClaimReservationRecord {
            reservation_id: reservation_id.clone(),
            request,
            status: ClaimReservationStatus::Reserved,
            reservation_root,
        };
        self.reservations.insert(reservation_id, record.clone());
        Ok(record)
    }

    pub fn attest_risk(
        &mut self,
        request: AttestInsuranceRiskRequest,
    ) -> PrivateL2ConfidentialInsurancePoolRuntimeResult<InsuranceRiskAttestationRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        require(
            self.risk_attestations.len() < self.config.max_risk_attestations,
            "risk attestation capacity exhausted",
        )?;
        require(
            self.pools.contains_key(&request.pool_id),
            "risk attestation references unknown insurance pool",
        )?;
        let coverage = self
            .coverages
            .get(&request.coverage_id)
            .ok_or_else(|| "risk attestation references unknown coverage".to_string())?;
        require(
            coverage.request.pool_id == request.pool_id,
            "risk attestation coverage belongs to a different pool",
        )?;
        self.consume_nullifier(&request.attestation_nullifier)?;
        let sequence = self.counters.next_risk_attestation;
        self.counters.next_risk_attestation = self.counters.next_risk_attestation.saturating_add(1);
        self.current_height = self.current_height.max(request.attested_at_height);
        let risk_attestation_id = insurance_risk_attestation_id(&request, sequence);
        let risk_root = payload_root(
            PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_RISK_SCHEME,
            &json!({"risk_attestation_id": risk_attestation_id, "sequence": sequence, "request": request.public_record()}),
        );
        if let Some(pool) = self.pools.get_mut(&request.pool_id) {
            pool.status = match request.verdict {
                RiskVerdict::Halted | RiskVerdict::Rejected => PoolStatus::Paused,
                RiskVerdict::Claimable | RiskVerdict::HighRisk => PoolStatus::ClaimOnly,
                _ => PoolStatus::Active,
            };
        }
        let record = InsuranceRiskAttestationRecord {
            risk_attestation_id: risk_attestation_id.clone(),
            request,
            risk_root,
        };
        self.risk_attestations
            .insert(risk_attestation_id, record.clone());
        Ok(record)
    }

    pub fn build_claim_batch(
        &mut self,
        request: BuildPrivateClaimBatchRequest,
    ) -> PrivateL2ConfidentialInsurancePoolRuntimeResult<PrivateClaimBatchRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        require(
            self.claim_batches.len() < self.config.max_claim_batches,
            "claim batch capacity exhausted",
        )?;
        let pool = self
            .pools
            .get(&request.pool_id)
            .ok_or_else(|| "claim batch references unknown insurance pool".to_string())?;
        require(
            pool.status.accepts_claims(),
            "insurance pool does not accept claim batches",
        )?;
        for coverage_id in &request.coverage_ids {
            let coverage = self
                .coverages
                .get(coverage_id)
                .ok_or_else(|| "claim batch references unknown coverage".to_string())?;
            require(
                coverage.request.pool_id == request.pool_id,
                "claim batch coverage belongs to a different pool",
            )?;
            require(coverage.status.live(), "claim batch coverage is not live")?;
        }
        for reservation_id in &request.reservation_ids {
            require(
                self.reservations.contains_key(reservation_id),
                "claim batch references unknown reservation",
            )?;
        }
        for risk_attestation_id in &request.risk_attestation_ids {
            let risk = self
                .risk_attestations
                .get(risk_attestation_id)
                .ok_or_else(|| "claim batch references unknown risk attestation".to_string())?;
            require(
                risk.request.verdict.allows_claim(),
                "risk attestation does not allow claim settlement",
            )?;
        }
        let sequence = self.counters.next_claim_batch;
        self.counters.next_claim_batch = self.counters.next_claim_batch.saturating_add(1);
        self.current_height = self.current_height.max(request.built_at_height);
        let claim_batch_id = private_claim_batch_id(&request, sequence);
        let claim_batch_root = payload_root(
            PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_CLAIM_BATCH_SCHEME,
            &json!({"claim_batch_id": claim_batch_id, "sequence": sequence, "request": request.public_record()}),
        );
        for coverage_id in &request.coverage_ids {
            if let Some(coverage) = self.coverages.get_mut(coverage_id) {
                coverage.status = CoverageStatus::ClaimPending;
            }
        }
        for reservation_id in &request.reservation_ids {
            if let Some(reservation) = self.reservations.get_mut(reservation_id) {
                reservation.status = ClaimReservationStatus::Matched;
            }
        }
        if let Some(pool) = self.pools.get_mut(&request.pool_id) {
            pool.claim_batch_ids.push(claim_batch_id.clone());
            pool.status = PoolStatus::ClaimOnly;
        }
        let record = PrivateClaimBatchRecord {
            claim_batch_id: claim_batch_id.clone(),
            request,
            status: ClaimBatchStatus::SettlementReady,
            settlement_deadline_height: self
                .current_height
                .saturating_add(self.config.settlement_ttl_blocks),
            claim_batch_root,
        };
        self.claim_batches.insert(claim_batch_id, record.clone());
        Ok(record)
    }

    pub fn publish_settlement_receipt(
        &mut self,
        request: PublishClaimSettlementReceiptRequest,
    ) -> PrivateL2ConfidentialInsurancePoolRuntimeResult<ClaimSettlementReceiptRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        require(
            self.settlement_receipts.len() < self.config.max_receipts,
            "settlement receipt capacity exhausted",
        )?;
        if request.receipt_kind == ReceiptKind::ClaimSettled {
            let batch = self
                .claim_batches
                .get(&request.subject_id)
                .ok_or_else(|| "receipt references unknown claim batch".to_string())?
                .clone();
            require(
                batch.status.can_settle(),
                "claim batch is not settlement-ready",
            )?;
            require(
                request.settled_at_height <= batch.settlement_deadline_height,
                "claim settlement deadline elapsed",
            )?;
            for coverage_id in &batch.request.coverage_ids {
                if let Some(coverage) = self.coverages.get_mut(coverage_id) {
                    coverage.status = CoverageStatus::Settled;
                    if let Some(premium_note) = self
                        .premium_notes
                        .get_mut(&coverage.request.premium_note_id)
                    {
                        premium_note.status = PremiumNoteStatus::Settled;
                    }
                }
            }
            for reservation_id in &batch.request.reservation_ids {
                if let Some(reservation) = self.reservations.get_mut(reservation_id) {
                    reservation.status = ClaimReservationStatus::Consumed;
                }
            }
            if let Some(stored_batch) = self.claim_batches.get_mut(&request.subject_id) {
                stored_batch.status = ClaimBatchStatus::Settled;
            }
            if let Some(pool) = self.pools.get_mut(&batch.request.pool_id) {
                pool.status = PoolStatus::Active;
                pool.latest_state_root = request.state_root_after.clone();
            }
        }
        let sequence = self.counters.next_receipt;
        self.counters.next_receipt = self.counters.next_receipt.saturating_add(1);
        self.current_height = self.current_height.max(request.settled_at_height);
        let receipt_id = claim_settlement_receipt_id(&request, sequence);
        let receipt_root = payload_root(
            PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_RECEIPT_SCHEME,
            &json!({"receipt_id": receipt_id, "sequence": sequence, "request": request.public_record()}),
        );
        let record = ClaimSettlementReceiptRecord {
            receipt_id: receipt_id.clone(),
            request,
            receipt_root,
        };
        self.settlement_receipts.insert(receipt_id, record.clone());
        Ok(record)
    }

    pub fn publish_rebate(
        &mut self,
        request: PublishPremiumRebateRequest,
    ) -> PrivateL2ConfidentialInsurancePoolRuntimeResult<PremiumRebateRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        require(
            self.rebates.len() < self.config.max_receipts,
            "rebate capacity exhausted",
        )?;
        require(
            self.settlement_receipts.contains_key(&request.receipt_id),
            "rebate references unknown settlement receipt",
        )?;
        for reservation_id in &request.reservation_ids {
            require(
                self.reservations.contains_key(reservation_id),
                "rebate references unknown reservation",
            )?;
        }
        let sequence = self.counters.next_rebate;
        self.counters.next_rebate = self.counters.next_rebate.saturating_add(1);
        self.current_height = self.current_height.max(request.published_at_height);
        let rebate_id = premium_rebate_id(&request, sequence);
        let rebate_root = payload_root(
            PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_REBATE_SCHEME,
            &json!({"rebate_id": rebate_id, "sequence": sequence, "request": request.public_record()}),
        );
        for reservation_id in &request.reservation_ids {
            if let Some(reservation) = self.reservations.get_mut(reservation_id) {
                reservation.status = ClaimReservationStatus::Rebated;
            }
        }
        let record = PremiumRebateRecord {
            rebate_id: rebate_id.clone(),
            request,
            rebate_root,
        };
        self.rebates.insert(rebate_id, record.clone());
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        let pool_root = public_record_root(
            PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_POOL_SCHEME,
            &self
                .pools
                .values()
                .map(ShieldedCoveragePoolRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let premium_note_root = public_record_root(
            PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_PREMIUM_SCHEME,
            &self
                .premium_notes
                .values()
                .map(ConfidentialPremiumNoteRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let coverage_root = public_record_root(
            PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_COVERAGE_SCHEME,
            &self
                .coverages
                .values()
                .map(ShieldedCoverageRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let risk_attestation_root = public_record_root(
            PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_RISK_SCHEME,
            &self
                .risk_attestations
                .values()
                .map(InsuranceRiskAttestationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let reservation_root = public_record_root(
            PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_RESERVATION_SCHEME,
            &self
                .reservations
                .values()
                .map(LowFeeClaimReservationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let claim_batch_root = public_record_root(
            PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_CLAIM_BATCH_SCHEME,
            &self
                .claim_batches
                .values()
                .map(PrivateClaimBatchRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let settlement_receipt_root = public_record_root(
            PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_RECEIPT_SCHEME,
            &self
                .settlement_receipts
                .values()
                .map(ClaimSettlementReceiptRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let rebate_root = public_record_root(
            PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_REBATE_SCHEME,
            &self
                .rebates
                .values()
                .map(PremiumRebateRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let nullifier_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-INSURANCE-POOL-NULLIFIERS",
            &self
                .consumed_nullifiers
                .iter()
                .map(|nullifier| json!(nullifier))
                .collect::<Vec<_>>(),
        );
        let state_root = state_root_from_record(&json!({
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "current_height": self.current_height,
            "pool_root": pool_root,
            "premium_note_root": premium_note_root,
            "coverage_root": coverage_root,
            "risk_attestation_root": risk_attestation_root,
            "reservation_root": reservation_root,
            "claim_batch_root": claim_batch_root,
            "settlement_receipt_root": settlement_receipt_root,
            "rebate_root": rebate_root,
            "nullifier_root": nullifier_root,
            "counters": self.counters.public_record(),
        }));
        Roots {
            pool_root,
            premium_note_root,
            coverage_root,
            risk_attestation_root,
            reservation_root,
            claim_batch_root,
            settlement_receipt_root,
            rebate_root,
            nullifier_root,
            state_root,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "pool_ids": self.pools.keys().cloned().collect::<Vec<_>>(),
            "premium_note_ids": self.premium_notes.keys().cloned().collect::<Vec<_>>(),
            "coverage_ids": self.coverages.keys().cloned().collect::<Vec<_>>(),
            "risk_attestation_ids": self.risk_attestations.keys().cloned().collect::<Vec<_>>(),
            "reservation_ids": self.reservations.keys().cloned().collect::<Vec<_>>(),
            "claim_batch_ids": self.claim_batches.keys().cloned().collect::<Vec<_>>(),
            "settlement_receipt_ids": self.settlement_receipts.keys().cloned().collect::<Vec<_>>(),
            "rebate_ids": self.rebates.keys().cloned().collect::<Vec<_>>(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn consume_nullifier(
        &mut self,
        nullifier: &str,
    ) -> PrivateL2ConfidentialInsurancePoolRuntimeResult<()> {
        let nullifier_hash = payload_id(
            "PRIVATE-L2-CONFIDENTIAL-INSURANCE-POOL-NULLIFIER-ID",
            &[HashPart::Str(nullifier)],
        );
        require(
            self.consumed_nullifiers.insert(nullifier_hash),
            "confidential insurance pool nullifier replay detected",
        )?;
        self.counters.consumed_nullifier_counter =
            self.counters.consumed_nullifier_counter.saturating_add(1);
        Ok(())
    }
}

pub fn shielded_coverage_pool_id(
    request: &OpenShieldedCoveragePoolRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-INSURANCE-POOL-ID",
        &[
            HashPart::Str(request.pool_kind.as_str()),
            HashPart::Str(&request.pool_commitment),
            HashPart::Str(&request.operator_commitment),
            HashPart::Str(&request.pool_nullifier),
            HashPart::Int(sequence as i128),
        ],
    )
}

pub fn confidential_premium_note_id(
    request: &SubmitConfidentialPremiumNoteRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-INSURANCE-PREMIUM-NOTE-ID",
        &[
            HashPart::Str(&request.pool_id),
            HashPart::Str(&request.payer_commitment),
            HashPart::Str(&request.premium_note_root),
            HashPart::Str(&request.premium_nullifier),
            HashPart::Int(sequence as i128),
        ],
    )
}

pub fn shielded_coverage_id(request: &OpenShieldedCoverageRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-INSURANCE-COVERAGE-ID",
        &[
            HashPart::Str(&request.pool_id),
            HashPart::Str(&request.premium_note_id),
            HashPart::Str(&request.insured_commitment),
            HashPart::Str(&request.coverage_vault_root),
            HashPart::Str(&request.coverage_nullifier),
            HashPart::Int(sequence as i128),
        ],
    )
}

pub fn low_fee_claim_reservation_id(
    request: &ReserveLowFeeClaimExecutionRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-INSURANCE-CLAIM-RESERVATION-ID",
        &[
            HashPart::Str(&request.pool_id),
            HashPart::Str(&request.coverage_id),
            HashPart::Str(&request.claim_note_root),
            HashPart::Str(&request.reservation_nullifier),
            HashPart::Int(sequence as i128),
        ],
    )
}

pub fn insurance_risk_attestation_id(
    request: &AttestInsuranceRiskRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-INSURANCE-RISK-ATTESTATION-ID",
        &[
            HashPart::Str(&request.pool_id),
            HashPart::Str(&request.coverage_id),
            HashPart::Str(request.verdict.as_str()),
            HashPart::Str(&request.pq_attestation_root),
            HashPart::Str(&request.attestation_nullifier),
            HashPart::Int(sequence as i128),
        ],
    )
}

pub fn private_claim_batch_id(request: &BuildPrivateClaimBatchRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-INSURANCE-CLAIM-BATCH-ID",
        &[
            HashPart::Str(&request.pool_id),
            HashPart::Json(&json!(&request.coverage_ids)),
            HashPart::Str(&request.claim_commitment_root),
            HashPart::Str(&request.payout_note_root),
            HashPart::Str(&request.recursive_batch_proof_root),
            HashPart::Int(sequence as i128),
        ],
    )
}

pub fn claim_settlement_receipt_id(
    request: &PublishClaimSettlementReceiptRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-INSURANCE-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(request.receipt_kind.as_str()),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.settlement_tx_root),
            HashPart::Str(&request.settlement_proof_root),
            HashPart::Str(&request.state_root_after),
            HashPart::Int(sequence as i128),
        ],
    )
}

pub fn premium_rebate_id(request: &PublishPremiumRebateRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-INSURANCE-PREMIUM-REBATE-ID",
        &[
            HashPart::Str(&request.receipt_id),
            HashPart::Json(&json!(&request.reservation_ids)),
            HashPart::Str(&request.rebate_pool_root),
            HashPart::Str(&request.rebate_output_root),
            HashPart::Int(sequence as i128),
        ],
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    root_from_record(domain, payload)
}

pub fn payload_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!(
            "{}:{}:{}",
            PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_PROTOCOL_VERSION, CHAIN_ID, domain
        ),
        parts,
        32,
    )
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    let leaves = records
        .iter()
        .map(|record| json!(root_from_record(domain, record)))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("PRIVATE-L2-CONFIDENTIAL-INSURANCE-POOL-STATE-ROOT", record)
}

fn require(condition: bool, message: &str) -> PrivateL2ConfidentialInsurancePoolRuntimeResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn require_non_empty(
    label: &str,
    value: &str,
) -> PrivateL2ConfidentialInsurancePoolRuntimeResult<()> {
    require(
        !value.trim().is_empty(),
        &format!("{label} must not be empty"),
    )
}

fn require_root(label: &str, value: &str) -> PrivateL2ConfidentialInsurancePoolRuntimeResult<()> {
    require_non_empty(label, value)?;
    require(
        value.len() >= 16,
        &format!("{label} must look like a commitment/root"),
    )
}

fn require_bps(label: &str, value: u64) -> PrivateL2ConfidentialInsurancePoolRuntimeResult<()> {
    require(
        value <= PRIVATE_L2_CONFIDENTIAL_INSURANCE_POOL_RUNTIME_MAX_BPS,
        &format!("{label} exceeds basis point maximum"),
    )
}

fn require_privacy_and_pq(
    privacy_set_size: u64,
    pq_security_bits: u16,
    min_privacy_set_size: u64,
    min_pq_security_bits: u16,
) -> PrivateL2ConfidentialInsurancePoolRuntimeResult<()> {
    require(
        privacy_set_size >= min_privacy_set_size,
        "privacy set is below configured anonymity threshold",
    )?;
    require(
        pq_security_bits >= min_pq_security_bits,
        "PQ authorization security bits below configured minimum",
    )
}

fn require_unique(
    label: &str,
    values: &[String],
) -> PrivateL2ConfidentialInsurancePoolRuntimeResult<()> {
    let unique = values.iter().collect::<BTreeSet<_>>();
    require(
        unique.len() == values.len(),
        &format!("{label} must be unique"),
    )
}
