use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedProverFailureInsuranceStructuredNoteRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_PROVER_FAILURE_INSURANCE_STRUCTURED_NOTE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-tokenized-prover-failure-insurance-structured-note-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_PROVER_FAILURE_INSURANCE_STRUCTURED_NOTE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_STRUCTURED_NOTE_AUTHORIZATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-prover-failure-structured-note-auth-v1";
pub const SEALED_NOTE_PROGRAM_SUITE: &str =
    "sealed-confidential-prover-failure-structured-note-program-root-v1";
pub const TOKENIZED_NOTE_ISSUANCE_SUITE: &str =
    "tokenized-confidential-prover-failure-structured-note-issuance-root-v1";
pub const NOTE_TRANCHE_LEDGER_SUITE: &str =
    "private-prover-failure-structured-note-tranche-ledger-root-v1";
pub const BARRIER_OBSERVATION_SUITE: &str =
    "pq-private-prover-failure-structured-note-barrier-observation-root-v1";
pub const COUPON_ACCRUAL_SUITE: &str =
    "private-prover-failure-structured-note-coupon-accrual-root-v1";
pub const REDEMPTION_BATCH_SUITE: &str =
    "low-fee-prover-failure-structured-note-redemption-batch-root-v1";
pub const SETTLEMENT_RECEIPT_SUITE: &str =
    "speedy-prover-failure-structured-note-settlement-receipt-root-v1";
pub const LIQUIDITY_BUFFER_SUITE: &str =
    "private-prover-failure-structured-note-liquidity-buffer-root-v1";
pub const HEDGE_BUCKET_SUITE: &str = "defi-prover-failure-structured-note-hedge-bucket-root-v1";
pub const PQ_COMMITTEE_ATTESTATION_SUITE: &str =
    "pq-prover-failure-structured-note-committee-attestation-root-v1";
pub const FEE_REBATE_EPOCH_SUITE: &str =
    "low-fee-prover-failure-structured-note-fee-rebate-epoch-root-v1";
pub const PRIVACY_NULLIFIER_SUITE: &str =
    "anti-replay-prover-failure-structured-note-nullifier-root-v1";
pub const PUBLIC_RECORD_SUITE: &str =
    "roots-only-prover-failure-insurance-structured-note-public-record-v1";
pub const STATE_ROOT_SUITE: &str =
    "private-l2-pq-confidential-tokenized-prover-failure-insurance-structured-note-state-root-v1";
pub const PAYLOAD_ROOT_SUITE: &str =
    "private-l2-pq-confidential-tokenized-prover-failure-insurance-structured-note-payload-root-v1";
pub const DEVNET_REPLAY_DOMAIN: &str =
    "nebula-private-l2-pq-prover-failure-insurance-structured-note-devnet";
pub const DEVNET_RUNTIME_ID: &str = "private-l2-pq-prover-failure-insurance-structured-note-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_704_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 5_402_000;
pub const DEVNET_EPOCH: u64 = 25_024;
pub const DEVNET_NOTE_TOKEN_ID: &str = "tpfi-note-devnet";
pub const DEVNET_COLLATERAL_ASSET_ID: &str = "dusd-private-devnet";
pub const DEVNET_COUPON_ASSET_ID: &str = "nebula-coupon-credit-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_FAILURE_INDEX_ID: &str = "monero-private-l2-prover-failure-index-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_PROTOCOL_FEE_BPS: u64 = 2;
pub const DEFAULT_STRUCTURING_FEE_BPS: u64 = 3;
pub const DEFAULT_SETTLEMENT_FEE_BPS: u64 = 1;
pub const DEFAULT_REBATE_SHARE_BPS: u64 = 2_500;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_OBSERVATION_QUORUM: u16 = 5;
pub const DEFAULT_SETTLEMENT_QUORUM: u16 = 3;
pub const DEFAULT_COMMITTEE_QUORUM: u16 = 4;
pub const DEFAULT_MIN_COLLATERAL_COVERAGE_BPS: u64 = 11_250;
pub const DEFAULT_TARGET_COLLATERAL_COVERAGE_BPS: u64 = 13_500;
pub const DEFAULT_MAX_PAYOUT_BPS: u64 = 8_500;
pub const DEFAULT_MAX_NOTE_UTILIZATION_BPS: u64 = 8_250;
pub const DEFAULT_MIN_FAILURE_BLOCKS: u64 = 8;
pub const DEFAULT_CATASTROPHIC_FAILURE_BLOCKS: u64 = 2_880;
pub const DEFAULT_FAST_SETTLEMENT_BLOCKS: u64 = 12;
pub const DEFAULT_REDEMPTION_WINDOW_BLOCKS: u64 = 24;
pub const DEFAULT_COUPON_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_NOTE_TTL_BLOCKS: u64 = 21_600;
pub const DEFAULT_LOW_FEE_BATCH_LIMIT: usize = 8192;
pub const DEFAULT_MAX_NOTE_PROGRAMS: usize = 65_536;
pub const DEFAULT_MAX_ISSUANCES: usize = 1_048_576;
pub const DEFAULT_MAX_TRANCHES: usize = 262_144;
pub const DEFAULT_MAX_OBSERVATIONS: usize = 524_288;
pub const DEFAULT_MAX_COUPONS: usize = 1_048_576;
pub const DEFAULT_MAX_REDEMPTIONS: usize = 524_288;
pub const DEFAULT_MAX_SETTLEMENTS: usize = 524_288;
pub const DEFAULT_MAX_NULLIFIERS: usize = 2_097_152;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StructuredNoteKind {
    PrincipalProtected,
    DigitalFailureCoupon,
    BarrierAutocall,
    ReverseConvertible,
    CapitalAtRisk,
    CatastrophicFailureProtection,
}

impl StructuredNoteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrincipalProtected => "principal_protected",
            Self::DigitalFailureCoupon => "digital_failure_coupon",
            Self::BarrierAutocall => "barrier_autocall",
            Self::ReverseConvertible => "reverse_convertible",
            Self::CapitalAtRisk => "capital_at_risk",
            Self::CatastrophicFailureProtection => "catastrophic_failure_protection",
        }
    }

    pub fn risk_weight_bps(self) -> u64 {
        match self {
            Self::PrincipalProtected => 700,
            Self::DigitalFailureCoupon => 1_150,
            Self::BarrierAutocall => 1_400,
            Self::ReverseConvertible => 1_850,
            Self::CapitalAtRisk => 2_400,
            Self::CatastrophicFailureProtection => 3_300,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProverFailureRiskKind {
    Timeout,
    InvalidProof,
    WitnessUnavailable,
    RecursiveProofStall,
    AggregatorOutage,
    DataAvailabilityGap,
    CatastrophicFailure,
}

impl ProverFailureRiskKind {
    pub fn severity_bps(self) -> u64 {
        match self {
            Self::Timeout => 850,
            Self::InvalidProof => 1_450,
            Self::WitnessUnavailable => 1_200,
            Self::RecursiveProofStall => 1_750,
            Self::AggregatorOutage => 2_050,
            Self::DataAvailabilityGap => 2_350,
            Self::CatastrophicFailure => 3_500,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BarrierKind {
    KnockIn,
    KnockOut,
    Autocall,
    CouponMemory,
    CapitalProtectionFloor,
    CatastropheTrigger,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponMode {
    Fixed,
    FloatingFailureIndex,
    DigitalIfNoFailure,
    MemoryCatchUp,
    RecoveryParticipation,
    ZeroCouponDiscount,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramStatus {
    Draft,
    Sealed,
    Open,
    Paused,
    ObservationOnly,
    RedemptionOnly,
    Settling,
    Settled,
    Retired,
    Quarantined,
}

impl ProgramStatus {
    pub fn accepts_issuance(self) -> bool {
        matches!(self, Self::Open)
    }

    pub fn accepts_observations(self) -> bool {
        matches!(self, Self::Open | Self::ObservationOnly | Self::Settling)
    }

    pub fn accepts_redemptions(self) -> bool {
        matches!(self, Self::Open | Self::RedemptionOnly | Self::Settling)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuanceStatus {
    Draft,
    PqAuthorized,
    Minted,
    CouponAccruing,
    BarrierTouched,
    Autocalled,
    RedemptionQueued,
    Settling,
    Settled,
    Defaulted,
    Expired,
    Quarantined,
}

impl IssuanceStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::PqAuthorized
                | Self::Minted
                | Self::CouponAccruing
                | Self::BarrierTouched
                | Self::RedemptionQueued
                | Self::Settling
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrancheSeniority {
    SuperSenior,
    Senior,
    Mezzanine,
    Junior,
    Equity,
}

impl TrancheSeniority {
    pub fn loss_priority(self) -> u8 {
        match self {
            Self::Equity => 0,
            Self::Junior => 1,
            Self::Mezzanine => 2,
            Self::Senior => 3,
            Self::SuperSenior => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStatus {
    Submitted,
    PrivacyChecked,
    PqAttested,
    QuorumReached,
    BarrierActionable,
    UsedForCoupon,
    UsedForSettlement,
    Dismissed,
    Expired,
    Quarantined,
}

impl ObservationStatus {
    pub fn actionable(self) -> bool {
        matches!(
            self,
            Self::PqAttested
                | Self::QuorumReached
                | Self::BarrierActionable
                | Self::UsedForCoupon
                | Self::UsedForSettlement
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Draft,
    Accrued,
    MemoryDeferred,
    Payable,
    Batched,
    Paid,
    Forfeited,
    Reinvested,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedemptionStatus {
    Open,
    Collecting,
    Frozen,
    Proving,
    Submitted,
    Settled,
    PartiallySettled,
    Rejected,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Queued,
    Netting,
    Proving,
    PqAuthorized,
    Posted,
    Settled,
    PartiallySettled,
    Rejected,
    Quarantined,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: u64,
    pub runtime_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub note_token_id: String,
    pub collateral_asset_id: String,
    pub coupon_asset_id: String,
    pub fee_asset_id: String,
    pub failure_index_id: String,
    pub protocol_fee_bps: u64,
    pub structuring_fee_bps: u64,
    pub settlement_fee_bps: u64,
    pub rebate_share_bps: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub observation_quorum: u16,
    pub settlement_quorum: u16,
    pub committee_quorum: u16,
    pub min_collateral_coverage_bps: u64,
    pub target_collateral_coverage_bps: u64,
    pub max_payout_bps: u64,
    pub max_note_utilization_bps: u64,
    pub min_failure_blocks: u64,
    pub catastrophic_failure_blocks: u64,
    pub fast_settlement_blocks: u64,
    pub redemption_window_blocks: u64,
    pub coupon_epoch_blocks: u64,
    pub note_ttl_blocks: u64,
    pub low_fee_batch_limit: usize,
    pub max_note_programs: usize,
    pub max_issuances: usize,
    pub max_tranches: usize,
    pub max_observations: usize,
    pub max_coupons: usize,
    pub max_redemptions: usize,
    pub max_settlements: usize,
    pub max_nullifiers: usize,
    pub require_roots_only_public_records: bool,
    pub pq_authorization_suite: String,
    pub hash_suite: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID,
            runtime_id: DEVNET_RUNTIME_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            epoch: DEVNET_EPOCH,
            note_token_id: DEVNET_NOTE_TOKEN_ID.to_string(),
            collateral_asset_id: DEVNET_COLLATERAL_ASSET_ID.to_string(),
            coupon_asset_id: DEVNET_COUPON_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            failure_index_id: DEVNET_FAILURE_INDEX_ID.to_string(),
            protocol_fee_bps: DEFAULT_PROTOCOL_FEE_BPS,
            structuring_fee_bps: DEFAULT_STRUCTURING_FEE_BPS,
            settlement_fee_bps: DEFAULT_SETTLEMENT_FEE_BPS,
            rebate_share_bps: DEFAULT_REBATE_SHARE_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            observation_quorum: DEFAULT_OBSERVATION_QUORUM,
            settlement_quorum: DEFAULT_SETTLEMENT_QUORUM,
            committee_quorum: DEFAULT_COMMITTEE_QUORUM,
            min_collateral_coverage_bps: DEFAULT_MIN_COLLATERAL_COVERAGE_BPS,
            target_collateral_coverage_bps: DEFAULT_TARGET_COLLATERAL_COVERAGE_BPS,
            max_payout_bps: DEFAULT_MAX_PAYOUT_BPS,
            max_note_utilization_bps: DEFAULT_MAX_NOTE_UTILIZATION_BPS,
            min_failure_blocks: DEFAULT_MIN_FAILURE_BLOCKS,
            catastrophic_failure_blocks: DEFAULT_CATASTROPHIC_FAILURE_BLOCKS,
            fast_settlement_blocks: DEFAULT_FAST_SETTLEMENT_BLOCKS,
            redemption_window_blocks: DEFAULT_REDEMPTION_WINDOW_BLOCKS,
            coupon_epoch_blocks: DEFAULT_COUPON_EPOCH_BLOCKS,
            note_ttl_blocks: DEFAULT_NOTE_TTL_BLOCKS,
            low_fee_batch_limit: DEFAULT_LOW_FEE_BATCH_LIMIT,
            max_note_programs: DEFAULT_MAX_NOTE_PROGRAMS,
            max_issuances: DEFAULT_MAX_ISSUANCES,
            max_tranches: DEFAULT_MAX_TRANCHES,
            max_observations: DEFAULT_MAX_OBSERVATIONS,
            max_coupons: DEFAULT_MAX_COUPONS,
            max_redemptions: DEFAULT_MAX_REDEMPTIONS,
            max_settlements: DEFAULT_MAX_SETTLEMENTS,
            max_nullifiers: DEFAULT_MAX_NULLIFIERS,
            require_roots_only_public_records: true,
            pq_authorization_suite: PQ_STRUCTURED_NOTE_AUTHORIZATION_SUITE.to_string(),
            hash_suite: HASH_SUITE.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "runtime_id": self.runtime_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
            "note_token_id": self.note_token_id,
            "collateral_asset_id": self.collateral_asset_id,
            "coupon_asset_id": self.coupon_asset_id,
            "fee_asset_id": self.fee_asset_id,
            "failure_index_id": self.failure_index_id,
            "protocol_fee_bps": self.protocol_fee_bps,
            "structuring_fee_bps": self.structuring_fee_bps,
            "settlement_fee_bps": self.settlement_fee_bps,
            "rebate_share_bps": self.rebate_share_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "observation_quorum": self.observation_quorum,
            "settlement_quorum": self.settlement_quorum,
            "committee_quorum": self.committee_quorum,
            "min_collateral_coverage_bps": self.min_collateral_coverage_bps,
            "target_collateral_coverage_bps": self.target_collateral_coverage_bps,
            "max_payout_bps": self.max_payout_bps,
            "max_note_utilization_bps": self.max_note_utilization_bps,
            "min_failure_blocks": self.min_failure_blocks,
            "catastrophic_failure_blocks": self.catastrophic_failure_blocks,
            "fast_settlement_blocks": self.fast_settlement_blocks,
            "redemption_window_blocks": self.redemption_window_blocks,
            "coupon_epoch_blocks": self.coupon_epoch_blocks,
            "note_ttl_blocks": self.note_ttl_blocks,
            "low_fee_batch_limit": self.low_fee_batch_limit,
            "require_roots_only_public_records": self.require_roots_only_public_records,
            "pq_authorization_suite": self.pq_authorization_suite,
            "hash_suite": self.hash_suite,
            "roots_only": true,
            "protocol_version": PROTOCOL_VERSION,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub note_programs: u64,
    pub issuances: u64,
    pub tranches: u64,
    pub observations: u64,
    pub coupons: u64,
    pub redemption_batches: u64,
    pub settlement_receipts: u64,
    pub liquidity_buffers: u64,
    pub hedge_buckets: u64,
    pub committee_attestations: u64,
    pub fee_rebate_epochs: u64,
    pub nullifiers: u64,
    pub public_records: u64,
    pub rejected: u64,
    pub quarantined: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        public_record_for(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub note_program_root: String,
    pub issuance_root: String,
    pub tranche_root: String,
    pub observation_root: String,
    pub coupon_root: String,
    pub redemption_root: String,
    pub settlement_root: String,
    pub liquidity_buffer_root: String,
    pub hedge_bucket_root: String,
    pub committee_attestation_root: String,
    pub fee_rebate_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        let empty = merkle_root(PUBLIC_RECORD_SUITE, &[]);
        Self {
            config_root: empty.clone(),
            note_program_root: empty.clone(),
            issuance_root: empty.clone(),
            tranche_root: empty.clone(),
            observation_root: empty.clone(),
            coupon_root: empty.clone(),
            redemption_root: empty.clone(),
            settlement_root: empty.clone(),
            liquidity_buffer_root: empty.clone(),
            hedge_bucket_root: empty.clone(),
            committee_attestation_root: empty.clone(),
            fee_rebate_root: empty.clone(),
            nullifier_root: empty.clone(),
            public_record_root: empty.clone(),
            counters_root: empty.clone(),
            state_root: empty,
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        public_record_for(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NoteProgram {
    pub program_id: String,
    pub note_kind: StructuredNoteKind,
    pub status: ProgramStatus,
    pub failure_risk: ProverFailureRiskKind,
    pub collateral_asset_id: String,
    pub note_token_id: String,
    pub coupon_asset_id: String,
    pub notional_cap_units: u128,
    pub issued_notional_units: u128,
    pub collateral_root: String,
    pub payoff_terms_root: String,
    pub barrier_schedule_root: String,
    pub coupon_schedule_root: String,
    pub token_metadata_root: String,
    pub hedge_policy_root: String,
    pub min_collateral_coverage_bps: u64,
    pub target_coupon_bps: u64,
    pub max_payout_bps: u64,
    pub maturity_height: u64,
    pub settlement_lag_blocks: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl NoteProgram {
    pub fn public_record(&self) -> Value {
        json!({
            "program_id": self.program_id,
            "note_kind": self.note_kind.as_str(),
            "status": self.status,
            "failure_risk": self.failure_risk,
            "collateral_asset_id": self.collateral_asset_id,
            "note_token_id": self.note_token_id,
            "coupon_asset_id": self.coupon_asset_id,
            "notional_cap_commitment": commitment("program_notional_cap", self.notional_cap_units),
            "issued_notional_commitment": commitment("program_issued_notional", self.issued_notional_units),
            "collateral_root": self.collateral_root,
            "payoff_terms_root": self.payoff_terms_root,
            "barrier_schedule_root": self.barrier_schedule_root,
            "coupon_schedule_root": self.coupon_schedule_root,
            "token_metadata_root": self.token_metadata_root,
            "hedge_policy_root": self.hedge_policy_root,
            "min_collateral_coverage_bps": self.min_collateral_coverage_bps,
            "target_coupon_bps": self.target_coupon_bps,
            "max_payout_bps": self.max_payout_bps,
            "maturity_height": self.maturity_height,
            "settlement_lag_blocks": self.settlement_lag_blocks,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "roots_only": true,
            "protocol_version": PROTOCOL_VERSION,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TokenizedNoteIssuance {
    pub issuance_id: String,
    pub program_id: String,
    pub tranche_id: String,
    pub status: IssuanceStatus,
    pub owner_commitment: String,
    pub note_commitment_root: String,
    pub principal_commitment_root: String,
    pub coupon_claim_root: String,
    pub mint_authorization_root: String,
    pub notional_units: u128,
    pub principal_paid_units: u128,
    pub accrued_coupon_units: u128,
    pub entry_index_bps: u64,
    pub protection_floor_bps: u64,
    pub participation_bps: u64,
    pub issued_height: u64,
    pub maturity_height: u64,
    pub nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl TokenizedNoteIssuance {
    pub fn public_record(&self) -> Value {
        json!({
            "issuance_id": self.issuance_id,
            "program_id": self.program_id,
            "tranche_id": self.tranche_id,
            "status": self.status,
            "owner_commitment": self.owner_commitment,
            "note_commitment_root": self.note_commitment_root,
            "principal_commitment_root": self.principal_commitment_root,
            "coupon_claim_root": self.coupon_claim_root,
            "mint_authorization_root": self.mint_authorization_root,
            "notional_commitment": commitment("issuance_notional", self.notional_units),
            "principal_paid_commitment": commitment("principal_paid", self.principal_paid_units),
            "accrued_coupon_commitment": commitment("accrued_coupon", self.accrued_coupon_units),
            "entry_index_bps": self.entry_index_bps,
            "protection_floor_bps": self.protection_floor_bps,
            "participation_bps": self.participation_bps,
            "issued_height": self.issued_height,
            "maturity_height": self.maturity_height,
            "nullifier_root": root_from_parts(PRIVACY_NULLIFIER_SUITE, &[&self.nullifier]),
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "roots_only": true,
            "protocol_version": PROTOCOL_VERSION,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NoteTranche {
    pub tranche_id: String,
    pub program_id: String,
    pub seniority: TrancheSeniority,
    pub attachment_bps: u64,
    pub detachment_bps: u64,
    pub coupon_spread_bps: u64,
    pub principal_protection_bps: u64,
    pub tranche_cap_units: u128,
    pub issued_units: u128,
    pub reserve_root: String,
    pub investor_set_root: String,
    pub waterfall_root: String,
    pub liquidity_buffer_id: String,
    pub status: ProgramStatus,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl NoteTranche {
    pub fn public_record(&self) -> Value {
        json!({
            "tranche_id": self.tranche_id,
            "program_id": self.program_id,
            "seniority": self.seniority,
            "attachment_bps": self.attachment_bps,
            "detachment_bps": self.detachment_bps,
            "coupon_spread_bps": self.coupon_spread_bps,
            "principal_protection_bps": self.principal_protection_bps,
            "tranche_cap_commitment": commitment("tranche_cap", self.tranche_cap_units),
            "issued_commitment": commitment("tranche_issued", self.issued_units),
            "reserve_root": self.reserve_root,
            "investor_set_root": self.investor_set_root,
            "waterfall_root": self.waterfall_root,
            "liquidity_buffer_id": self.liquidity_buffer_id,
            "status": self.status,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "roots_only": true,
            "protocol_version": PROTOCOL_VERSION,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BarrierObservation {
    pub observation_id: String,
    pub program_id: String,
    pub barrier_kind: BarrierKind,
    pub risk_kind: ProverFailureRiskKind,
    pub status: ObservationStatus,
    pub prover_set_root: String,
    pub circuit_root: String,
    pub failed_proof_root: String,
    pub recovery_proof_root: String,
    pub index_snapshot_root: String,
    pub observed_failure_blocks: u64,
    pub observed_index_bps: u64,
    pub barrier_level_bps: u64,
    pub oracle_attestation_root: String,
    pub committee_attestation_id: String,
    pub observer_quorum_weight: u16,
    pub nullifier: String,
    pub observed_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl BarrierObservation {
    pub fn public_record(&self) -> Value {
        json!({
            "observation_id": self.observation_id,
            "program_id": self.program_id,
            "barrier_kind": self.barrier_kind,
            "risk_kind": self.risk_kind,
            "status": self.status,
            "prover_set_root": self.prover_set_root,
            "circuit_root": self.circuit_root,
            "failed_proof_root": self.failed_proof_root,
            "recovery_proof_root": self.recovery_proof_root,
            "index_snapshot_root": self.index_snapshot_root,
            "observed_failure_blocks": self.observed_failure_blocks,
            "observed_index_bps": self.observed_index_bps,
            "barrier_level_bps": self.barrier_level_bps,
            "oracle_attestation_root": self.oracle_attestation_root,
            "committee_attestation_id": self.committee_attestation_id,
            "observer_quorum_weight": self.observer_quorum_weight,
            "nullifier_root": root_from_parts(PRIVACY_NULLIFIER_SUITE, &[&self.nullifier]),
            "observed_height": self.observed_height,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "roots_only": true,
            "protocol_version": PROTOCOL_VERSION,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CouponAccrual {
    pub coupon_id: String,
    pub issuance_id: String,
    pub program_id: String,
    pub epoch: u64,
    pub mode: CouponMode,
    pub status: CouponStatus,
    pub coupon_rate_bps: u64,
    pub accrued_units: u128,
    pub memory_carry_units: u128,
    pub observation_root: String,
    pub payment_commitment_root: String,
    pub fee_commitment_root: String,
    pub rebate_commitment_root: String,
    pub nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl CouponAccrual {
    pub fn public_record(&self) -> Value {
        json!({
            "coupon_id": self.coupon_id,
            "issuance_id": self.issuance_id,
            "program_id": self.program_id,
            "epoch": self.epoch,
            "mode": self.mode,
            "status": self.status,
            "coupon_rate_bps": self.coupon_rate_bps,
            "accrued_commitment": commitment("coupon_accrued", self.accrued_units),
            "memory_carry_commitment": commitment("coupon_memory_carry", self.memory_carry_units),
            "observation_root": self.observation_root,
            "payment_commitment_root": self.payment_commitment_root,
            "fee_commitment_root": self.fee_commitment_root,
            "rebate_commitment_root": self.rebate_commitment_root,
            "nullifier_root": root_from_parts(PRIVACY_NULLIFIER_SUITE, &[&self.nullifier]),
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "roots_only": true,
            "protocol_version": PROTOCOL_VERSION,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedemptionBatch {
    pub batch_id: String,
    pub program_id: String,
    pub status: RedemptionStatus,
    pub issuance_set_root: String,
    pub coupon_set_root: String,
    pub principal_debit_root: String,
    pub coupon_credit_root: String,
    pub fee_root: String,
    pub rebate_root: String,
    pub gross_principal_units: u128,
    pub gross_coupon_units: u128,
    pub protocol_fee_units: u128,
    pub settlement_fee_units: u128,
    pub item_count: u64,
    pub opened_height: u64,
    pub target_settlement_height: u64,
    pub pq_authorization_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl RedemptionBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "program_id": self.program_id,
            "status": self.status,
            "issuance_set_root": self.issuance_set_root,
            "coupon_set_root": self.coupon_set_root,
            "principal_debit_root": self.principal_debit_root,
            "coupon_credit_root": self.coupon_credit_root,
            "fee_root": self.fee_root,
            "rebate_root": self.rebate_root,
            "gross_principal_commitment": commitment("redemption_principal", self.gross_principal_units),
            "gross_coupon_commitment": commitment("redemption_coupon", self.gross_coupon_units),
            "protocol_fee_commitment": commitment("redemption_protocol_fee", self.protocol_fee_units),
            "settlement_fee_commitment": commitment("redemption_settlement_fee", self.settlement_fee_units),
            "item_count": self.item_count,
            "opened_height": self.opened_height,
            "target_settlement_height": self.target_settlement_height,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "roots_only": true,
            "protocol_version": PROTOCOL_VERSION,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementReceipt {
    pub settlement_id: String,
    pub batch_id: String,
    pub program_id: String,
    pub status: SettlementStatus,
    pub debit_root: String,
    pub credit_root: String,
    pub fee_root: String,
    pub state_transition_root: String,
    pub proof_receipt_root: String,
    pub committee_attestation_root: String,
    pub settled_principal_units: u128,
    pub settled_coupon_units: u128,
    pub paid_fee_units: u128,
    pub settled_items: u64,
    pub posted_height: u64,
    pub finality_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "batch_id": self.batch_id,
            "program_id": self.program_id,
            "status": self.status,
            "debit_root": self.debit_root,
            "credit_root": self.credit_root,
            "fee_root": self.fee_root,
            "state_transition_root": self.state_transition_root,
            "proof_receipt_root": self.proof_receipt_root,
            "committee_attestation_root": self.committee_attestation_root,
            "settled_principal_commitment": commitment("settled_principal", self.settled_principal_units),
            "settled_coupon_commitment": commitment("settled_coupon", self.settled_coupon_units),
            "paid_fee_commitment": commitment("settled_fee", self.paid_fee_units),
            "settled_items": self.settled_items,
            "posted_height": self.posted_height,
            "finality_height": self.finality_height,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "roots_only": true,
            "protocol_version": PROTOCOL_VERSION,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityBuffer {
    pub buffer_id: String,
    pub program_id: String,
    pub tranche_id: String,
    pub collateral_root: String,
    pub liquidity_provider_root: String,
    pub reserve_commitment_root: String,
    pub pending_claim_root: String,
    pub available_units: u128,
    pub locked_units: u128,
    pub coverage_bps: u64,
    pub utilization_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl LiquidityBuffer {
    pub fn public_record(&self) -> Value {
        json!({
            "buffer_id": self.buffer_id,
            "program_id": self.program_id,
            "tranche_id": self.tranche_id,
            "collateral_root": self.collateral_root,
            "liquidity_provider_root": self.liquidity_provider_root,
            "reserve_commitment_root": self.reserve_commitment_root,
            "pending_claim_root": self.pending_claim_root,
            "available_commitment": commitment("buffer_available", self.available_units),
            "locked_commitment": commitment("buffer_locked", self.locked_units),
            "coverage_bps": self.coverage_bps,
            "utilization_bps": self.utilization_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "roots_only": true,
            "protocol_version": PROTOCOL_VERSION,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HedgeBucket {
    pub bucket_id: String,
    pub program_id: String,
    pub hedge_strategy_root: String,
    pub collateral_swap_root: String,
    pub perps_overlay_root: String,
    pub option_overlay_root: String,
    pub target_delta_bps: i64,
    pub current_delta_bps: i64,
    pub target_liquidity_bps: u64,
    pub low_fee_route_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl HedgeBucket {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "program_id": self.program_id,
            "hedge_strategy_root": self.hedge_strategy_root,
            "collateral_swap_root": self.collateral_swap_root,
            "perps_overlay_root": self.perps_overlay_root,
            "option_overlay_root": self.option_overlay_root,
            "target_delta_bps": self.target_delta_bps,
            "current_delta_bps": self.current_delta_bps,
            "target_liquidity_bps": self.target_liquidity_bps,
            "low_fee_route_root": self.low_fee_route_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "roots_only": true,
            "protocol_version": PROTOCOL_VERSION,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqCommitteeAttestation {
    pub attestation_id: String,
    pub subject_id: String,
    pub subject_kind: String,
    pub committee_root: String,
    pub ml_dsa_signature_root: String,
    pub slh_dsa_signature_root: String,
    pub ml_kem_transcript_root: String,
    pub quorum_weight: u16,
    pub attested_height: u64,
    pub replay_domain: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl PqCommitteeAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "subject_id": self.subject_id,
            "subject_kind": self.subject_kind,
            "committee_root": self.committee_root,
            "ml_dsa_signature_root": self.ml_dsa_signature_root,
            "slh_dsa_signature_root": self.slh_dsa_signature_root,
            "ml_kem_transcript_root": self.ml_kem_transcript_root,
            "quorum_weight": self.quorum_weight,
            "attested_height": self.attested_height,
            "replay_domain": self.replay_domain,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "roots_only": true,
            "protocol_version": PROTOCOL_VERSION,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebateEpoch {
    pub rebate_epoch_id: String,
    pub program_id: String,
    pub fee_pool_root: String,
    pub eligible_note_root: String,
    pub rebate_distribution_root: String,
    pub total_fee_units: u128,
    pub rebate_units: u128,
    pub epoch_start_height: u64,
    pub epoch_end_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl FeeRebateEpoch {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_epoch_id": self.rebate_epoch_id,
            "program_id": self.program_id,
            "fee_pool_root": self.fee_pool_root,
            "eligible_note_root": self.eligible_note_root,
            "rebate_distribution_root": self.rebate_distribution_root,
            "total_fee_commitment": commitment("rebate_total_fee", self.total_fee_units),
            "rebate_commitment": commitment("rebate_units", self.rebate_units),
            "epoch_start_height": self.epoch_start_height,
            "epoch_end_height": self.epoch_end_height,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "roots_only": true,
            "protocol_version": PROTOCOL_VERSION,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyNullifier {
    pub nullifier: String,
    pub source_kind: String,
    pub source_id: String,
    pub seen_height: u64,
}

impl PrivacyNullifier {
    pub fn public_record(&self) -> Value {
        json!({
            "nullifier_root": root_from_parts(PRIVACY_NULLIFIER_SUITE, &[&self.nullifier]),
            "source_kind": self.source_kind,
            "source_id": self.source_id,
            "seen_height": self.seen_height,
            "roots_only": true,
            "protocol_version": PROTOCOL_VERSION,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealNoteProgramInput {
    pub program_id: String,
    pub note_kind: StructuredNoteKind,
    pub failure_risk: ProverFailureRiskKind,
    pub notional_cap_units: u128,
    pub collateral_root: String,
    pub payoff_terms_root: String,
    pub barrier_schedule_root: String,
    pub coupon_schedule_root: String,
    pub token_metadata_root: String,
    pub hedge_policy_root: String,
    pub min_collateral_coverage_bps: u64,
    pub target_coupon_bps: u64,
    pub max_payout_bps: u64,
    pub maturity_height: u64,
    pub settlement_lag_blocks: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl SealNoteProgramInput {
    pub fn public_record(&self) -> Value {
        public_record_for(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AddTrancheInput {
    pub tranche_id: String,
    pub program_id: String,
    pub seniority: TrancheSeniority,
    pub attachment_bps: u64,
    pub detachment_bps: u64,
    pub coupon_spread_bps: u64,
    pub principal_protection_bps: u64,
    pub tranche_cap_units: u128,
    pub reserve_root: String,
    pub investor_set_root: String,
    pub waterfall_root: String,
    pub liquidity_buffer_id: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl AddTrancheInput {
    pub fn public_record(&self) -> Value {
        public_record_for(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssueNoteInput {
    pub issuance_id: String,
    pub program_id: String,
    pub tranche_id: String,
    pub owner_commitment: String,
    pub note_commitment_root: String,
    pub principal_commitment_root: String,
    pub coupon_claim_root: String,
    pub mint_authorization_root: String,
    pub notional_units: u128,
    pub principal_paid_units: u128,
    pub entry_index_bps: u64,
    pub protection_floor_bps: u64,
    pub participation_bps: u64,
    pub issued_height: u64,
    pub maturity_height: u64,
    pub nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl IssueNoteInput {
    pub fn public_record(&self) -> Value {
        public_record_for(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObserveBarrierInput {
    pub observation_id: String,
    pub program_id: String,
    pub barrier_kind: BarrierKind,
    pub risk_kind: ProverFailureRiskKind,
    pub prover_set_root: String,
    pub circuit_root: String,
    pub failed_proof_root: String,
    pub recovery_proof_root: String,
    pub index_snapshot_root: String,
    pub observed_failure_blocks: u64,
    pub observed_index_bps: u64,
    pub barrier_level_bps: u64,
    pub oracle_attestation_root: String,
    pub committee_attestation_id: String,
    pub observer_quorum_weight: u16,
    pub nullifier: String,
    pub observed_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl ObserveBarrierInput {
    pub fn public_record(&self) -> Value {
        public_record_for(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AccrueCouponInput {
    pub coupon_id: String,
    pub issuance_id: String,
    pub program_id: String,
    pub epoch: u64,
    pub mode: CouponMode,
    pub coupon_rate_bps: u64,
    pub accrued_units: u128,
    pub memory_carry_units: u128,
    pub observation_root: String,
    pub payment_commitment_root: String,
    pub fee_commitment_root: String,
    pub rebate_commitment_root: String,
    pub nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl AccrueCouponInput {
    pub fn public_record(&self) -> Value {
        public_record_for(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedemptionBatchInput {
    pub batch_id: String,
    pub program_id: String,
    pub issuance_set_root: String,
    pub coupon_set_root: String,
    pub principal_debit_root: String,
    pub coupon_credit_root: String,
    pub fee_root: String,
    pub rebate_root: String,
    pub gross_principal_units: u128,
    pub gross_coupon_units: u128,
    pub protocol_fee_units: u128,
    pub settlement_fee_units: u128,
    pub item_count: u64,
    pub opened_height: u64,
    pub target_settlement_height: u64,
    pub pq_authorization_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl RedemptionBatchInput {
    pub fn public_record(&self) -> Value {
        public_record_for(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementReceiptInput {
    pub settlement_id: String,
    pub batch_id: String,
    pub program_id: String,
    pub debit_root: String,
    pub credit_root: String,
    pub fee_root: String,
    pub state_transition_root: String,
    pub proof_receipt_root: String,
    pub committee_attestation_root: String,
    pub settled_principal_units: u128,
    pub settled_coupon_units: u128,
    pub paid_fee_units: u128,
    pub settled_items: u64,
    pub posted_height: u64,
    pub finality_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl SettlementReceiptInput {
    pub fn public_record(&self) -> Value {
        public_record_for(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityBufferInput {
    pub buffer_id: String,
    pub program_id: String,
    pub tranche_id: String,
    pub collateral_root: String,
    pub liquidity_provider_root: String,
    pub reserve_commitment_root: String,
    pub pending_claim_root: String,
    pub available_units: u128,
    pub locked_units: u128,
    pub coverage_bps: u64,
    pub utilization_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl LiquidityBufferInput {
    pub fn public_record(&self) -> Value {
        public_record_for(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HedgeBucketInput {
    pub bucket_id: String,
    pub program_id: String,
    pub hedge_strategy_root: String,
    pub collateral_swap_root: String,
    pub perps_overlay_root: String,
    pub option_overlay_root: String,
    pub target_delta_bps: i64,
    pub current_delta_bps: i64,
    pub target_liquidity_bps: u64,
    pub low_fee_route_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl HedgeBucketInput {
    pub fn public_record(&self) -> Value {
        public_record_for(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitteeAttestationInput {
    pub attestation_id: String,
    pub subject_id: String,
    pub subject_kind: String,
    pub committee_root: String,
    pub ml_dsa_signature_root: String,
    pub slh_dsa_signature_root: String,
    pub ml_kem_transcript_root: String,
    pub quorum_weight: u16,
    pub attested_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl CommitteeAttestationInput {
    pub fn public_record(&self) -> Value {
        public_record_for(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebateEpochInput {
    pub rebate_epoch_id: String,
    pub program_id: String,
    pub fee_pool_root: String,
    pub eligible_note_root: String,
    pub rebate_distribution_root: String,
    pub total_fee_units: u128,
    pub rebate_units: u128,
    pub epoch_start_height: u64,
    pub epoch_end_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl FeeRebateEpochInput {
    pub fn public_record(&self) -> Value {
        public_record_for(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub note_programs: BTreeMap<String, NoteProgram>,
    pub issuances: BTreeMap<String, TokenizedNoteIssuance>,
    pub tranches: BTreeMap<String, NoteTranche>,
    pub observations: BTreeMap<String, BarrierObservation>,
    pub coupons: BTreeMap<String, CouponAccrual>,
    pub redemption_batches: BTreeMap<String, RedemptionBatch>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub liquidity_buffers: BTreeMap<String, LiquidityBuffer>,
    pub hedge_buckets: BTreeMap<String, HedgeBucket>,
    pub committee_attestations: BTreeMap<String, PqCommitteeAttestation>,
    pub fee_rebate_epochs: BTreeMap<String, FeeRebateEpoch>,
    pub nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, Value>,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            note_programs: BTreeMap::new(),
            issuances: BTreeMap::new(),
            tranches: BTreeMap::new(),
            observations: BTreeMap::new(),
            coupons: BTreeMap::new(),
            redemption_batches: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            liquidity_buffers: BTreeMap::new(),
            hedge_buckets: BTreeMap::new(),
            committee_attestations: BTreeMap::new(),
            fee_rebate_epochs: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        state.seed_devnet().expect("valid structured note devnet");
        state.refresh_roots();
        state
    }

    pub fn state_root(&self) -> String {
        self.compute_roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.compute_roots();
        json!({
            "chain_id": self.config.chain_id,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "public_record_suite": PUBLIC_RECORD_SUITE,
            "roots_only": true,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
        })
    }

    pub fn seal_note_program(&mut self, input: SealNoteProgramInput) -> Result<NoteProgram> {
        ensure_capacity(
            "note programs",
            self.note_programs.len(),
            self.config.max_note_programs,
        )?;
        require_nonempty("program_id", &input.program_id)?;
        require_unique_absent(&self.note_programs, &input.program_id, "program")?;
        require(
            input.notional_cap_units > 0,
            "notional cap must be positive",
        )?;
        require_bps(
            "min_collateral_coverage_bps",
            input.min_collateral_coverage_bps,
        )?;
        require_bps("target_coupon_bps", input.target_coupon_bps)?;
        require_bps("max_payout_bps", input.max_payout_bps)?;
        require(
            input.min_collateral_coverage_bps >= self.config.min_collateral_coverage_bps,
            "collateral coverage below runtime minimum",
        )?;
        require(
            input.max_payout_bps <= self.config.max_payout_bps,
            "max payout exceeds runtime cap",
        )?;
        require_privacy_and_pq(
            input.privacy_set_size,
            input.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        let program = NoteProgram {
            program_id: input.program_id,
            note_kind: input.note_kind,
            status: ProgramStatus::Open,
            failure_risk: input.failure_risk,
            collateral_asset_id: self.config.collateral_asset_id.clone(),
            note_token_id: self.config.note_token_id.clone(),
            coupon_asset_id: self.config.coupon_asset_id.clone(),
            notional_cap_units: input.notional_cap_units,
            issued_notional_units: 0,
            collateral_root: input.collateral_root,
            payoff_terms_root: input.payoff_terms_root,
            barrier_schedule_root: input.barrier_schedule_root,
            coupon_schedule_root: input.coupon_schedule_root,
            token_metadata_root: input.token_metadata_root,
            hedge_policy_root: input.hedge_policy_root,
            min_collateral_coverage_bps: input.min_collateral_coverage_bps,
            target_coupon_bps: input.target_coupon_bps,
            max_payout_bps: input.max_payout_bps,
            maturity_height: input.maturity_height,
            settlement_lag_blocks: input.settlement_lag_blocks,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
        };
        self.publish_roots_only(
            format!("program:{}", program.program_id),
            program.public_record(),
        )?;
        self.note_programs
            .insert(program.program_id.clone(), program.clone());
        self.counters.note_programs += 1;
        self.refresh_roots();
        Ok(program)
    }

    pub fn add_tranche(&mut self, input: AddTrancheInput) -> Result<NoteTranche> {
        ensure_capacity("tranches", self.tranches.len(), self.config.max_tranches)?;
        require_nonempty("tranche_id", &input.tranche_id)?;
        require_unique_absent(&self.tranches, &input.tranche_id, "tranche")?;
        require(
            self.note_programs.contains_key(&input.program_id),
            "program must exist",
        )?;
        require_bps("attachment_bps", input.attachment_bps)?;
        require_bps("detachment_bps", input.detachment_bps)?;
        require_bps("coupon_spread_bps", input.coupon_spread_bps)?;
        require_bps("principal_protection_bps", input.principal_protection_bps)?;
        require(
            input.attachment_bps < input.detachment_bps,
            "attachment must be below detachment",
        )?;
        require(input.tranche_cap_units > 0, "tranche cap must be positive")?;
        require_privacy_and_pq(
            input.privacy_set_size,
            input.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        let tranche = NoteTranche {
            tranche_id: input.tranche_id,
            program_id: input.program_id,
            seniority: input.seniority,
            attachment_bps: input.attachment_bps,
            detachment_bps: input.detachment_bps,
            coupon_spread_bps: input.coupon_spread_bps,
            principal_protection_bps: input.principal_protection_bps,
            tranche_cap_units: input.tranche_cap_units,
            issued_units: 0,
            reserve_root: input.reserve_root,
            investor_set_root: input.investor_set_root,
            waterfall_root: input.waterfall_root,
            liquidity_buffer_id: input.liquidity_buffer_id,
            status: ProgramStatus::Open,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
        };
        self.publish_roots_only(
            format!("tranche:{}", tranche.tranche_id),
            tranche.public_record(),
        )?;
        self.tranches
            .insert(tranche.tranche_id.clone(), tranche.clone());
        self.counters.tranches += 1;
        self.refresh_roots();
        Ok(tranche)
    }

    pub fn issue_note(&mut self, input: IssueNoteInput) -> Result<TokenizedNoteIssuance> {
        ensure_capacity("issuances", self.issuances.len(), self.config.max_issuances)?;
        require_nonempty("issuance_id", &input.issuance_id)?;
        require_unique_absent(&self.issuances, &input.issuance_id, "issuance")?;
        require(
            !self.nullifiers.contains(&input.nullifier),
            "duplicate nullifier",
        )?;
        require_bps("entry_index_bps", input.entry_index_bps)?;
        require_bps("protection_floor_bps", input.protection_floor_bps)?;
        require_bps("participation_bps", input.participation_bps)?;
        require(input.notional_units > 0, "notional must be positive")?;
        require(input.principal_paid_units > 0, "principal must be positive")?;
        require_privacy_and_pq(
            input.privacy_set_size,
            input.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        {
            let program = self
                .note_programs
                .get(&input.program_id)
                .ok_or_else(|| "program must exist".to_string())?;
            require(program.status.accepts_issuance(), "program is not open")?;
            require(
                program
                    .issued_notional_units
                    .saturating_add(input.notional_units)
                    <= program.notional_cap_units,
                "program notional cap exceeded",
            )?;
        }
        {
            let tranche = self
                .tranches
                .get(&input.tranche_id)
                .ok_or_else(|| "tranche must exist".to_string())?;
            require(
                tranche.program_id == input.program_id,
                "tranche/program mismatch",
            )?;
            require(
                tranche.issued_units.saturating_add(input.notional_units)
                    <= tranche.tranche_cap_units,
                "tranche cap exceeded",
            )?;
        }
        let issuance = TokenizedNoteIssuance {
            issuance_id: input.issuance_id,
            program_id: input.program_id,
            tranche_id: input.tranche_id,
            status: IssuanceStatus::Minted,
            owner_commitment: input.owner_commitment,
            note_commitment_root: input.note_commitment_root,
            principal_commitment_root: input.principal_commitment_root,
            coupon_claim_root: input.coupon_claim_root,
            mint_authorization_root: input.mint_authorization_root,
            notional_units: input.notional_units,
            principal_paid_units: input.principal_paid_units,
            accrued_coupon_units: 0,
            entry_index_bps: input.entry_index_bps,
            protection_floor_bps: input.protection_floor_bps,
            participation_bps: input.participation_bps,
            issued_height: input.issued_height,
            maturity_height: input.maturity_height,
            nullifier: input.nullifier,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
        };
        self.note_programs
            .get_mut(&issuance.program_id)
            .expect("checked")
            .issued_notional_units += issuance.notional_units;
        self.tranches
            .get_mut(&issuance.tranche_id)
            .expect("checked")
            .issued_units += issuance.notional_units;
        self.insert_nullifier(
            issuance.nullifier.clone(),
            "issuance",
            &issuance.issuance_id,
            issuance.issued_height,
        )?;
        self.publish_roots_only(
            format!("issuance:{}", issuance.issuance_id),
            issuance.public_record(),
        )?;
        self.issuances
            .insert(issuance.issuance_id.clone(), issuance.clone());
        self.counters.issuances += 1;
        self.refresh_roots();
        Ok(issuance)
    }

    pub fn observe_barrier(&mut self, input: ObserveBarrierInput) -> Result<BarrierObservation> {
        ensure_capacity(
            "observations",
            self.observations.len(),
            self.config.max_observations,
        )?;
        require_nonempty("observation_id", &input.observation_id)?;
        require_unique_absent(&self.observations, &input.observation_id, "observation")?;
        require(
            !self.nullifiers.contains(&input.nullifier),
            "duplicate nullifier",
        )?;
        let program = self
            .note_programs
            .get(&input.program_id)
            .ok_or_else(|| "program must exist".to_string())?;
        require(
            program.status.accepts_observations(),
            "program does not accept observations",
        )?;
        require(
            input.observed_failure_blocks >= self.config.min_failure_blocks,
            "failure duration below minimum",
        )?;
        require_bps("observed_index_bps", input.observed_index_bps)?;
        require_bps("barrier_level_bps", input.barrier_level_bps)?;
        require(
            input.observer_quorum_weight >= self.config.observation_quorum,
            "observer quorum below configured threshold",
        )?;
        require_privacy_and_pq(
            input.privacy_set_size,
            input.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        let actionable = input.observed_index_bps >= input.barrier_level_bps
            || input.observed_failure_blocks >= self.config.catastrophic_failure_blocks;
        let status = if actionable {
            ObservationStatus::BarrierActionable
        } else {
            ObservationStatus::QuorumReached
        };
        let observation = BarrierObservation {
            observation_id: input.observation_id,
            program_id: input.program_id,
            barrier_kind: input.barrier_kind,
            risk_kind: input.risk_kind,
            status,
            prover_set_root: input.prover_set_root,
            circuit_root: input.circuit_root,
            failed_proof_root: input.failed_proof_root,
            recovery_proof_root: input.recovery_proof_root,
            index_snapshot_root: input.index_snapshot_root,
            observed_failure_blocks: input.observed_failure_blocks,
            observed_index_bps: input.observed_index_bps,
            barrier_level_bps: input.barrier_level_bps,
            oracle_attestation_root: input.oracle_attestation_root,
            committee_attestation_id: input.committee_attestation_id,
            observer_quorum_weight: input.observer_quorum_weight,
            nullifier: input.nullifier,
            observed_height: input.observed_height,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
        };
        self.insert_nullifier(
            observation.nullifier.clone(),
            "observation",
            &observation.observation_id,
            observation.observed_height,
        )?;
        self.publish_roots_only(
            format!("observation:{}", observation.observation_id),
            observation.public_record(),
        )?;
        self.observations
            .insert(observation.observation_id.clone(), observation.clone());
        self.counters.observations += 1;
        self.refresh_roots();
        Ok(observation)
    }

    pub fn accrue_coupon(&mut self, input: AccrueCouponInput) -> Result<CouponAccrual> {
        ensure_capacity("coupons", self.coupons.len(), self.config.max_coupons)?;
        require_nonempty("coupon_id", &input.coupon_id)?;
        require_unique_absent(&self.coupons, &input.coupon_id, "coupon")?;
        require(
            !self.nullifiers.contains(&input.nullifier),
            "duplicate nullifier",
        )?;
        require_bps("coupon_rate_bps", input.coupon_rate_bps)?;
        require(input.accrued_units > 0, "accrued coupon must be positive")?;
        let issuance = self
            .issuances
            .get(&input.issuance_id)
            .ok_or_else(|| "issuance must exist".to_string())?;
        require(issuance.live(), "issuance is not live")?;
        require(
            issuance.program_id == input.program_id,
            "issuance/program mismatch",
        )?;
        require_privacy_and_pq(
            input.privacy_set_size,
            input.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        let status = match input.mode {
            CouponMode::MemoryCatchUp if input.memory_carry_units > 0 => CouponStatus::Payable,
            CouponMode::DigitalIfNoFailure => CouponStatus::Payable,
            _ => CouponStatus::Accrued,
        };
        let coupon = CouponAccrual {
            coupon_id: input.coupon_id,
            issuance_id: input.issuance_id,
            program_id: input.program_id,
            epoch: input.epoch,
            mode: input.mode,
            status,
            coupon_rate_bps: input.coupon_rate_bps,
            accrued_units: input.accrued_units,
            memory_carry_units: input.memory_carry_units,
            observation_root: input.observation_root,
            payment_commitment_root: input.payment_commitment_root,
            fee_commitment_root: input.fee_commitment_root,
            rebate_commitment_root: input.rebate_commitment_root,
            nullifier: input.nullifier,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
        };
        self.issuances
            .get_mut(&coupon.issuance_id)
            .expect("checked")
            .accrued_coupon_units += coupon.accrued_units;
        self.insert_nullifier(
            coupon.nullifier.clone(),
            "coupon",
            &coupon.coupon_id,
            self.config.l2_height,
        )?;
        self.publish_roots_only(
            format!("coupon:{}", coupon.coupon_id),
            coupon.public_record(),
        )?;
        self.coupons
            .insert(coupon.coupon_id.clone(), coupon.clone());
        self.counters.coupons += 1;
        self.refresh_roots();
        Ok(coupon)
    }

    pub fn open_redemption_batch(
        &mut self,
        input: RedemptionBatchInput,
    ) -> Result<RedemptionBatch> {
        ensure_capacity(
            "redemption batches",
            self.redemption_batches.len(),
            self.config.max_redemptions,
        )?;
        require_nonempty("batch_id", &input.batch_id)?;
        require_unique_absent(
            &self.redemption_batches,
            &input.batch_id,
            "redemption batch",
        )?;
        let program = self
            .note_programs
            .get(&input.program_id)
            .ok_or_else(|| "program must exist".to_string())?;
        require(
            program.status.accepts_redemptions(),
            "program does not accept redemptions",
        )?;
        require(
            input.item_count > 0 && input.item_count as usize <= self.config.low_fee_batch_limit,
            "batch item count outside low-fee limits",
        )?;
        require(
            input.target_settlement_height
                <= input.opened_height + self.config.fast_settlement_blocks,
            "settlement target misses fast settlement SLA",
        )?;
        require_privacy_and_pq(
            input.privacy_set_size,
            input.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        let batch = RedemptionBatch {
            batch_id: input.batch_id,
            program_id: input.program_id,
            status: RedemptionStatus::Collecting,
            issuance_set_root: input.issuance_set_root,
            coupon_set_root: input.coupon_set_root,
            principal_debit_root: input.principal_debit_root,
            coupon_credit_root: input.coupon_credit_root,
            fee_root: input.fee_root,
            rebate_root: input.rebate_root,
            gross_principal_units: input.gross_principal_units,
            gross_coupon_units: input.gross_coupon_units,
            protocol_fee_units: input.protocol_fee_units,
            settlement_fee_units: input.settlement_fee_units,
            item_count: input.item_count,
            opened_height: input.opened_height,
            target_settlement_height: input.target_settlement_height,
            pq_authorization_root: input.pq_authorization_root,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
        };
        self.publish_roots_only(
            format!("redemption_batch:{}", batch.batch_id),
            batch.public_record(),
        )?;
        self.redemption_batches
            .insert(batch.batch_id.clone(), batch.clone());
        self.counters.redemption_batches += 1;
        self.refresh_roots();
        Ok(batch)
    }

    pub fn post_settlement_receipt(
        &mut self,
        input: SettlementReceiptInput,
    ) -> Result<SettlementReceipt> {
        ensure_capacity(
            "settlement receipts",
            self.settlement_receipts.len(),
            self.config.max_settlements,
        )?;
        require_nonempty("settlement_id", &input.settlement_id)?;
        require_unique_absent(
            &self.settlement_receipts,
            &input.settlement_id,
            "settlement",
        )?;
        let batch = self
            .redemption_batches
            .get(&input.batch_id)
            .ok_or_else(|| "redemption batch must exist".to_string())?;
        require(
            batch.program_id == input.program_id,
            "batch/program mismatch",
        )?;
        require(
            input.finality_height <= input.posted_height + self.config.fast_settlement_blocks,
            "finality height misses speedy settlement SLA",
        )?;
        require_privacy_and_pq(
            input.privacy_set_size,
            input.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        let status = if input.settled_items == batch.item_count {
            SettlementStatus::Settled
        } else {
            SettlementStatus::PartiallySettled
        };
        let receipt = SettlementReceipt {
            settlement_id: input.settlement_id,
            batch_id: input.batch_id,
            program_id: input.program_id,
            status,
            debit_root: input.debit_root,
            credit_root: input.credit_root,
            fee_root: input.fee_root,
            state_transition_root: input.state_transition_root,
            proof_receipt_root: input.proof_receipt_root,
            committee_attestation_root: input.committee_attestation_root,
            settled_principal_units: input.settled_principal_units,
            settled_coupon_units: input.settled_coupon_units,
            paid_fee_units: input.paid_fee_units,
            settled_items: input.settled_items,
            posted_height: input.posted_height,
            finality_height: input.finality_height,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
        };
        if let Some(batch) = self.redemption_batches.get_mut(&receipt.batch_id) {
            batch.status = if receipt.status == SettlementStatus::Settled {
                RedemptionStatus::Settled
            } else {
                RedemptionStatus::PartiallySettled
            };
        }
        self.publish_roots_only(
            format!("settlement:{}", receipt.settlement_id),
            receipt.public_record(),
        )?;
        self.settlement_receipts
            .insert(receipt.settlement_id.clone(), receipt.clone());
        self.counters.settlement_receipts += 1;
        self.refresh_roots();
        Ok(receipt)
    }

    pub fn add_liquidity_buffer(&mut self, input: LiquidityBufferInput) -> Result<LiquidityBuffer> {
        require_nonempty("buffer_id", &input.buffer_id)?;
        require_unique_absent(
            &self.liquidity_buffers,
            &input.buffer_id,
            "liquidity buffer",
        )?;
        require(
            self.note_programs.contains_key(&input.program_id),
            "program must exist",
        )?;
        require(
            self.tranches.contains_key(&input.tranche_id),
            "tranche must exist",
        )?;
        require_bps("coverage_bps", input.coverage_bps)?;
        require_bps("utilization_bps", input.utilization_bps)?;
        require(
            input.coverage_bps >= self.config.min_collateral_coverage_bps,
            "buffer coverage below runtime minimum",
        )?;
        require_privacy_and_pq(
            input.privacy_set_size,
            input.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        let buffer = LiquidityBuffer {
            buffer_id: input.buffer_id,
            program_id: input.program_id,
            tranche_id: input.tranche_id,
            collateral_root: input.collateral_root,
            liquidity_provider_root: input.liquidity_provider_root,
            reserve_commitment_root: input.reserve_commitment_root,
            pending_claim_root: input.pending_claim_root,
            available_units: input.available_units,
            locked_units: input.locked_units,
            coverage_bps: input.coverage_bps,
            utilization_bps: input.utilization_bps,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
        };
        self.publish_roots_only(
            format!("liquidity_buffer:{}", buffer.buffer_id),
            buffer.public_record(),
        )?;
        self.liquidity_buffers
            .insert(buffer.buffer_id.clone(), buffer.clone());
        self.counters.liquidity_buffers += 1;
        self.refresh_roots();
        Ok(buffer)
    }

    pub fn add_hedge_bucket(&mut self, input: HedgeBucketInput) -> Result<HedgeBucket> {
        require_nonempty("bucket_id", &input.bucket_id)?;
        require_unique_absent(&self.hedge_buckets, &input.bucket_id, "hedge bucket")?;
        require(
            self.note_programs.contains_key(&input.program_id),
            "program must exist",
        )?;
        require_bps("target_liquidity_bps", input.target_liquidity_bps)?;
        require_privacy_and_pq(
            input.privacy_set_size,
            input.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        let bucket = HedgeBucket {
            bucket_id: input.bucket_id,
            program_id: input.program_id,
            hedge_strategy_root: input.hedge_strategy_root,
            collateral_swap_root: input.collateral_swap_root,
            perps_overlay_root: input.perps_overlay_root,
            option_overlay_root: input.option_overlay_root,
            target_delta_bps: input.target_delta_bps,
            current_delta_bps: input.current_delta_bps,
            target_liquidity_bps: input.target_liquidity_bps,
            low_fee_route_root: input.low_fee_route_root,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
        };
        self.publish_roots_only(
            format!("hedge_bucket:{}", bucket.bucket_id),
            bucket.public_record(),
        )?;
        self.hedge_buckets
            .insert(bucket.bucket_id.clone(), bucket.clone());
        self.counters.hedge_buckets += 1;
        self.refresh_roots();
        Ok(bucket)
    }

    pub fn add_committee_attestation(
        &mut self,
        input: CommitteeAttestationInput,
    ) -> Result<PqCommitteeAttestation> {
        require_nonempty("attestation_id", &input.attestation_id)?;
        require_unique_absent(
            &self.committee_attestations,
            &input.attestation_id,
            "committee attestation",
        )?;
        require(
            input.quorum_weight >= self.config.committee_quorum,
            "committee quorum below configured threshold",
        )?;
        require_privacy_and_pq(
            input.privacy_set_size,
            input.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        let attestation = PqCommitteeAttestation {
            attestation_id: input.attestation_id,
            subject_id: input.subject_id,
            subject_kind: input.subject_kind,
            committee_root: input.committee_root,
            ml_dsa_signature_root: input.ml_dsa_signature_root,
            slh_dsa_signature_root: input.slh_dsa_signature_root,
            ml_kem_transcript_root: input.ml_kem_transcript_root,
            quorum_weight: input.quorum_weight,
            attested_height: input.attested_height,
            replay_domain: DEVNET_REPLAY_DOMAIN.to_string(),
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
        };
        self.publish_roots_only(
            format!("committee_attestation:{}", attestation.attestation_id),
            attestation.public_record(),
        )?;
        self.committee_attestations
            .insert(attestation.attestation_id.clone(), attestation.clone());
        self.counters.committee_attestations += 1;
        self.refresh_roots();
        Ok(attestation)
    }

    pub fn add_fee_rebate_epoch(&mut self, input: FeeRebateEpochInput) -> Result<FeeRebateEpoch> {
        require_nonempty("rebate_epoch_id", &input.rebate_epoch_id)?;
        require_unique_absent(
            &self.fee_rebate_epochs,
            &input.rebate_epoch_id,
            "fee rebate epoch",
        )?;
        require(
            self.note_programs.contains_key(&input.program_id),
            "program must exist",
        )?;
        require(
            input.epoch_start_height < input.epoch_end_height,
            "rebate epoch heights invalid",
        )?;
        require(
            input.rebate_units <= input.total_fee_units,
            "rebate exceeds fee pool",
        )?;
        require_privacy_and_pq(
            input.privacy_set_size,
            input.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        let rebate = FeeRebateEpoch {
            rebate_epoch_id: input.rebate_epoch_id,
            program_id: input.program_id,
            fee_pool_root: input.fee_pool_root,
            eligible_note_root: input.eligible_note_root,
            rebate_distribution_root: input.rebate_distribution_root,
            total_fee_units: input.total_fee_units,
            rebate_units: input.rebate_units,
            epoch_start_height: input.epoch_start_height,
            epoch_end_height: input.epoch_end_height,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
        };
        self.publish_roots_only(
            format!("fee_rebate:{}", rebate.rebate_epoch_id),
            rebate.public_record(),
        )?;
        self.fee_rebate_epochs
            .insert(rebate.rebate_epoch_id.clone(), rebate.clone());
        self.counters.fee_rebate_epochs += 1;
        self.refresh_roots();
        Ok(rebate)
    }

    fn insert_nullifier(
        &mut self,
        nullifier: String,
        source_kind: &str,
        source_id: &str,
        seen_height: u64,
    ) -> Result<()> {
        ensure_capacity(
            "nullifiers",
            self.nullifiers.len(),
            self.config.max_nullifiers,
        )?;
        require_nonempty("nullifier", &nullifier)?;
        require(!self.nullifiers.contains(&nullifier), "duplicate nullifier")?;
        self.nullifiers.insert(nullifier.clone());
        let record = PrivacyNullifier {
            nullifier,
            source_kind: source_kind.to_string(),
            source_id: source_id.to_string(),
            seen_height,
        };
        self.publish_roots_only(
            format!("nullifier:{source_kind}:{source_id}"),
            record.public_record(),
        )?;
        self.counters.nullifiers += 1;
        Ok(())
    }

    fn compute_roots(&self) -> Roots {
        let config_root = root_from_record("CONFIG", &self.config.public_record());
        let note_program_root = map_public_root(
            SEALED_NOTE_PROGRAM_SUITE,
            &self.note_programs,
            NoteProgram::public_record,
        );
        let issuance_root = map_public_root(
            TOKENIZED_NOTE_ISSUANCE_SUITE,
            &self.issuances,
            TokenizedNoteIssuance::public_record,
        );
        let tranche_root = map_public_root(
            NOTE_TRANCHE_LEDGER_SUITE,
            &self.tranches,
            NoteTranche::public_record,
        );
        let observation_root = map_public_root(
            BARRIER_OBSERVATION_SUITE,
            &self.observations,
            BarrierObservation::public_record,
        );
        let coupon_root = map_public_root(
            COUPON_ACCRUAL_SUITE,
            &self.coupons,
            CouponAccrual::public_record,
        );
        let redemption_root = map_public_root(
            REDEMPTION_BATCH_SUITE,
            &self.redemption_batches,
            RedemptionBatch::public_record,
        );
        let settlement_root = map_public_root(
            SETTLEMENT_RECEIPT_SUITE,
            &self.settlement_receipts,
            SettlementReceipt::public_record,
        );
        let liquidity_buffer_root = map_public_root(
            LIQUIDITY_BUFFER_SUITE,
            &self.liquidity_buffers,
            LiquidityBuffer::public_record,
        );
        let hedge_bucket_root = map_public_root(
            HEDGE_BUCKET_SUITE,
            &self.hedge_buckets,
            HedgeBucket::public_record,
        );
        let committee_attestation_root = map_public_root(
            PQ_COMMITTEE_ATTESTATION_SUITE,
            &self.committee_attestations,
            PqCommitteeAttestation::public_record,
        );
        let fee_rebate_root = map_public_root(
            FEE_REBATE_EPOCH_SUITE,
            &self.fee_rebate_epochs,
            FeeRebateEpoch::public_record,
        );
        let nullifier_root = set_root(PRIVACY_NULLIFIER_SUITE, &self.nullifiers);
        let public_record_root = value_map_root(PUBLIC_RECORD_SUITE, &self.public_records);
        let counters_root = root_from_record("COUNTERS", &self.counters.public_record());
        let state_payload = json!({
            "config_root": config_root,
            "note_program_root": note_program_root,
            "issuance_root": issuance_root,
            "tranche_root": tranche_root,
            "observation_root": observation_root,
            "coupon_root": coupon_root,
            "redemption_root": redemption_root,
            "settlement_root": settlement_root,
            "liquidity_buffer_root": liquidity_buffer_root,
            "hedge_bucket_root": hedge_bucket_root,
            "committee_attestation_root": committee_attestation_root,
            "fee_rebate_root": fee_rebate_root,
            "nullifier_root": nullifier_root,
            "public_record_root": public_record_root,
            "counters_root": counters_root,
        });
        let state_root = root_from_record(STATE_ROOT_SUITE, &state_payload);
        Roots {
            config_root,
            note_program_root,
            issuance_root,
            tranche_root,
            observation_root,
            coupon_root,
            redemption_root,
            settlement_root,
            liquidity_buffer_root,
            hedge_bucket_root,
            committee_attestation_root,
            fee_rebate_root,
            nullifier_root,
            public_record_root,
            counters_root,
            state_root,
        }
    }

    fn refresh_roots(&mut self) {
        self.roots = self.compute_roots();
    }

    fn publish_roots_only(&mut self, key: String, record: Value) -> Result<()> {
        if self.config.require_roots_only_public_records
            && !record
                .get("roots_only")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        {
            return Err("public record must be roots-only".to_string());
        }
        self.public_records.insert(key, record);
        self.counters.public_records = self.public_records.len() as u64;
        Ok(())
    }

    fn seed_devnet(&mut self) -> Result<()> {
        let program = self.seal_note_program(SealNoteProgramInput {
            program_id: "pf-structured-note-autocall-devnet".to_string(),
            note_kind: StructuredNoteKind::BarrierAutocall,
            failure_risk: ProverFailureRiskKind::RecursiveProofStall,
            notional_cap_units: 75_000_000_000,
            collateral_root: demo_root("collateral", "program"),
            payoff_terms_root: demo_root("payoff_terms", "autocall"),
            barrier_schedule_root: demo_root("barrier_schedule", "quarterly"),
            coupon_schedule_root: demo_root("coupon_schedule", "memory"),
            token_metadata_root: demo_root("token_metadata", "tpfi-note"),
            hedge_policy_root: demo_root("hedge_policy", "low-fee-defi"),
            min_collateral_coverage_bps: self.config.target_collateral_coverage_bps,
            target_coupon_bps: 1_200,
            max_payout_bps: 8_000,
            maturity_height: self.config.l2_height + self.config.note_ttl_blocks,
            settlement_lag_blocks: self.config.fast_settlement_blocks,
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })?;
        let tranche = self.add_tranche(AddTrancheInput {
            tranche_id: "pf-note-senior-devnet".to_string(),
            program_id: program.program_id.clone(),
            seniority: TrancheSeniority::Senior,
            attachment_bps: 2_500,
            detachment_bps: 8_500,
            coupon_spread_bps: 280,
            principal_protection_bps: 9_500,
            tranche_cap_units: 40_000_000_000,
            reserve_root: demo_root("tranche_reserve", "senior"),
            investor_set_root: demo_root("investor_set", "senior"),
            waterfall_root: demo_root("waterfall", "senior"),
            liquidity_buffer_id: "pf-note-buffer-senior-devnet".to_string(),
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })?;
        self.add_liquidity_buffer(LiquidityBufferInput {
            buffer_id: "pf-note-buffer-senior-devnet".to_string(),
            program_id: program.program_id.clone(),
            tranche_id: tranche.tranche_id.clone(),
            collateral_root: demo_root("buffer_collateral", "senior"),
            liquidity_provider_root: demo_root("lp_set", "senior"),
            reserve_commitment_root: demo_root("reserve", "senior"),
            pending_claim_root: demo_root("pending_claim", "senior"),
            available_units: 18_500_000_000,
            locked_units: 2_250_000_000,
            coverage_bps: self.config.target_collateral_coverage_bps,
            utilization_bps: 2_900,
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })?;
        self.add_hedge_bucket(HedgeBucketInput {
            bucket_id: "pf-note-hedge-autocall-devnet".to_string(),
            program_id: program.program_id.clone(),
            hedge_strategy_root: demo_root("hedge_strategy", "autocall"),
            collateral_swap_root: demo_root("collateral_swap", "dusd"),
            perps_overlay_root: demo_root("perps_overlay", "recursive-stall"),
            option_overlay_root: demo_root("option_overlay", "catastrophe"),
            target_delta_bps: -1_250,
            current_delta_bps: -1_120,
            target_liquidity_bps: 7_500,
            low_fee_route_root: demo_root("low_fee_route", "batch-netting"),
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })?;
        let attestation = self.add_committee_attestation(CommitteeAttestationInput {
            attestation_id: "pq-attest-pf-note-devnet-0".to_string(),
            subject_id: program.program_id.clone(),
            subject_kind: "note_program".to_string(),
            committee_root: demo_root("committee", "pf-note"),
            ml_dsa_signature_root: demo_root("ml_dsa", "pf-note"),
            slh_dsa_signature_root: demo_root("slh_dsa", "pf-note"),
            ml_kem_transcript_root: demo_root("ml_kem", "pf-note"),
            quorum_weight: self.config.committee_quorum,
            attested_height: self.config.l2_height,
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })?;
        let issuance = self.issue_note(IssueNoteInput {
            issuance_id: "pf-note-issuance-devnet-0".to_string(),
            program_id: program.program_id.clone(),
            tranche_id: tranche.tranche_id.clone(),
            owner_commitment: demo_root("owner", "alice"),
            note_commitment_root: demo_root("note_commitment", "alice"),
            principal_commitment_root: demo_root("principal", "alice"),
            coupon_claim_root: demo_root("coupon_claim", "alice"),
            mint_authorization_root: demo_root("mint_auth", "alice"),
            notional_units: 1_000_000_000,
            principal_paid_units: 1_000_000_000,
            entry_index_bps: 1_050,
            protection_floor_bps: 9_500,
            participation_bps: 6_500,
            issued_height: self.config.l2_height,
            maturity_height: self.config.l2_height + self.config.note_ttl_blocks,
            nullifier: demo_root("nullifier", "issuance-0"),
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })?;
        let observation = self.observe_barrier(ObserveBarrierInput {
            observation_id: "pf-note-observation-devnet-0".to_string(),
            program_id: program.program_id.clone(),
            barrier_kind: BarrierKind::CouponMemory,
            risk_kind: ProverFailureRiskKind::RecursiveProofStall,
            prover_set_root: demo_root("prover_set", "committee-a"),
            circuit_root: demo_root("circuit", "rollup-a"),
            failed_proof_root: demo_root("failed_proof", "batch-a"),
            recovery_proof_root: demo_root("recovery_proof", "batch-a"),
            index_snapshot_root: demo_root("failure_index", "snapshot-a"),
            observed_failure_blocks: 18,
            observed_index_bps: 1_280,
            barrier_level_bps: 1_000,
            oracle_attestation_root: demo_root("oracle_attestation", "batch-a"),
            committee_attestation_id: attestation.attestation_id,
            observer_quorum_weight: self.config.observation_quorum,
            nullifier: demo_root("nullifier", "observation-0"),
            observed_height: self.config.l2_height + 4,
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })?;
        self.accrue_coupon(AccrueCouponInput {
            coupon_id: "pf-note-coupon-devnet-0".to_string(),
            issuance_id: issuance.issuance_id,
            program_id: program.program_id.clone(),
            epoch: self.config.epoch,
            mode: CouponMode::MemoryCatchUp,
            coupon_rate_bps: 1_200,
            accrued_units: 12_000_000,
            memory_carry_units: 2_000_000,
            observation_root: root_from_record("DEVNET_OBSERVATION", &observation.public_record()),
            payment_commitment_root: demo_root("coupon_payment", "epoch-0"),
            fee_commitment_root: demo_root("coupon_fee", "epoch-0"),
            rebate_commitment_root: demo_root("coupon_rebate", "epoch-0"),
            nullifier: demo_root("nullifier", "coupon-0"),
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })?;
        self.open_redemption_batch(RedemptionBatchInput {
            batch_id: "pf-note-redemption-batch-devnet-0".to_string(),
            program_id: program.program_id.clone(),
            issuance_set_root: demo_root("issuance_set", "batch-0"),
            coupon_set_root: demo_root("coupon_set", "batch-0"),
            principal_debit_root: demo_root("principal_debit", "batch-0"),
            coupon_credit_root: demo_root("coupon_credit", "batch-0"),
            fee_root: demo_root("fees", "batch-0"),
            rebate_root: demo_root("rebates", "batch-0"),
            gross_principal_units: 1_000_000_000,
            gross_coupon_units: 12_000_000,
            protocol_fee_units: 20_000,
            settlement_fee_units: 10_000,
            item_count: 1,
            opened_height: self.config.l2_height + 8,
            target_settlement_height: self.config.l2_height + 12,
            pq_authorization_root: demo_root("redemption_pq_auth", "batch-0"),
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })?;
        self.post_settlement_receipt(SettlementReceiptInput {
            settlement_id: "pf-note-settlement-devnet-0".to_string(),
            batch_id: "pf-note-redemption-batch-devnet-0".to_string(),
            program_id: program.program_id.clone(),
            debit_root: demo_root("settlement_debits", "batch-0"),
            credit_root: demo_root("settlement_credits", "batch-0"),
            fee_root: demo_root("settlement_fees", "batch-0"),
            state_transition_root: demo_root("state_transition", "batch-0"),
            proof_receipt_root: demo_root("proof_receipt", "batch-0"),
            committee_attestation_root: demo_root("settlement_committee", "batch-0"),
            settled_principal_units: 1_000_000_000,
            settled_coupon_units: 12_000_000,
            paid_fee_units: 30_000,
            settled_items: 1,
            posted_height: self.config.l2_height + 12,
            finality_height: self.config.l2_height + 14,
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })?;
        self.add_fee_rebate_epoch(FeeRebateEpochInput {
            rebate_epoch_id: "pf-note-fee-rebate-devnet-0".to_string(),
            program_id: program.program_id,
            fee_pool_root: demo_root("fee_pool", "epoch-0"),
            eligible_note_root: demo_root("eligible_notes", "epoch-0"),
            rebate_distribution_root: demo_root("rebate_distribution", "epoch-0"),
            total_fee_units: 30_000,
            rebate_units: 7_500,
            epoch_start_height: self.config.l2_height,
            epoch_end_height: self.config.l2_height + self.config.coupon_epoch_blocks,
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })?;
        Ok(())
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}

pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

pub fn deterministic_id(domain: &str, record: &Value, sequence: u64) -> String {
    domain_hash(
        domain,
        &[HashPart::Json(record), HashPart::U64(sequence)],
        20,
    )
}

pub fn commitment(label: &str, value: u128) -> String {
    let value = value.min(i128::MAX as u128) as i128;
    domain_hash(
        "PROVER-FAILURE-STRUCTURED-NOTE-COMMITMENT",
        &[HashPart::Str(label), HashPart::Int(value)],
        32,
    )
}

pub fn root_from_parts(domain: &str, parts: &[&str]) -> String {
    let values = parts.iter().map(|part| json!(part)).collect::<Vec<_>>();
    merkle_root(domain, &values)
}

fn demo_root(label: &str, salt: &str) -> String {
    domain_hash(
        &format!("{PAYLOAD_ROOT_SUITE}:devnet:{label}"),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(salt)],
        32,
    )
}

fn public_record_for<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("runtime record serialization")
}

fn map_public_root<T, F>(label: &str, map: &BTreeMap<String, T>, f: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "label": label,
                "key": key,
                "record": f(value),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(label, &leaves)
}

fn value_map_root(label: &str, map: &BTreeMap<String, Value>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "label": label,
                "key": key,
                "record": value,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(label, &leaves)
}

fn set_root(label: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| {
            json!({
                "label": label,
                "value_root": root_from_parts(label, &[value]),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(label, &leaves)
}

fn ensure_capacity(label: &str, len: usize, max: usize) -> Result<()> {
    if len >= max {
        Err(format!("{label} capacity exceeded"))
    } else {
        Ok(())
    }
}

fn require_unique_absent<T>(map: &BTreeMap<String, T>, key: &str, label: &str) -> Result<()> {
    if map.contains_key(key) {
        Err(format!("duplicate {label} {key}"))
    } else {
        Ok(())
    }
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn require_nonempty(label: &str, value: &str) -> Result<()> {
    require(
        !value.trim().is_empty(),
        &format!("{label} must not be empty"),
    )
}

fn require_bps(label: &str, value: u64) -> Result<()> {
    require(value <= MAX_BPS, &format!("{label} exceeds MAX_BPS"))
}

fn require_privacy_and_pq(
    privacy_set_size: u64,
    pq_security_bits: u16,
    min_privacy_set_size: u64,
    min_pq_security_bits: u16,
) -> Result<()> {
    require(
        privacy_set_size >= min_privacy_set_size,
        "privacy set is below configured anonymity threshold",
    )?;
    require(
        pq_security_bits >= min_pq_security_bits,
        "PQ authorization security bits below configured minimum",
    )
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeSurfaceMarker {
    pub name: String,
    pub category: String,
    pub root_suite: String,
    pub privacy_note: String,
}

impl RuntimeSurfaceMarker {
    pub fn public_record(&self) -> Value {
        public_record_for(self)
    }
}

pub fn surface_markers() -> Vec<RuntimeSurfaceMarker> {
    vec![
        RuntimeSurfaceMarker {
            name: "sealed_note_programs".to_string(),
            category: "tokenized_structured_notes".to_string(),
            root_suite: SEALED_NOTE_PROGRAM_SUITE.to_string(),
            privacy_note: "commitments-and-roots-only".to_string(),
        },
        RuntimeSurfaceMarker {
            name: "tokenized_note_issuances".to_string(),
            category: "defi_notes".to_string(),
            root_suite: TOKENIZED_NOTE_ISSUANCE_SUITE.to_string(),
            privacy_note: "commitments-and-roots-only".to_string(),
        },
        RuntimeSurfaceMarker {
            name: "note_tranche_ledger".to_string(),
            category: "structured_credit".to_string(),
            root_suite: NOTE_TRANCHE_LEDGER_SUITE.to_string(),
            privacy_note: "commitments-and-roots-only".to_string(),
        },
        RuntimeSurfaceMarker {
            name: "barrier_observations".to_string(),
            category: "prover_failure".to_string(),
            root_suite: BARRIER_OBSERVATION_SUITE.to_string(),
            privacy_note: "commitments-and-roots-only".to_string(),
        },
        RuntimeSurfaceMarker {
            name: "coupon_accruals".to_string(),
            category: "yield".to_string(),
            root_suite: COUPON_ACCRUAL_SUITE.to_string(),
            privacy_note: "commitments-and-roots-only".to_string(),
        },
        RuntimeSurfaceMarker {
            name: "low_fee_redemption_batches".to_string(),
            category: "low_fee".to_string(),
            root_suite: REDEMPTION_BATCH_SUITE.to_string(),
            privacy_note: "commitments-and-roots-only".to_string(),
        },
        RuntimeSurfaceMarker {
            name: "speedy_settlement_receipts".to_string(),
            category: "settlement".to_string(),
            root_suite: SETTLEMENT_RECEIPT_SUITE.to_string(),
            privacy_note: "commitments-and-roots-only".to_string(),
        },
        RuntimeSurfaceMarker {
            name: "pq_committee_attestations".to_string(),
            category: "quantum_resistance".to_string(),
            root_suite: PQ_COMMITTEE_ATTESTATION_SUITE.to_string(),
            privacy_note: "commitments-and-roots-only".to_string(),
        },
        RuntimeSurfaceMarker {
            name: "anti_replay_nullifiers".to_string(),
            category: "privacy".to_string(),
            root_suite: PRIVACY_NULLIFIER_SUITE.to_string(),
            privacy_note: "commitments-and-roots-only".to_string(),
        },
        RuntimeSurfaceMarker {
            name: "roots_only_public_records".to_string(),
            category: "public_audit".to_string(),
            root_suite: PUBLIC_RECORD_SUITE.to_string(),
            privacy_note: "commitments-and-roots-only".to_string(),
        },
    ]
}
