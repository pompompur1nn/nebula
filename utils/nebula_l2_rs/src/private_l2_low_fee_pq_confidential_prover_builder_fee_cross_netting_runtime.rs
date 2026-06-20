use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePqConfidentialProverBuilderFeeCrossNettingRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROVER_BUILDER_FEE_CROSS_NETTING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-prover-builder-fee-cross-netting-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROVER_BUILDER_FEE_CROSS_NETTING_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_REBATE_ASSET_ID: &str = "sealed-builder-rebate-credit-devnet";
pub const DEVNET_HEIGHT: u64 = 2_744_000;
pub const DEVNET_EPOCH: u64 = 5_488;
pub const SEALED_PROVER_FEE_CREDIT_SCHEME: &str = "ml-kem-sealed-prover-fee-credit-root-v1";
pub const BUILDER_REBATE_BUCKET_SCHEME: &str = "confidential-builder-rebate-bucket-root-v1";
pub const PROOF_BLOB_OFFSET_SCHEME: &str = "proof-blob-cost-offset-root-v1";
pub const PQ_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256f-builder-prover-cross-netting-attestation-v1";
pub const SPONSOR_COUPON_SCHEME: &str = "ml-kem-sealed-sponsor-coupon-root-v1";
pub const CONGESTION_SMOOTHING_SCHEME: &str = "low-fee-congestion-smoothing-window-root-v1";
pub const CROSS_BATCH_SETTLEMENT_SCHEME: &str = "cross-batch-low-fee-settlement-root-v1";
pub const NETTING_LEDGER_SCHEME: &str = "confidential-prover-builder-cross-netting-ledger-root-v1";
pub const PRIVACY_GUARD_SCHEME: &str = "roots-only-private-fee-cross-netting-guard-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "roots-only-prover-builder-fee-cross-netting-public-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_addresses_amounts_key_images_view_keys_builder_orderflow_or_prover_payloads";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 48;
pub const DEFAULT_CREDIT_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_BUCKET_TTL_BLOCKS: u64 = 5_760;
pub const DEFAULT_OFFSET_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_COUPON_TTL_BLOCKS: u64 = 1_080;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_SMOOTHING_HALF_LIFE_BLOCKS: u64 = 24;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_TARGET_FEE_BPS: u64 = 8;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const DEFAULT_MAX_BUILDER_TAKE_BPS: u64 = 35;
pub const DEFAULT_MIN_REBATE_BPS: u64 = 4;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 11;
pub const DEFAULT_MAX_CONGESTION_PREMIUM_BPS: u64 = 75;
pub const DEFAULT_MAX_BLOB_OFFSET_BPS: u64 = 4_500;
pub const DEFAULT_MAX_PROOF_OFFSET_BPS: u64 = 5_500;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_800;
pub const DEFAULT_MIN_PROVER_BOND_PICONERO: u64 = 2_000_000_000;
pub const DEFAULT_MIN_BUILDER_BOND_PICONERO: u64 = 3_000_000_000;
pub const DEFAULT_LOW_FEE_CAP_PICONERO: u64 = 60_000;
pub const DEFAULT_DUST_FLOOR_PICONERO: u64 = 400;
pub const DEFAULT_RESERVE_TARGET_BPS: u64 = 1_800;
pub const DEFAULT_BATCH_FINALITY_BLOCKS: u64 = 8;
pub const MAX_SEALED_CREDITS: usize = 4_194_304;
pub const MAX_REBATE_BUCKETS: usize = 1_048_576;
pub const MAX_COST_OFFSETS: usize = 2_097_152;
pub const MAX_ATTESTATIONS: usize = 2_097_152;
pub const MAX_SPONSOR_COUPONS: usize = 2_097_152;
pub const MAX_SMOOTHING_WINDOWS: usize = 524_288;
pub const MAX_SETTLEMENT_BATCHES: usize = 1_048_576;
pub const MAX_NETTING_EVENTS: usize = 8_388_608;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

macro_rules! snake_status {
    ($name:ident { $($variant:ident => $text:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            pub fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $text),+
                }
            }
        }
    };
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ParticipantRole {
    Prover,
    Builder,
    Sponsor,
    Sequencer,
    Watchtower,
    SettlementCommittee,
    BlobProvider,
    ProofAggregator,
}

impl ParticipantRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prover => "prover",
            Self::Builder => "builder",
            Self::Sponsor => "sponsor",
            Self::Sequencer => "sequencer",
            Self::Watchtower => "watchtower",
            Self::SettlementCommittee => "settlement_committee",
            Self::BlobProvider => "blob_provider",
            Self::ProofAggregator => "proof_aggregator",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeLane {
    WalletTransfer,
    MerchantCheckout,
    PrivateContractCall,
    MoneroDeposit,
    MoneroWithdrawal,
    TokenNetting,
    DefiSettlement,
    RecursiveProof,
    BlobOnly,
    ProofOnly,
    EmergencyEscape,
    LowFeeBulk,
}

impl FeeLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletTransfer => "wallet_transfer",
            Self::MerchantCheckout => "merchant_checkout",
            Self::PrivateContractCall => "private_contract_call",
            Self::MoneroDeposit => "monero_deposit",
            Self::MoneroWithdrawal => "monero_withdrawal",
            Self::TokenNetting => "token_netting",
            Self::DefiSettlement => "defi_settlement",
            Self::RecursiveProof => "recursive_proof",
            Self::BlobOnly => "blob_only",
            Self::ProofOnly => "proof_only",
            Self::EmergencyEscape => "emergency_escape",
            Self::LowFeeBulk => "low_fee_bulk",
        }
    }

    pub fn cost_weight(self) -> u64 {
        match self {
            Self::EmergencyEscape => 1_350,
            Self::DefiSettlement => 1_150,
            Self::PrivateContractCall => 1_000,
            Self::MoneroWithdrawal => 960,
            Self::RecursiveProof => 920,
            Self::TokenNetting => 820,
            Self::MoneroDeposit => 760,
            Self::ProofOnly => 700,
            Self::BlobOnly => 650,
            Self::MerchantCheckout => 540,
            Self::WalletTransfer => 500,
            Self::LowFeeBulk => 420,
        }
    }
}

snake_status!(CreditStatus {
    Sealed => "sealed",
    Attested => "attested",
    Bucketed => "bucketed",
    OffsetReserved => "offset_reserved",
    Netting => "netting",
    Settled => "settled",
    Claimed => "claimed",
    Expired => "expired",
    Rejected => "rejected",
    Slashed => "slashed"
});

impl CreditStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::Attested | Self::Bucketed | Self::OffsetReserved | Self::Netting
        )
    }
}

snake_status!(BucketStatus {
    Proposed => "proposed",
    Active => "active",
    Filling => "filling",
    OffsetReady => "offset_ready",
    Smoothing => "smoothing",
    Settling => "settling",
    Drained => "drained",
    Frozen => "frozen",
    Retired => "retired"
});

impl BucketStatus {
    pub fn usable(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Filling | Self::OffsetReady | Self::Smoothing | Self::Settling
        )
    }
}

snake_status!(OffsetStatus {
    Quoted => "quoted",
    Reserved => "reserved",
    Applied => "applied",
    PartiallyApplied => "partially_applied",
    Rebalanced => "rebalanced",
    Settled => "settled",
    Expired => "expired",
    Rejected => "rejected"
});

impl OffsetStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Quoted | Self::Reserved | Self::Applied | Self::PartiallyApplied
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OffsetKind {
    ProofCost,
    BlobCost,
    RecursiveAggregation,
    WitnessAvailability,
    Preconfirmation,
    CouponTopUp,
    CongestionRelief,
    BuilderRebate,
}

impl OffsetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProofCost => "proof_cost",
            Self::BlobCost => "blob_cost",
            Self::RecursiveAggregation => "recursive_aggregation",
            Self::WitnessAvailability => "witness_availability",
            Self::Preconfirmation => "preconfirmation",
            Self::CouponTopUp => "coupon_top_up",
            Self::CongestionRelief => "congestion_relief",
            Self::BuilderRebate => "builder_rebate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    BuilderFeeQuote,
    ProverFeeCredit,
    JointNettingIntent,
    BlobCostWitness,
    ProofCostWitness,
    SponsorCoupon,
    CongestionSmoothing,
    SettlementRoot,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BuilderFeeQuote => "builder_fee_quote",
            Self::ProverFeeCredit => "prover_fee_credit",
            Self::JointNettingIntent => "joint_netting_intent",
            Self::BlobCostWitness => "blob_cost_witness",
            Self::ProofCostWitness => "proof_cost_witness",
            Self::SponsorCoupon => "sponsor_coupon",
            Self::CongestionSmoothing => "congestion_smoothing",
            Self::SettlementRoot => "settlement_root",
        }
    }
}

snake_status!(AttestationStatus {
    Submitted => "submitted",
    ProverSigned => "prover_signed",
    BuilderSigned => "builder_signed",
    JointlySigned => "jointly_signed",
    CommitteeWitnessed => "committee_witnessed",
    Accepted => "accepted",
    Expired => "expired",
    Rejected => "rejected",
    Slashed => "slashed"
});

snake_status!(CouponStatus {
    Sealed => "sealed",
    Reserved => "reserved",
    Applied => "applied",
    PartiallyApplied => "partially_applied",
    Exhausted => "exhausted",
    Expired => "expired",
    Revoked => "revoked"
});

snake_status!(SmoothingStatus {
    Scheduled => "scheduled",
    Open => "open",
    Dampening => "dampening",
    Subsidizing => "subsidizing",
    Settling => "settling",
    Settled => "settled",
    GuardHalted => "guard_halted",
    Expired => "expired"
});

snake_status!(BatchStatus {
    Open => "open",
    Collecting => "collecting",
    Netting => "netting",
    OffsetApplied => "offset_applied",
    Attested => "attested",
    Settling => "settling",
    Settled => "settled",
    PublicRootPublished => "public_root_published",
    Expired => "expired",
    Cancelled => "cancelled"
});

impl BatchStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open
                | Self::Collecting
                | Self::Netting
                | Self::OffsetApplied
                | Self::Attested
                | Self::Settling
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NettingEventKind {
    CreditSealed,
    BucketOpened,
    OffsetReserved,
    CouponApplied,
    CongestionSmoothed,
    BatchCrossNetted,
    BuilderRebateIssued,
    ProverCreditSettled,
    PublicRootPublished,
    PrivacyGuardRaised,
}

impl NettingEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CreditSealed => "credit_sealed",
            Self::BucketOpened => "bucket_opened",
            Self::OffsetReserved => "offset_reserved",
            Self::CouponApplied => "coupon_applied",
            Self::CongestionSmoothed => "congestion_smoothed",
            Self::BatchCrossNetted => "batch_cross_netted",
            Self::BuilderRebateIssued => "builder_rebate_issued",
            Self::ProverCreditSettled => "prover_credit_settled",
            Self::PublicRootPublished => "public_root_published",
            Self::PrivacyGuardRaised => "privacy_guard_raised",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub epoch_blocks: u64,
    pub settlement_window_blocks: u64,
    pub credit_ttl_blocks: u64,
    pub bucket_ttl_blocks: u64,
    pub offset_ttl_blocks: u64,
    pub coupon_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub smoothing_half_life_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub target_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub max_builder_take_bps: u64,
    pub min_rebate_bps: u64,
    pub target_rebate_bps: u64,
    pub max_congestion_premium_bps: u64,
    pub max_blob_offset_bps: u64,
    pub max_proof_offset_bps: u64,
    pub sponsor_cover_bps: u64,
    pub min_prover_bond_piconero: u64,
    pub min_builder_bond_piconero: u64,
    pub low_fee_cap_piconero: u64,
    pub dust_floor_piconero: u64,
    pub reserve_target_bps: u64,
    pub batch_finality_blocks: u64,
    pub allow_cross_batch_netting: bool,
    pub roots_only_public_records: bool,
    pub require_joint_pq_attestation: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEVNET_REBATE_ASSET_ID.to_string(),
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            settlement_window_blocks: DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            credit_ttl_blocks: DEFAULT_CREDIT_TTL_BLOCKS,
            bucket_ttl_blocks: DEFAULT_BUCKET_TTL_BLOCKS,
            offset_ttl_blocks: DEFAULT_OFFSET_TTL_BLOCKS,
            coupon_ttl_blocks: DEFAULT_COUPON_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            smoothing_half_life_blocks: DEFAULT_SMOOTHING_HALF_LIFE_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_fee_bps: DEFAULT_TARGET_FEE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_builder_take_bps: DEFAULT_MAX_BUILDER_TAKE_BPS,
            min_rebate_bps: DEFAULT_MIN_REBATE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            max_congestion_premium_bps: DEFAULT_MAX_CONGESTION_PREMIUM_BPS,
            max_blob_offset_bps: DEFAULT_MAX_BLOB_OFFSET_BPS,
            max_proof_offset_bps: DEFAULT_MAX_PROOF_OFFSET_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            min_prover_bond_piconero: DEFAULT_MIN_PROVER_BOND_PICONERO,
            min_builder_bond_piconero: DEFAULT_MIN_BUILDER_BOND_PICONERO,
            low_fee_cap_piconero: DEFAULT_LOW_FEE_CAP_PICONERO,
            dust_floor_piconero: DEFAULT_DUST_FLOOR_PICONERO,
            reserve_target_bps: DEFAULT_RESERVE_TARGET_BPS,
            batch_finality_blocks: DEFAULT_BATCH_FINALITY_BLOCKS,
            allow_cross_batch_netting: true,
            roots_only_public_records: true,
            require_joint_pq_attestation: true,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub sealed_credits: u64,
    pub rebate_buckets: u64,
    pub cost_offsets: u64,
    pub pq_attestations: u64,
    pub sponsor_coupons: u64,
    pub smoothing_windows: u64,
    pub settlement_batches: u64,
    pub netting_events: u64,
    pub public_snapshots: u64,
    pub settled_credits: u64,
    pub applied_offsets: u64,
    pub applied_coupons: u64,
    pub low_fee_batches: u64,
    pub privacy_guard_raises: u64,
    pub rejected_records: u64,
    pub total_user_fee_piconero: u128,
    pub total_builder_rebate_piconero: u128,
    pub total_prover_credit_piconero: u128,
    pub total_proof_offset_piconero: u128,
    pub total_blob_offset_piconero: u128,
    pub total_sponsor_cover_piconero: u128,
    pub total_congestion_relief_piconero: u128,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub sealed_credit_root: String,
    pub builder_rebate_bucket_root: String,
    pub proof_blob_offset_root: String,
    pub pq_attestation_root: String,
    pub sponsor_coupon_root: String,
    pub congestion_smoothing_root: String,
    pub cross_batch_settlement_root: String,
    pub netting_event_root: String,
    pub privacy_guard_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SealedProverFeeCredit {
    pub credit_id: String,
    pub prover_commitment: String,
    pub builder_commitment: String,
    pub lane: FeeLane,
    pub status: CreditStatus,
    pub sealed_credit_root: String,
    pub encrypted_credit_payload_root: String,
    pub nullifier_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub gross_fee_piconero: u64,
    pub low_fee_cap_piconero: u64,
    pub eligible_credit_piconero: u64,
    pub reserved_offset_piconero: u64,
    pub coupon_cover_piconero: u64,
    pub settled_credit_piconero: u64,
    pub created_height: u64,
    pub expires_height: u64,
    pub attestation_ids: BTreeSet<String>,
    pub bucket_id: Option<String>,
    pub batch_id: Option<String>,
    pub notes_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BuilderRebateBucket {
    pub bucket_id: String,
    pub builder_commitment: String,
    pub lane: FeeLane,
    pub status: BucketStatus,
    pub bucket_root: String,
    pub rebate_policy_root: String,
    pub reserve_commitment_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub target_rebate_bps: u64,
    pub max_builder_take_bps: u64,
    pub accumulated_rebate_piconero: u64,
    pub reserved_for_offsets_piconero: u64,
    pub settled_rebate_piconero: u64,
    pub opened_height: u64,
    pub expires_height: u64,
    pub credit_ids: BTreeSet<String>,
    pub offset_ids: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProofBlobCostOffset {
    pub offset_id: String,
    pub credit_id: String,
    pub bucket_id: String,
    pub kind: OffsetKind,
    pub status: OffsetStatus,
    pub offset_root: String,
    pub cost_witness_root: String,
    pub pricing_curve_root: String,
    pub proof_cost_piconero: u64,
    pub blob_cost_piconero: u64,
    pub requested_offset_piconero: u64,
    pub approved_offset_piconero: u64,
    pub applied_offset_piconero: u64,
    pub congestion_premium_bps: u64,
    pub created_height: u64,
    pub expires_height: u64,
    pub attestation_ids: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqBuilderProverAttestation {
    pub attestation_id: String,
    pub kind: AttestationKind,
    pub status: AttestationStatus,
    pub role: ParticipantRole,
    pub subject_root: String,
    pub prover_pq_key_commitment: String,
    pub builder_pq_key_commitment: String,
    pub ml_dsa_signature_root: String,
    pub slh_dsa_signature_root: String,
    pub transcript_root: String,
    pub quote_root: String,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub signed_height: u64,
    pub expires_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsorCoupon {
    pub coupon_id: String,
    pub sponsor_commitment: String,
    pub lane: FeeLane,
    pub status: CouponStatus,
    pub coupon_root: String,
    pub sealed_terms_root: String,
    pub redemption_nullifier_root: String,
    pub cover_bps: u64,
    pub max_cover_piconero: u64,
    pub reserved_cover_piconero: u64,
    pub applied_cover_piconero: u64,
    pub issued_height: u64,
    pub expires_height: u64,
    pub credit_ids: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CongestionSmoothingWindow {
    pub window_id: String,
    pub lane: FeeLane,
    pub status: SmoothingStatus,
    pub window_root: String,
    pub observed_load_bps: u64,
    pub target_load_bps: u64,
    pub congestion_premium_bps: u64,
    pub dampened_premium_bps: u64,
    pub subsidy_piconero: u64,
    pub reserve_after_piconero: u64,
    pub opened_height: u64,
    pub closes_height: u64,
    pub batch_ids: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CrossBatchSettlement {
    pub batch_id: String,
    pub lane: FeeLane,
    pub status: BatchStatus,
    pub settlement_root: String,
    pub input_credit_root: String,
    pub output_credit_root: String,
    pub bucket_root: String,
    pub offset_root: String,
    pub coupon_root: String,
    pub attestation_root: String,
    pub public_root: String,
    pub gross_user_fee_piconero: u64,
    pub net_user_fee_piconero: u64,
    pub total_builder_rebate_piconero: u64,
    pub total_prover_credit_piconero: u64,
    pub total_offsets_piconero: u64,
    pub total_coupon_cover_piconero: u64,
    pub settlement_height: u64,
    pub finality_height: u64,
    pub credit_ids: BTreeSet<String>,
    pub bucket_ids: BTreeSet<String>,
    pub offset_ids: BTreeSet<String>,
    pub coupon_ids: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NettingEvent {
    pub event_id: String,
    pub kind: NettingEventKind,
    pub lane: FeeLane,
    pub event_root: String,
    pub subject_root: String,
    pub batch_id: Option<String>,
    pub credit_id: Option<String>,
    pub bucket_id: Option<String>,
    pub amount_piconero: u64,
    pub height: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RegisterSealedCreditInput {
    pub prover_commitment: String,
    pub builder_commitment: String,
    pub lane: FeeLane,
    pub encrypted_credit_payload_root: String,
    pub nullifier_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub gross_fee_piconero: u64,
    pub sealed_credit_salt: String,
    pub notes_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpenRebateBucketInput {
    pub builder_commitment: String,
    pub lane: FeeLane,
    pub rebate_policy_root: String,
    pub reserve_commitment_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub target_rebate_bps: u64,
    pub max_builder_take_bps: u64,
    pub initial_rebate_piconero: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReserveCostOffsetInput {
    pub credit_id: String,
    pub bucket_id: String,
    pub kind: OffsetKind,
    pub cost_witness_root: String,
    pub pricing_curve_root: String,
    pub proof_cost_piconero: u64,
    pub blob_cost_piconero: u64,
    pub requested_offset_piconero: u64,
    pub congestion_premium_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SubmitPqAttestationInput {
    pub kind: AttestationKind,
    pub role: ParticipantRole,
    pub subject_root: String,
    pub prover_pq_key_commitment: String,
    pub builder_pq_key_commitment: String,
    pub ml_dsa_signature_root: String,
    pub slh_dsa_signature_root: String,
    pub transcript_root: String,
    pub quote_root: String,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IssueSponsorCouponInput {
    pub sponsor_commitment: String,
    pub lane: FeeLane,
    pub sealed_terms_root: String,
    pub redemption_nullifier_root: String,
    pub cover_bps: u64,
    pub max_cover_piconero: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ApplySponsorCouponInput {
    pub coupon_id: String,
    pub credit_id: String,
    pub requested_cover_piconero: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpenSmoothingWindowInput {
    pub lane: FeeLane,
    pub observed_load_bps: u64,
    pub target_load_bps: u64,
    pub reserve_after_piconero: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CrossBatchSettlementInput {
    pub lane: FeeLane,
    pub credit_ids: Vec<String>,
    pub bucket_ids: Vec<String>,
    pub offset_ids: Vec<String>,
    pub coupon_ids: Vec<String>,
    pub external_batch_salt: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub height: u64,
    pub epoch: u64,
    pub sealed_credits: BTreeMap<String, SealedProverFeeCredit>,
    pub builder_rebate_buckets: BTreeMap<String, BuilderRebateBucket>,
    pub proof_blob_offsets: BTreeMap<String, ProofBlobCostOffset>,
    pub pq_attestations: BTreeMap<String, PqBuilderProverAttestation>,
    pub sponsor_coupons: BTreeMap<String, SponsorCoupon>,
    pub congestion_windows: BTreeMap<String, CongestionSmoothingWindow>,
    pub settlement_batches: BTreeMap<String, CrossBatchSettlement>,
    pub netting_events: BTreeMap<String, NettingEvent>,
    pub nullifier_index: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default(), DEVNET_HEIGHT, DEVNET_EPOCH)
    }
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            height,
            epoch,
            sealed_credits: BTreeMap::new(),
            builder_rebate_buckets: BTreeMap::new(),
            proof_blob_offsets: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            sponsor_coupons: BTreeMap::new(),
            congestion_windows: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            netting_events: BTreeMap::new(),
            nullifier_index: BTreeSet::new(),
        };
        state.recompute_roots();
        state
    }

    pub fn validate_config(&self) -> Result<()> {
        ensure!(
            self.config.roots_only_public_records,
            "public records must be roots-only"
        );
        ensure!(
            self.config.min_privacy_set_size >= DEFAULT_MIN_PRIVACY_SET_SIZE,
            "privacy set too small: {}",
            self.config.min_privacy_set_size
        );
        ensure!(
            self.config.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "pq security below floor: {}",
            self.config.min_pq_security_bits
        );
        ensure!(
            self.config.target_fee_bps <= self.config.max_user_fee_bps,
            "target fee bps exceeds user cap"
        );
        ensure!(
            self.config.max_builder_take_bps <= MAX_BPS,
            "builder take bps exceeds max"
        );
        ensure!(
            self.config.sponsor_cover_bps <= MAX_BPS,
            "sponsor cover bps exceeds max"
        );
        Ok(())
    }

    pub fn register_sealed_credit(&mut self, input: RegisterSealedCreditInput) -> Result<String> {
        self.validate_config()?;
        ensure!(
            self.sealed_credits.len() < MAX_SEALED_CREDITS,
            "sealed credit capacity reached"
        );
        ensure!(
            input.privacy_set_size >= self.config.min_privacy_set_size,
            "credit privacy set too small"
        );
        ensure!(
            input.pq_security_bits >= self.config.min_pq_security_bits,
            "credit pq security too low"
        );
        ensure!(
            input.gross_fee_piconero >= self.config.dust_floor_piconero,
            "credit gross fee below dust floor"
        );
        ensure!(
            !self.nullifier_index.contains(&input.nullifier_root),
            "duplicate credit nullifier root"
        );

        let credit_id = self.next_id(
            "sealed-credit",
            &[
                HashPart::Str(input.prover_commitment.as_str()),
                HashPart::Str(input.builder_commitment.as_str()),
                HashPart::Str(input.encrypted_credit_payload_root.as_str()),
                HashPart::Str(input.nullifier_root.as_str()),
                HashPart::Str(input.sealed_credit_salt.as_str()),
            ],
        );
        let eligible_credit_piconero = self.low_fee_credit(input.gross_fee_piconero, input.lane);
        let sealed_credit_root = domain_hash(
            SEALED_PROVER_FEE_CREDIT_SCHEME,
            &[
                HashPart::Str(credit_id.as_str()),
                HashPart::Str(input.encrypted_credit_payload_root.as_str()),
                HashPart::Str(input.nullifier_root.as_str()),
                HashPart::U64(input.gross_fee_piconero),
                HashPart::U64(eligible_credit_piconero),
            ],
            32,
        );
        let credit = SealedProverFeeCredit {
            credit_id: credit_id.clone(),
            prover_commitment: input.prover_commitment,
            builder_commitment: input.builder_commitment,
            lane: input.lane,
            status: CreditStatus::Sealed,
            sealed_credit_root: sealed_credit_root.clone(),
            encrypted_credit_payload_root: input.encrypted_credit_payload_root,
            nullifier_root: input.nullifier_root.clone(),
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            gross_fee_piconero: input.gross_fee_piconero,
            low_fee_cap_piconero: self.config.low_fee_cap_piconero,
            eligible_credit_piconero,
            reserved_offset_piconero: 0,
            coupon_cover_piconero: 0,
            settled_credit_piconero: 0,
            created_height: self.height,
            expires_height: self.height.saturating_add(self.config.credit_ttl_blocks),
            attestation_ids: BTreeSet::new(),
            bucket_id: None,
            batch_id: None,
            notes_root: input.notes_root,
        };
        self.nullifier_index.insert(input.nullifier_root);
        self.sealed_credits.insert(credit_id.clone(), credit);
        self.counters.sealed_credits = self.counters.sealed_credits.saturating_add(1);
        self.counters.total_user_fee_piconero = self
            .counters
            .total_user_fee_piconero
            .saturating_add(input.gross_fee_piconero as u128);
        self.record_event(
            NettingEventKind::CreditSealed,
            input.lane,
            sealed_credit_root,
            None,
            Some(credit_id.clone()),
            None,
            eligible_credit_piconero,
        )?;
        self.recompute_roots();
        Ok(credit_id)
    }

    pub fn open_rebate_bucket(&mut self, input: OpenRebateBucketInput) -> Result<String> {
        self.validate_config()?;
        ensure!(
            self.builder_rebate_buckets.len() < MAX_REBATE_BUCKETS,
            "rebate bucket capacity reached"
        );
        ensure!(
            input.privacy_set_size >= self.config.min_privacy_set_size,
            "bucket privacy set too small"
        );
        ensure!(
            input.pq_security_bits >= self.config.min_pq_security_bits,
            "bucket pq security too low"
        );
        ensure!(
            input.target_rebate_bps >= self.config.min_rebate_bps,
            "bucket rebate below configured floor"
        );
        ensure!(
            input.max_builder_take_bps <= self.config.max_builder_take_bps,
            "builder take exceeds configured cap"
        );

        let bucket_id = self.next_id(
            "builder-rebate-bucket",
            &[
                HashPart::Str(input.builder_commitment.as_str()),
                HashPart::Str(input.rebate_policy_root.as_str()),
                HashPart::Str(input.reserve_commitment_root.as_str()),
                HashPart::U64(input.initial_rebate_piconero),
            ],
        );
        let bucket_root = domain_hash(
            BUILDER_REBATE_BUCKET_SCHEME,
            &[
                HashPart::Str(bucket_id.as_str()),
                HashPart::Str(input.builder_commitment.as_str()),
                HashPart::Str(input.reserve_commitment_root.as_str()),
                HashPart::U64(input.target_rebate_bps),
                HashPart::U64(input.initial_rebate_piconero),
            ],
            32,
        );
        let bucket = BuilderRebateBucket {
            bucket_id: bucket_id.clone(),
            builder_commitment: input.builder_commitment,
            lane: input.lane,
            status: BucketStatus::Active,
            bucket_root: bucket_root.clone(),
            rebate_policy_root: input.rebate_policy_root,
            reserve_commitment_root: input.reserve_commitment_root,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            target_rebate_bps: input.target_rebate_bps,
            max_builder_take_bps: input.max_builder_take_bps,
            accumulated_rebate_piconero: input.initial_rebate_piconero,
            reserved_for_offsets_piconero: 0,
            settled_rebate_piconero: 0,
            opened_height: self.height,
            expires_height: self.height.saturating_add(self.config.bucket_ttl_blocks),
            credit_ids: BTreeSet::new(),
            offset_ids: BTreeSet::new(),
        };
        self.builder_rebate_buckets
            .insert(bucket_id.clone(), bucket);
        self.counters.rebate_buckets = self.counters.rebate_buckets.saturating_add(1);
        self.counters.total_builder_rebate_piconero = self
            .counters
            .total_builder_rebate_piconero
            .saturating_add(input.initial_rebate_piconero as u128);
        self.record_event(
            NettingEventKind::BucketOpened,
            input.lane,
            bucket_root,
            None,
            None,
            Some(bucket_id.clone()),
            input.initial_rebate_piconero,
        )?;
        self.recompute_roots();
        Ok(bucket_id)
    }

    pub fn reserve_cost_offset(&mut self, input: ReserveCostOffsetInput) -> Result<String> {
        self.validate_config()?;
        ensure!(
            self.proof_blob_offsets.len() < MAX_COST_OFFSETS,
            "cost offset capacity reached"
        );
        ensure!(
            input.congestion_premium_bps <= self.config.max_congestion_premium_bps,
            "congestion premium exceeds low-fee cap"
        );
        let credit = self
            .sealed_credits
            .get(&input.credit_id)
            .ok_or_else(|| format!("unknown credit {}", input.credit_id))?
            .clone();
        ensure!(credit.status.live(), "credit is not live");
        let bucket = self
            .builder_rebate_buckets
            .get(&input.bucket_id)
            .ok_or_else(|| format!("unknown bucket {}", input.bucket_id))?
            .clone();
        ensure!(bucket.status.usable(), "bucket is not usable");
        ensure!(bucket.lane == credit.lane, "bucket and credit lanes differ");

        let proof_cap = mul_bps(input.proof_cost_piconero, self.config.max_proof_offset_bps);
        let blob_cap = mul_bps(input.blob_cost_piconero, self.config.max_blob_offset_bps);
        let available = bucket
            .accumulated_rebate_piconero
            .saturating_sub(bucket.reserved_for_offsets_piconero);
        let approved_offset_piconero = input
            .requested_offset_piconero
            .min(proof_cap.saturating_add(blob_cap))
            .min(available)
            .min(
                credit
                    .eligible_credit_piconero
                    .saturating_sub(credit.reserved_offset_piconero),
            );
        ensure!(
            approved_offset_piconero >= self.config.dust_floor_piconero,
            "approved offset below dust floor"
        );

        let offset_id = self.next_id(
            "proof-blob-offset",
            &[
                HashPart::Str(input.credit_id.as_str()),
                HashPart::Str(input.bucket_id.as_str()),
                HashPart::Str(input.cost_witness_root.as_str()),
                HashPart::Str(input.pricing_curve_root.as_str()),
                HashPart::U64(input.requested_offset_piconero),
            ],
        );
        let offset_root = domain_hash(
            PROOF_BLOB_OFFSET_SCHEME,
            &[
                HashPart::Str(offset_id.as_str()),
                HashPart::Str(input.credit_id.as_str()),
                HashPart::Str(input.bucket_id.as_str()),
                HashPart::Str(input.cost_witness_root.as_str()),
                HashPart::U64(approved_offset_piconero),
            ],
            32,
        );
        let offset = ProofBlobCostOffset {
            offset_id: offset_id.clone(),
            credit_id: input.credit_id.clone(),
            bucket_id: input.bucket_id.clone(),
            kind: input.kind,
            status: OffsetStatus::Reserved,
            offset_root: offset_root.clone(),
            cost_witness_root: input.cost_witness_root,
            pricing_curve_root: input.pricing_curve_root,
            proof_cost_piconero: input.proof_cost_piconero,
            blob_cost_piconero: input.blob_cost_piconero,
            requested_offset_piconero: input.requested_offset_piconero,
            approved_offset_piconero,
            applied_offset_piconero: 0,
            congestion_premium_bps: input.congestion_premium_bps,
            created_height: self.height,
            expires_height: self.height.saturating_add(self.config.offset_ttl_blocks),
            attestation_ids: BTreeSet::new(),
        };
        self.proof_blob_offsets.insert(offset_id.clone(), offset);
        if let Some(credit) = self.sealed_credits.get_mut(&input.credit_id) {
            credit.reserved_offset_piconero = credit
                .reserved_offset_piconero
                .saturating_add(approved_offset_piconero);
            credit.bucket_id = Some(input.bucket_id.clone());
            credit.status = CreditStatus::OffsetReserved;
        }
        if let Some(bucket) = self.builder_rebate_buckets.get_mut(&input.bucket_id) {
            bucket.reserved_for_offsets_piconero = bucket
                .reserved_for_offsets_piconero
                .saturating_add(approved_offset_piconero);
            bucket.credit_ids.insert(input.credit_id.clone());
            bucket.offset_ids.insert(offset_id.clone());
            bucket.status = BucketStatus::OffsetReady;
        }
        self.counters.cost_offsets = self.counters.cost_offsets.saturating_add(1);
        self.counters.total_proof_offset_piconero = self
            .counters
            .total_proof_offset_piconero
            .saturating_add(proof_cap.min(approved_offset_piconero) as u128);
        self.counters.total_blob_offset_piconero = self
            .counters
            .total_blob_offset_piconero
            .saturating_add(approved_offset_piconero.saturating_sub(proof_cap) as u128);
        self.record_event(
            NettingEventKind::OffsetReserved,
            credit.lane,
            offset_root,
            None,
            Some(input.credit_id),
            Some(input.bucket_id),
            approved_offset_piconero,
        )?;
        self.recompute_roots();
        Ok(offset_id)
    }

    pub fn submit_pq_attestation(&mut self, input: SubmitPqAttestationInput) -> Result<String> {
        self.validate_config()?;
        ensure!(
            self.pq_attestations.len() < MAX_ATTESTATIONS,
            "pq attestation capacity reached"
        );
        ensure!(
            input.pq_security_bits >= self.config.min_pq_security_bits,
            "attestation pq security too low"
        );
        ensure!(
            input.privacy_set_size >= self.config.min_privacy_set_size,
            "attestation privacy set too small"
        );
        ensure!(
            !input.ml_dsa_signature_root.is_empty() && !input.slh_dsa_signature_root.is_empty(),
            "hybrid pq signature roots are required"
        );
        let attestation_id = self.next_id(
            "pq-attestation",
            &[
                HashPart::Str(input.subject_root.as_str()),
                HashPart::Str(input.prover_pq_key_commitment.as_str()),
                HashPart::Str(input.builder_pq_key_commitment.as_str()),
                HashPart::Str(input.transcript_root.as_str()),
                HashPart::Str(input.quote_root.as_str()),
            ],
        );
        let status = match input.role {
            ParticipantRole::Prover => AttestationStatus::ProverSigned,
            ParticipantRole::Builder => AttestationStatus::BuilderSigned,
            ParticipantRole::SettlementCommittee | ParticipantRole::Watchtower => {
                AttestationStatus::CommitteeWitnessed
            }
            _ => AttestationStatus::Submitted,
        };
        let attestation = PqBuilderProverAttestation {
            attestation_id: attestation_id.clone(),
            kind: input.kind,
            status,
            role: input.role,
            subject_root: input.subject_root.clone(),
            prover_pq_key_commitment: input.prover_pq_key_commitment,
            builder_pq_key_commitment: input.builder_pq_key_commitment,
            ml_dsa_signature_root: input.ml_dsa_signature_root,
            slh_dsa_signature_root: input.slh_dsa_signature_root,
            transcript_root: input.transcript_root,
            quote_root: input.quote_root,
            pq_security_bits: input.pq_security_bits,
            privacy_set_size: input.privacy_set_size,
            signed_height: self.height,
            expires_height: self
                .height
                .saturating_add(self.config.attestation_ttl_blocks),
        };
        self.attach_attestation(input.subject_root.as_str(), attestation_id.as_str());
        self.pq_attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.pq_attestations = self.counters.pq_attestations.saturating_add(1);
        self.recompute_roots();
        Ok(attestation_id)
    }

    pub fn issue_sponsor_coupon(&mut self, input: IssueSponsorCouponInput) -> Result<String> {
        self.validate_config()?;
        ensure!(
            self.sponsor_coupons.len() < MAX_SPONSOR_COUPONS,
            "sponsor coupon capacity reached"
        );
        ensure!(
            input.cover_bps <= self.config.sponsor_cover_bps,
            "coupon cover exceeds sponsor cover cap"
        );
        ensure!(
            input.max_cover_piconero >= self.config.dust_floor_piconero,
            "coupon max cover below dust floor"
        );
        let coupon_id = self.next_id(
            "sponsor-coupon",
            &[
                HashPart::Str(input.sponsor_commitment.as_str()),
                HashPart::Str(input.sealed_terms_root.as_str()),
                HashPart::Str(input.redemption_nullifier_root.as_str()),
                HashPart::U64(input.max_cover_piconero),
            ],
        );
        let coupon_root = domain_hash(
            SPONSOR_COUPON_SCHEME,
            &[
                HashPart::Str(coupon_id.as_str()),
                HashPart::Str(input.sealed_terms_root.as_str()),
                HashPart::Str(input.redemption_nullifier_root.as_str()),
                HashPart::U64(input.cover_bps),
                HashPart::U64(input.max_cover_piconero),
            ],
            32,
        );
        let coupon = SponsorCoupon {
            coupon_id: coupon_id.clone(),
            sponsor_commitment: input.sponsor_commitment,
            lane: input.lane,
            status: CouponStatus::Sealed,
            coupon_root,
            sealed_terms_root: input.sealed_terms_root,
            redemption_nullifier_root: input.redemption_nullifier_root,
            cover_bps: input.cover_bps,
            max_cover_piconero: input.max_cover_piconero,
            reserved_cover_piconero: 0,
            applied_cover_piconero: 0,
            issued_height: self.height,
            expires_height: self.height.saturating_add(self.config.coupon_ttl_blocks),
            credit_ids: BTreeSet::new(),
        };
        self.sponsor_coupons.insert(coupon_id.clone(), coupon);
        self.counters.sponsor_coupons = self.counters.sponsor_coupons.saturating_add(1);
        self.recompute_roots();
        Ok(coupon_id)
    }

    pub fn apply_sponsor_coupon(&mut self, input: ApplySponsorCouponInput) -> Result<u64> {
        let credit = self
            .sealed_credits
            .get(&input.credit_id)
            .ok_or_else(|| format!("unknown credit {}", input.credit_id))?
            .clone();
        ensure!(credit.status.live(), "credit is not live");
        let coupon = self
            .sponsor_coupons
            .get(&input.coupon_id)
            .ok_or_else(|| format!("unknown coupon {}", input.coupon_id))?
            .clone();
        ensure!(coupon.lane == credit.lane, "coupon and credit lanes differ");
        ensure!(
            matches!(
                coupon.status,
                CouponStatus::Sealed | CouponStatus::Reserved | CouponStatus::PartiallyApplied
            ),
            "coupon cannot be applied"
        );
        ensure!(self.height <= coupon.expires_height, "coupon expired");
        let remaining_coupon = coupon
            .max_cover_piconero
            .saturating_sub(coupon.applied_cover_piconero)
            .saturating_sub(coupon.reserved_cover_piconero);
        let bps_cover = mul_bps(credit.gross_fee_piconero, coupon.cover_bps);
        let cover = input
            .requested_cover_piconero
            .min(bps_cover)
            .min(remaining_coupon)
            .min(
                credit
                    .eligible_credit_piconero
                    .saturating_sub(credit.coupon_cover_piconero),
            );
        ensure!(cover > 0, "coupon cover resolved to zero");
        if let Some(coupon) = self.sponsor_coupons.get_mut(&input.coupon_id) {
            coupon.applied_cover_piconero = coupon.applied_cover_piconero.saturating_add(cover);
            coupon.credit_ids.insert(input.credit_id.clone());
            coupon.status = if coupon.applied_cover_piconero >= coupon.max_cover_piconero {
                CouponStatus::Exhausted
            } else {
                CouponStatus::PartiallyApplied
            };
        }
        if let Some(credit) = self.sealed_credits.get_mut(&input.credit_id) {
            credit.coupon_cover_piconero = credit.coupon_cover_piconero.saturating_add(cover);
        }
        self.counters.applied_coupons = self.counters.applied_coupons.saturating_add(1);
        self.counters.total_sponsor_cover_piconero = self
            .counters
            .total_sponsor_cover_piconero
            .saturating_add(cover as u128);
        self.record_event(
            NettingEventKind::CouponApplied,
            credit.lane,
            coupon.coupon_root,
            None,
            Some(input.credit_id),
            None,
            cover,
        )?;
        self.recompute_roots();
        Ok(cover)
    }

    pub fn open_smoothing_window(&mut self, input: OpenSmoothingWindowInput) -> Result<String> {
        ensure!(
            self.congestion_windows.len() < MAX_SMOOTHING_WINDOWS,
            "smoothing window capacity reached"
        );
        ensure!(input.target_load_bps <= MAX_BPS, "target load bps invalid");
        ensure!(
            input.observed_load_bps <= MAX_BPS * 2,
            "observed load bps invalid"
        );
        let overload = input
            .observed_load_bps
            .saturating_sub(input.target_load_bps);
        let congestion_premium_bps = overload.min(self.config.max_congestion_premium_bps);
        let dampened_premium_bps = congestion_premium_bps
            .saturating_mul(self.config.smoothing_half_life_blocks)
            / self.config.settlement_window_blocks.max(1);
        let subsidy_piconero = mul_bps(
            input.lane.cost_weight().saturating_mul(100),
            dampened_premium_bps,
        );
        let window_id = self.next_id(
            "congestion-window",
            &[
                HashPart::Str(input.lane.as_str()),
                HashPart::U64(input.observed_load_bps),
                HashPart::U64(input.target_load_bps),
                HashPart::U64(input.reserve_after_piconero),
            ],
        );
        let window_root = domain_hash(
            CONGESTION_SMOOTHING_SCHEME,
            &[
                HashPart::Str(window_id.as_str()),
                HashPart::Str(input.lane.as_str()),
                HashPart::U64(input.observed_load_bps),
                HashPart::U64(dampened_premium_bps),
                HashPart::U64(subsidy_piconero),
            ],
            32,
        );
        let window = CongestionSmoothingWindow {
            window_id: window_id.clone(),
            lane: input.lane,
            status: if subsidy_piconero > 0 {
                SmoothingStatus::Subsidizing
            } else {
                SmoothingStatus::Open
            },
            window_root: window_root.clone(),
            observed_load_bps: input.observed_load_bps,
            target_load_bps: input.target_load_bps,
            congestion_premium_bps,
            dampened_premium_bps,
            subsidy_piconero,
            reserve_after_piconero: input.reserve_after_piconero,
            opened_height: self.height,
            closes_height: self
                .height
                .saturating_add(self.config.settlement_window_blocks),
            batch_ids: BTreeSet::new(),
        };
        self.congestion_windows.insert(window_id.clone(), window);
        self.counters.smoothing_windows = self.counters.smoothing_windows.saturating_add(1);
        self.counters.total_congestion_relief_piconero = self
            .counters
            .total_congestion_relief_piconero
            .saturating_add(subsidy_piconero as u128);
        self.record_event(
            NettingEventKind::CongestionSmoothed,
            input.lane,
            window_root,
            None,
            None,
            None,
            subsidy_piconero,
        )?;
        self.recompute_roots();
        Ok(window_id)
    }

    pub fn settle_cross_batch(&mut self, input: CrossBatchSettlementInput) -> Result<String> {
        ensure!(
            self.config.allow_cross_batch_netting,
            "cross-batch netting is disabled"
        );
        ensure!(
            self.settlement_batches.len() < MAX_SETTLEMENT_BATCHES,
            "settlement batch capacity reached"
        );
        ensure!(
            !input.credit_ids.is_empty(),
            "settlement needs at least one credit"
        );
        let credit_ids = input.credit_ids.into_iter().collect::<BTreeSet<_>>();
        let bucket_ids = input.bucket_ids.into_iter().collect::<BTreeSet<_>>();
        let offset_ids = input.offset_ids.into_iter().collect::<BTreeSet<_>>();
        let coupon_ids = input.coupon_ids.into_iter().collect::<BTreeSet<_>>();
        let mut gross_user_fee_piconero = 0_u64;
        let mut total_prover_credit_piconero = 0_u64;
        let mut total_offsets_piconero = 0_u64;
        let mut total_coupon_cover_piconero = 0_u64;
        for credit_id in &credit_ids {
            let credit = self
                .sealed_credits
                .get(credit_id)
                .ok_or_else(|| format!("unknown credit {credit_id}"))?;
            ensure!(credit.lane == input.lane, "settlement credit lane mismatch");
            ensure!(credit.status.live(), "settlement credit is not live");
            gross_user_fee_piconero =
                gross_user_fee_piconero.saturating_add(credit.gross_fee_piconero);
            total_offsets_piconero =
                total_offsets_piconero.saturating_add(credit.reserved_offset_piconero);
            total_coupon_cover_piconero =
                total_coupon_cover_piconero.saturating_add(credit.coupon_cover_piconero);
            total_prover_credit_piconero =
                total_prover_credit_piconero.saturating_add(credit.eligible_credit_piconero);
        }
        let mut total_builder_rebate_piconero = 0_u64;
        for bucket_id in &bucket_ids {
            let bucket = self
                .builder_rebate_buckets
                .get(bucket_id)
                .ok_or_else(|| format!("unknown bucket {bucket_id}"))?;
            ensure!(bucket.lane == input.lane, "settlement bucket lane mismatch");
            total_builder_rebate_piconero =
                total_builder_rebate_piconero.saturating_add(bucket.reserved_for_offsets_piconero);
        }
        let input_credit_root = self.id_root("settlement-input-credit-root", &credit_ids);
        let bucket_root = self.id_root("settlement-bucket-root", &bucket_ids);
        let offset_root = self.id_root("settlement-offset-root", &offset_ids);
        let coupon_root = self.id_root("settlement-coupon-root", &coupon_ids);
        let output_credit_root = domain_hash(
            "cross-batch-output-credit-root",
            &[
                HashPart::Str(input_credit_root.as_str()),
                HashPart::U64(total_prover_credit_piconero),
                HashPart::U64(total_offsets_piconero),
                HashPart::U64(total_coupon_cover_piconero),
            ],
            32,
        );
        let attestation_root = self.filtered_attestation_root(&credit_ids, &offset_ids);
        let net_user_fee_piconero = gross_user_fee_piconero
            .saturating_sub(total_offsets_piconero)
            .saturating_sub(total_coupon_cover_piconero)
            .min(
                self.config
                    .low_fee_cap_piconero
                    .saturating_mul(credit_ids.len() as u64),
            );
        let batch_id = self.next_id(
            "cross-batch-settlement",
            &[
                HashPart::Str(input.lane.as_str()),
                HashPart::Str(input_credit_root.as_str()),
                HashPart::Str(bucket_root.as_str()),
                HashPart::Str(input.external_batch_salt.as_str()),
            ],
        );
        let settlement_root = domain_hash(
            CROSS_BATCH_SETTLEMENT_SCHEME,
            &[
                HashPart::Str(batch_id.as_str()),
                HashPart::Str(input_credit_root.as_str()),
                HashPart::Str(output_credit_root.as_str()),
                HashPart::Str(offset_root.as_str()),
                HashPart::U64(net_user_fee_piconero),
            ],
            32,
        );
        let public_root = domain_hash(
            PUBLIC_RECORD_SCHEME,
            &[
                HashPart::Str(settlement_root.as_str()),
                HashPart::Str(attestation_root.as_str()),
                HashPart::U64(self.height),
            ],
            32,
        );
        let settlement = CrossBatchSettlement {
            batch_id: batch_id.clone(),
            lane: input.lane,
            status: BatchStatus::Settled,
            settlement_root: settlement_root.clone(),
            input_credit_root,
            output_credit_root,
            bucket_root,
            offset_root,
            coupon_root,
            attestation_root,
            public_root,
            gross_user_fee_piconero,
            net_user_fee_piconero,
            total_builder_rebate_piconero,
            total_prover_credit_piconero,
            total_offsets_piconero,
            total_coupon_cover_piconero,
            settlement_height: self.height,
            finality_height: self
                .height
                .saturating_add(self.config.batch_finality_blocks),
            credit_ids: credit_ids.clone(),
            bucket_ids: bucket_ids.clone(),
            offset_ids: offset_ids.clone(),
            coupon_ids: coupon_ids.clone(),
        };
        self.settlement_batches.insert(batch_id.clone(), settlement);
        for credit_id in &credit_ids {
            if let Some(credit) = self.sealed_credits.get_mut(credit_id) {
                credit.status = CreditStatus::Settled;
                credit.settled_credit_piconero = credit
                    .eligible_credit_piconero
                    .saturating_sub(credit.reserved_offset_piconero)
                    .saturating_sub(credit.coupon_cover_piconero);
                credit.batch_id = Some(batch_id.clone());
            }
        }
        for bucket_id in &bucket_ids {
            if let Some(bucket) = self.builder_rebate_buckets.get_mut(bucket_id) {
                bucket.status = BucketStatus::Settling;
                bucket.settled_rebate_piconero = bucket
                    .settled_rebate_piconero
                    .saturating_add(bucket.reserved_for_offsets_piconero);
            }
        }
        for offset_id in &offset_ids {
            if let Some(offset) = self.proof_blob_offsets.get_mut(offset_id) {
                offset.status = OffsetStatus::Settled;
                offset.applied_offset_piconero = offset.approved_offset_piconero;
            }
        }
        self.counters.settlement_batches = self.counters.settlement_batches.saturating_add(1);
        self.counters.settled_credits = self
            .counters
            .settled_credits
            .saturating_add(credit_ids.len() as u64);
        self.counters.applied_offsets = self
            .counters
            .applied_offsets
            .saturating_add(offset_ids.len() as u64);
        self.counters.low_fee_batches = self.counters.low_fee_batches.saturating_add(1);
        self.counters.total_prover_credit_piconero = self
            .counters
            .total_prover_credit_piconero
            .saturating_add(total_prover_credit_piconero as u128);
        self.record_event(
            NettingEventKind::BatchCrossNetted,
            input.lane,
            settlement_root,
            Some(batch_id.clone()),
            None,
            None,
            net_user_fee_piconero,
        )?;
        self.recompute_roots();
        Ok(batch_id)
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_attestation_scheme": PQ_ATTESTATION_SCHEME,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "height": self.height,
            "epoch": self.epoch,
            "roots": self.roots,
            "counters": self.counters,
            "status_counts": self.status_counts(),
            "config_root": self.roots.config_root,
            "roots_only_public_records": self.config.roots_only_public_records,
            "allow_cross_batch_netting": self.config.allow_cross_batch_netting,
            "require_joint_pq_attestation": self.config.require_joint_pq_attestation,
        })
    }

    fn recompute_roots(&mut self) {
        let config_json = json!(self.config);
        let counters_json = json!(self.counters);
        let credit_records = self
            .sealed_credits
            .values()
            .map(|record| json!(record))
            .collect::<Vec<_>>();
        let bucket_records = self
            .builder_rebate_buckets
            .values()
            .map(|record| json!(record))
            .collect::<Vec<_>>();
        let offset_records = self
            .proof_blob_offsets
            .values()
            .map(|record| json!(record))
            .collect::<Vec<_>>();
        let attestation_records = self
            .pq_attestations
            .values()
            .map(|record| json!(record))
            .collect::<Vec<_>>();
        let coupon_records = self
            .sponsor_coupons
            .values()
            .map(|record| json!(record))
            .collect::<Vec<_>>();
        let smoothing_records = self
            .congestion_windows
            .values()
            .map(|record| json!(record))
            .collect::<Vec<_>>();
        let batch_records = self
            .settlement_batches
            .values()
            .map(|record| json!(record))
            .collect::<Vec<_>>();
        let event_records = self
            .netting_events
            .values()
            .map(|record| json!(record))
            .collect::<Vec<_>>();
        let privacy_records = self
            .nullifier_index
            .iter()
            .map(|root| json!({ "nullifier_root": root }))
            .collect::<Vec<_>>();
        self.roots.config_root = domain_hash("config-root", &[HashPart::Json(&config_json)], 32);
        self.roots.counters_root =
            domain_hash("counters-root", &[HashPart::Json(&counters_json)], 32);
        self.roots.sealed_credit_root =
            merkle_root(SEALED_PROVER_FEE_CREDIT_SCHEME, &credit_records);
        self.roots.builder_rebate_bucket_root =
            merkle_root(BUILDER_REBATE_BUCKET_SCHEME, &bucket_records);
        self.roots.proof_blob_offset_root = merkle_root(PROOF_BLOB_OFFSET_SCHEME, &offset_records);
        self.roots.pq_attestation_root = merkle_root(PQ_ATTESTATION_SCHEME, &attestation_records);
        self.roots.sponsor_coupon_root = merkle_root(SPONSOR_COUPON_SCHEME, &coupon_records);
        self.roots.congestion_smoothing_root =
            merkle_root(CONGESTION_SMOOTHING_SCHEME, &smoothing_records);
        self.roots.cross_batch_settlement_root =
            merkle_root(CROSS_BATCH_SETTLEMENT_SCHEME, &batch_records);
        self.roots.netting_event_root = merkle_root(NETTING_LEDGER_SCHEME, &event_records);
        self.roots.privacy_guard_root = merkle_root(PRIVACY_GUARD_SCHEME, &privacy_records);
        self.roots.state_root = domain_hash(
            PROTOCOL_VERSION,
            &[
                HashPart::Str(self.roots.config_root.as_str()),
                HashPart::Str(self.roots.counters_root.as_str()),
                HashPart::Str(self.roots.sealed_credit_root.as_str()),
                HashPart::Str(self.roots.builder_rebate_bucket_root.as_str()),
                HashPart::Str(self.roots.proof_blob_offset_root.as_str()),
                HashPart::Str(self.roots.pq_attestation_root.as_str()),
                HashPart::Str(self.roots.sponsor_coupon_root.as_str()),
                HashPart::Str(self.roots.congestion_smoothing_root.as_str()),
                HashPart::Str(self.roots.cross_batch_settlement_root.as_str()),
                HashPart::Str(self.roots.netting_event_root.as_str()),
                HashPart::Str(self.roots.privacy_guard_root.as_str()),
                HashPart::U64(self.height),
                HashPart::U64(self.epoch),
            ],
            32,
        );
    }

    fn status_counts(&self) -> BTreeMap<String, u64> {
        let mut counts = BTreeMap::new();
        for credit in self.sealed_credits.values() {
            bump(&mut counts, format!("credit:{}", credit.status.as_str()));
        }
        for bucket in self.builder_rebate_buckets.values() {
            bump(&mut counts, format!("bucket:{}", bucket.status.as_str()));
        }
        for offset in self.proof_blob_offsets.values() {
            bump(&mut counts, format!("offset:{}", offset.status.as_str()));
        }
        for attestation in self.pq_attestations.values() {
            bump(
                &mut counts,
                format!("attestation:{}", attestation.status.as_str()),
            );
        }
        for coupon in self.sponsor_coupons.values() {
            bump(&mut counts, format!("coupon:{}", coupon.status.as_str()));
        }
        for window in self.congestion_windows.values() {
            bump(&mut counts, format!("smoothing:{}", window.status.as_str()));
        }
        for batch in self.settlement_batches.values() {
            bump(&mut counts, format!("batch:{}", batch.status.as_str()));
        }
        counts
    }

    fn record_event(
        &mut self,
        kind: NettingEventKind,
        lane: FeeLane,
        subject_root: String,
        batch_id: Option<String>,
        credit_id: Option<String>,
        bucket_id: Option<String>,
        amount_piconero: u64,
    ) -> Result<String> {
        ensure!(
            self.netting_events.len() < MAX_NETTING_EVENTS,
            "netting event capacity reached"
        );
        let event_id = self.next_id(
            "netting-event",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(lane.as_str()),
                HashPart::Str(subject_root.as_str()),
                HashPart::U64(amount_piconero),
                HashPart::U64(self.netting_events.len() as u64),
            ],
        );
        let event_root = domain_hash(
            NETTING_LEDGER_SCHEME,
            &[
                HashPart::Str(event_id.as_str()),
                HashPart::Str(kind.as_str()),
                HashPart::Str(subject_root.as_str()),
                HashPart::U64(amount_piconero),
                HashPart::U64(self.height),
            ],
            32,
        );
        let event = NettingEvent {
            event_id: event_id.clone(),
            kind,
            lane,
            event_root,
            subject_root,
            batch_id,
            credit_id,
            bucket_id,
            amount_piconero,
            height: self.height,
        };
        self.netting_events.insert(event_id.clone(), event);
        self.counters.netting_events = self.counters.netting_events.saturating_add(1);
        Ok(event_id)
    }

    fn attach_attestation(&mut self, subject_root: &str, attestation_id: &str) {
        for credit in self.sealed_credits.values_mut() {
            if credit.sealed_credit_root == subject_root {
                credit.attestation_ids.insert(attestation_id.to_string());
                credit.status = CreditStatus::Attested;
            }
        }
        for offset in self.proof_blob_offsets.values_mut() {
            if offset.offset_root == subject_root {
                offset.attestation_ids.insert(attestation_id.to_string());
            }
        }
    }

    fn filtered_attestation_root(
        &self,
        credit_ids: &BTreeSet<String>,
        offset_ids: &BTreeSet<String>,
    ) -> String {
        let mut roots = Vec::new();
        for credit_id in credit_ids {
            if let Some(credit) = self.sealed_credits.get(credit_id) {
                for attestation_id in &credit.attestation_ids {
                    if let Some(attestation) = self.pq_attestations.get(attestation_id) {
                        roots.push(json!(attestation));
                    }
                }
            }
        }
        for offset_id in offset_ids {
            if let Some(offset) = self.proof_blob_offsets.get(offset_id) {
                for attestation_id in &offset.attestation_ids {
                    if let Some(attestation) = self.pq_attestations.get(attestation_id) {
                        roots.push(json!(attestation));
                    }
                }
            }
        }
        merkle_root("filtered-cross-batch-pq-attestation-root", &roots)
    }

    fn id_root(&self, domain: &str, ids: &BTreeSet<String>) -> String {
        let leaves = ids.iter().map(|id| json!({ "id": id })).collect::<Vec<_>>();
        merkle_root(domain, &leaves)
    }

    fn low_fee_credit(&self, gross_fee_piconero: u64, lane: FeeLane) -> u64 {
        let lane_adjustment_bps = match lane {
            FeeLane::LowFeeBulk => 9_500,
            FeeLane::WalletTransfer => 8_500,
            FeeLane::MerchantCheckout => 8_000,
            FeeLane::BlobOnly => 7_200,
            FeeLane::ProofOnly => 7_000,
            FeeLane::TokenNetting => 6_800,
            FeeLane::MoneroDeposit => 6_500,
            FeeLane::MoneroWithdrawal => 6_200,
            FeeLane::PrivateContractCall => 5_800,
            FeeLane::RecursiveProof => 5_400,
            FeeLane::DefiSettlement => 5_000,
            FeeLane::EmergencyEscape => 3_500,
        };
        gross_fee_piconero
            .saturating_sub(self.config.low_fee_cap_piconero)
            .saturating_add(mul_bps(gross_fee_piconero, self.config.target_rebate_bps))
            .saturating_add(mul_bps(gross_fee_piconero, lane_adjustment_bps) / 16)
    }

    fn next_id(&self, domain: &str, parts: &[HashPart<'_>]) -> String {
        let payload_root = domain_hash(&format!("{domain}:payload"), parts, 32);
        domain_hash(
            domain,
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(self.height),
                HashPart::U64(self.epoch),
                HashPart::U64(self.counters.netting_events),
                HashPart::Str(payload_root.as_str()),
            ],
            16,
        )
    }
}

fn mul_bps(value: u64, bps: u64) -> u64 {
    ((value as u128).saturating_mul(bps as u128) / MAX_BPS as u128) as u64
}

fn bump(counts: &mut BTreeMap<String, u64>, key: String) {
    let next = counts
        .get(&key)
        .copied()
        .unwrap_or_default()
        .saturating_add(1);
    counts.insert(key, next);
}

pub fn devnet() -> State {
    State::default()
}
pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}
