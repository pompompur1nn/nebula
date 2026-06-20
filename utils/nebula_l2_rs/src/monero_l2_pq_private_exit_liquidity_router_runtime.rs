use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_ROUTER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-exit-liquidity-router-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_EXIT_LIQUIDITY_ROUTER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_ROUTER_ID: &str = "monero-l2-pq-private-exit-liquidity-router-devnet";
pub const DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 1_284_000;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ENCRYPTED_WITHDRAWAL_NOTE_SCHEME: &str =
    "ml-kem-1024-sealed-monero-private-exit-withdrawal-note-root-v1";
pub const MAKER_ROUTE_QUOTE_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-192f-maker-private-exit-route-quote-root-v1";
pub const RESERVE_PROOF_SCHEME: &str = "monero-view-key-redacted-reserve-proof-root-v1";
pub const SUBADDRESS_VIEWTAG_PRIVACY_SCHEME: &str =
    "monero-subaddress-viewtag-private-scan-routing-root-v1";
pub const FAST_EXIT_RESERVATION_SCHEME: &str = "pq-private-fast-exit-liquidity-reservation-root-v1";
pub const NETTED_EXIT_BATCH_SCHEME: &str = "monero-private-exit-netted-batch-root-v1";
pub const FEE_COUPON_SCHEME: &str = "private-exit-fee-coupon-nullifier-root-v1";
pub const REORG_INSURANCE_SCHEME: &str = "watchtower-backed-reorg-insurance-root-v1";
pub const WATCHTOWER_RECEIPT_SCHEME: &str = "pq-watchtower-private-exit-receipt-root-v1";
pub const NULLIFIER_FENCE_SCHEME: &str = "monero-private-exit-nullifier-fence-root-v1";
pub const PQ_ATTESTATION_SCHEME: &str = "ml-dsa-87+slh-dsa-shake-256f-router-attestation-root-v1";
pub const SLASHING_EVIDENCE_SCHEME: &str = "private-exit-router-slashing-evidence-root-v1";
pub const REPLAY_DOMAIN: &str = "monero-l2-pq-private-exit-liquidity-router-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_NOTE_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_QUOTE_TTL_BLOCKS: u64 = 18;
pub const DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 12;
pub const DEFAULT_BATCH_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_COUPON_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_INSURANCE_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_RECEIPT_FINALITY_BLOCKS: u64 = 20;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_MIN_VIEWTAG_BUCKET_SIZE: u64 = 4_096;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_500;
pub const DEFAULT_TARGET_RESERVE_COVERAGE_BPS: u64 = 12_500;
pub const DEFAULT_LOW_FEE_BPS: u64 = 3;
pub const DEFAULT_STANDARD_FEE_BPS: u64 = 9;
pub const DEFAULT_FAST_FEE_BPS: u64 = 16;
pub const DEFAULT_EMERGENCY_FEE_BPS: u64 = 24;
pub const DEFAULT_REORG_INSURANCE_BPS: u64 = 7;
pub const DEFAULT_COUPON_REBATE_BPS: u64 = 5;
pub const DEFAULT_SLASH_DOUBLE_EXIT_BPS: u64 = 5_000;
pub const DEFAULT_SLASH_FALSE_RESERVE_BPS: u64 = 3_500;
pub const DEFAULT_SLASH_MISROUTE_BPS: u64 = 1_750;
pub const DEFAULT_SLASH_STALE_RECEIPT_BPS: u64 = 900;
pub const DEFAULT_MAX_BATCH_ITEMS: usize = 768;
pub const MAX_WITHDRAWAL_NOTES: usize = 4_194_304;
pub const MAX_MAKER_QUOTES: usize = 4_194_304;
pub const MAX_RESERVE_PROOFS: usize = 2_097_152;
pub const MAX_PRIVACY_ADDRESSES: usize = 2_097_152;
pub const MAX_FAST_RESERVATIONS: usize = 4_194_304;
pub const MAX_NETTED_BATCHES: usize = 1_048_576;
pub const MAX_FEE_COUPONS: usize = 2_097_152;
pub const MAX_REORG_POLICIES: usize = 1_048_576;
pub const MAX_WATCHTOWER_RECEIPTS: usize = 4_194_304;
pub const MAX_NULLIFIER_FENCES: usize = 8_388_608;
pub const MAX_PQ_ATTESTATIONS: usize = 4_194_304;
pub const MAX_SLASHING_EVIDENCE: usize = 1_048_576;
pub const MAX_EVENTS: usize = 8_388_608;

macro_rules! snake_enum {
    ($name:ident { $($variant:ident => $text:expr),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name { $($variant),+ }
        impl $name {
            pub fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $text),+ }
            }
        }
    };
}

snake_enum!(NoteKind { WalletExit => "wallet_exit", LiquidityProviderRedeem => "liquidity_provider_redeem", DexUnwind => "dex_unwind", AtomicSwapPayout => "atomic_swap_payout", EmergencyEscape => "emergency_escape" });
snake_enum!(MakerKind { RetailFastExit => "retail_fast_exit", InstitutionalPool => "institutional_pool", DefiBackstop => "defi_backstop", BridgeOperator => "bridge_operator", EmergencyUnderwriter => "emergency_underwriter" });
snake_enum!(ReservationStatus { Held => "held", Bound => "bound", Netted => "netted", Released => "released", Expired => "expired", Slashed => "slashed" });
snake_enum!(BatchStatus { Open => "open", Sealed => "sealed", WatchtowerObserved => "watchtower_observed", MoneroBroadcast => "monero_broadcast", Finalized => "finalized", Reorged => "reorged", Disputed => "disputed", Slashed => "slashed" });
snake_enum!(CouponStatus { Minted => "minted", Reserved => "reserved", Applied => "applied", Refunded => "refunded", Expired => "expired", Slashed => "slashed" });
snake_enum!(InsuranceStatus { Quoted => "quoted", Active => "active", Locked => "locked", Claimed => "claimed", Paid => "paid", Denied => "denied", Expired => "expired" });
snake_enum!(WatchtowerReceiptKind { ViewtagScan => "viewtag_scan", ReserveObserved => "reserve_observed", BatchBroadcast => "batch_broadcast", FinalityReached => "finality_reached", ReorgDetected => "reorg_detected", MisrouteDetected => "misroute_detected", SlashingSubmitted => "slashing_submitted" });
snake_enum!(FenceKind { WithdrawalNullifier => "withdrawal_nullifier", ViewtagBucket => "viewtag_bucket", SubaddressReplay => "subaddress_replay", MakerQuoteReplay => "maker_quote_replay", ReservationReplay => "reservation_replay", CouponNullifier => "coupon_nullifier", BatchNullifier => "batch_nullifier", InsuranceClaim => "insurance_claim" });
snake_enum!(AttestationKind { MakerSolvency => "maker_solvency", ReserveProof => "reserve_proof", RoutePrivacy => "route_privacy", BatchCorrectness => "batch_correctness", WatchtowerQuorum => "watchtower_quorum", CouponValidity => "coupon_validity", InsuranceCoverage => "insurance_coverage", SlashableFault => "slashable_fault" });

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitLane {
    LowFee,
    Standard,
    Fast,
    MarketMaker,
    DefiUnwind,
    Emergency,
}
impl ExitLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::Standard => "standard",
            Self::Fast => "fast",
            Self::MarketMaker => "market_maker",
            Self::DefiUnwind => "defi_unwind",
            Self::Emergency => "emergency",
        }
    }
    pub fn fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::LowFee => config.low_fee_bps,
            Self::Standard => config.standard_fee_bps,
            Self::Fast | Self::MarketMaker => config.fast_fee_bps,
            Self::DefiUnwind => config.standard_fee_bps.saturating_add(config.low_fee_bps),
            Self::Emergency => config.emergency_fee_bps,
        }
    }
    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Emergency => 1_000,
            Self::Fast => 940,
            Self::MarketMaker => 910,
            Self::DefiUnwind => 860,
            Self::Standard => 740,
            Self::LowFee => 660,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteStatus {
    Sealed,
    Routed,
    Reserved,
    Netted,
    Settling,
    Settled,
    Expired,
    Cancelled,
    Slashed,
}
impl NoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Routed => "routed",
            Self::Reserved => "reserved",
            Self::Netted => "netted",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Slashed => "slashed",
        }
    }
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::Routed | Self::Reserved | Self::Netted | Self::Settling
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Posted,
    Matched,
    Reserved,
    Batched,
    Filled,
    Expired,
    Cancelled,
    Slashed,
}
impl QuoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Matched => "matched",
            Self::Reserved => "reserved",
            Self::Batched => "batched",
            Self::Filled => "filled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Slashed => "slashed",
        }
    }
    pub fn fillable(self) -> bool {
        matches!(self, Self::Posted | Self::Matched | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveProofStatus {
    Submitted,
    Accepted,
    Degraded,
    Superseded,
    Rejected,
    Slashed,
}
impl ReserveProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Degraded => "degraded",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
        }
    }
    pub fn usable(self) -> bool {
        matches!(self, Self::Submitted | Self::Accepted | Self::Degraded)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingReason {
    DoubleExit,
    FalseReserveProof,
    QuoteMisroute,
    StaleWatchtowerReceipt,
    InvalidPqAttestation,
    CouponReplay,
    InsuranceFraud,
    BatchWithheld,
}
impl SlashingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DoubleExit => "double_exit",
            Self::FalseReserveProof => "false_reserve_proof",
            Self::QuoteMisroute => "quote_misroute",
            Self::StaleWatchtowerReceipt => "stale_watchtower_receipt",
            Self::InvalidPqAttestation => "invalid_pq_attestation",
            Self::CouponReplay => "coupon_replay",
            Self::InsuranceFraud => "insurance_fraud",
            Self::BatchWithheld => "batch_withheld",
        }
    }
    pub fn penalty_bps(self, config: &Config) -> u64 {
        match self {
            Self::DoubleExit => config.slash_double_exit_bps,
            Self::FalseReserveProof | Self::InvalidPqAttestation => config.slash_false_reserve_bps,
            Self::StaleWatchtowerReceipt => config.slash_stale_receipt_bps,
            Self::QuoteMisroute
            | Self::CouponReplay
            | Self::InsuranceFraud
            | Self::BatchWithheld => config.slash_misroute_bps,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub router_id: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub encrypted_withdrawal_note_scheme: String,
    pub maker_route_quote_scheme: String,
    pub reserve_proof_scheme: String,
    pub subaddress_viewtag_privacy_scheme: String,
    pub fast_exit_reservation_scheme: String,
    pub netted_exit_batch_scheme: String,
    pub fee_coupon_scheme: String,
    pub reorg_insurance_scheme: String,
    pub watchtower_receipt_scheme: String,
    pub nullifier_fence_scheme: String,
    pub pq_attestation_scheme: String,
    pub slashing_evidence_scheme: String,
    pub replay_domain: String,
    pub note_ttl_blocks: u64,
    pub quote_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub coupon_ttl_blocks: u64,
    pub insurance_ttl_blocks: u64,
    pub receipt_finality_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_viewtag_bucket_size: u64,
    pub min_pq_security_bits: u16,
    pub min_reserve_coverage_bps: u64,
    pub target_reserve_coverage_bps: u64,
    pub low_fee_bps: u64,
    pub standard_fee_bps: u64,
    pub fast_fee_bps: u64,
    pub emergency_fee_bps: u64,
    pub reorg_insurance_bps: u64,
    pub coupon_rebate_bps: u64,
    pub slash_double_exit_bps: u64,
    pub slash_false_reserve_bps: u64,
    pub slash_misroute_bps: u64,
    pub slash_stale_receipt_bps: u64,
    pub max_batch_items: usize,
}
impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            router_id: DEVNET_ROUTER_ID.to_string(),
            asset_id: DEVNET_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            encrypted_withdrawal_note_scheme: ENCRYPTED_WITHDRAWAL_NOTE_SCHEME.to_string(),
            maker_route_quote_scheme: MAKER_ROUTE_QUOTE_SCHEME.to_string(),
            reserve_proof_scheme: RESERVE_PROOF_SCHEME.to_string(),
            subaddress_viewtag_privacy_scheme: SUBADDRESS_VIEWTAG_PRIVACY_SCHEME.to_string(),
            fast_exit_reservation_scheme: FAST_EXIT_RESERVATION_SCHEME.to_string(),
            netted_exit_batch_scheme: NETTED_EXIT_BATCH_SCHEME.to_string(),
            fee_coupon_scheme: FEE_COUPON_SCHEME.to_string(),
            reorg_insurance_scheme: REORG_INSURANCE_SCHEME.to_string(),
            watchtower_receipt_scheme: WATCHTOWER_RECEIPT_SCHEME.to_string(),
            nullifier_fence_scheme: NULLIFIER_FENCE_SCHEME.to_string(),
            pq_attestation_scheme: PQ_ATTESTATION_SCHEME.to_string(),
            slashing_evidence_scheme: SLASHING_EVIDENCE_SCHEME.to_string(),
            replay_domain: REPLAY_DOMAIN.to_string(),
            note_ttl_blocks: DEFAULT_NOTE_TTL_BLOCKS,
            quote_ttl_blocks: DEFAULT_QUOTE_TTL_BLOCKS,
            reservation_ttl_blocks: DEFAULT_RESERVATION_TTL_BLOCKS,
            batch_ttl_blocks: DEFAULT_BATCH_TTL_BLOCKS,
            coupon_ttl_blocks: DEFAULT_COUPON_TTL_BLOCKS,
            insurance_ttl_blocks: DEFAULT_INSURANCE_TTL_BLOCKS,
            receipt_finality_blocks: DEFAULT_RECEIPT_FINALITY_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_viewtag_bucket_size: DEFAULT_MIN_VIEWTAG_BUCKET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            target_reserve_coverage_bps: DEFAULT_TARGET_RESERVE_COVERAGE_BPS,
            low_fee_bps: DEFAULT_LOW_FEE_BPS,
            standard_fee_bps: DEFAULT_STANDARD_FEE_BPS,
            fast_fee_bps: DEFAULT_FAST_FEE_BPS,
            emergency_fee_bps: DEFAULT_EMERGENCY_FEE_BPS,
            reorg_insurance_bps: DEFAULT_REORG_INSURANCE_BPS,
            coupon_rebate_bps: DEFAULT_COUPON_REBATE_BPS,
            slash_double_exit_bps: DEFAULT_SLASH_DOUBLE_EXIT_BPS,
            slash_false_reserve_bps: DEFAULT_SLASH_FALSE_RESERVE_BPS,
            slash_misroute_bps: DEFAULT_SLASH_MISROUTE_BPS,
            slash_stale_receipt_bps: DEFAULT_SLASH_STALE_RECEIPT_BPS,
            max_batch_items: DEFAULT_MAX_BATCH_ITEMS,
        }
    }
    pub fn validate(&self) -> Result<()> {
        if self.chain_id != CHAIN_ID {
            return Err("config chain id does not match crate chain id".to_string());
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err("unsupported schema version".to_string());
        }
        validate_bps("low fee", self.low_fee_bps, MAX_BPS)?;
        validate_bps("standard fee", self.standard_fee_bps, MAX_BPS)?;
        validate_bps("fast fee", self.fast_fee_bps, MAX_BPS)?;
        validate_bps("emergency fee", self.emergency_fee_bps, MAX_BPS)?;
        validate_bps("slash double exit", self.slash_double_exit_bps, MAX_BPS)?;
        validate_bps("slash false reserve", self.slash_false_reserve_bps, MAX_BPS)?;
        validate_bps("slash misroute", self.slash_misroute_bps, MAX_BPS)?;
        validate_bps("slash stale receipt", self.slash_stale_receipt_bps, MAX_BPS)?;
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq security bits below router floor".to_string());
        }
        if self.max_batch_items == 0 {
            return Err("max batch items must be positive".to_string());
        }
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

macro_rules! record_type { ($name:ident { $($field:ident : $ty:ty),+ $(,)? }, $domain:expr) => { #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)] pub struct $name { $(pub $field: $ty),+ } impl $name { pub fn public_record(&self) -> Value { json!(self) } pub fn record_root(&self) -> String { payload_root($domain, &self.public_record()) } } }; }

record_type!(
    EncryptedWithdrawalNote {
        note_id: String,
        note_kind: NoteKind,
        lane: ExitLane,
        status: NoteStatus,
        owner_commitment: String,
        withdrawal_nullifier: String,
        amount_commitment: String,
        fee_commitment: String,
        encrypted_payload_root: String,
        recipient_subaddress_commitment: String,
        viewtag_bucket: String,
        viewtag_hint_root: String,
        decoy_set_root: String,
        route_blinding_root: String,
        min_maker_reserve_bps: u64,
        max_fee_bps: u64,
        privacy_set_size: u64,
        pq_security_bits: u16,
        opened_l2_height: u64,
        expires_l2_height: u64
    },
    "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-NOTE"
);
record_type!(
    MakerRouteQuote {
        quote_id: String,
        maker_id: String,
        maker_kind: MakerKind,
        note_id: String,
        lane: ExitLane,
        status: QuoteStatus,
        reserve_proof_id: String,
        quote_commitment_root: String,
        payout_commitment_root: String,
        fee_bps: u64,
        maker_fee_piconero: u128,
        max_fill_piconero: u128,
        min_fill_piconero: u128,
        reserve_coverage_bps: u64,
        priority_weight: u64,
        posted_l2_height: u64,
        expires_l2_height: u64
    },
    "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-QUOTE"
);
record_type!(
    ReserveProof {
        reserve_proof_id: String,
        maker_id: String,
        status: ReserveProofStatus,
        reserve_epoch: u64,
        reserve_commitment_root: String,
        view_key_audit_root: String,
        spend_key_redaction_root: String,
        liability_commitment_root: String,
        watchtower_quorum_root: String,
        coverage_bps: u64,
        liquid_piconero_commitment: String,
        locked_piconero_commitment: String,
        pq_attestation_root: String,
        observed_monero_height: u64,
        accepted_l2_height: u64
    },
    "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-RESERVE-PROOF"
);
record_type!(
    PrivacyAddressRecord {
        privacy_address_id: String,
        note_id: String,
        subaddress_commitment: String,
        viewtag_bucket: String,
        scan_hint_root: String,
        decoy_set_root: String,
        one_time_address_root: String,
        route_guard_root: String,
        min_bucket_size: u64,
        observed_bucket_size: u64,
        opened_l2_height: u64
    },
    "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-PRIVACY-ADDRESS"
);
record_type!(FastExitReservation { reservation_id: String, note_id: String, quote_id: String, maker_id: String, status: ReservationStatus, reserved_amount_commitment: String, reserved_fee_commitment: String, liquidity_ticket_root: String, coupon_id: Option<String>, insurance_policy_id: Option<String>, reservation_nullifier: String, held_l2_height: u64, expires_l2_height: u64 }, "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-RESERVATION");
record_type!(
    NettedExitBatch {
        batch_id: String,
        lane: ExitLane,
        status: BatchStatus,
        coordinator_id: String,
        note_root: String,
        quote_root: String,
        reservation_root: String,
        payout_root: String,
        nullifier_root: String,
        viewtag_bucket_root: String,
        maker_net_position_root: String,
        fee_coupon_root: String,
        insurance_root: String,
        item_count: usize,
        total_fee_piconero: u128,
        sealed_l2_height: u64,
        target_monero_height: u64
    },
    "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-BATCH"
);
record_type!(FeeCoupon { coupon_id: String, owner_commitment: String, note_id: Option<String>, status: CouponStatus, coupon_nullifier: String, sponsor_commitment: String, discount_bps: u64, max_discount_piconero: u128, eligibility_root: String, issued_l2_height: u64, expires_l2_height: u64 }, "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-COUPON");
record_type!(
    ReorgInsurancePolicy {
        policy_id: String,
        note_id: String,
        maker_id: String,
        status: InsuranceStatus,
        coverage_commitment: String,
        premium_commitment: String,
        insured_batch_root: String,
        watchtower_committee_root: String,
        claim_nullifier: String,
        coverage_bps: u64,
        opened_l2_height: u64,
        expires_l2_height: u64
    },
    "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-INSURANCE"
);
record_type!(WatchtowerReceipt { receipt_id: String, receipt_kind: WatchtowerReceiptKind, subject_id: String, batch_id: Option<String>, maker_id: Option<String>, observation_root: String, quorum_root: String, encrypted_evidence_root: String, monero_anchor_root: String, l2_anchor_root: String, observed_monero_height: u64, observed_l2_height: u64, finality_l2_height: u64 }, "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-WATCHTOWER-RECEIPT");
record_type!(NullifierFence { fence_id: String, fence_kind: FenceKind, subject_id: String, nullifier_value: String, scope_root: String, note_id: Option<String>, batch_id: Option<String>, inserted_l2_height: u64 }, "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-FENCE");
record_type!(
    PqAttestation {
        attestation_id: String,
        attestation_kind: AttestationKind,
        subject_id: String,
        signer_commitment: String,
        signature_root: String,
        transcript_root: String,
        public_key_root: String,
        security_bits: u16,
        signed_l2_height: u64
    },
    "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-PQ-ATTESTATION"
);
record_type!(SlashingEvidence { evidence_id: String, reason: SlashingReason, offender_id: String, note_id: Option<String>, quote_id: Option<String>, batch_id: Option<String>, receipt_id: Option<String>, evidence_root: String, witness_root: String, penalty_bps: u64, slashed_piconero: u128, submitted_l2_height: u64 }, "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-SLASHING");
record_type!(
    RouterEvent {
        event_id: String,
        event_type: String,
        subject_id: String,
        payload_root: String,
        sequence: u64,
        l2_height: u64
    },
    "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-EVENT"
);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub withdrawal_notes: u64,
    pub maker_quotes: u64,
    pub reserve_proofs: u64,
    pub privacy_addresses: u64,
    pub fast_reservations: u64,
    pub netted_batches: u64,
    pub fee_coupons: u64,
    pub reorg_policies: u64,
    pub watchtower_receipts: u64,
    pub nullifier_fences: u64,
    pub pq_attestations: u64,
    pub slashing_evidence: u64,
    pub events: u64,
    pub total_reserved_piconero: u128,
    pub total_fee_piconero: u128,
    pub total_coupon_discount_piconero: u128,
    pub total_insured_piconero: u128,
    pub total_slashed_piconero: u128,
}
impl Counters {
    pub fn empty() -> Self {
        Self {
            withdrawal_notes: 0,
            maker_quotes: 0,
            reserve_proofs: 0,
            privacy_addresses: 0,
            fast_reservations: 0,
            netted_batches: 0,
            fee_coupons: 0,
            reorg_policies: 0,
            watchtower_receipts: 0,
            nullifier_fences: 0,
            pq_attestations: 0,
            slashing_evidence: 0,
            events: 0,
            total_reserved_piconero: 0,
            total_fee_piconero: 0,
            total_coupon_discount_piconero: 0,
            total_insured_piconero: 0,
            total_slashed_piconero: 0,
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub withdrawal_note_root: String,
    pub maker_quote_root: String,
    pub reserve_proof_root: String,
    pub privacy_address_root: String,
    pub fast_reservation_root: String,
    pub netted_batch_root: String,
    pub fee_coupon_root: String,
    pub reorg_policy_root: String,
    pub watchtower_receipt_root: String,
    pub nullifier_fence_root: String,
    pub pq_attestation_root: String,
    pub slashing_evidence_root: String,
    pub event_root: String,
    pub maker_index_root: String,
    pub note_quote_index_root: String,
    pub batch_note_index_root: String,
    pub live_nullifier_root: String,
}
impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub current_l2_height: u64,
    pub current_monero_height: u64,
    pub withdrawal_notes: BTreeMap<String, EncryptedWithdrawalNote>,
    pub maker_quotes: BTreeMap<String, MakerRouteQuote>,
    pub reserve_proofs: BTreeMap<String, ReserveProof>,
    pub privacy_addresses: BTreeMap<String, PrivacyAddressRecord>,
    pub fast_reservations: BTreeMap<String, FastExitReservation>,
    pub netted_batches: BTreeMap<String, NettedExitBatch>,
    pub fee_coupons: BTreeMap<String, FeeCoupon>,
    pub reorg_policies: BTreeMap<String, ReorgInsurancePolicy>,
    pub watchtower_receipts: BTreeMap<String, WatchtowerReceipt>,
    pub nullifier_fences: BTreeMap<String, NullifierFence>,
    pub pq_attestations: BTreeMap<String, PqAttestation>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub events: BTreeMap<String, RouterEvent>,
    pub maker_quote_index: BTreeMap<String, BTreeSet<String>>,
    pub note_quote_index: BTreeMap<String, BTreeSet<String>>,
    pub batch_note_index: BTreeMap<String, BTreeSet<String>>,
    pub live_nullifiers: BTreeSet<String>,
    pub counters: Counters,
}

impl State {
    pub fn new(config: Config, current_l2_height: u64, current_monero_height: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            current_l2_height,
            current_monero_height,
            withdrawal_notes: BTreeMap::new(),
            maker_quotes: BTreeMap::new(),
            reserve_proofs: BTreeMap::new(),
            privacy_addresses: BTreeMap::new(),
            fast_reservations: BTreeMap::new(),
            netted_batches: BTreeMap::new(),
            fee_coupons: BTreeMap::new(),
            reorg_policies: BTreeMap::new(),
            watchtower_receipts: BTreeMap::new(),
            nullifier_fences: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            events: BTreeMap::new(),
            maker_quote_index: BTreeMap::new(),
            note_quote_index: BTreeMap::new(),
            batch_note_index: BTreeMap::new(),
            live_nullifiers: BTreeSet::new(),
            counters: Counters::empty(),
        })
    }
    pub fn devnet() -> Self {
        let mut state =
            Self::new(Config::devnet(), DEVNET_HEIGHT, 3_120_000).expect("devnet config is valid");
        for idx in 0..6_u64 {
            let maker_id = deterministic_commitment("maker", &format!("devnet-maker-{idx}"));
            let reserve = state
                .submit_reserve_proof(SubmitReserveProofRequest {
                    maker_id: maker_id.clone(),
                    reserve_epoch: 42 + idx,
                    reserve_commitment_root: deterministic_root(
                        "reserve",
                        &format!("{maker_id}:{idx}"),
                    ),
                    view_key_audit_root: deterministic_root("view-key-audit", &maker_id),
                    spend_key_redaction_root: deterministic_root("spend-key-redaction", &maker_id),
                    liability_commitment_root: deterministic_root("liability", &maker_id),
                    watchtower_quorum_root: deterministic_root("watchtower-quorum", &maker_id),
                    coverage_bps: 12_500 + (idx * 100),
                    liquid_piconero_commitment: deterministic_commitment("liquid", &maker_id),
                    locked_piconero_commitment: deterministic_commitment("locked", &maker_id),
                    pq_attestation_root: deterministic_root("reserve-pq", &maker_id),
                    observed_monero_height: state.current_monero_height + idx,
                })
                .expect("devnet reserve proof");
            let note = state
                .seal_withdrawal_note(SealWithdrawalNoteRequest {
                    note_kind: if idx % 2 == 0 {
                        NoteKind::WalletExit
                    } else {
                        NoteKind::DexUnwind
                    },
                    lane: match idx % 4 {
                        0 => ExitLane::LowFee,
                        1 => ExitLane::Standard,
                        2 => ExitLane::Fast,
                        _ => ExitLane::MarketMaker,
                    },
                    owner_commitment: deterministic_commitment(
                        "owner",
                        &format!("devnet-owner-{idx}"),
                    ),
                    withdrawal_nullifier: deterministic_nullifier(
                        "withdrawal",
                        &format!("devnet-note-{idx}"),
                    ),
                    amount_commitment: deterministic_commitment(
                        "amount",
                        &format!("devnet-note-{idx}"),
                    ),
                    fee_commitment: deterministic_commitment("fee", &format!("devnet-note-{idx}")),
                    encrypted_payload_root: deterministic_root(
                        "encrypted-note",
                        &format!("devnet-note-{idx}"),
                    ),
                    recipient_subaddress_commitment: deterministic_commitment(
                        "subaddress",
                        &format!("devnet-note-{idx}"),
                    ),
                    viewtag_bucket: format!("bucket-{idx:04}"),
                    viewtag_hint_root: deterministic_root(
                        "viewtag-hint",
                        &format!("devnet-note-{idx}"),
                    ),
                    decoy_set_root: deterministic_root("decoy-set", &format!("devnet-note-{idx}")),
                    route_blinding_root: deterministic_root(
                        "route-blinding",
                        &format!("devnet-note-{idx}"),
                    ),
                    min_maker_reserve_bps: 10_500,
                    max_fee_bps: 24,
                    privacy_set_size: 131_072 + idx * 4_096,
                    pq_security_bits: 256,
                })
                .expect("devnet withdrawal note");
            state
                .register_privacy_address(RegisterPrivacyAddressRequest {
                    note_id: note.note_id.clone(),
                    subaddress_commitment: note.recipient_subaddress_commitment.clone(),
                    viewtag_bucket: note.viewtag_bucket.clone(),
                    scan_hint_root: deterministic_root("scan-hint", &note.note_id),
                    decoy_set_root: note.decoy_set_root.clone(),
                    one_time_address_root: deterministic_root("one-time-address", &note.note_id),
                    route_guard_root: deterministic_root("route-guard", &note.note_id),
                    observed_bucket_size: 8_192 + idx * 512,
                })
                .expect("devnet privacy address");
            let quote = state
                .post_maker_quote(PostMakerQuoteRequest {
                    maker_id: maker_id.clone(),
                    maker_kind: if idx % 2 == 0 {
                        MakerKind::RetailFastExit
                    } else {
                        MakerKind::BridgeOperator
                    },
                    note_id: note.note_id.clone(),
                    lane: note.lane,
                    reserve_proof_id: reserve.reserve_proof_id.clone(),
                    quote_commitment_root: deterministic_root(
                        "quote",
                        &format!("{maker_id}:{}", note.note_id),
                    ),
                    payout_commitment_root: deterministic_root("payout", &note.note_id),
                    fee_bps: note.lane.fee_bps(&state.config),
                    maker_fee_piconero: 10_000 + idx as u128 * 1_000,
                    max_fill_piconero: 50_000_000_000 + idx as u128 * 1_000_000,
                    min_fill_piconero: 1_000_000,
                    reserve_coverage_bps: reserve.coverage_bps,
                })
                .expect("devnet quote");
            let coupon = state
                .mint_fee_coupon(MintFeeCouponRequest {
                    owner_commitment: note.owner_commitment.clone(),
                    note_id: Some(note.note_id.clone()),
                    coupon_nullifier: deterministic_nullifier("coupon", &note.note_id),
                    sponsor_commitment: deterministic_commitment(
                        "sponsor",
                        &format!("devnet-sponsor-{idx}"),
                    ),
                    discount_bps: state.config.coupon_rebate_bps,
                    max_discount_piconero: 5_000 + idx as u128 * 100,
                    eligibility_root: deterministic_root("coupon-eligibility", &note.note_id),
                })
                .expect("devnet coupon");
            let policy = state
                .open_reorg_insurance(OpenReorgInsuranceRequest {
                    note_id: note.note_id.clone(),
                    maker_id: maker_id.clone(),
                    coverage_commitment: deterministic_commitment("coverage", &note.note_id),
                    premium_commitment: deterministic_commitment("premium", &note.note_id),
                    insured_batch_root: deterministic_root("insured-batch", &note.note_id),
                    watchtower_committee_root: deterministic_root(
                        "watchtower-committee",
                        &maker_id,
                    ),
                    claim_nullifier: deterministic_nullifier("insurance-claim", &note.note_id),
                    coverage_bps: 10_000,
                })
                .expect("devnet insurance");
            let reservation = state
                .reserve_fast_exit(ReserveFastExitRequest {
                    note_id: note.note_id.clone(),
                    quote_id: quote.quote_id.clone(),
                    maker_id: maker_id.clone(),
                    reserved_amount_commitment: note.amount_commitment.clone(),
                    reserved_fee_commitment: note.fee_commitment.clone(),
                    liquidity_ticket_root: deterministic_root("liquidity-ticket", &note.note_id),
                    coupon_id: Some(coupon.coupon_id.clone()),
                    insurance_policy_id: Some(policy.policy_id.clone()),
                    reservation_nullifier: deterministic_nullifier("reservation", &note.note_id),
                })
                .expect("devnet reservation");
            state
                .submit_pq_attestation(SubmitPqAttestationRequest {
                    attestation_kind: AttestationKind::RoutePrivacy,
                    subject_id: reservation.reservation_id.clone(),
                    signer_commitment: deterministic_commitment("attestor", &maker_id),
                    signature_root: deterministic_root(
                        "attestation-signature",
                        &reservation.reservation_id,
                    ),
                    transcript_root: reservation.record_root(),
                    public_key_root: deterministic_root("attestation-pk", &maker_id),
                    security_bits: 256,
                })
                .expect("devnet attestation");
        }
        let note_ids = state
            .withdrawal_notes
            .keys()
            .take(4)
            .cloned()
            .collect::<Vec<_>>();
        state
            .seal_netted_batch(SealNettedBatchRequest {
                lane: ExitLane::Fast,
                coordinator_id: deterministic_commitment("coordinator", "devnet-fast-batch"),
                note_ids,
                payout_root: deterministic_root("batch-payout", "devnet-fast-batch"),
                maker_net_position_root: deterministic_root("maker-net", "devnet-fast-batch"),
                target_monero_height: state.current_monero_height + 24,
            })
            .expect("devnet batch");
        state
            .submit_watchtower_receipt(SubmitWatchtowerReceiptRequest {
                receipt_kind: WatchtowerReceiptKind::FinalityReached,
                subject_id: DEVNET_ROUTER_ID.to_string(),
                batch_id: state.netted_batches.keys().next().cloned(),
                maker_id: None,
                observation_root: deterministic_root("watchtower-observation", "devnet-finality"),
                quorum_root: deterministic_root("watchtower-quorum", "devnet-finality"),
                encrypted_evidence_root: deterministic_root(
                    "watchtower-evidence",
                    "devnet-finality",
                ),
                monero_anchor_root: deterministic_root("monero-anchor", "devnet-finality"),
                l2_anchor_root: deterministic_root("l2-anchor", "devnet-finality"),
                observed_monero_height: state.current_monero_height + 30,
            })
            .expect("devnet receipt");
        state
    }
    pub fn roots(&self) -> Roots {
        Roots {
            config_root: payload_root(
                "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-CONFIG",
                &self.config.public_record(),
            ),
            withdrawal_note_root: map_root(
                "monero-l2-pq-private-exit-liquidity-router:notes",
                &self.withdrawal_notes,
            ),
            maker_quote_root: map_root(
                "monero-l2-pq-private-exit-liquidity-router:quotes",
                &self.maker_quotes,
            ),
            reserve_proof_root: map_root(
                "monero-l2-pq-private-exit-liquidity-router:reserve-proofs",
                &self.reserve_proofs,
            ),
            privacy_address_root: map_root(
                "monero-l2-pq-private-exit-liquidity-router:privacy-addresses",
                &self.privacy_addresses,
            ),
            fast_reservation_root: map_root(
                "monero-l2-pq-private-exit-liquidity-router:reservations",
                &self.fast_reservations,
            ),
            netted_batch_root: map_root(
                "monero-l2-pq-private-exit-liquidity-router:batches",
                &self.netted_batches,
            ),
            fee_coupon_root: map_root(
                "monero-l2-pq-private-exit-liquidity-router:coupons",
                &self.fee_coupons,
            ),
            reorg_policy_root: map_root(
                "monero-l2-pq-private-exit-liquidity-router:insurance",
                &self.reorg_policies,
            ),
            watchtower_receipt_root: map_root(
                "monero-l2-pq-private-exit-liquidity-router:watchtower-receipts",
                &self.watchtower_receipts,
            ),
            nullifier_fence_root: map_root(
                "monero-l2-pq-private-exit-liquidity-router:nullifier-fences",
                &self.nullifier_fences,
            ),
            pq_attestation_root: map_root(
                "monero-l2-pq-private-exit-liquidity-router:pq-attestations",
                &self.pq_attestations,
            ),
            slashing_evidence_root: map_root(
                "monero-l2-pq-private-exit-liquidity-router:slashing-evidence",
                &self.slashing_evidence,
            ),
            event_root: map_root(
                "monero-l2-pq-private-exit-liquidity-router:events",
                &self.events,
            ),
            maker_index_root: nested_set_root(
                "monero-l2-pq-private-exit-liquidity-router:maker-index",
                &self.maker_quote_index,
            ),
            note_quote_index_root: nested_set_root(
                "monero-l2-pq-private-exit-liquidity-router:note-quote-index",
                &self.note_quote_index,
            ),
            batch_note_index_root: nested_set_root(
                "monero-l2-pq-private-exit-liquidity-router:batch-note-index",
                &self.batch_note_index,
            ),
            live_nullifier_root: set_root(
                "monero-l2-pq-private-exit-liquidity-router:live-nullifiers",
                &self.live_nullifiers,
            ),
        }
    }
    pub fn public_record(&self) -> Value {
        json!({ "protocol_version": PROTOCOL_VERSION, "chain_id": CHAIN_ID, "current_l2_height": self.current_l2_height, "current_monero_height": self.current_monero_height, "config": self.config.public_record(), "roots": self.roots().public_record(), "counters": self.counters.public_record() })
    }
    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record())
    }

    pub fn seal_withdrawal_note(
        &mut self,
        request: SealWithdrawalNoteRequest,
    ) -> Result<EncryptedWithdrawalNote> {
        self.ensure_capacity(
            "withdrawal notes",
            self.withdrawal_notes.len(),
            MAX_WITHDRAWAL_NOTES,
        )?;
        require_nonempty("owner commitment", &request.owner_commitment)?;
        require_nonempty("withdrawal nullifier", &request.withdrawal_nullifier)?;
        require_absent(
            &self.live_nullifiers,
            "withdrawal nullifier",
            &request.withdrawal_nullifier,
        )?;
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("withdrawal note privacy set below router floor".to_string());
        }
        if request.pq_security_bits < self.config.min_pq_security_bits {
            return Err("withdrawal note pq security below router floor".to_string());
        }
        validate_bps("max fee", request.max_fee_bps, MAX_BPS)?;
        validate_bps("min maker reserve", request.min_maker_reserve_bps, 20_000)?;
        let sequence = self.withdrawal_notes.len() as u64;
        let note_id = withdrawal_note_id(sequence, &request, self.current_l2_height);
        let note = EncryptedWithdrawalNote {
            note_id: note_id.clone(),
            note_kind: request.note_kind,
            lane: request.lane,
            status: NoteStatus::Sealed,
            owner_commitment: request.owner_commitment,
            withdrawal_nullifier: request.withdrawal_nullifier.clone(),
            amount_commitment: request.amount_commitment,
            fee_commitment: request.fee_commitment,
            encrypted_payload_root: request.encrypted_payload_root,
            recipient_subaddress_commitment: request.recipient_subaddress_commitment,
            viewtag_bucket: request.viewtag_bucket,
            viewtag_hint_root: request.viewtag_hint_root,
            decoy_set_root: request.decoy_set_root,
            route_blinding_root: request.route_blinding_root,
            min_maker_reserve_bps: request.min_maker_reserve_bps,
            max_fee_bps: request.max_fee_bps,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            opened_l2_height: self.current_l2_height,
            expires_l2_height: self
                .current_l2_height
                .saturating_add(self.config.note_ttl_blocks),
        };
        self.live_nullifiers
            .insert(request.withdrawal_nullifier.clone());
        self.insert_fence(
            FenceKind::WithdrawalNullifier,
            note_id.clone(),
            request.withdrawal_nullifier,
            Some(note_id.clone()),
            None,
        )?;
        self.withdrawal_notes.insert(note_id.clone(), note.clone());
        self.counters.withdrawal_notes += 1;
        self.record_event("withdrawal_note_sealed", &note_id, &note.public_record())?;
        Ok(note)
    }
    pub fn register_privacy_address(
        &mut self,
        request: RegisterPrivacyAddressRequest,
    ) -> Result<PrivacyAddressRecord> {
        self.ensure_capacity(
            "privacy addresses",
            self.privacy_addresses.len(),
            MAX_PRIVACY_ADDRESSES,
        )?;
        require_present(&self.withdrawal_notes, "note", &request.note_id)?;
        if request.observed_bucket_size < self.config.min_viewtag_bucket_size {
            return Err("viewtag bucket below privacy floor".to_string());
        }
        let privacy_address_id = privacy_address_id(
            &request.note_id,
            &request.subaddress_commitment,
            &request.viewtag_bucket,
            self.current_l2_height,
        );
        let record = PrivacyAddressRecord {
            privacy_address_id: privacy_address_id.clone(),
            note_id: request.note_id.clone(),
            subaddress_commitment: request.subaddress_commitment.clone(),
            viewtag_bucket: request.viewtag_bucket.clone(),
            scan_hint_root: request.scan_hint_root,
            decoy_set_root: request.decoy_set_root,
            one_time_address_root: request.one_time_address_root,
            route_guard_root: request.route_guard_root,
            min_bucket_size: self.config.min_viewtag_bucket_size,
            observed_bucket_size: request.observed_bucket_size,
            opened_l2_height: self.current_l2_height,
        };
        self.insert_fence(
            FenceKind::SubaddressReplay,
            request.note_id.clone(),
            request.subaddress_commitment,
            Some(request.note_id.clone()),
            None,
        )?;
        self.insert_fence(
            FenceKind::ViewtagBucket,
            request.note_id.clone(),
            request.viewtag_bucket,
            Some(request.note_id),
            None,
        )?;
        self.privacy_addresses
            .insert(privacy_address_id.clone(), record.clone());
        self.counters.privacy_addresses += 1;
        self.record_event(
            "privacy_address_registered",
            &privacy_address_id,
            &record.public_record(),
        )?;
        Ok(record)
    }
    pub fn submit_reserve_proof(
        &mut self,
        request: SubmitReserveProofRequest,
    ) -> Result<ReserveProof> {
        self.ensure_capacity(
            "reserve proofs",
            self.reserve_proofs.len(),
            MAX_RESERVE_PROOFS,
        )?;
        require_nonempty("maker id", &request.maker_id)?;
        validate_bps("coverage", request.coverage_bps, 20_000)?;
        let status = if request.coverage_bps >= self.config.min_reserve_coverage_bps {
            ReserveProofStatus::Accepted
        } else {
            ReserveProofStatus::Degraded
        };
        let reserve_proof_id = reserve_proof_id(
            &request.maker_id,
            request.reserve_epoch,
            &request.reserve_commitment_root,
            self.current_l2_height,
        );
        let proof = ReserveProof {
            reserve_proof_id: reserve_proof_id.clone(),
            maker_id: request.maker_id.clone(),
            status,
            reserve_epoch: request.reserve_epoch,
            reserve_commitment_root: request.reserve_commitment_root,
            view_key_audit_root: request.view_key_audit_root,
            spend_key_redaction_root: request.spend_key_redaction_root,
            liability_commitment_root: request.liability_commitment_root,
            watchtower_quorum_root: request.watchtower_quorum_root,
            coverage_bps: request.coverage_bps,
            liquid_piconero_commitment: request.liquid_piconero_commitment,
            locked_piconero_commitment: request.locked_piconero_commitment,
            pq_attestation_root: request.pq_attestation_root,
            observed_monero_height: request.observed_monero_height,
            accepted_l2_height: self.current_l2_height,
        };
        self.reserve_proofs
            .insert(reserve_proof_id.clone(), proof.clone());
        self.counters.reserve_proofs += 1;
        self.record_event(
            "reserve_proof_submitted",
            &reserve_proof_id,
            &proof.public_record(),
        )?;
        Ok(proof)
    }
    pub fn post_maker_quote(&mut self, request: PostMakerQuoteRequest) -> Result<MakerRouteQuote> {
        self.ensure_capacity("maker quotes", self.maker_quotes.len(), MAX_MAKER_QUOTES)?;
        let note = require_present(&self.withdrawal_notes, "note", &request.note_id)?;
        let proof = require_present(
            &self.reserve_proofs,
            "reserve proof",
            &request.reserve_proof_id,
        )?;
        if proof.maker_id != request.maker_id {
            return Err("reserve proof maker does not match quote maker".to_string());
        }
        if !proof.status.usable() {
            return Err("reserve proof is not usable for quote".to_string());
        }
        if request.reserve_coverage_bps < note.min_maker_reserve_bps {
            return Err("quote reserve coverage below note requirement".to_string());
        }
        if request.fee_bps > note.max_fee_bps {
            return Err("quote fee exceeds note max fee".to_string());
        }
        let quote_id = maker_quote_id(
            &request.maker_id,
            &request.note_id,
            &request.quote_commitment_root,
            self.current_l2_height,
        );
        let quote = MakerRouteQuote {
            quote_id: quote_id.clone(),
            maker_id: request.maker_id.clone(),
            maker_kind: request.maker_kind,
            note_id: request.note_id.clone(),
            lane: request.lane,
            status: QuoteStatus::Posted,
            reserve_proof_id: request.reserve_proof_id,
            quote_commitment_root: request.quote_commitment_root.clone(),
            payout_commitment_root: request.payout_commitment_root,
            fee_bps: request.fee_bps,
            maker_fee_piconero: request.maker_fee_piconero,
            max_fill_piconero: request.max_fill_piconero,
            min_fill_piconero: request.min_fill_piconero,
            reserve_coverage_bps: request.reserve_coverage_bps,
            priority_weight: request.lane.priority_weight(),
            posted_l2_height: self.current_l2_height,
            expires_l2_height: self
                .current_l2_height
                .saturating_add(self.config.quote_ttl_blocks),
        };
        self.insert_fence(
            FenceKind::MakerQuoteReplay,
            quote_id.clone(),
            request.quote_commitment_root,
            Some(request.note_id.clone()),
            None,
        )?;
        self.maker_quote_index
            .entry(request.maker_id)
            .or_default()
            .insert(quote_id.clone());
        self.note_quote_index
            .entry(request.note_id.clone())
            .or_default()
            .insert(quote_id.clone());
        self.maker_quotes.insert(quote_id.clone(), quote.clone());
        self.counters.maker_quotes += 1;
        if let Some(note) = self.withdrawal_notes.get_mut(&request.note_id) {
            note.status = NoteStatus::Routed;
        }
        self.record_event("maker_quote_posted", &quote_id, &quote.public_record())?;
        Ok(quote)
    }
    pub fn reserve_fast_exit(
        &mut self,
        request: ReserveFastExitRequest,
    ) -> Result<FastExitReservation> {
        self.ensure_capacity(
            "fast reservations",
            self.fast_reservations.len(),
            MAX_FAST_RESERVATIONS,
        )?;
        require_present(&self.withdrawal_notes, "note", &request.note_id)?;
        let quote = require_present(&self.maker_quotes, "quote", &request.quote_id)?;
        if quote.maker_id != request.maker_id || quote.note_id != request.note_id {
            return Err("reservation quote binding mismatch".to_string());
        }
        if !quote.status.fillable() {
            return Err("quote is not fillable".to_string());
        }
        require_absent(
            &self.live_nullifiers,
            "reservation nullifier",
            &request.reservation_nullifier,
        )?;
        let reservation_id = fast_reservation_id(
            &request.note_id,
            &request.quote_id,
            &request.reservation_nullifier,
            self.current_l2_height,
        );
        let reservation = FastExitReservation {
            reservation_id: reservation_id.clone(),
            note_id: request.note_id.clone(),
            quote_id: request.quote_id.clone(),
            maker_id: request.maker_id,
            status: ReservationStatus::Held,
            reserved_amount_commitment: request.reserved_amount_commitment,
            reserved_fee_commitment: request.reserved_fee_commitment,
            liquidity_ticket_root: request.liquidity_ticket_root,
            coupon_id: request.coupon_id,
            insurance_policy_id: request.insurance_policy_id,
            reservation_nullifier: request.reservation_nullifier.clone(),
            held_l2_height: self.current_l2_height,
            expires_l2_height: self
                .current_l2_height
                .saturating_add(self.config.reservation_ttl_blocks),
        };
        self.live_nullifiers
            .insert(request.reservation_nullifier.clone());
        self.insert_fence(
            FenceKind::ReservationReplay,
            reservation_id.clone(),
            request.reservation_nullifier,
            Some(request.note_id.clone()),
            None,
        )?;
        if let Some(note) = self.withdrawal_notes.get_mut(&request.note_id) {
            note.status = NoteStatus::Reserved;
        }
        if let Some(quote) = self.maker_quotes.get_mut(&request.quote_id) {
            quote.status = QuoteStatus::Reserved;
        }
        self.fast_reservations
            .insert(reservation_id.clone(), reservation.clone());
        self.counters.fast_reservations += 1;
        self.record_event(
            "fast_exit_reserved",
            &reservation_id,
            &reservation.public_record(),
        )?;
        Ok(reservation)
    }
    pub fn mint_fee_coupon(&mut self, request: MintFeeCouponRequest) -> Result<FeeCoupon> {
        self.ensure_capacity("fee coupons", self.fee_coupons.len(), MAX_FEE_COUPONS)?;
        require_nonempty("coupon nullifier", &request.coupon_nullifier)?;
        require_absent(
            &self.live_nullifiers,
            "coupon nullifier",
            &request.coupon_nullifier,
        )?;
        validate_bps("discount", request.discount_bps, MAX_BPS)?;
        let coupon_id = fee_coupon_id(
            &request.owner_commitment,
            &request.coupon_nullifier,
            self.current_l2_height,
        );
        let coupon = FeeCoupon {
            coupon_id: coupon_id.clone(),
            owner_commitment: request.owner_commitment,
            note_id: request.note_id.clone(),
            status: CouponStatus::Minted,
            coupon_nullifier: request.coupon_nullifier.clone(),
            sponsor_commitment: request.sponsor_commitment,
            discount_bps: request.discount_bps,
            max_discount_piconero: request.max_discount_piconero,
            eligibility_root: request.eligibility_root,
            issued_l2_height: self.current_l2_height,
            expires_l2_height: self
                .current_l2_height
                .saturating_add(self.config.coupon_ttl_blocks),
        };
        self.live_nullifiers
            .insert(request.coupon_nullifier.clone());
        self.insert_fence(
            FenceKind::CouponNullifier,
            coupon_id.clone(),
            request.coupon_nullifier,
            request.note_id,
            None,
        )?;
        self.counters.total_coupon_discount_piconero = self
            .counters
            .total_coupon_discount_piconero
            .saturating_add(coupon.max_discount_piconero);
        self.fee_coupons.insert(coupon_id.clone(), coupon.clone());
        self.counters.fee_coupons += 1;
        self.record_event("fee_coupon_minted", &coupon_id, &coupon.public_record())?;
        Ok(coupon)
    }
    pub fn open_reorg_insurance(
        &mut self,
        request: OpenReorgInsuranceRequest,
    ) -> Result<ReorgInsurancePolicy> {
        self.ensure_capacity(
            "reorg policies",
            self.reorg_policies.len(),
            MAX_REORG_POLICIES,
        )?;
        require_present(&self.withdrawal_notes, "note", &request.note_id)?;
        require_nonempty("claim nullifier", &request.claim_nullifier)?;
        require_absent(
            &self.live_nullifiers,
            "claim nullifier",
            &request.claim_nullifier,
        )?;
        validate_bps("coverage", request.coverage_bps, MAX_BPS)?;
        let policy_id = reorg_policy_id(
            &request.note_id,
            &request.maker_id,
            &request.claim_nullifier,
            self.current_l2_height,
        );
        let policy = ReorgInsurancePolicy {
            policy_id: policy_id.clone(),
            note_id: request.note_id.clone(),
            maker_id: request.maker_id,
            status: InsuranceStatus::Active,
            coverage_commitment: request.coverage_commitment,
            premium_commitment: request.premium_commitment,
            insured_batch_root: request.insured_batch_root,
            watchtower_committee_root: request.watchtower_committee_root,
            claim_nullifier: request.claim_nullifier.clone(),
            coverage_bps: request.coverage_bps,
            opened_l2_height: self.current_l2_height,
            expires_l2_height: self
                .current_l2_height
                .saturating_add(self.config.insurance_ttl_blocks),
        };
        self.live_nullifiers.insert(request.claim_nullifier.clone());
        self.insert_fence(
            FenceKind::InsuranceClaim,
            policy_id.clone(),
            request.claim_nullifier,
            Some(request.note_id.clone()),
            None,
        )?;
        self.counters.total_insured_piconero =
            self.counters.total_insured_piconero.saturating_add(1);
        self.reorg_policies
            .insert(policy_id.clone(), policy.clone());
        self.counters.reorg_policies += 1;
        self.record_event(
            "reorg_insurance_opened",
            &policy_id,
            &policy.public_record(),
        )?;
        Ok(policy)
    }

    pub fn seal_netted_batch(
        &mut self,
        request: SealNettedBatchRequest,
    ) -> Result<NettedExitBatch> {
        self.ensure_capacity(
            "netted batches",
            self.netted_batches.len(),
            MAX_NETTED_BATCHES,
        )?;
        if request.note_ids.is_empty() {
            return Err("netted batch requires notes".to_string());
        }
        if request.note_ids.len() > self.config.max_batch_items {
            return Err("netted batch exceeds max item count".to_string());
        }
        let mut note_records = Vec::new();
        let mut quote_records = Vec::new();
        let mut reservation_records = Vec::new();
        let mut nullifiers = BTreeSet::new();
        for note_id in &request.note_ids {
            let note = require_present(&self.withdrawal_notes, "note", note_id)?;
            if !note.status.live() {
                return Err("batch contains non-live note".to_string());
            }
            note_records.push(note.public_record());
            nullifiers.insert(note.withdrawal_nullifier.clone());
            if let Some(quote_ids) = self.note_quote_index.get(note_id) {
                for quote_id in quote_ids {
                    if let Some(quote) = self.maker_quotes.get(quote_id) {
                        quote_records.push(quote.public_record());
                    }
                }
            }
            for reservation in self
                .fast_reservations
                .values()
                .filter(|reservation| reservation.note_id == *note_id)
            {
                reservation_records.push(reservation.public_record());
            }
        }
        let note_root = merkle_root(
            "monero-l2-pq-private-exit-router:batch-notes",
            &note_records,
        );
        let quote_root = merkle_root(
            "monero-l2-pq-private-exit-router:batch-quotes",
            &quote_records,
        );
        let reservation_root = merkle_root(
            "monero-l2-pq-private-exit-router:batch-reservations",
            &reservation_records,
        );
        let nullifier_leaves = nullifiers
            .iter()
            .map(|value| json!({ "nullifier": value }))
            .collect::<Vec<_>>();
        let nullifier_root = merkle_root(
            "monero-l2-pq-private-exit-router:batch-nullifiers",
            &nullifier_leaves,
        );
        let viewtag_leaves = request
            .note_ids
            .iter()
            .filter_map(|note_id| self.withdrawal_notes.get(note_id))
            .map(|note| json!({ "note_id": note.note_id, "viewtag_bucket": note.viewtag_bucket }))
            .collect::<Vec<_>>();
        let viewtag_bucket_root = merkle_root(
            "monero-l2-pq-private-exit-router:batch-viewtags",
            &viewtag_leaves,
        );
        let coupon_leaves = self
            .fee_coupons
            .values()
            .filter(|coupon| {
                coupon
                    .note_id
                    .as_ref()
                    .map(|note_id| request.note_ids.contains(note_id))
                    .unwrap_or(false)
            })
            .map(FeeCoupon::public_record)
            .collect::<Vec<_>>();
        let fee_coupon_root = merkle_root(
            "monero-l2-pq-private-exit-router:batch-coupons",
            &coupon_leaves,
        );
        let insurance_leaves = self
            .reorg_policies
            .values()
            .filter(|policy| request.note_ids.contains(&policy.note_id))
            .map(ReorgInsurancePolicy::public_record)
            .collect::<Vec<_>>();
        let insurance_root = merkle_root(
            "monero-l2-pq-private-exit-router:batch-insurance",
            &insurance_leaves,
        );
        let batch_id = netted_batch_id(
            &request.coordinator_id,
            request.lane,
            &note_root,
            &nullifier_root,
            self.current_l2_height,
        );
        let batch = NettedExitBatch {
            batch_id: batch_id.clone(),
            lane: request.lane,
            status: BatchStatus::Sealed,
            coordinator_id: request.coordinator_id,
            note_root,
            quote_root,
            reservation_root,
            payout_root: request.payout_root,
            nullifier_root: nullifier_root.clone(),
            viewtag_bucket_root,
            maker_net_position_root: request.maker_net_position_root,
            fee_coupon_root,
            insurance_root,
            item_count: request.note_ids.len(),
            total_fee_piconero: 0,
            sealed_l2_height: self.current_l2_height,
            target_monero_height: request.target_monero_height,
        };
        for note_id in &request.note_ids {
            if let Some(note) = self.withdrawal_notes.get_mut(note_id) {
                note.status = NoteStatus::Netted;
            }
            self.batch_note_index
                .entry(batch_id.clone())
                .or_default()
                .insert(note_id.clone());
        }
        self.insert_fence(
            FenceKind::BatchNullifier,
            batch_id.clone(),
            nullifier_root,
            None,
            Some(batch_id.clone()),
        )?;
        self.netted_batches.insert(batch_id.clone(), batch.clone());
        self.counters.netted_batches += 1;
        self.record_event(
            "netted_exit_batch_sealed",
            &batch_id,
            &batch.public_record(),
        )?;
        Ok(batch)
    }
    pub fn submit_watchtower_receipt(
        &mut self,
        request: SubmitWatchtowerReceiptRequest,
    ) -> Result<WatchtowerReceipt> {
        self.ensure_capacity(
            "watchtower receipts",
            self.watchtower_receipts.len(),
            MAX_WATCHTOWER_RECEIPTS,
        )?;
        let receipt_id = watchtower_receipt_id(
            request.receipt_kind,
            &request.subject_id,
            &request.observation_root,
            self.current_l2_height,
        );
        let receipt = WatchtowerReceipt {
            receipt_id: receipt_id.clone(),
            receipt_kind: request.receipt_kind,
            subject_id: request.subject_id,
            batch_id: request.batch_id,
            maker_id: request.maker_id,
            observation_root: request.observation_root,
            quorum_root: request.quorum_root,
            encrypted_evidence_root: request.encrypted_evidence_root,
            monero_anchor_root: request.monero_anchor_root,
            l2_anchor_root: request.l2_anchor_root,
            observed_monero_height: request.observed_monero_height,
            observed_l2_height: self.current_l2_height,
            finality_l2_height: self
                .current_l2_height
                .saturating_add(self.config.receipt_finality_blocks),
        };
        self.watchtower_receipts
            .insert(receipt_id.clone(), receipt.clone());
        self.counters.watchtower_receipts += 1;
        self.record_event(
            "watchtower_receipt_submitted",
            &receipt_id,
            &receipt.public_record(),
        )?;
        Ok(receipt)
    }
    pub fn submit_pq_attestation(
        &mut self,
        request: SubmitPqAttestationRequest,
    ) -> Result<PqAttestation> {
        self.ensure_capacity(
            "pq attestations",
            self.pq_attestations.len(),
            MAX_PQ_ATTESTATIONS,
        )?;
        if request.security_bits < self.config.min_pq_security_bits {
            return Err("pq attestation below security floor".to_string());
        }
        let attestation_id = pq_attestation_id(
            request.attestation_kind,
            &request.subject_id,
            &request.signer_commitment,
            &request.transcript_root,
            self.current_l2_height,
        );
        let attestation = PqAttestation {
            attestation_id: attestation_id.clone(),
            attestation_kind: request.attestation_kind,
            subject_id: request.subject_id,
            signer_commitment: request.signer_commitment,
            signature_root: request.signature_root,
            transcript_root: request.transcript_root,
            public_key_root: request.public_key_root,
            security_bits: request.security_bits,
            signed_l2_height: self.current_l2_height,
        };
        self.pq_attestations
            .insert(attestation_id.clone(), attestation.clone());
        self.counters.pq_attestations += 1;
        self.record_event(
            "pq_attestation_submitted",
            &attestation_id,
            &attestation.public_record(),
        )?;
        Ok(attestation)
    }
    pub fn submit_slashing_evidence(
        &mut self,
        request: SubmitSlashingEvidenceRequest,
    ) -> Result<SlashingEvidence> {
        self.ensure_capacity(
            "slashing evidence",
            self.slashing_evidence.len(),
            MAX_SLASHING_EVIDENCE,
        )?;
        require_nonempty("offender id", &request.offender_id)?;
        let penalty_bps = request.reason.penalty_bps(&self.config);
        let slashed_piconero = bps_amount(request.base_bond_piconero, penalty_bps);
        let evidence_id = slashing_evidence_id(
            &request.offender_id,
            request.reason,
            &request.evidence_root,
            self.current_l2_height,
        );
        let evidence = SlashingEvidence {
            evidence_id: evidence_id.clone(),
            reason: request.reason,
            offender_id: request.offender_id,
            note_id: request.note_id,
            quote_id: request.quote_id,
            batch_id: request.batch_id,
            receipt_id: request.receipt_id,
            evidence_root: request.evidence_root,
            witness_root: request.witness_root,
            penalty_bps,
            slashed_piconero,
            submitted_l2_height: self.current_l2_height,
        };
        self.counters.total_slashed_piconero = self
            .counters
            .total_slashed_piconero
            .saturating_add(slashed_piconero);
        self.slashing_evidence
            .insert(evidence_id.clone(), evidence.clone());
        self.counters.slashing_evidence += 1;
        self.record_event(
            "slashing_evidence_submitted",
            &evidence_id,
            &evidence.public_record(),
        )?;
        Ok(evidence)
    }
    fn insert_fence(
        &mut self,
        fence_kind: FenceKind,
        subject_id: String,
        nullifier_value: String,
        note_id: Option<String>,
        batch_id: Option<String>,
    ) -> Result<NullifierFence> {
        self.ensure_capacity(
            "nullifier fences",
            self.nullifier_fences.len(),
            MAX_NULLIFIER_FENCES,
        )?;
        let scope_root = nullifier_fence_scope_root(fence_kind, &subject_id, &nullifier_value);
        let fence_id = nullifier_fence_id(
            fence_kind,
            &subject_id,
            &nullifier_value,
            self.current_l2_height,
        );
        let fence = NullifierFence {
            fence_id: fence_id.clone(),
            fence_kind,
            subject_id,
            nullifier_value,
            scope_root,
            note_id,
            batch_id,
            inserted_l2_height: self.current_l2_height,
        };
        self.nullifier_fences.insert(fence_id, fence.clone());
        self.counters.nullifier_fences += 1;
        Ok(fence)
    }
    fn record_event(
        &mut self,
        event_type: &str,
        subject_id: &str,
        payload: &Value,
    ) -> Result<RouterEvent> {
        self.ensure_capacity("events", self.events.len(), MAX_EVENTS)?;
        let payload_root = payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-EVENT-PAYLOAD",
            payload,
        );
        let sequence = self.events.len() as u64;
        let event_id = router_event_id(
            event_type,
            subject_id,
            &payload_root,
            self.current_l2_height,
            sequence,
        );
        let event = RouterEvent {
            event_id: event_id.clone(),
            event_type: event_type.to_string(),
            subject_id: subject_id.to_string(),
            payload_root,
            sequence,
            l2_height: self.current_l2_height,
        };
        self.events.insert(event_id, event.clone());
        self.counters.events += 1;
        Ok(event)
    }
    fn ensure_capacity(&self, label: &str, len: usize, max: usize) -> Result<()> {
        if len >= max {
            Err(format!("{label} capacity exceeded"))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealWithdrawalNoteRequest {
    pub note_kind: NoteKind,
    pub lane: ExitLane,
    pub owner_commitment: String,
    pub withdrawal_nullifier: String,
    pub amount_commitment: String,
    pub fee_commitment: String,
    pub encrypted_payload_root: String,
    pub recipient_subaddress_commitment: String,
    pub viewtag_bucket: String,
    pub viewtag_hint_root: String,
    pub decoy_set_root: String,
    pub route_blinding_root: String,
    pub min_maker_reserve_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterPrivacyAddressRequest {
    pub note_id: String,
    pub subaddress_commitment: String,
    pub viewtag_bucket: String,
    pub scan_hint_root: String,
    pub decoy_set_root: String,
    pub one_time_address_root: String,
    pub route_guard_root: String,
    pub observed_bucket_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitReserveProofRequest {
    pub maker_id: String,
    pub reserve_epoch: u64,
    pub reserve_commitment_root: String,
    pub view_key_audit_root: String,
    pub spend_key_redaction_root: String,
    pub liability_commitment_root: String,
    pub watchtower_quorum_root: String,
    pub coverage_bps: u64,
    pub liquid_piconero_commitment: String,
    pub locked_piconero_commitment: String,
    pub pq_attestation_root: String,
    pub observed_monero_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PostMakerQuoteRequest {
    pub maker_id: String,
    pub maker_kind: MakerKind,
    pub note_id: String,
    pub lane: ExitLane,
    pub reserve_proof_id: String,
    pub quote_commitment_root: String,
    pub payout_commitment_root: String,
    pub fee_bps: u64,
    pub maker_fee_piconero: u128,
    pub max_fill_piconero: u128,
    pub min_fill_piconero: u128,
    pub reserve_coverage_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveFastExitRequest {
    pub note_id: String,
    pub quote_id: String,
    pub maker_id: String,
    pub reserved_amount_commitment: String,
    pub reserved_fee_commitment: String,
    pub liquidity_ticket_root: String,
    pub coupon_id: Option<String>,
    pub insurance_policy_id: Option<String>,
    pub reservation_nullifier: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MintFeeCouponRequest {
    pub owner_commitment: String,
    pub note_id: Option<String>,
    pub coupon_nullifier: String,
    pub sponsor_commitment: String,
    pub discount_bps: u64,
    pub max_discount_piconero: u128,
    pub eligibility_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenReorgInsuranceRequest {
    pub note_id: String,
    pub maker_id: String,
    pub coverage_commitment: String,
    pub premium_commitment: String,
    pub insured_batch_root: String,
    pub watchtower_committee_root: String,
    pub claim_nullifier: String,
    pub coverage_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealNettedBatchRequest {
    pub lane: ExitLane,
    pub coordinator_id: String,
    pub note_ids: Vec<String>,
    pub payout_root: String,
    pub maker_net_position_root: String,
    pub target_monero_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitWatchtowerReceiptRequest {
    pub receipt_kind: WatchtowerReceiptKind,
    pub subject_id: String,
    pub batch_id: Option<String>,
    pub maker_id: Option<String>,
    pub observation_root: String,
    pub quorum_root: String,
    pub encrypted_evidence_root: String,
    pub monero_anchor_root: String,
    pub l2_anchor_root: String,
    pub observed_monero_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitPqAttestationRequest {
    pub attestation_kind: AttestationKind,
    pub subject_id: String,
    pub signer_commitment: String,
    pub signature_root: String,
    pub transcript_root: String,
    pub public_key_root: String,
    pub security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitSlashingEvidenceRequest {
    pub reason: SlashingReason,
    pub offender_id: String,
    pub note_id: Option<String>,
    pub quote_id: Option<String>,
    pub batch_id: Option<String>,
    pub receipt_id: Option<String>,
    pub evidence_root: String,
    pub witness_root: String,
    pub base_bond_piconero: u128,
}

pub fn devnet() -> State {
    State::devnet()
}
pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}
pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}
pub fn monero_l2_pq_private_exit_liquidity_router_runtime_public_record(state: &State) -> Value {
    state.public_record()
}
pub fn monero_l2_pq_private_exit_liquidity_router_runtime_state_root(state: &State) -> String {
    state.state_root()
}
pub fn state_root_from_public_record(record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-STATE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}
pub fn payload_root(domain: &str, record: &Value) -> String {
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
pub fn withdrawal_note_id(
    sequence: u64,
    request: &SealWithdrawalNoteRequest,
    opened_l2_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-WITHDRAWAL-NOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(request.note_kind.as_str()),
            HashPart::Str(request.lane.as_str()),
            HashPart::Str(&request.owner_commitment),
            HashPart::Str(&request.withdrawal_nullifier),
            HashPart::Str(&request.amount_commitment),
            HashPart::U64(opened_l2_height),
        ],
        32,
    )
}
pub fn privacy_address_id(
    note_id: &str,
    subaddress_commitment: &str,
    viewtag_bucket: &str,
    height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-PRIVACY-ADDRESS-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(note_id),
            HashPart::Str(subaddress_commitment),
            HashPart::Str(viewtag_bucket),
            HashPart::U64(height),
        ],
        32,
    )
}
pub fn reserve_proof_id(
    maker_id: &str,
    reserve_epoch: u64,
    reserve_commitment_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-RESERVE-PROOF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(maker_id),
            HashPart::U64(reserve_epoch),
            HashPart::Str(reserve_commitment_root),
            HashPart::U64(height),
        ],
        32,
    )
}
pub fn maker_quote_id(
    maker_id: &str,
    note_id: &str,
    quote_commitment_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-MAKER-QUOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(maker_id),
            HashPart::Str(note_id),
            HashPart::Str(quote_commitment_root),
            HashPart::U64(height),
        ],
        32,
    )
}
pub fn fast_reservation_id(
    note_id: &str,
    quote_id: &str,
    reservation_nullifier: &str,
    height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-FAST-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(note_id),
            HashPart::Str(quote_id),
            HashPart::Str(reservation_nullifier),
            HashPart::U64(height),
        ],
        32,
    )
}
pub fn netted_batch_id(
    coordinator_id: &str,
    lane: ExitLane,
    note_root: &str,
    nullifier_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-NETTED-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(coordinator_id),
            HashPart::Str(lane.as_str()),
            HashPart::Str(note_root),
            HashPart::Str(nullifier_root),
            HashPart::U64(height),
        ],
        32,
    )
}
pub fn fee_coupon_id(owner_commitment: &str, coupon_nullifier: &str, height: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-FEE-COUPON-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(owner_commitment),
            HashPart::Str(coupon_nullifier),
            HashPart::U64(height),
        ],
        32,
    )
}
pub fn reorg_policy_id(
    note_id: &str,
    maker_id: &str,
    claim_nullifier: &str,
    height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-REORG-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(note_id),
            HashPart::Str(maker_id),
            HashPart::Str(claim_nullifier),
            HashPart::U64(height),
        ],
        32,
    )
}
pub fn watchtower_receipt_id(
    kind: WatchtowerReceiptKind,
    subject_id: &str,
    observation_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-WATCHTOWER-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(observation_root),
            HashPart::U64(height),
        ],
        32,
    )
}
pub fn nullifier_fence_id(
    kind: FenceKind,
    subject_id: &str,
    nullifier_value: &str,
    height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-NULLIFIER-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(nullifier_value),
            HashPart::U64(height),
        ],
        32,
    )
}
pub fn pq_attestation_id(
    kind: AttestationKind,
    subject_id: &str,
    signer_commitment: &str,
    transcript_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-PQ-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(signer_commitment),
            HashPart::Str(transcript_root),
            HashPart::U64(height),
        ],
        32,
    )
}
pub fn slashing_evidence_id(
    offender_id: &str,
    reason: SlashingReason,
    evidence_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(offender_id),
            HashPart::Str(reason.as_str()),
            HashPart::Str(evidence_root),
            HashPart::U64(height),
        ],
        32,
    )
}
pub fn router_event_id(
    event_type: &str,
    subject_id: &str,
    payload_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(event_type),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn nullifier_fence_scope_root(
    kind: FenceKind,
    subject_id: &str,
    nullifier_value: &str,
) -> String {
    payload_root(
        "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-NULLIFIER-FENCE-SCOPE",
        &json!({ "kind": kind.as_str(), "subject_id": subject_id, "nullifier_value": nullifier_value }),
    )
}
pub fn deterministic_commitment(domain: &str, label: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-DETERMINISTIC-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_nullifier(domain: &str, label: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-DETERMINISTIC-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(REPLAY_DOMAIN),
            HashPart::Str(domain),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_root(domain: &str, label: &str) -> String {
    payload_root(
        "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-DETERMINISTIC-ROOT",
        &json!({ "domain": domain, "label": label }),
    )
}
pub fn map_root<T: Serialize>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map.iter().map(|(key, value)| json!({ "key": key, "value": serde_json::to_value(value).expect("serializable map value") })).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}
pub fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}
pub fn nested_set_root(domain: &str, map: &BTreeMap<String, BTreeSet<String>>) -> String {
    let leaves = map.iter().map(|(key, set)| json!({ "key": key, "set_root": set_root(&format!("{domain}:{key}"), set) })).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}
pub fn bps_amount(amount: u128, bps: u64) -> u128 {
    amount.saturating_mul(bps as u128) / MAX_BPS as u128
}
fn validate_bps(label: &str, bps: u64, max: u64) -> Result<()> {
    if bps > max {
        Err(format!("{label} bps exceeds maximum"))
    } else {
        Ok(())
    }
}
fn require_nonempty(label: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}
fn require_absent(set: &BTreeSet<String>, label: &str, value: &str) -> Result<()> {
    if set.contains(value) {
        Err(format!("{label} already used"))
    } else {
        Ok(())
    }
}
fn require_present<'a, T>(map: &'a BTreeMap<String, T>, label: &str, key: &str) -> Result<&'a T> {
    map.get(key)
        .ok_or_else(|| format!("missing {label}: {key}"))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard0 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard0 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-0",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-0",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-0-note", label),
            quote_root: deterministic_root("audit-shard-0-quote", label),
            reserve_root: deterministic_root("audit-shard-0-reserve", label),
            reservation_root: deterministic_root("audit-shard-0-reservation", label),
            batch_root: deterministic_root("audit-shard-0-batch", label),
            watchtower_root: deterministic_root("audit-shard-0-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-0-nullifier", label),
            attestation_root: deterministic_root("audit-shard-0-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard1 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard1 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-1",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-1",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-1-note", label),
            quote_root: deterministic_root("audit-shard-1-quote", label),
            reserve_root: deterministic_root("audit-shard-1-reserve", label),
            reservation_root: deterministic_root("audit-shard-1-reservation", label),
            batch_root: deterministic_root("audit-shard-1-batch", label),
            watchtower_root: deterministic_root("audit-shard-1-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-1-nullifier", label),
            attestation_root: deterministic_root("audit-shard-1-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard2 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard2 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-2",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-2",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-2-note", label),
            quote_root: deterministic_root("audit-shard-2-quote", label),
            reserve_root: deterministic_root("audit-shard-2-reserve", label),
            reservation_root: deterministic_root("audit-shard-2-reservation", label),
            batch_root: deterministic_root("audit-shard-2-batch", label),
            watchtower_root: deterministic_root("audit-shard-2-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-2-nullifier", label),
            attestation_root: deterministic_root("audit-shard-2-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard3 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard3 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-3",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-3",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-3-note", label),
            quote_root: deterministic_root("audit-shard-3-quote", label),
            reserve_root: deterministic_root("audit-shard-3-reserve", label),
            reservation_root: deterministic_root("audit-shard-3-reservation", label),
            batch_root: deterministic_root("audit-shard-3-batch", label),
            watchtower_root: deterministic_root("audit-shard-3-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-3-nullifier", label),
            attestation_root: deterministic_root("audit-shard-3-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard4 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard4 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-4",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-4",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-4-note", label),
            quote_root: deterministic_root("audit-shard-4-quote", label),
            reserve_root: deterministic_root("audit-shard-4-reserve", label),
            reservation_root: deterministic_root("audit-shard-4-reservation", label),
            batch_root: deterministic_root("audit-shard-4-batch", label),
            watchtower_root: deterministic_root("audit-shard-4-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-4-nullifier", label),
            attestation_root: deterministic_root("audit-shard-4-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard5 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard5 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-5",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-5",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-5-note", label),
            quote_root: deterministic_root("audit-shard-5-quote", label),
            reserve_root: deterministic_root("audit-shard-5-reserve", label),
            reservation_root: deterministic_root("audit-shard-5-reservation", label),
            batch_root: deterministic_root("audit-shard-5-batch", label),
            watchtower_root: deterministic_root("audit-shard-5-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-5-nullifier", label),
            attestation_root: deterministic_root("audit-shard-5-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard6 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard6 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-6",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-6",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-6-note", label),
            quote_root: deterministic_root("audit-shard-6-quote", label),
            reserve_root: deterministic_root("audit-shard-6-reserve", label),
            reservation_root: deterministic_root("audit-shard-6-reservation", label),
            batch_root: deterministic_root("audit-shard-6-batch", label),
            watchtower_root: deterministic_root("audit-shard-6-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-6-nullifier", label),
            attestation_root: deterministic_root("audit-shard-6-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard7 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard7 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-7",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-7",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-7-note", label),
            quote_root: deterministic_root("audit-shard-7-quote", label),
            reserve_root: deterministic_root("audit-shard-7-reserve", label),
            reservation_root: deterministic_root("audit-shard-7-reservation", label),
            batch_root: deterministic_root("audit-shard-7-batch", label),
            watchtower_root: deterministic_root("audit-shard-7-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-7-nullifier", label),
            attestation_root: deterministic_root("audit-shard-7-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard8 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard8 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-8",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-8",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-8-note", label),
            quote_root: deterministic_root("audit-shard-8-quote", label),
            reserve_root: deterministic_root("audit-shard-8-reserve", label),
            reservation_root: deterministic_root("audit-shard-8-reservation", label),
            batch_root: deterministic_root("audit-shard-8-batch", label),
            watchtower_root: deterministic_root("audit-shard-8-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-8-nullifier", label),
            attestation_root: deterministic_root("audit-shard-8-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard9 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard9 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-9",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-9",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-9-note", label),
            quote_root: deterministic_root("audit-shard-9-quote", label),
            reserve_root: deterministic_root("audit-shard-9-reserve", label),
            reservation_root: deterministic_root("audit-shard-9-reservation", label),
            batch_root: deterministic_root("audit-shard-9-batch", label),
            watchtower_root: deterministic_root("audit-shard-9-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-9-nullifier", label),
            attestation_root: deterministic_root("audit-shard-9-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard10 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard10 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-10",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-10",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-10-note", label),
            quote_root: deterministic_root("audit-shard-10-quote", label),
            reserve_root: deterministic_root("audit-shard-10-reserve", label),
            reservation_root: deterministic_root("audit-shard-10-reservation", label),
            batch_root: deterministic_root("audit-shard-10-batch", label),
            watchtower_root: deterministic_root("audit-shard-10-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-10-nullifier", label),
            attestation_root: deterministic_root("audit-shard-10-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard11 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard11 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-11",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-11",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-11-note", label),
            quote_root: deterministic_root("audit-shard-11-quote", label),
            reserve_root: deterministic_root("audit-shard-11-reserve", label),
            reservation_root: deterministic_root("audit-shard-11-reservation", label),
            batch_root: deterministic_root("audit-shard-11-batch", label),
            watchtower_root: deterministic_root("audit-shard-11-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-11-nullifier", label),
            attestation_root: deterministic_root("audit-shard-11-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard12 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard12 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-12",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-12",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-12-note", label),
            quote_root: deterministic_root("audit-shard-12-quote", label),
            reserve_root: deterministic_root("audit-shard-12-reserve", label),
            reservation_root: deterministic_root("audit-shard-12-reservation", label),
            batch_root: deterministic_root("audit-shard-12-batch", label),
            watchtower_root: deterministic_root("audit-shard-12-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-12-nullifier", label),
            attestation_root: deterministic_root("audit-shard-12-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard13 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard13 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-13",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-13",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-13-note", label),
            quote_root: deterministic_root("audit-shard-13-quote", label),
            reserve_root: deterministic_root("audit-shard-13-reserve", label),
            reservation_root: deterministic_root("audit-shard-13-reservation", label),
            batch_root: deterministic_root("audit-shard-13-batch", label),
            watchtower_root: deterministic_root("audit-shard-13-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-13-nullifier", label),
            attestation_root: deterministic_root("audit-shard-13-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard14 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard14 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-14",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-14",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-14-note", label),
            quote_root: deterministic_root("audit-shard-14-quote", label),
            reserve_root: deterministic_root("audit-shard-14-reserve", label),
            reservation_root: deterministic_root("audit-shard-14-reservation", label),
            batch_root: deterministic_root("audit-shard-14-batch", label),
            watchtower_root: deterministic_root("audit-shard-14-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-14-nullifier", label),
            attestation_root: deterministic_root("audit-shard-14-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard15 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard15 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-15",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-15",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-15-note", label),
            quote_root: deterministic_root("audit-shard-15-quote", label),
            reserve_root: deterministic_root("audit-shard-15-reserve", label),
            reservation_root: deterministic_root("audit-shard-15-reservation", label),
            batch_root: deterministic_root("audit-shard-15-batch", label),
            watchtower_root: deterministic_root("audit-shard-15-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-15-nullifier", label),
            attestation_root: deterministic_root("audit-shard-15-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard16 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard16 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-16",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-16",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-16-note", label),
            quote_root: deterministic_root("audit-shard-16-quote", label),
            reserve_root: deterministic_root("audit-shard-16-reserve", label),
            reservation_root: deterministic_root("audit-shard-16-reservation", label),
            batch_root: deterministic_root("audit-shard-16-batch", label),
            watchtower_root: deterministic_root("audit-shard-16-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-16-nullifier", label),
            attestation_root: deterministic_root("audit-shard-16-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard17 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard17 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-17",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-17",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-17-note", label),
            quote_root: deterministic_root("audit-shard-17-quote", label),
            reserve_root: deterministic_root("audit-shard-17-reserve", label),
            reservation_root: deterministic_root("audit-shard-17-reservation", label),
            batch_root: deterministic_root("audit-shard-17-batch", label),
            watchtower_root: deterministic_root("audit-shard-17-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-17-nullifier", label),
            attestation_root: deterministic_root("audit-shard-17-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard18 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard18 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-18",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-18",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-18-note", label),
            quote_root: deterministic_root("audit-shard-18-quote", label),
            reserve_root: deterministic_root("audit-shard-18-reserve", label),
            reservation_root: deterministic_root("audit-shard-18-reservation", label),
            batch_root: deterministic_root("audit-shard-18-batch", label),
            watchtower_root: deterministic_root("audit-shard-18-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-18-nullifier", label),
            attestation_root: deterministic_root("audit-shard-18-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard19 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard19 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-19",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-19",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-19-note", label),
            quote_root: deterministic_root("audit-shard-19-quote", label),
            reserve_root: deterministic_root("audit-shard-19-reserve", label),
            reservation_root: deterministic_root("audit-shard-19-reservation", label),
            batch_root: deterministic_root("audit-shard-19-batch", label),
            watchtower_root: deterministic_root("audit-shard-19-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-19-nullifier", label),
            attestation_root: deterministic_root("audit-shard-19-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard20 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard20 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-20",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-20",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-20-note", label),
            quote_root: deterministic_root("audit-shard-20-quote", label),
            reserve_root: deterministic_root("audit-shard-20-reserve", label),
            reservation_root: deterministic_root("audit-shard-20-reservation", label),
            batch_root: deterministic_root("audit-shard-20-batch", label),
            watchtower_root: deterministic_root("audit-shard-20-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-20-nullifier", label),
            attestation_root: deterministic_root("audit-shard-20-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard21 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard21 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-21",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-21",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-21-note", label),
            quote_root: deterministic_root("audit-shard-21-quote", label),
            reserve_root: deterministic_root("audit-shard-21-reserve", label),
            reservation_root: deterministic_root("audit-shard-21-reservation", label),
            batch_root: deterministic_root("audit-shard-21-batch", label),
            watchtower_root: deterministic_root("audit-shard-21-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-21-nullifier", label),
            attestation_root: deterministic_root("audit-shard-21-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard22 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard22 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-22",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-22",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-22-note", label),
            quote_root: deterministic_root("audit-shard-22-quote", label),
            reserve_root: deterministic_root("audit-shard-22-reserve", label),
            reservation_root: deterministic_root("audit-shard-22-reservation", label),
            batch_root: deterministic_root("audit-shard-22-batch", label),
            watchtower_root: deterministic_root("audit-shard-22-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-22-nullifier", label),
            attestation_root: deterministic_root("audit-shard-22-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard23 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard23 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-23",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-23",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-23-note", label),
            quote_root: deterministic_root("audit-shard-23-quote", label),
            reserve_root: deterministic_root("audit-shard-23-reserve", label),
            reservation_root: deterministic_root("audit-shard-23-reservation", label),
            batch_root: deterministic_root("audit-shard-23-batch", label),
            watchtower_root: deterministic_root("audit-shard-23-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-23-nullifier", label),
            attestation_root: deterministic_root("audit-shard-23-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard24 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard24 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-24",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-24",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-24-note", label),
            quote_root: deterministic_root("audit-shard-24-quote", label),
            reserve_root: deterministic_root("audit-shard-24-reserve", label),
            reservation_root: deterministic_root("audit-shard-24-reservation", label),
            batch_root: deterministic_root("audit-shard-24-batch", label),
            watchtower_root: deterministic_root("audit-shard-24-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-24-nullifier", label),
            attestation_root: deterministic_root("audit-shard-24-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard25 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard25 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-25",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-25",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-25-note", label),
            quote_root: deterministic_root("audit-shard-25-quote", label),
            reserve_root: deterministic_root("audit-shard-25-reserve", label),
            reservation_root: deterministic_root("audit-shard-25-reservation", label),
            batch_root: deterministic_root("audit-shard-25-batch", label),
            watchtower_root: deterministic_root("audit-shard-25-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-25-nullifier", label),
            attestation_root: deterministic_root("audit-shard-25-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard26 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard26 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-26",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-26",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-26-note", label),
            quote_root: deterministic_root("audit-shard-26-quote", label),
            reserve_root: deterministic_root("audit-shard-26-reserve", label),
            reservation_root: deterministic_root("audit-shard-26-reservation", label),
            batch_root: deterministic_root("audit-shard-26-batch", label),
            watchtower_root: deterministic_root("audit-shard-26-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-26-nullifier", label),
            attestation_root: deterministic_root("audit-shard-26-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard27 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard27 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-27",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-27",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-27-note", label),
            quote_root: deterministic_root("audit-shard-27-quote", label),
            reserve_root: deterministic_root("audit-shard-27-reserve", label),
            reservation_root: deterministic_root("audit-shard-27-reservation", label),
            batch_root: deterministic_root("audit-shard-27-batch", label),
            watchtower_root: deterministic_root("audit-shard-27-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-27-nullifier", label),
            attestation_root: deterministic_root("audit-shard-27-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard28 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard28 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-28",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-28",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-28-note", label),
            quote_root: deterministic_root("audit-shard-28-quote", label),
            reserve_root: deterministic_root("audit-shard-28-reserve", label),
            reservation_root: deterministic_root("audit-shard-28-reservation", label),
            batch_root: deterministic_root("audit-shard-28-batch", label),
            watchtower_root: deterministic_root("audit-shard-28-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-28-nullifier", label),
            attestation_root: deterministic_root("audit-shard-28-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard29 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard29 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-29",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-29",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-29-note", label),
            quote_root: deterministic_root("audit-shard-29-quote", label),
            reserve_root: deterministic_root("audit-shard-29-reserve", label),
            reservation_root: deterministic_root("audit-shard-29-reservation", label),
            batch_root: deterministic_root("audit-shard-29-batch", label),
            watchtower_root: deterministic_root("audit-shard-29-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-29-nullifier", label),
            attestation_root: deterministic_root("audit-shard-29-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard30 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard30 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-30",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-30",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-30-note", label),
            quote_root: deterministic_root("audit-shard-30-quote", label),
            reserve_root: deterministic_root("audit-shard-30-reserve", label),
            reservation_root: deterministic_root("audit-shard-30-reservation", label),
            batch_root: deterministic_root("audit-shard-30-batch", label),
            watchtower_root: deterministic_root("audit-shard-30-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-30-nullifier", label),
            attestation_root: deterministic_root("audit-shard-30-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard31 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard31 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-31",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-31",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-31-note", label),
            quote_root: deterministic_root("audit-shard-31-quote", label),
            reserve_root: deterministic_root("audit-shard-31-reserve", label),
            reservation_root: deterministic_root("audit-shard-31-reservation", label),
            batch_root: deterministic_root("audit-shard-31-batch", label),
            watchtower_root: deterministic_root("audit-shard-31-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-31-nullifier", label),
            attestation_root: deterministic_root("audit-shard-31-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard32 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard32 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-32",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-32",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-32-note", label),
            quote_root: deterministic_root("audit-shard-32-quote", label),
            reserve_root: deterministic_root("audit-shard-32-reserve", label),
            reservation_root: deterministic_root("audit-shard-32-reservation", label),
            batch_root: deterministic_root("audit-shard-32-batch", label),
            watchtower_root: deterministic_root("audit-shard-32-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-32-nullifier", label),
            attestation_root: deterministic_root("audit-shard-32-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard33 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard33 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-33",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-33",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-33-note", label),
            quote_root: deterministic_root("audit-shard-33-quote", label),
            reserve_root: deterministic_root("audit-shard-33-reserve", label),
            reservation_root: deterministic_root("audit-shard-33-reservation", label),
            batch_root: deterministic_root("audit-shard-33-batch", label),
            watchtower_root: deterministic_root("audit-shard-33-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-33-nullifier", label),
            attestation_root: deterministic_root("audit-shard-33-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard34 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard34 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-34",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-34",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-34-note", label),
            quote_root: deterministic_root("audit-shard-34-quote", label),
            reserve_root: deterministic_root("audit-shard-34-reserve", label),
            reservation_root: deterministic_root("audit-shard-34-reservation", label),
            batch_root: deterministic_root("audit-shard-34-batch", label),
            watchtower_root: deterministic_root("audit-shard-34-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-34-nullifier", label),
            attestation_root: deterministic_root("audit-shard-34-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard35 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard35 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-35",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-35",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-35-note", label),
            quote_root: deterministic_root("audit-shard-35-quote", label),
            reserve_root: deterministic_root("audit-shard-35-reserve", label),
            reservation_root: deterministic_root("audit-shard-35-reservation", label),
            batch_root: deterministic_root("audit-shard-35-batch", label),
            watchtower_root: deterministic_root("audit-shard-35-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-35-nullifier", label),
            attestation_root: deterministic_root("audit-shard-35-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard36 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard36 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-36",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-36",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-36-note", label),
            quote_root: deterministic_root("audit-shard-36-quote", label),
            reserve_root: deterministic_root("audit-shard-36-reserve", label),
            reservation_root: deterministic_root("audit-shard-36-reservation", label),
            batch_root: deterministic_root("audit-shard-36-batch", label),
            watchtower_root: deterministic_root("audit-shard-36-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-36-nullifier", label),
            attestation_root: deterministic_root("audit-shard-36-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard37 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard37 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-37",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-37",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-37-note", label),
            quote_root: deterministic_root("audit-shard-37-quote", label),
            reserve_root: deterministic_root("audit-shard-37-reserve", label),
            reservation_root: deterministic_root("audit-shard-37-reservation", label),
            batch_root: deterministic_root("audit-shard-37-batch", label),
            watchtower_root: deterministic_root("audit-shard-37-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-37-nullifier", label),
            attestation_root: deterministic_root("audit-shard-37-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard38 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard38 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-38",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-38",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-38-note", label),
            quote_root: deterministic_root("audit-shard-38-quote", label),
            reserve_root: deterministic_root("audit-shard-38-reserve", label),
            reservation_root: deterministic_root("audit-shard-38-reservation", label),
            batch_root: deterministic_root("audit-shard-38-batch", label),
            watchtower_root: deterministic_root("audit-shard-38-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-38-nullifier", label),
            attestation_root: deterministic_root("audit-shard-38-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard39 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard39 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-39",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-39",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-39-note", label),
            quote_root: deterministic_root("audit-shard-39-quote", label),
            reserve_root: deterministic_root("audit-shard-39-reserve", label),
            reservation_root: deterministic_root("audit-shard-39-reservation", label),
            batch_root: deterministic_root("audit-shard-39-batch", label),
            watchtower_root: deterministic_root("audit-shard-39-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-39-nullifier", label),
            attestation_root: deterministic_root("audit-shard-39-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard40 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard40 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-40",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-40",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-40-note", label),
            quote_root: deterministic_root("audit-shard-40-quote", label),
            reserve_root: deterministic_root("audit-shard-40-reserve", label),
            reservation_root: deterministic_root("audit-shard-40-reservation", label),
            batch_root: deterministic_root("audit-shard-40-batch", label),
            watchtower_root: deterministic_root("audit-shard-40-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-40-nullifier", label),
            attestation_root: deterministic_root("audit-shard-40-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard41 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard41 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-41",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-41",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-41-note", label),
            quote_root: deterministic_root("audit-shard-41-quote", label),
            reserve_root: deterministic_root("audit-shard-41-reserve", label),
            reservation_root: deterministic_root("audit-shard-41-reservation", label),
            batch_root: deterministic_root("audit-shard-41-batch", label),
            watchtower_root: deterministic_root("audit-shard-41-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-41-nullifier", label),
            attestation_root: deterministic_root("audit-shard-41-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard42 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard42 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-42",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-42",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-42-note", label),
            quote_root: deterministic_root("audit-shard-42-quote", label),
            reserve_root: deterministic_root("audit-shard-42-reserve", label),
            reservation_root: deterministic_root("audit-shard-42-reservation", label),
            batch_root: deterministic_root("audit-shard-42-batch", label),
            watchtower_root: deterministic_root("audit-shard-42-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-42-nullifier", label),
            attestation_root: deterministic_root("audit-shard-42-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard43 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard43 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-43",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-43",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-43-note", label),
            quote_root: deterministic_root("audit-shard-43-quote", label),
            reserve_root: deterministic_root("audit-shard-43-reserve", label),
            reservation_root: deterministic_root("audit-shard-43-reservation", label),
            batch_root: deterministic_root("audit-shard-43-batch", label),
            watchtower_root: deterministic_root("audit-shard-43-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-43-nullifier", label),
            attestation_root: deterministic_root("audit-shard-43-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard44 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard44 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-44",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-44",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-44-note", label),
            quote_root: deterministic_root("audit-shard-44-quote", label),
            reserve_root: deterministic_root("audit-shard-44-reserve", label),
            reservation_root: deterministic_root("audit-shard-44-reservation", label),
            batch_root: deterministic_root("audit-shard-44-batch", label),
            watchtower_root: deterministic_root("audit-shard-44-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-44-nullifier", label),
            attestation_root: deterministic_root("audit-shard-44-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard45 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard45 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-45",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-45",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-45-note", label),
            quote_root: deterministic_root("audit-shard-45-quote", label),
            reserve_root: deterministic_root("audit-shard-45-reserve", label),
            reservation_root: deterministic_root("audit-shard-45-reservation", label),
            batch_root: deterministic_root("audit-shard-45-batch", label),
            watchtower_root: deterministic_root("audit-shard-45-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-45-nullifier", label),
            attestation_root: deterministic_root("audit-shard-45-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard46 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard46 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-46",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-46",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-46-note", label),
            quote_root: deterministic_root("audit-shard-46-quote", label),
            reserve_root: deterministic_root("audit-shard-46-reserve", label),
            reservation_root: deterministic_root("audit-shard-46-reservation", label),
            batch_root: deterministic_root("audit-shard-46-batch", label),
            watchtower_root: deterministic_root("audit-shard-46-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-46-nullifier", label),
            attestation_root: deterministic_root("audit-shard-46-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard47 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard47 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-47",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-47",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-47-note", label),
            quote_root: deterministic_root("audit-shard-47-quote", label),
            reserve_root: deterministic_root("audit-shard-47-reserve", label),
            reservation_root: deterministic_root("audit-shard-47-reservation", label),
            batch_root: deterministic_root("audit-shard-47-batch", label),
            watchtower_root: deterministic_root("audit-shard-47-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-47-nullifier", label),
            attestation_root: deterministic_root("audit-shard-47-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard48 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard48 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-48",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-48",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-48-note", label),
            quote_root: deterministic_root("audit-shard-48-quote", label),
            reserve_root: deterministic_root("audit-shard-48-reserve", label),
            reservation_root: deterministic_root("audit-shard-48-reservation", label),
            batch_root: deterministic_root("audit-shard-48-batch", label),
            watchtower_root: deterministic_root("audit-shard-48-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-48-nullifier", label),
            attestation_root: deterministic_root("audit-shard-48-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard49 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard49 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-49",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-49",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-49-note", label),
            quote_root: deterministic_root("audit-shard-49-quote", label),
            reserve_root: deterministic_root("audit-shard-49-reserve", label),
            reservation_root: deterministic_root("audit-shard-49-reservation", label),
            batch_root: deterministic_root("audit-shard-49-batch", label),
            watchtower_root: deterministic_root("audit-shard-49-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-49-nullifier", label),
            attestation_root: deterministic_root("audit-shard-49-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard50 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard50 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-50",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-50",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-50-note", label),
            quote_root: deterministic_root("audit-shard-50-quote", label),
            reserve_root: deterministic_root("audit-shard-50-reserve", label),
            reservation_root: deterministic_root("audit-shard-50-reservation", label),
            batch_root: deterministic_root("audit-shard-50-batch", label),
            watchtower_root: deterministic_root("audit-shard-50-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-50-nullifier", label),
            attestation_root: deterministic_root("audit-shard-50-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard51 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard51 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-51",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-51",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-51-note", label),
            quote_root: deterministic_root("audit-shard-51-quote", label),
            reserve_root: deterministic_root("audit-shard-51-reserve", label),
            reservation_root: deterministic_root("audit-shard-51-reservation", label),
            batch_root: deterministic_root("audit-shard-51-batch", label),
            watchtower_root: deterministic_root("audit-shard-51-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-51-nullifier", label),
            attestation_root: deterministic_root("audit-shard-51-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard52 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard52 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-52",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-52",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-52-note", label),
            quote_root: deterministic_root("audit-shard-52-quote", label),
            reserve_root: deterministic_root("audit-shard-52-reserve", label),
            reservation_root: deterministic_root("audit-shard-52-reservation", label),
            batch_root: deterministic_root("audit-shard-52-batch", label),
            watchtower_root: deterministic_root("audit-shard-52-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-52-nullifier", label),
            attestation_root: deterministic_root("audit-shard-52-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard53 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard53 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-53",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-53",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-53-note", label),
            quote_root: deterministic_root("audit-shard-53-quote", label),
            reserve_root: deterministic_root("audit-shard-53-reserve", label),
            reservation_root: deterministic_root("audit-shard-53-reservation", label),
            batch_root: deterministic_root("audit-shard-53-batch", label),
            watchtower_root: deterministic_root("audit-shard-53-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-53-nullifier", label),
            attestation_root: deterministic_root("audit-shard-53-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard54 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard54 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-54",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-54",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-54-note", label),
            quote_root: deterministic_root("audit-shard-54-quote", label),
            reserve_root: deterministic_root("audit-shard-54-reserve", label),
            reservation_root: deterministic_root("audit-shard-54-reservation", label),
            batch_root: deterministic_root("audit-shard-54-batch", label),
            watchtower_root: deterministic_root("audit-shard-54-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-54-nullifier", label),
            attestation_root: deterministic_root("audit-shard-54-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard55 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard55 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-55",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-55",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-55-note", label),
            quote_root: deterministic_root("audit-shard-55-quote", label),
            reserve_root: deterministic_root("audit-shard-55-reserve", label),
            reservation_root: deterministic_root("audit-shard-55-reservation", label),
            batch_root: deterministic_root("audit-shard-55-batch", label),
            watchtower_root: deterministic_root("audit-shard-55-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-55-nullifier", label),
            attestation_root: deterministic_root("audit-shard-55-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard56 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard56 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-56",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-56",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-56-note", label),
            quote_root: deterministic_root("audit-shard-56-quote", label),
            reserve_root: deterministic_root("audit-shard-56-reserve", label),
            reservation_root: deterministic_root("audit-shard-56-reservation", label),
            batch_root: deterministic_root("audit-shard-56-batch", label),
            watchtower_root: deterministic_root("audit-shard-56-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-56-nullifier", label),
            attestation_root: deterministic_root("audit-shard-56-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard57 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard57 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-57",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-57",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-57-note", label),
            quote_root: deterministic_root("audit-shard-57-quote", label),
            reserve_root: deterministic_root("audit-shard-57-reserve", label),
            reservation_root: deterministic_root("audit-shard-57-reservation", label),
            batch_root: deterministic_root("audit-shard-57-batch", label),
            watchtower_root: deterministic_root("audit-shard-57-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-57-nullifier", label),
            attestation_root: deterministic_root("audit-shard-57-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard58 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard58 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-58",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-58",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-58-note", label),
            quote_root: deterministic_root("audit-shard-58-quote", label),
            reserve_root: deterministic_root("audit-shard-58-reserve", label),
            reservation_root: deterministic_root("audit-shard-58-reservation", label),
            batch_root: deterministic_root("audit-shard-58-batch", label),
            watchtower_root: deterministic_root("audit-shard-58-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-58-nullifier", label),
            attestation_root: deterministic_root("audit-shard-58-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard59 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard59 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-59",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-59",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-59-note", label),
            quote_root: deterministic_root("audit-shard-59-quote", label),
            reserve_root: deterministic_root("audit-shard-59-reserve", label),
            reservation_root: deterministic_root("audit-shard-59-reservation", label),
            batch_root: deterministic_root("audit-shard-59-batch", label),
            watchtower_root: deterministic_root("audit-shard-59-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-59-nullifier", label),
            attestation_root: deterministic_root("audit-shard-59-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard60 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard60 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-60",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-60",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-60-note", label),
            quote_root: deterministic_root("audit-shard-60-quote", label),
            reserve_root: deterministic_root("audit-shard-60-reserve", label),
            reservation_root: deterministic_root("audit-shard-60-reservation", label),
            batch_root: deterministic_root("audit-shard-60-batch", label),
            watchtower_root: deterministic_root("audit-shard-60-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-60-nullifier", label),
            attestation_root: deterministic_root("audit-shard-60-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard61 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard61 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-61",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-61",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-61-note", label),
            quote_root: deterministic_root("audit-shard-61-quote", label),
            reserve_root: deterministic_root("audit-shard-61-reserve", label),
            reservation_root: deterministic_root("audit-shard-61-reservation", label),
            batch_root: deterministic_root("audit-shard-61-batch", label),
            watchtower_root: deterministic_root("audit-shard-61-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-61-nullifier", label),
            attestation_root: deterministic_root("audit-shard-61-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard62 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard62 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-62",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-62",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-62-note", label),
            quote_root: deterministic_root("audit-shard-62-quote", label),
            reserve_root: deterministic_root("audit-shard-62-reserve", label),
            reservation_root: deterministic_root("audit-shard-62-reservation", label),
            batch_root: deterministic_root("audit-shard-62-batch", label),
            watchtower_root: deterministic_root("audit-shard-62-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-62-nullifier", label),
            attestation_root: deterministic_root("audit-shard-62-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard63 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard63 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-63",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-63",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-63-note", label),
            quote_root: deterministic_root("audit-shard-63-quote", label),
            reserve_root: deterministic_root("audit-shard-63-reserve", label),
            reservation_root: deterministic_root("audit-shard-63-reservation", label),
            batch_root: deterministic_root("audit-shard-63-batch", label),
            watchtower_root: deterministic_root("audit-shard-63-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-63-nullifier", label),
            attestation_root: deterministic_root("audit-shard-63-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard64 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard64 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-64",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-64",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-64-note", label),
            quote_root: deterministic_root("audit-shard-64-quote", label),
            reserve_root: deterministic_root("audit-shard-64-reserve", label),
            reservation_root: deterministic_root("audit-shard-64-reservation", label),
            batch_root: deterministic_root("audit-shard-64-batch", label),
            watchtower_root: deterministic_root("audit-shard-64-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-64-nullifier", label),
            attestation_root: deterministic_root("audit-shard-64-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard65 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard65 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-65",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-65",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-65-note", label),
            quote_root: deterministic_root("audit-shard-65-quote", label),
            reserve_root: deterministic_root("audit-shard-65-reserve", label),
            reservation_root: deterministic_root("audit-shard-65-reservation", label),
            batch_root: deterministic_root("audit-shard-65-batch", label),
            watchtower_root: deterministic_root("audit-shard-65-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-65-nullifier", label),
            attestation_root: deterministic_root("audit-shard-65-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard66 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard66 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-66",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-66",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-66-note", label),
            quote_root: deterministic_root("audit-shard-66-quote", label),
            reserve_root: deterministic_root("audit-shard-66-reserve", label),
            reservation_root: deterministic_root("audit-shard-66-reservation", label),
            batch_root: deterministic_root("audit-shard-66-batch", label),
            watchtower_root: deterministic_root("audit-shard-66-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-66-nullifier", label),
            attestation_root: deterministic_root("audit-shard-66-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard67 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard67 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-67",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-67",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-67-note", label),
            quote_root: deterministic_root("audit-shard-67-quote", label),
            reserve_root: deterministic_root("audit-shard-67-reserve", label),
            reservation_root: deterministic_root("audit-shard-67-reservation", label),
            batch_root: deterministic_root("audit-shard-67-batch", label),
            watchtower_root: deterministic_root("audit-shard-67-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-67-nullifier", label),
            attestation_root: deterministic_root("audit-shard-67-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard68 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard68 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-68",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-68",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-68-note", label),
            quote_root: deterministic_root("audit-shard-68-quote", label),
            reserve_root: deterministic_root("audit-shard-68-reserve", label),
            reservation_root: deterministic_root("audit-shard-68-reservation", label),
            batch_root: deterministic_root("audit-shard-68-batch", label),
            watchtower_root: deterministic_root("audit-shard-68-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-68-nullifier", label),
            attestation_root: deterministic_root("audit-shard-68-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard69 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard69 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-69",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-69",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-69-note", label),
            quote_root: deterministic_root("audit-shard-69-quote", label),
            reserve_root: deterministic_root("audit-shard-69-reserve", label),
            reservation_root: deterministic_root("audit-shard-69-reservation", label),
            batch_root: deterministic_root("audit-shard-69-batch", label),
            watchtower_root: deterministic_root("audit-shard-69-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-69-nullifier", label),
            attestation_root: deterministic_root("audit-shard-69-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard70 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard70 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-70",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-70",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-70-note", label),
            quote_root: deterministic_root("audit-shard-70-quote", label),
            reserve_root: deterministic_root("audit-shard-70-reserve", label),
            reservation_root: deterministic_root("audit-shard-70-reservation", label),
            batch_root: deterministic_root("audit-shard-70-batch", label),
            watchtower_root: deterministic_root("audit-shard-70-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-70-nullifier", label),
            attestation_root: deterministic_root("audit-shard-70-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard71 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard71 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-71",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-71",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-71-note", label),
            quote_root: deterministic_root("audit-shard-71-quote", label),
            reserve_root: deterministic_root("audit-shard-71-reserve", label),
            reservation_root: deterministic_root("audit-shard-71-reservation", label),
            batch_root: deterministic_root("audit-shard-71-batch", label),
            watchtower_root: deterministic_root("audit-shard-71-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-71-nullifier", label),
            attestation_root: deterministic_root("audit-shard-71-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard72 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard72 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-72",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-72",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-72-note", label),
            quote_root: deterministic_root("audit-shard-72-quote", label),
            reserve_root: deterministic_root("audit-shard-72-reserve", label),
            reservation_root: deterministic_root("audit-shard-72-reservation", label),
            batch_root: deterministic_root("audit-shard-72-batch", label),
            watchtower_root: deterministic_root("audit-shard-72-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-72-nullifier", label),
            attestation_root: deterministic_root("audit-shard-72-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard73 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard73 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-73",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-73",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-73-note", label),
            quote_root: deterministic_root("audit-shard-73-quote", label),
            reserve_root: deterministic_root("audit-shard-73-reserve", label),
            reservation_root: deterministic_root("audit-shard-73-reservation", label),
            batch_root: deterministic_root("audit-shard-73-batch", label),
            watchtower_root: deterministic_root("audit-shard-73-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-73-nullifier", label),
            attestation_root: deterministic_root("audit-shard-73-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard74 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard74 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-74",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-74",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-74-note", label),
            quote_root: deterministic_root("audit-shard-74-quote", label),
            reserve_root: deterministic_root("audit-shard-74-reserve", label),
            reservation_root: deterministic_root("audit-shard-74-reservation", label),
            batch_root: deterministic_root("audit-shard-74-batch", label),
            watchtower_root: deterministic_root("audit-shard-74-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-74-nullifier", label),
            attestation_root: deterministic_root("audit-shard-74-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard75 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard75 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-75",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-75",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-75-note", label),
            quote_root: deterministic_root("audit-shard-75-quote", label),
            reserve_root: deterministic_root("audit-shard-75-reserve", label),
            reservation_root: deterministic_root("audit-shard-75-reservation", label),
            batch_root: deterministic_root("audit-shard-75-batch", label),
            watchtower_root: deterministic_root("audit-shard-75-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-75-nullifier", label),
            attestation_root: deterministic_root("audit-shard-75-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard76 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard76 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-76",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-76",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-76-note", label),
            quote_root: deterministic_root("audit-shard-76-quote", label),
            reserve_root: deterministic_root("audit-shard-76-reserve", label),
            reservation_root: deterministic_root("audit-shard-76-reservation", label),
            batch_root: deterministic_root("audit-shard-76-batch", label),
            watchtower_root: deterministic_root("audit-shard-76-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-76-nullifier", label),
            attestation_root: deterministic_root("audit-shard-76-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard77 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard77 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-77",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-77",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-77-note", label),
            quote_root: deterministic_root("audit-shard-77-quote", label),
            reserve_root: deterministic_root("audit-shard-77-reserve", label),
            reservation_root: deterministic_root("audit-shard-77-reservation", label),
            batch_root: deterministic_root("audit-shard-77-batch", label),
            watchtower_root: deterministic_root("audit-shard-77-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-77-nullifier", label),
            attestation_root: deterministic_root("audit-shard-77-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard78 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard78 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-78",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-78",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-78-note", label),
            quote_root: deterministic_root("audit-shard-78-quote", label),
            reserve_root: deterministic_root("audit-shard-78-reserve", label),
            reservation_root: deterministic_root("audit-shard-78-reservation", label),
            batch_root: deterministic_root("audit-shard-78-batch", label),
            watchtower_root: deterministic_root("audit-shard-78-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-78-nullifier", label),
            attestation_root: deterministic_root("audit-shard-78-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard79 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard79 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-79",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-79",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-79-note", label),
            quote_root: deterministic_root("audit-shard-79-quote", label),
            reserve_root: deterministic_root("audit-shard-79-reserve", label),
            reservation_root: deterministic_root("audit-shard-79-reservation", label),
            batch_root: deterministic_root("audit-shard-79-batch", label),
            watchtower_root: deterministic_root("audit-shard-79-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-79-nullifier", label),
            attestation_root: deterministic_root("audit-shard-79-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard80 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard80 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-80",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-80",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-80-note", label),
            quote_root: deterministic_root("audit-shard-80-quote", label),
            reserve_root: deterministic_root("audit-shard-80-reserve", label),
            reservation_root: deterministic_root("audit-shard-80-reservation", label),
            batch_root: deterministic_root("audit-shard-80-batch", label),
            watchtower_root: deterministic_root("audit-shard-80-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-80-nullifier", label),
            attestation_root: deterministic_root("audit-shard-80-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard81 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard81 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-81",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-81",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-81-note", label),
            quote_root: deterministic_root("audit-shard-81-quote", label),
            reserve_root: deterministic_root("audit-shard-81-reserve", label),
            reservation_root: deterministic_root("audit-shard-81-reservation", label),
            batch_root: deterministic_root("audit-shard-81-batch", label),
            watchtower_root: deterministic_root("audit-shard-81-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-81-nullifier", label),
            attestation_root: deterministic_root("audit-shard-81-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard82 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard82 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-82",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-82",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-82-note", label),
            quote_root: deterministic_root("audit-shard-82-quote", label),
            reserve_root: deterministic_root("audit-shard-82-reserve", label),
            reservation_root: deterministic_root("audit-shard-82-reservation", label),
            batch_root: deterministic_root("audit-shard-82-batch", label),
            watchtower_root: deterministic_root("audit-shard-82-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-82-nullifier", label),
            attestation_root: deterministic_root("audit-shard-82-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard83 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard83 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-83",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-83",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-83-note", label),
            quote_root: deterministic_root("audit-shard-83-quote", label),
            reserve_root: deterministic_root("audit-shard-83-reserve", label),
            reservation_root: deterministic_root("audit-shard-83-reservation", label),
            batch_root: deterministic_root("audit-shard-83-batch", label),
            watchtower_root: deterministic_root("audit-shard-83-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-83-nullifier", label),
            attestation_root: deterministic_root("audit-shard-83-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard84 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard84 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-84",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-84",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-84-note", label),
            quote_root: deterministic_root("audit-shard-84-quote", label),
            reserve_root: deterministic_root("audit-shard-84-reserve", label),
            reservation_root: deterministic_root("audit-shard-84-reservation", label),
            batch_root: deterministic_root("audit-shard-84-batch", label),
            watchtower_root: deterministic_root("audit-shard-84-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-84-nullifier", label),
            attestation_root: deterministic_root("audit-shard-84-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard85 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard85 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-85",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-85",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-85-note", label),
            quote_root: deterministic_root("audit-shard-85-quote", label),
            reserve_root: deterministic_root("audit-shard-85-reserve", label),
            reservation_root: deterministic_root("audit-shard-85-reservation", label),
            batch_root: deterministic_root("audit-shard-85-batch", label),
            watchtower_root: deterministic_root("audit-shard-85-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-85-nullifier", label),
            attestation_root: deterministic_root("audit-shard-85-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard86 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard86 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-86",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-86",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-86-note", label),
            quote_root: deterministic_root("audit-shard-86-quote", label),
            reserve_root: deterministic_root("audit-shard-86-reserve", label),
            reservation_root: deterministic_root("audit-shard-86-reservation", label),
            batch_root: deterministic_root("audit-shard-86-batch", label),
            watchtower_root: deterministic_root("audit-shard-86-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-86-nullifier", label),
            attestation_root: deterministic_root("audit-shard-86-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard87 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard87 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-87",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-87",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-87-note", label),
            quote_root: deterministic_root("audit-shard-87-quote", label),
            reserve_root: deterministic_root("audit-shard-87-reserve", label),
            reservation_root: deterministic_root("audit-shard-87-reservation", label),
            batch_root: deterministic_root("audit-shard-87-batch", label),
            watchtower_root: deterministic_root("audit-shard-87-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-87-nullifier", label),
            attestation_root: deterministic_root("audit-shard-87-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard88 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard88 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-88",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-88",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-88-note", label),
            quote_root: deterministic_root("audit-shard-88-quote", label),
            reserve_root: deterministic_root("audit-shard-88-reserve", label),
            reservation_root: deterministic_root("audit-shard-88-reservation", label),
            batch_root: deterministic_root("audit-shard-88-batch", label),
            watchtower_root: deterministic_root("audit-shard-88-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-88-nullifier", label),
            attestation_root: deterministic_root("audit-shard-88-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard89 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard89 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-89",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-89",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-89-note", label),
            quote_root: deterministic_root("audit-shard-89-quote", label),
            reserve_root: deterministic_root("audit-shard-89-reserve", label),
            reservation_root: deterministic_root("audit-shard-89-reservation", label),
            batch_root: deterministic_root("audit-shard-89-batch", label),
            watchtower_root: deterministic_root("audit-shard-89-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-89-nullifier", label),
            attestation_root: deterministic_root("audit-shard-89-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard90 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard90 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-90",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-90",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-90-note", label),
            quote_root: deterministic_root("audit-shard-90-quote", label),
            reserve_root: deterministic_root("audit-shard-90-reserve", label),
            reservation_root: deterministic_root("audit-shard-90-reservation", label),
            batch_root: deterministic_root("audit-shard-90-batch", label),
            watchtower_root: deterministic_root("audit-shard-90-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-90-nullifier", label),
            attestation_root: deterministic_root("audit-shard-90-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard91 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard91 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-91",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-91",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-91-note", label),
            quote_root: deterministic_root("audit-shard-91-quote", label),
            reserve_root: deterministic_root("audit-shard-91-reserve", label),
            reservation_root: deterministic_root("audit-shard-91-reservation", label),
            batch_root: deterministic_root("audit-shard-91-batch", label),
            watchtower_root: deterministic_root("audit-shard-91-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-91-nullifier", label),
            attestation_root: deterministic_root("audit-shard-91-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard92 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard92 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-92",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-92",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-92-note", label),
            quote_root: deterministic_root("audit-shard-92-quote", label),
            reserve_root: deterministic_root("audit-shard-92-reserve", label),
            reservation_root: deterministic_root("audit-shard-92-reservation", label),
            batch_root: deterministic_root("audit-shard-92-batch", label),
            watchtower_root: deterministic_root("audit-shard-92-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-92-nullifier", label),
            attestation_root: deterministic_root("audit-shard-92-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard93 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard93 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-93",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-93",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-93-note", label),
            quote_root: deterministic_root("audit-shard-93-quote", label),
            reserve_root: deterministic_root("audit-shard-93-reserve", label),
            reservation_root: deterministic_root("audit-shard-93-reservation", label),
            batch_root: deterministic_root("audit-shard-93-batch", label),
            watchtower_root: deterministic_root("audit-shard-93-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-93-nullifier", label),
            attestation_root: deterministic_root("audit-shard-93-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard94 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard94 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-94",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-94",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-94-note", label),
            quote_root: deterministic_root("audit-shard-94-quote", label),
            reserve_root: deterministic_root("audit-shard-94-reserve", label),
            reservation_root: deterministic_root("audit-shard-94-reservation", label),
            batch_root: deterministic_root("audit-shard-94-batch", label),
            watchtower_root: deterministic_root("audit-shard-94-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-94-nullifier", label),
            attestation_root: deterministic_root("audit-shard-94-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard95 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard95 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-95",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-95",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-95-note", label),
            quote_root: deterministic_root("audit-shard-95-quote", label),
            reserve_root: deterministic_root("audit-shard-95-reserve", label),
            reservation_root: deterministic_root("audit-shard-95-reservation", label),
            batch_root: deterministic_root("audit-shard-95-batch", label),
            watchtower_root: deterministic_root("audit-shard-95-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-95-nullifier", label),
            attestation_root: deterministic_root("audit-shard-95-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard96 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard96 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-96",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-96",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-96-note", label),
            quote_root: deterministic_root("audit-shard-96-quote", label),
            reserve_root: deterministic_root("audit-shard-96-reserve", label),
            reservation_root: deterministic_root("audit-shard-96-reservation", label),
            batch_root: deterministic_root("audit-shard-96-batch", label),
            watchtower_root: deterministic_root("audit-shard-96-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-96-nullifier", label),
            attestation_root: deterministic_root("audit-shard-96-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard97 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard97 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-97",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-97",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-97-note", label),
            quote_root: deterministic_root("audit-shard-97-quote", label),
            reserve_root: deterministic_root("audit-shard-97-reserve", label),
            reservation_root: deterministic_root("audit-shard-97-reservation", label),
            batch_root: deterministic_root("audit-shard-97-batch", label),
            watchtower_root: deterministic_root("audit-shard-97-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-97-nullifier", label),
            attestation_root: deterministic_root("audit-shard-97-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard98 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard98 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-98",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-98",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-98-note", label),
            quote_root: deterministic_root("audit-shard-98-quote", label),
            reserve_root: deterministic_root("audit-shard-98-reserve", label),
            reservation_root: deterministic_root("audit-shard-98-reservation", label),
            batch_root: deterministic_root("audit-shard-98-batch", label),
            watchtower_root: deterministic_root("audit-shard-98-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-98-nullifier", label),
            attestation_root: deterministic_root("audit-shard-98-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard99 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard99 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-99",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-99",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-99-note", label),
            quote_root: deterministic_root("audit-shard-99-quote", label),
            reserve_root: deterministic_root("audit-shard-99-reserve", label),
            reservation_root: deterministic_root("audit-shard-99-reservation", label),
            batch_root: deterministic_root("audit-shard-99-batch", label),
            watchtower_root: deterministic_root("audit-shard-99-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-99-nullifier", label),
            attestation_root: deterministic_root("audit-shard-99-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard100 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard100 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-100",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-100",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-100-note", label),
            quote_root: deterministic_root("audit-shard-100-quote", label),
            reserve_root: deterministic_root("audit-shard-100-reserve", label),
            reservation_root: deterministic_root("audit-shard-100-reservation", label),
            batch_root: deterministic_root("audit-shard-100-batch", label),
            watchtower_root: deterministic_root("audit-shard-100-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-100-nullifier", label),
            attestation_root: deterministic_root("audit-shard-100-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard101 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard101 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-101",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-101",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-101-note", label),
            quote_root: deterministic_root("audit-shard-101-quote", label),
            reserve_root: deterministic_root("audit-shard-101-reserve", label),
            reservation_root: deterministic_root("audit-shard-101-reservation", label),
            batch_root: deterministic_root("audit-shard-101-batch", label),
            watchtower_root: deterministic_root("audit-shard-101-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-101-nullifier", label),
            attestation_root: deterministic_root("audit-shard-101-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard102 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard102 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-102",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-102",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-102-note", label),
            quote_root: deterministic_root("audit-shard-102-quote", label),
            reserve_root: deterministic_root("audit-shard-102-reserve", label),
            reservation_root: deterministic_root("audit-shard-102-reservation", label),
            batch_root: deterministic_root("audit-shard-102-batch", label),
            watchtower_root: deterministic_root("audit-shard-102-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-102-nullifier", label),
            attestation_root: deterministic_root("audit-shard-102-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard103 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard103 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-103",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-103",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-103-note", label),
            quote_root: deterministic_root("audit-shard-103-quote", label),
            reserve_root: deterministic_root("audit-shard-103-reserve", label),
            reservation_root: deterministic_root("audit-shard-103-reservation", label),
            batch_root: deterministic_root("audit-shard-103-batch", label),
            watchtower_root: deterministic_root("audit-shard-103-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-103-nullifier", label),
            attestation_root: deterministic_root("audit-shard-103-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard104 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard104 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-104",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-104",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-104-note", label),
            quote_root: deterministic_root("audit-shard-104-quote", label),
            reserve_root: deterministic_root("audit-shard-104-reserve", label),
            reservation_root: deterministic_root("audit-shard-104-reservation", label),
            batch_root: deterministic_root("audit-shard-104-batch", label),
            watchtower_root: deterministic_root("audit-shard-104-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-104-nullifier", label),
            attestation_root: deterministic_root("audit-shard-104-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard105 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard105 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-105",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-105",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-105-note", label),
            quote_root: deterministic_root("audit-shard-105-quote", label),
            reserve_root: deterministic_root("audit-shard-105-reserve", label),
            reservation_root: deterministic_root("audit-shard-105-reservation", label),
            batch_root: deterministic_root("audit-shard-105-batch", label),
            watchtower_root: deterministic_root("audit-shard-105-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-105-nullifier", label),
            attestation_root: deterministic_root("audit-shard-105-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard106 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard106 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-106",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-106",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-106-note", label),
            quote_root: deterministic_root("audit-shard-106-quote", label),
            reserve_root: deterministic_root("audit-shard-106-reserve", label),
            reservation_root: deterministic_root("audit-shard-106-reservation", label),
            batch_root: deterministic_root("audit-shard-106-batch", label),
            watchtower_root: deterministic_root("audit-shard-106-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-106-nullifier", label),
            attestation_root: deterministic_root("audit-shard-106-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard107 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard107 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-107",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-107",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-107-note", label),
            quote_root: deterministic_root("audit-shard-107-quote", label),
            reserve_root: deterministic_root("audit-shard-107-reserve", label),
            reservation_root: deterministic_root("audit-shard-107-reservation", label),
            batch_root: deterministic_root("audit-shard-107-batch", label),
            watchtower_root: deterministic_root("audit-shard-107-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-107-nullifier", label),
            attestation_root: deterministic_root("audit-shard-107-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard108 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard108 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-108",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-108",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-108-note", label),
            quote_root: deterministic_root("audit-shard-108-quote", label),
            reserve_root: deterministic_root("audit-shard-108-reserve", label),
            reservation_root: deterministic_root("audit-shard-108-reservation", label),
            batch_root: deterministic_root("audit-shard-108-batch", label),
            watchtower_root: deterministic_root("audit-shard-108-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-108-nullifier", label),
            attestation_root: deterministic_root("audit-shard-108-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard109 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard109 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-109",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-109",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-109-note", label),
            quote_root: deterministic_root("audit-shard-109-quote", label),
            reserve_root: deterministic_root("audit-shard-109-reserve", label),
            reservation_root: deterministic_root("audit-shard-109-reservation", label),
            batch_root: deterministic_root("audit-shard-109-batch", label),
            watchtower_root: deterministic_root("audit-shard-109-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-109-nullifier", label),
            attestation_root: deterministic_root("audit-shard-109-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard110 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard110 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-110",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-110",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-110-note", label),
            quote_root: deterministic_root("audit-shard-110-quote", label),
            reserve_root: deterministic_root("audit-shard-110-reserve", label),
            reservation_root: deterministic_root("audit-shard-110-reservation", label),
            batch_root: deterministic_root("audit-shard-110-batch", label),
            watchtower_root: deterministic_root("audit-shard-110-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-110-nullifier", label),
            attestation_root: deterministic_root("audit-shard-110-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard111 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard111 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-111",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-111",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-111-note", label),
            quote_root: deterministic_root("audit-shard-111-quote", label),
            reserve_root: deterministic_root("audit-shard-111-reserve", label),
            reservation_root: deterministic_root("audit-shard-111-reservation", label),
            batch_root: deterministic_root("audit-shard-111-batch", label),
            watchtower_root: deterministic_root("audit-shard-111-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-111-nullifier", label),
            attestation_root: deterministic_root("audit-shard-111-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard112 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard112 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-112",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-112",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-112-note", label),
            quote_root: deterministic_root("audit-shard-112-quote", label),
            reserve_root: deterministic_root("audit-shard-112-reserve", label),
            reservation_root: deterministic_root("audit-shard-112-reservation", label),
            batch_root: deterministic_root("audit-shard-112-batch", label),
            watchtower_root: deterministic_root("audit-shard-112-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-112-nullifier", label),
            attestation_root: deterministic_root("audit-shard-112-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard113 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard113 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-113",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-113",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-113-note", label),
            quote_root: deterministic_root("audit-shard-113-quote", label),
            reserve_root: deterministic_root("audit-shard-113-reserve", label),
            reservation_root: deterministic_root("audit-shard-113-reservation", label),
            batch_root: deterministic_root("audit-shard-113-batch", label),
            watchtower_root: deterministic_root("audit-shard-113-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-113-nullifier", label),
            attestation_root: deterministic_root("audit-shard-113-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard114 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard114 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-114",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-114",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-114-note", label),
            quote_root: deterministic_root("audit-shard-114-quote", label),
            reserve_root: deterministic_root("audit-shard-114-reserve", label),
            reservation_root: deterministic_root("audit-shard-114-reservation", label),
            batch_root: deterministic_root("audit-shard-114-batch", label),
            watchtower_root: deterministic_root("audit-shard-114-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-114-nullifier", label),
            attestation_root: deterministic_root("audit-shard-114-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard115 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard115 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-115",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-115",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-115-note", label),
            quote_root: deterministic_root("audit-shard-115-quote", label),
            reserve_root: deterministic_root("audit-shard-115-reserve", label),
            reservation_root: deterministic_root("audit-shard-115-reservation", label),
            batch_root: deterministic_root("audit-shard-115-batch", label),
            watchtower_root: deterministic_root("audit-shard-115-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-115-nullifier", label),
            attestation_root: deterministic_root("audit-shard-115-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard116 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard116 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-116",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-116",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-116-note", label),
            quote_root: deterministic_root("audit-shard-116-quote", label),
            reserve_root: deterministic_root("audit-shard-116-reserve", label),
            reservation_root: deterministic_root("audit-shard-116-reservation", label),
            batch_root: deterministic_root("audit-shard-116-batch", label),
            watchtower_root: deterministic_root("audit-shard-116-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-116-nullifier", label),
            attestation_root: deterministic_root("audit-shard-116-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard117 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard117 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-117",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-117",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-117-note", label),
            quote_root: deterministic_root("audit-shard-117-quote", label),
            reserve_root: deterministic_root("audit-shard-117-reserve", label),
            reservation_root: deterministic_root("audit-shard-117-reservation", label),
            batch_root: deterministic_root("audit-shard-117-batch", label),
            watchtower_root: deterministic_root("audit-shard-117-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-117-nullifier", label),
            attestation_root: deterministic_root("audit-shard-117-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard118 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard118 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-118",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-118",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-118-note", label),
            quote_root: deterministic_root("audit-shard-118-quote", label),
            reserve_root: deterministic_root("audit-shard-118-reserve", label),
            reservation_root: deterministic_root("audit-shard-118-reservation", label),
            batch_root: deterministic_root("audit-shard-118-batch", label),
            watchtower_root: deterministic_root("audit-shard-118-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-118-nullifier", label),
            attestation_root: deterministic_root("audit-shard-118-attestation", label),
            sequence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterDeterministicAuditShard119 {
    pub shard_id: String,
    pub note_root: String,
    pub quote_root: String,
    pub reserve_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub watchtower_root: String,
    pub nullifier_root: String,
    pub attestation_root: String,
    pub sequence: u64,
}
impl RouterDeterministicAuditShard119 {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_root(&self) -> String {
        payload_root(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-119",
            &self.public_record(),
        )
    }
    pub fn deterministic(label: &str, sequence: u64) -> Self {
        let shard_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-EXIT-LIQUIDITY-ROUTER-AUDIT-SHARD-ID-119",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(label),
                HashPart::U64(sequence),
            ],
            32,
        );
        Self {
            shard_id,
            note_root: deterministic_root("audit-shard-119-note", label),
            quote_root: deterministic_root("audit-shard-119-quote", label),
            reserve_root: deterministic_root("audit-shard-119-reserve", label),
            reservation_root: deterministic_root("audit-shard-119-reservation", label),
            batch_root: deterministic_root("audit-shard-119-batch", label),
            watchtower_root: deterministic_root("audit-shard-119-watchtower", label),
            nullifier_root: deterministic_root("audit-shard-119-nullifier", label),
            attestation_root: deterministic_root("audit-shard-119-attestation", label),
            sequence,
        }
    }
}
