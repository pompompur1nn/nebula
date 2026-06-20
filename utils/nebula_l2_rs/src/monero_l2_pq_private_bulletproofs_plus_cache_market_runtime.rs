use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateBulletproofsPlusCacheMarketRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_BULLETPROOFS_PLUS_CACHE_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-bulletproofs-plus-cache-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_BULLETPROOFS_PLUS_CACHE_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RANGE_PROOF_CACHE_TICKET_SCHEME: &str =
    "monero-bulletproofs-plus-range-proof-cache-ticket-root-v1";
pub const PROVER_RESERVATION_SCHEME: &str = "private-bulletproofs-plus-prover-reservation-root-v1";
pub const PQ_CACHE_ATTESTATION_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-bulletproofs-plus-cache-attestation-v1";
pub const BATCH_VERIFICATION_HINT_SCHEME: &str =
    "monero-bulletproofs-plus-batch-verification-hint-root-v1";
pub const LOW_FEE_PROOF_REBATE_SCHEME: &str =
    "low-fee-private-bulletproofs-plus-cache-rebate-root-v1";
pub const PRIVACY_REDACTION_BUDGET_SCHEME: &str =
    "view-key-safe-cache-market-redaction-budget-root-v1";
pub const STALE_PROOF_QUARANTINE_SCHEME: &str = "stale-bulletproofs-plus-cache-quarantine-root-v1";
pub const PUBLIC_MARKET_RECORD_SCHEME: &str =
    "deterministic-public-bulletproofs-plus-cache-market-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_amounts_addresses_view_keys_key_images_decoy_graphs_or_proof_bytes";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_RING_SIZE: u64 = 16;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_BATCH_PROOFS: u64 = 8;
pub const DEFAULT_TARGET_BATCH_PROOFS: u64 = 128;
pub const DEFAULT_MAX_BATCH_PROOFS: u64 = 512;
pub const DEFAULT_CACHE_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 20;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_QUARANTINE_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 7;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 4;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_250;
pub const DEFAULT_MAX_REDACTION_UNITS_PER_TICKET: u64 = 32;
pub const DEFAULT_PUBLIC_BUCKET_SIZE: u64 = 64;
pub const DEFAULT_MAX_TICKETS: usize = 4_194_304;
pub const DEFAULT_MAX_RESERVATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_HINTS: usize = 2_097_152;
pub const DEFAULT_MAX_REBATES: usize = 4_194_304;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 1_048_576;
pub const DEFAULT_MAX_QUARANTINES: usize = 1_048_576;
pub const DEFAULT_MAX_NULLIFIERS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RangeProofCacheKind {
    WalletOutput,
    BridgeDeposit,
    BridgeWithdrawal,
    SwapSettlement,
    MerchantPayment,
    MicropaymentNetting,
    LiquidityRebalance,
    AuditWindow,
}

impl RangeProofCacheKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletOutput => "wallet_output",
            Self::BridgeDeposit => "bridge_deposit",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::SwapSettlement => "swap_settlement",
            Self::MerchantPayment => "merchant_payment",
            Self::MicropaymentNetting => "micropayment_netting",
            Self::LiquidityRebalance => "liquidity_rebalance",
            Self::AuditWindow => "audit_window",
        }
    }

    pub fn complexity_weight(self) -> u64 {
        match self {
            Self::AuditWindow => 1_000,
            Self::BridgeWithdrawal => 940,
            Self::BridgeDeposit => 900,
            Self::SwapSettlement => 840,
            Self::LiquidityRebalance => 780,
            Self::MerchantPayment => 700,
            Self::MicropaymentNetting => 640,
            Self::WalletOutput => 560,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    Open,
    Reserved,
    Attested,
    HintPublished,
    RebateQueued,
    Settled,
    Quarantined,
    Expired,
    Rejected,
}

impl TicketStatus {
    pub fn accepts_reservation(self) -> bool {
        matches!(self, Self::Open)
    }

    pub fn is_publicly_usable(self) -> bool {
        matches!(
            self,
            Self::Attested | Self::HintPublished | Self::RebateQueued | Self::Settled
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Posted,
    Accepted,
    Proving,
    Fulfilled,
    RebateEligible,
    Refunded,
    Expired,
    Slashed,
}

impl ReservationStatus {
    pub fn active(self) -> bool {
        matches!(self, Self::Posted | Self::Accepted | Self::Proving)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    Quorum,
    Expired,
    Revoked,
    Rejected,
}

impl AttestationStatus {
    pub fn counts_for_cache(self) -> bool {
        matches!(self, Self::Accepted | Self::Quorum)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchHintStatus {
    Draft,
    Published,
    Consumed,
    Superseded,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Queued,
    Sponsored,
    Paid,
    Refunded,
    Expired,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionBudgetStatus {
    Open,
    Reserved,
    Applied,
    Exhausted,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    StaleProofRoot,
    AttestationExpired,
    TranscriptMismatch,
    NullifierReuse,
    PrivacyBudgetExceeded,
    BatchHintDrift,
    FeeOvercharge,
    OperatorRedactionLeak,
}

impl QuarantineReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaleProofRoot => "stale_proof_root",
            Self::AttestationExpired => "attestation_expired",
            Self::TranscriptMismatch => "transcript_mismatch",
            Self::NullifierReuse => "nullifier_reuse",
            Self::PrivacyBudgetExceeded => "privacy_budget_exceeded",
            Self::BatchHintDrift => "batch_hint_drift",
            Self::FeeOvercharge => "fee_overcharge",
            Self::OperatorRedactionLeak => "operator_redaction_leak",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicRecordAudience {
    Wallet,
    Prover,
    Sponsor,
    Watchtower,
    Auditor,
    Operator,
}

impl PublicRecordAudience {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wallet => "wallet",
            Self::Prover => "prover",
            Self::Sponsor => "sponsor",
            Self::Watchtower => "watchtower",
            Self::Auditor => "auditor",
            Self::Operator => "operator",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub ticket_scheme: String,
    pub reservation_scheme: String,
    pub pq_attestation_scheme: String,
    pub batch_hint_scheme: String,
    pub rebate_scheme: String,
    pub redaction_budget_scheme: String,
    pub quarantine_scheme: String,
    pub public_record_scheme: String,
    pub privacy_boundary: String,
    pub min_ring_size: u64,
    pub min_privacy_set_size: u64,
    pub min_batch_proofs: u64,
    pub target_batch_proofs: u64,
    pub max_batch_proofs: u64,
    pub cache_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub quarantine_ttl_blocks: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub max_redaction_units_per_ticket: u64,
    pub public_bucket_size: u64,
    pub max_tickets: usize,
    pub max_reservations: usize,
    pub max_attestations: usize,
    pub max_hints: usize,
    pub max_rebates: usize,
    pub max_redaction_budgets: usize,
    pub max_quarantines: usize,
    pub max_nullifiers: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            asset_id: DEVNET_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            ticket_scheme: RANGE_PROOF_CACHE_TICKET_SCHEME.to_string(),
            reservation_scheme: PROVER_RESERVATION_SCHEME.to_string(),
            pq_attestation_scheme: PQ_CACHE_ATTESTATION_SCHEME.to_string(),
            batch_hint_scheme: BATCH_VERIFICATION_HINT_SCHEME.to_string(),
            rebate_scheme: LOW_FEE_PROOF_REBATE_SCHEME.to_string(),
            redaction_budget_scheme: PRIVACY_REDACTION_BUDGET_SCHEME.to_string(),
            quarantine_scheme: STALE_PROOF_QUARANTINE_SCHEME.to_string(),
            public_record_scheme: PUBLIC_MARKET_RECORD_SCHEME.to_string(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            min_ring_size: DEFAULT_MIN_RING_SIZE,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_batch_proofs: DEFAULT_MIN_BATCH_PROOFS,
            target_batch_proofs: DEFAULT_TARGET_BATCH_PROOFS,
            max_batch_proofs: DEFAULT_MAX_BATCH_PROOFS,
            cache_ttl_blocks: DEFAULT_CACHE_TTL_BLOCKS,
            reservation_ttl_blocks: DEFAULT_RESERVATION_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            quarantine_ttl_blocks: DEFAULT_QUARANTINE_TTL_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            max_redaction_units_per_ticket: DEFAULT_MAX_REDACTION_UNITS_PER_TICKET,
            public_bucket_size: DEFAULT_PUBLIC_BUCKET_SIZE,
            max_tickets: DEFAULT_MAX_TICKETS,
            max_reservations: DEFAULT_MAX_RESERVATIONS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_hints: DEFAULT_MAX_HINTS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
            max_quarantines: DEFAULT_MAX_QUARANTINES,
            max_nullifiers: DEFAULT_MAX_NULLIFIERS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("protocol_version", &self.protocol_version)?;
        ensure_nonempty("chain_id", &self.chain_id)?;
        ensure_nonempty("l2_network", &self.l2_network)?;
        ensure_nonempty("monero_network", &self.monero_network)?;
        ensure_nonempty("asset_id", &self.asset_id)?;
        ensure_nonempty("fee_asset_id", &self.fee_asset_id)?;
        ensure_nonempty("hash_suite", &self.hash_suite)?;
        ensure_nonempty("ticket_scheme", &self.ticket_scheme)?;
        ensure_nonempty("reservation_scheme", &self.reservation_scheme)?;
        ensure_nonempty("pq_attestation_scheme", &self.pq_attestation_scheme)?;
        ensure_nonempty("batch_hint_scheme", &self.batch_hint_scheme)?;
        ensure_nonempty("rebate_scheme", &self.rebate_scheme)?;
        ensure_nonempty("redaction_budget_scheme", &self.redaction_budget_scheme)?;
        ensure_nonempty("quarantine_scheme", &self.quarantine_scheme)?;
        ensure_nonempty("public_record_scheme", &self.public_record_scheme)?;
        ensure_nonempty("privacy_boundary", &self.privacy_boundary)?;
        ensure_positive_u64("min_ring_size", self.min_ring_size)?;
        ensure_positive_u64("min_privacy_set_size", self.min_privacy_set_size)?;
        ensure_positive_u64("min_batch_proofs", self.min_batch_proofs)?;
        ensure_positive_u64("target_batch_proofs", self.target_batch_proofs)?;
        ensure_positive_u64("max_batch_proofs", self.max_batch_proofs)?;
        ensure_positive_u64("cache_ttl_blocks", self.cache_ttl_blocks)?;
        ensure_positive_u64("reservation_ttl_blocks", self.reservation_ttl_blocks)?;
        ensure_positive_u64("attestation_ttl_blocks", self.attestation_ttl_blocks)?;
        ensure_positive_u64("quarantine_ttl_blocks", self.quarantine_ttl_blocks)?;
        ensure_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        ensure_bps("target_rebate_bps", self.target_rebate_bps)?;
        ensure_bps("sponsor_cover_bps", self.sponsor_cover_bps)?;
        ensure_positive_usize("max_tickets", self.max_tickets)?;
        ensure_positive_usize("max_reservations", self.max_reservations)?;
        ensure_positive_usize("max_attestations", self.max_attestations)?;
        ensure_positive_usize("max_hints", self.max_hints)?;
        ensure_positive_usize("max_rebates", self.max_rebates)?;
        ensure_positive_usize("max_redaction_budgets", self.max_redaction_budgets)?;
        ensure_positive_usize("max_quarantines", self.max_quarantines)?;
        ensure_positive_usize("max_nullifiers", self.max_nullifiers)?;
        if self.target_batch_proofs < self.min_batch_proofs {
            return Err("target_batch_proofs cannot be below min_batch_proofs".to_string());
        }
        if self.max_batch_proofs < self.target_batch_proofs {
            return Err("max_batch_proofs cannot be below target_batch_proofs".to_string());
        }
        if self.target_pq_security_bits < self.min_pq_security_bits {
            return Err("target_pq_security_bits cannot be below min_pq_security_bits".to_string());
        }
        if self.target_rebate_bps > self.max_user_fee_bps {
            return Err("target_rebate_bps cannot exceed max_user_fee_bps".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_ticket_sequence: u64,
    pub next_reservation_sequence: u64,
    pub next_attestation_sequence: u64,
    pub next_hint_sequence: u64,
    pub next_rebate_sequence: u64,
    pub next_redaction_budget_sequence: u64,
    pub next_quarantine_sequence: u64,
    pub ticket_count: u64,
    pub reservation_count: u64,
    pub attestation_count: u64,
    pub hint_count: u64,
    pub rebate_count: u64,
    pub redaction_budget_count: u64,
    pub quarantine_count: u64,
    pub public_record_count: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub ticket_root: String,
    pub reservation_root: String,
    pub attestation_root: String,
    pub hint_root: String,
    pub rebate_root: String,
    pub redaction_budget_root: String,
    pub quarantine_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RangeProofCacheTicketRequest {
    pub owner_commitment: String,
    pub kind: RangeProofCacheKind,
    pub range_proof_transcript_root: String,
    pub amount_commitment_root: String,
    pub output_commitment_root: String,
    pub cache_key_root: String,
    pub privacy_set_root: String,
    pub ticket_nullifier: String,
    pub min_ring_size: u64,
    pub privacy_set_size: u64,
    pub max_fee_micro_units: u64,
    pub requested_rebate_bps: u64,
    pub redaction_units_reserved: u64,
    pub opened_height: u64,
}

impl RangeProofCacheTicketRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_nonempty("owner_commitment", &self.owner_commitment)?;
        ensure_root(
            "range_proof_transcript_root",
            &self.range_proof_transcript_root,
        )?;
        ensure_root("amount_commitment_root", &self.amount_commitment_root)?;
        ensure_root("output_commitment_root", &self.output_commitment_root)?;
        ensure_root("cache_key_root", &self.cache_key_root)?;
        ensure_root("privacy_set_root", &self.privacy_set_root)?;
        ensure_nonempty("ticket_nullifier", &self.ticket_nullifier)?;
        ensure_positive_u64("min_ring_size", self.min_ring_size)?;
        ensure_positive_u64("privacy_set_size", self.privacy_set_size)?;
        ensure_bps("requested_rebate_bps", self.requested_rebate_bps)?;
        if self.min_ring_size < config.min_ring_size {
            return Err("ticket min_ring_size below configured privacy floor".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("ticket privacy_set_size below configured privacy floor".to_string());
        }
        if self.requested_rebate_bps > config.target_rebate_bps {
            return Err("requested_rebate_bps exceeds configured target".to_string());
        }
        if self.redaction_units_reserved > config.max_redaction_units_per_ticket {
            return Err("redaction_units_reserved exceeds configured per-ticket cap".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RangeProofCacheTicketRecord {
    pub ticket_id: String,
    pub owner_commitment: String,
    pub kind: RangeProofCacheKind,
    pub status: TicketStatus,
    pub range_proof_transcript_root: String,
    pub amount_commitment_root: String,
    pub output_commitment_root: String,
    pub cache_key_root: String,
    pub privacy_set_root: String,
    pub ticket_nullifier_root: String,
    pub min_ring_size: u64,
    pub privacy_set_size: u64,
    pub max_fee_micro_units: u64,
    pub requested_rebate_bps: u64,
    pub redaction_units_reserved: u64,
    pub opened_height: u64,
    pub expires_height: u64,
    pub priority_score: u64,
    pub public_bucket: u64,
}

impl RangeProofCacheTicketRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProverReservationRequest {
    pub ticket_id: String,
    pub prover_commitment: String,
    pub proving_key_root: String,
    pub reservation_bid_root: String,
    pub pq_identity_root: String,
    pub max_latency_ms: u64,
    pub fee_micro_units: u64,
    pub bond_micro_units: u64,
    pub reserved_height: u64,
}

impl ProverReservationRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_nonempty("ticket_id", &self.ticket_id)?;
        ensure_nonempty("prover_commitment", &self.prover_commitment)?;
        ensure_root("proving_key_root", &self.proving_key_root)?;
        ensure_root("reservation_bid_root", &self.reservation_bid_root)?;
        ensure_root("pq_identity_root", &self.pq_identity_root)?;
        ensure_positive_u64("max_latency_ms", self.max_latency_ms)?;
        ensure_positive_u64("bond_micro_units", self.bond_micro_units)?;
        if self.fee_micro_units > fee_cap_micro_units(config.max_user_fee_bps) {
            return Err("fee_micro_units exceeds configured low-fee cap".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProverReservationRecord {
    pub reservation_id: String,
    pub ticket_id: String,
    pub prover_commitment: String,
    pub status: ReservationStatus,
    pub proving_key_root: String,
    pub reservation_bid_root: String,
    pub pq_identity_root: String,
    pub max_latency_ms: u64,
    pub fee_micro_units: u64,
    pub bond_micro_units: u64,
    pub reserved_height: u64,
    pub expires_height: u64,
    pub reservation_score: u64,
}

impl ProverReservationRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqCacheAttestationRequest {
    pub ticket_id: String,
    pub reservation_id: String,
    pub attestor_commitment: String,
    pub cache_attestation_root: String,
    pub pq_signature_root: String,
    pub batch_transcript_root: String,
    pub cache_hit_bitmap_root: String,
    pub pq_security_bits: u16,
    pub attested_height: u64,
}

impl PqCacheAttestationRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_nonempty("ticket_id", &self.ticket_id)?;
        ensure_nonempty("reservation_id", &self.reservation_id)?;
        ensure_nonempty("attestor_commitment", &self.attestor_commitment)?;
        ensure_root("cache_attestation_root", &self.cache_attestation_root)?;
        ensure_root("pq_signature_root", &self.pq_signature_root)?;
        ensure_root("batch_transcript_root", &self.batch_transcript_root)?;
        ensure_root("cache_hit_bitmap_root", &self.cache_hit_bitmap_root)?;
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("pq_security_bits below configured minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqCacheAttestationRecord {
    pub attestation_id: String,
    pub ticket_id: String,
    pub reservation_id: String,
    pub attestor_commitment: String,
    pub status: AttestationStatus,
    pub cache_attestation_root: String,
    pub pq_signature_root: String,
    pub batch_transcript_root: String,
    pub cache_hit_bitmap_root: String,
    pub pq_security_bits: u16,
    pub attested_height: u64,
    pub expires_height: u64,
}

impl PqCacheAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BatchVerificationHintRequest {
    pub ticket_ids: Vec<String>,
    pub attestation_ids: Vec<String>,
    pub hint_publisher_commitment: String,
    pub batch_hint_root: String,
    pub verifier_key_root: String,
    pub msm_bucket_root: String,
    pub transcript_challenge_root: String,
    pub proof_count: u64,
    pub expected_verify_ms: u64,
    pub published_height: u64,
}

impl BatchVerificationHintRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_unique_nonempty("ticket_ids", &self.ticket_ids)?;
        ensure_unique_nonempty("attestation_ids", &self.attestation_ids)?;
        ensure_nonempty("hint_publisher_commitment", &self.hint_publisher_commitment)?;
        ensure_root("batch_hint_root", &self.batch_hint_root)?;
        ensure_root("verifier_key_root", &self.verifier_key_root)?;
        ensure_root("msm_bucket_root", &self.msm_bucket_root)?;
        ensure_root("transcript_challenge_root", &self.transcript_challenge_root)?;
        if self.proof_count < config.min_batch_proofs {
            return Err("proof_count below min_batch_proofs".to_string());
        }
        if self.proof_count > config.max_batch_proofs {
            return Err("proof_count exceeds max_batch_proofs".to_string());
        }
        ensure_positive_u64("expected_verify_ms", self.expected_verify_ms)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BatchVerificationHintRecord {
    pub hint_id: String,
    pub ticket_ids_root: String,
    pub attestation_ids_root: String,
    pub hint_publisher_commitment: String,
    pub status: BatchHintStatus,
    pub batch_hint_root: String,
    pub verifier_key_root: String,
    pub msm_bucket_root: String,
    pub transcript_challenge_root: String,
    pub proof_count: u64,
    pub expected_verify_ms: u64,
    pub published_height: u64,
}

impl BatchVerificationHintRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeProofRebateRequest {
    pub ticket_id: String,
    pub reservation_id: String,
    pub sponsor_commitment: String,
    pub beneficiary_commitment: String,
    pub fee_paid_micro_units: u64,
    pub rebate_commitment_root: String,
    pub sponsor_budget_root: String,
    pub rebate_nullifier: String,
    pub issued_height: u64,
}

impl LowFeeProofRebateRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_nonempty("ticket_id", &self.ticket_id)?;
        ensure_nonempty("reservation_id", &self.reservation_id)?;
        ensure_nonempty("sponsor_commitment", &self.sponsor_commitment)?;
        ensure_nonempty("beneficiary_commitment", &self.beneficiary_commitment)?;
        ensure_positive_u64("fee_paid_micro_units", self.fee_paid_micro_units)?;
        ensure_root("rebate_commitment_root", &self.rebate_commitment_root)?;
        ensure_root("sponsor_budget_root", &self.sponsor_budget_root)?;
        ensure_nonempty("rebate_nullifier", &self.rebate_nullifier)?;
        if proof_rebate_micro_units(config, self.fee_paid_micro_units) == 0 {
            return Err("rebate amount rounds to zero".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeProofRebateRecord {
    pub rebate_id: String,
    pub ticket_id: String,
    pub reservation_id: String,
    pub sponsor_commitment: String,
    pub beneficiary_commitment: String,
    pub status: RebateStatus,
    pub fee_paid_micro_units: u64,
    pub rebate_micro_units: u64,
    pub rebate_commitment_root: String,
    pub sponsor_budget_root: String,
    pub rebate_nullifier_root: String,
    pub issued_height: u64,
}

impl LowFeeProofRebateRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudgetRequest {
    pub owner_commitment: String,
    pub ticket_ids: Vec<String>,
    pub redaction_policy_root: String,
    pub viewkey_scope_root: String,
    pub budget_nullifier: String,
    pub redaction_units: u64,
    pub opened_height: u64,
}

impl PrivacyRedactionBudgetRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_nonempty("owner_commitment", &self.owner_commitment)?;
        ensure_unique_nonempty("ticket_ids", &self.ticket_ids)?;
        ensure_root("redaction_policy_root", &self.redaction_policy_root)?;
        ensure_root("viewkey_scope_root", &self.viewkey_scope_root)?;
        ensure_nonempty("budget_nullifier", &self.budget_nullifier)?;
        ensure_positive_u64("redaction_units", self.redaction_units)?;
        if self.redaction_units
            > config
                .max_redaction_units_per_ticket
                .saturating_mul(self.ticket_ids.len() as u64)
        {
            return Err("redaction_units exceed configured ticket budget".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudgetRecord {
    pub budget_id: String,
    pub owner_commitment: String,
    pub ticket_ids_root: String,
    pub status: RedactionBudgetStatus,
    pub redaction_policy_root: String,
    pub viewkey_scope_root: String,
    pub budget_nullifier_root: String,
    pub redaction_units: u64,
    pub spent_redaction_units: u64,
    pub opened_height: u64,
}

impl PrivacyRedactionBudgetRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StaleProofQuarantineRequest {
    pub ticket_id: String,
    pub subject_root: String,
    pub reporter_commitment: String,
    pub reason: QuarantineReason,
    pub evidence_root: String,
    pub stale_height: u64,
    pub reported_height: u64,
}

impl StaleProofQuarantineRequest {
    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("ticket_id", &self.ticket_id)?;
        ensure_root("subject_root", &self.subject_root)?;
        ensure_nonempty("reporter_commitment", &self.reporter_commitment)?;
        ensure_root("evidence_root", &self.evidence_root)?;
        if self.reported_height < self.stale_height {
            return Err("reported_height cannot be below stale_height".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StaleProofQuarantineRecord {
    pub quarantine_id: String,
    pub ticket_id: String,
    pub subject_root: String,
    pub reporter_commitment: String,
    pub reason: QuarantineReason,
    pub evidence_root: String,
    pub stale_height: u64,
    pub reported_height: u64,
    pub expires_height: u64,
}

impl StaleProofQuarantineRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeterministicPublicRecordRequest {
    pub subject_id: String,
    pub audience: PublicRecordAudience,
    pub public_summary_root: String,
    pub redacted_field_root: String,
    pub operator_commitment: String,
    pub published_height: u64,
}

impl DeterministicPublicRecordRequest {
    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("subject_id", &self.subject_id)?;
        ensure_root("public_summary_root", &self.public_summary_root)?;
        ensure_root("redacted_field_root", &self.redacted_field_root)?;
        ensure_nonempty("operator_commitment", &self.operator_commitment)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeterministicPublicRecord {
    pub public_record_id: String,
    pub subject_id: String,
    pub audience: PublicRecordAudience,
    pub public_summary_root: String,
    pub redacted_field_root: String,
    pub operator_commitment: String,
    pub published_height: u64,
}

impl DeterministicPublicRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub tickets: BTreeMap<String, RangeProofCacheTicketRecord>,
    pub reservations: BTreeMap<String, ProverReservationRecord>,
    pub attestations: BTreeMap<String, PqCacheAttestationRecord>,
    pub hints: BTreeMap<String, BatchVerificationHintRecord>,
    pub rebates: BTreeMap<String, LowFeeProofRebateRecord>,
    pub redaction_budgets: BTreeMap<String, PrivacyRedactionBudgetRecord>,
    pub quarantines: BTreeMap<String, StaleProofQuarantineRecord>,
    pub public_records: BTreeMap<String, DeterministicPublicRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            tickets: BTreeMap::new(),
            reservations: BTreeMap::new(),
            attestations: BTreeMap::new(),
            hints: BTreeMap::new(),
            rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            quarantines: BTreeMap::new(),
            public_records: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        })
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet()).expect("devnet config is valid")
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let ticket = state
            .open_range_proof_cache_ticket(RangeProofCacheTicketRequest {
                owner_commitment: "owner:wallet-cache-demo".to_string(),
                kind: RangeProofCacheKind::BridgeWithdrawal,
                range_proof_transcript_root: demo_root("range-proof-transcript"),
                amount_commitment_root: demo_root("amount-commitment"),
                output_commitment_root: demo_root("output-commitment"),
                cache_key_root: demo_root("cache-key"),
                privacy_set_root: demo_root("privacy-set"),
                ticket_nullifier: "ticket-nullifier-demo-001".to_string(),
                min_ring_size: DEFAULT_MIN_RING_SIZE,
                privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
                max_fee_micro_units: 12_000,
                requested_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
                redaction_units_reserved: 8,
                opened_height: 1_024_000,
            })
            .expect("demo ticket opens");
        let reservation = state
            .reserve_prover(ProverReservationRequest {
                ticket_id: ticket.ticket_id.clone(),
                prover_commitment: "prover:bp-plus-cache-demo".to_string(),
                proving_key_root: demo_root("proving-key"),
                reservation_bid_root: demo_root("reservation-bid"),
                pq_identity_root: demo_root("pq-identity"),
                max_latency_ms: 850,
                fee_micro_units: 8_400,
                bond_micro_units: 500_000,
                reserved_height: 1_024_001,
            })
            .expect("demo prover reservation");
        let attestation = state
            .submit_pq_cache_attestation(PqCacheAttestationRequest {
                ticket_id: ticket.ticket_id.clone(),
                reservation_id: reservation.reservation_id.clone(),
                attestor_commitment: "attestor:cache-auditor-demo".to_string(),
                cache_attestation_root: demo_root("cache-attestation"),
                pq_signature_root: demo_root("pq-signature"),
                batch_transcript_root: demo_root("batch-transcript"),
                cache_hit_bitmap_root: demo_root("cache-hit-bitmap"),
                pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
                attested_height: 1_024_002,
            })
            .expect("demo cache attestation");
        state
            .publish_batch_verification_hint(BatchVerificationHintRequest {
                ticket_ids: vec![ticket.ticket_id.clone()],
                attestation_ids: vec![attestation.attestation_id.clone()],
                hint_publisher_commitment: "operator:batch-hint-demo".to_string(),
                batch_hint_root: demo_root("batch-hint"),
                verifier_key_root: demo_root("verifier-key"),
                msm_bucket_root: demo_root("msm-bucket"),
                transcript_challenge_root: demo_root("transcript-challenge"),
                proof_count: DEFAULT_MIN_BATCH_PROOFS,
                expected_verify_ms: 42,
                published_height: 1_024_003,
            })
            .expect("demo batch hint");
        state
            .open_redaction_budget(PrivacyRedactionBudgetRequest {
                owner_commitment: "owner:wallet-cache-demo".to_string(),
                ticket_ids: vec![ticket.ticket_id.clone()],
                redaction_policy_root: demo_root("redaction-policy"),
                viewkey_scope_root: demo_root("viewkey-scope"),
                budget_nullifier: "budget-nullifier-demo-001".to_string(),
                redaction_units: 8,
                opened_height: 1_024_004,
            })
            .expect("demo redaction budget");
        state
            .queue_low_fee_rebate(LowFeeProofRebateRequest {
                ticket_id: ticket.ticket_id.clone(),
                reservation_id: reservation.reservation_id.clone(),
                sponsor_commitment: "sponsor:low-fee-cache-demo".to_string(),
                beneficiary_commitment: "beneficiary:wallet-demo".to_string(),
                fee_paid_micro_units: 8_400,
                rebate_commitment_root: demo_root("rebate-commitment"),
                sponsor_budget_root: demo_root("sponsor-budget"),
                rebate_nullifier: "rebate-nullifier-demo-001".to_string(),
                issued_height: 1_024_005,
            })
            .expect("demo rebate");
        state
            .publish_deterministic_public_record(DeterministicPublicRecordRequest {
                subject_id: ticket.ticket_id.clone(),
                audience: PublicRecordAudience::Watchtower,
                public_summary_root: demo_root("public-summary"),
                redacted_field_root: demo_root("redacted-fields"),
                operator_commitment: "operator:public-record-demo".to_string(),
                published_height: 1_024_006,
            })
            .expect("demo public record");
        state
    }

    pub fn open_range_proof_cache_ticket(
        &mut self,
        request: RangeProofCacheTicketRequest,
    ) -> Result<RangeProofCacheTicketRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        ensure_capacity("tickets", self.tickets.len(), self.config.max_tickets)?;
        ensure_nullifier_available(&self.consumed_nullifiers, &request.ticket_nullifier)?;
        let sequence = self.counters.next_ticket_sequence;
        let ticket_id = range_proof_cache_ticket_id(&request, sequence);
        ensure_absent("ticket", &self.tickets, &ticket_id)?;
        let ticket_nullifier_root = payload_root(
            "MONERO-L2-BPPLUS-CACHE-TICKET-NULLIFIER",
            &json!({ "ticket_nullifier": request.ticket_nullifier }),
        );
        let record = RangeProofCacheTicketRecord {
            ticket_id: ticket_id.clone(),
            owner_commitment: request.owner_commitment,
            kind: request.kind,
            status: TicketStatus::Open,
            range_proof_transcript_root: request.range_proof_transcript_root,
            amount_commitment_root: request.amount_commitment_root,
            output_commitment_root: request.output_commitment_root,
            cache_key_root: request.cache_key_root,
            privacy_set_root: request.privacy_set_root,
            ticket_nullifier_root,
            min_ring_size: request.min_ring_size,
            privacy_set_size: request.privacy_set_size,
            max_fee_micro_units: request.max_fee_micro_units,
            requested_rebate_bps: request.requested_rebate_bps,
            redaction_units_reserved: request.redaction_units_reserved,
            opened_height: request.opened_height,
            expires_height: request
                .opened_height
                .saturating_add(self.config.cache_ttl_blocks),
            priority_score: ticket_priority_score(
                request.kind,
                request.privacy_set_size,
                request.max_fee_micro_units,
                request.requested_rebate_bps,
            ),
            public_bucket: public_bucket(request.opened_height, self.config.public_bucket_size),
        };
        self.consumed_nullifiers.insert(request.ticket_nullifier);
        self.counters.next_ticket_sequence = self.counters.next_ticket_sequence.saturating_add(1);
        self.counters.ticket_count = self.counters.ticket_count.saturating_add(1);
        self.tickets.insert(ticket_id, record.clone());
        Ok(record)
    }

    pub fn reserve_prover(
        &mut self,
        request: ProverReservationRequest,
    ) -> Result<ProverReservationRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        ensure_capacity(
            "reservations",
            self.reservations.len(),
            self.config.max_reservations,
        )?;
        let ticket = self.require_ticket(&request.ticket_id)?;
        if !ticket.status.accepts_reservation() {
            return Err("ticket does not accept prover reservations".to_string());
        }
        let sequence = self.counters.next_reservation_sequence;
        let reservation_id = prover_reservation_id(&request, sequence);
        ensure_absent("reservation", &self.reservations, &reservation_id)?;
        let record = ProverReservationRecord {
            reservation_id: reservation_id.clone(),
            ticket_id: request.ticket_id.clone(),
            prover_commitment: request.prover_commitment,
            status: ReservationStatus::Accepted,
            proving_key_root: request.proving_key_root,
            reservation_bid_root: request.reservation_bid_root,
            pq_identity_root: request.pq_identity_root,
            max_latency_ms: request.max_latency_ms,
            fee_micro_units: request.fee_micro_units,
            bond_micro_units: request.bond_micro_units,
            reserved_height: request.reserved_height,
            expires_height: request
                .reserved_height
                .saturating_add(self.config.reservation_ttl_blocks),
            reservation_score: prover_reservation_score(
                request.fee_micro_units,
                request.max_latency_ms,
                request.bond_micro_units,
            ),
        };
        if let Some(ticket) = self.tickets.get_mut(&request.ticket_id) {
            ticket.status = TicketStatus::Reserved;
        }
        self.counters.next_reservation_sequence =
            self.counters.next_reservation_sequence.saturating_add(1);
        self.counters.reservation_count = self.counters.reservation_count.saturating_add(1);
        self.reservations.insert(reservation_id, record.clone());
        Ok(record)
    }

    pub fn submit_pq_cache_attestation(
        &mut self,
        request: PqCacheAttestationRequest,
    ) -> Result<PqCacheAttestationRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        ensure_capacity(
            "attestations",
            self.attestations.len(),
            self.config.max_attestations,
        )?;
        self.require_ticket(&request.ticket_id)?;
        let reservation = self.require_reservation(&request.reservation_id)?;
        if reservation.ticket_id != request.ticket_id {
            return Err("reservation does not belong to ticket".to_string());
        }
        let sequence = self.counters.next_attestation_sequence;
        let attestation_id = pq_cache_attestation_id(&request, sequence);
        ensure_absent("attestation", &self.attestations, &attestation_id)?;
        let status = if request.pq_security_bits >= self.config.target_pq_security_bits {
            AttestationStatus::Quorum
        } else {
            AttestationStatus::Accepted
        };
        let record = PqCacheAttestationRecord {
            attestation_id: attestation_id.clone(),
            ticket_id: request.ticket_id.clone(),
            reservation_id: request.reservation_id.clone(),
            attestor_commitment: request.attestor_commitment,
            status,
            cache_attestation_root: request.cache_attestation_root,
            pq_signature_root: request.pq_signature_root,
            batch_transcript_root: request.batch_transcript_root,
            cache_hit_bitmap_root: request.cache_hit_bitmap_root,
            pq_security_bits: request.pq_security_bits,
            attested_height: request.attested_height,
            expires_height: request
                .attested_height
                .saturating_add(self.config.attestation_ttl_blocks),
        };
        if let Some(ticket) = self.tickets.get_mut(&request.ticket_id) {
            ticket.status = TicketStatus::Attested;
        }
        if let Some(reservation) = self.reservations.get_mut(&request.reservation_id) {
            reservation.status = ReservationStatus::Fulfilled;
        }
        self.counters.next_attestation_sequence =
            self.counters.next_attestation_sequence.saturating_add(1);
        self.counters.attestation_count = self.counters.attestation_count.saturating_add(1);
        self.attestations.insert(attestation_id, record.clone());
        Ok(record)
    }

    pub fn publish_batch_verification_hint(
        &mut self,
        request: BatchVerificationHintRequest,
    ) -> Result<BatchVerificationHintRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        ensure_capacity("hints", self.hints.len(), self.config.max_hints)?;
        for ticket_id in &request.ticket_ids {
            self.require_ticket(ticket_id)?;
        }
        for attestation_id in &request.attestation_ids {
            let attestation = self.require_attestation(attestation_id)?;
            if !attestation.status.counts_for_cache() {
                return Err(format!(
                    "attestation {attestation_id} does not count for cache"
                ));
            }
        }
        let sequence = self.counters.next_hint_sequence;
        let hint_id = batch_verification_hint_id(&request, sequence);
        ensure_absent("batch hint", &self.hints, &hint_id)?;
        let record = BatchVerificationHintRecord {
            hint_id: hint_id.clone(),
            ticket_ids_root: id_list_root("hint-ticket-ids", &request.ticket_ids),
            attestation_ids_root: id_list_root("hint-attestation-ids", &request.attestation_ids),
            hint_publisher_commitment: request.hint_publisher_commitment,
            status: BatchHintStatus::Published,
            batch_hint_root: request.batch_hint_root,
            verifier_key_root: request.verifier_key_root,
            msm_bucket_root: request.msm_bucket_root,
            transcript_challenge_root: request.transcript_challenge_root,
            proof_count: request.proof_count,
            expected_verify_ms: request.expected_verify_ms,
            published_height: request.published_height,
        };
        for ticket_id in &request.ticket_ids {
            if let Some(ticket) = self.tickets.get_mut(ticket_id) {
                if ticket.status.is_publicly_usable() || ticket.status == TicketStatus::Reserved {
                    ticket.status = TicketStatus::HintPublished;
                }
            }
        }
        self.counters.next_hint_sequence = self.counters.next_hint_sequence.saturating_add(1);
        self.counters.hint_count = self.counters.hint_count.saturating_add(1);
        self.hints.insert(hint_id, record.clone());
        Ok(record)
    }

    pub fn queue_low_fee_rebate(
        &mut self,
        request: LowFeeProofRebateRequest,
    ) -> Result<LowFeeProofRebateRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        ensure_capacity("rebates", self.rebates.len(), self.config.max_rebates)?;
        self.require_ticket(&request.ticket_id)?;
        let reservation = self.require_reservation(&request.reservation_id)?;
        if reservation.ticket_id != request.ticket_id {
            return Err("reservation does not belong to ticket".to_string());
        }
        ensure_nullifier_available(&self.consumed_nullifiers, &request.rebate_nullifier)?;
        let sequence = self.counters.next_rebate_sequence;
        let rebate_id = low_fee_proof_rebate_id(&request, sequence);
        ensure_absent("rebate", &self.rebates, &rebate_id)?;
        let rebate_nullifier_root = payload_root(
            "MONERO-L2-BPPLUS-CACHE-REBATE-NULLIFIER",
            &json!({ "rebate_nullifier": request.rebate_nullifier }),
        );
        let record = LowFeeProofRebateRecord {
            rebate_id: rebate_id.clone(),
            ticket_id: request.ticket_id.clone(),
            reservation_id: request.reservation_id.clone(),
            sponsor_commitment: request.sponsor_commitment,
            beneficiary_commitment: request.beneficiary_commitment,
            status: RebateStatus::Queued,
            fee_paid_micro_units: request.fee_paid_micro_units,
            rebate_micro_units: proof_rebate_micro_units(
                &self.config,
                request.fee_paid_micro_units,
            ),
            rebate_commitment_root: request.rebate_commitment_root,
            sponsor_budget_root: request.sponsor_budget_root,
            rebate_nullifier_root,
            issued_height: request.issued_height,
        };
        self.consumed_nullifiers.insert(request.rebate_nullifier);
        if let Some(ticket) = self.tickets.get_mut(&request.ticket_id) {
            ticket.status = TicketStatus::RebateQueued;
        }
        if let Some(reservation) = self.reservations.get_mut(&request.reservation_id) {
            reservation.status = ReservationStatus::RebateEligible;
        }
        self.counters.next_rebate_sequence = self.counters.next_rebate_sequence.saturating_add(1);
        self.counters.rebate_count = self.counters.rebate_count.saturating_add(1);
        self.rebates.insert(rebate_id, record.clone());
        Ok(record)
    }

    pub fn open_redaction_budget(
        &mut self,
        request: PrivacyRedactionBudgetRequest,
    ) -> Result<PrivacyRedactionBudgetRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        ensure_capacity(
            "redaction budgets",
            self.redaction_budgets.len(),
            self.config.max_redaction_budgets,
        )?;
        for ticket_id in &request.ticket_ids {
            self.require_ticket(ticket_id)?;
        }
        ensure_nullifier_available(&self.consumed_nullifiers, &request.budget_nullifier)?;
        let sequence = self.counters.next_redaction_budget_sequence;
        let budget_id = privacy_redaction_budget_id(&request, sequence);
        ensure_absent("redaction budget", &self.redaction_budgets, &budget_id)?;
        let budget_nullifier_root = payload_root(
            "MONERO-L2-BPPLUS-CACHE-REDACTION-BUDGET-NULLIFIER",
            &json!({ "budget_nullifier": request.budget_nullifier }),
        );
        let record = PrivacyRedactionBudgetRecord {
            budget_id: budget_id.clone(),
            owner_commitment: request.owner_commitment,
            ticket_ids_root: id_list_root("redaction-budget-ticket-ids", &request.ticket_ids),
            status: RedactionBudgetStatus::Open,
            redaction_policy_root: request.redaction_policy_root,
            viewkey_scope_root: request.viewkey_scope_root,
            budget_nullifier_root,
            redaction_units: request.redaction_units,
            spent_redaction_units: 0,
            opened_height: request.opened_height,
        };
        self.consumed_nullifiers.insert(request.budget_nullifier);
        self.counters.next_redaction_budget_sequence = self
            .counters
            .next_redaction_budget_sequence
            .saturating_add(1);
        self.counters.redaction_budget_count =
            self.counters.redaction_budget_count.saturating_add(1);
        self.redaction_budgets.insert(budget_id, record.clone());
        Ok(record)
    }

    pub fn quarantine_stale_proof(
        &mut self,
        request: StaleProofQuarantineRequest,
    ) -> Result<StaleProofQuarantineRecord> {
        self.config.validate()?;
        request.validate()?;
        ensure_capacity(
            "quarantines",
            self.quarantines.len(),
            self.config.max_quarantines,
        )?;
        self.require_ticket(&request.ticket_id)?;
        let sequence = self.counters.next_quarantine_sequence;
        let quarantine_id = stale_proof_quarantine_id(&request, sequence);
        ensure_absent("quarantine", &self.quarantines, &quarantine_id)?;
        let record = StaleProofQuarantineRecord {
            quarantine_id: quarantine_id.clone(),
            ticket_id: request.ticket_id.clone(),
            subject_root: request.subject_root,
            reporter_commitment: request.reporter_commitment,
            reason: request.reason,
            evidence_root: request.evidence_root,
            stale_height: request.stale_height,
            reported_height: request.reported_height,
            expires_height: request
                .reported_height
                .saturating_add(self.config.quarantine_ttl_blocks),
        };
        if let Some(ticket) = self.tickets.get_mut(&request.ticket_id) {
            ticket.status = TicketStatus::Quarantined;
        }
        self.counters.next_quarantine_sequence =
            self.counters.next_quarantine_sequence.saturating_add(1);
        self.counters.quarantine_count = self.counters.quarantine_count.saturating_add(1);
        self.quarantines.insert(quarantine_id, record.clone());
        Ok(record)
    }

    pub fn publish_deterministic_public_record(
        &mut self,
        request: DeterministicPublicRecordRequest,
    ) -> Result<DeterministicPublicRecord> {
        self.config.validate()?;
        request.validate()?;
        let sequence = self.counters.public_record_count;
        let public_record_id = deterministic_public_record_id(&request, sequence);
        ensure_absent("public record", &self.public_records, &public_record_id)?;
        let record = DeterministicPublicRecord {
            public_record_id: public_record_id.clone(),
            subject_id: request.subject_id,
            audience: request.audience,
            public_summary_root: request.public_summary_root,
            redacted_field_root: request.redacted_field_root,
            operator_commitment: request.operator_commitment,
            published_height: request.published_height,
        };
        self.counters.public_record_count = self.counters.public_record_count.saturating_add(1);
        self.public_records.insert(public_record_id, record.clone());
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        let ticket_root = map_root("MONERO-L2-BPPLUS-CACHE-TICKETS", &self.tickets);
        let reservation_root = map_root("MONERO-L2-BPPLUS-CACHE-RESERVATIONS", &self.reservations);
        let attestation_root = map_root("MONERO-L2-BPPLUS-CACHE-ATTESTATIONS", &self.attestations);
        let hint_root = map_root("MONERO-L2-BPPLUS-CACHE-HINTS", &self.hints);
        let rebate_root = map_root("MONERO-L2-BPPLUS-CACHE-REBATES", &self.rebates);
        let redaction_budget_root = map_root(
            "MONERO-L2-BPPLUS-CACHE-REDACTION-BUDGETS",
            &self.redaction_budgets,
        );
        let quarantine_root = map_root("MONERO-L2-BPPLUS-CACHE-QUARANTINES", &self.quarantines);
        let nullifier_root = set_root(
            "MONERO-L2-BPPLUS-CACHE-CONSUMED-NULLIFIERS",
            &self.consumed_nullifiers,
        );
        let public_record_root = map_root(
            "MONERO-L2-BPPLUS-CACHE-PUBLIC-RECORDS",
            &self.public_records,
        );
        let state_root = state_root_from_record(&json!({
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "ticket_root": ticket_root,
            "reservation_root": reservation_root,
            "attestation_root": attestation_root,
            "hint_root": hint_root,
            "rebate_root": rebate_root,
            "redaction_budget_root": redaction_budget_root,
            "quarantine_root": quarantine_root,
            "nullifier_root": nullifier_root,
            "public_record_root": public_record_root,
        }));
        Roots {
            ticket_root,
            reservation_root,
            attestation_root,
            hint_root,
            rebate_root,
            redaction_budget_root,
            quarantine_root,
            nullifier_root,
            public_record_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "tickets": public_values(&self.tickets),
            "reservations": public_values(&self.reservations),
            "attestations": public_values(&self.attestations),
            "hints": public_values(&self.hints),
            "rebates": public_values(&self.rebates),
            "redaction_budgets": public_values(&self.redaction_budgets),
            "quarantines": public_values(&self.quarantines),
            "public_records": public_values(&self.public_records),
            "privacy_boundary": PRIVACY_BOUNDARY,
            "state_root": roots.state_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn require_ticket(&self, ticket_id: &str) -> Result<&RangeProofCacheTicketRecord> {
        self.tickets
            .get(ticket_id)
            .ok_or_else(|| format!("unknown range proof cache ticket {ticket_id}"))
    }

    fn require_reservation(&self, reservation_id: &str) -> Result<&ProverReservationRecord> {
        self.reservations
            .get(reservation_id)
            .ok_or_else(|| format!("unknown prover reservation {reservation_id}"))
    }

    fn require_attestation(&self, attestation_id: &str) -> Result<&PqCacheAttestationRecord> {
        self.attestations
            .get(attestation_id)
            .ok_or_else(|| format!("unknown pq cache attestation {attestation_id}"))
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

pub fn range_proof_cache_ticket_id(
    request: &RangeProofCacheTicketRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "MONERO-L2-BPPLUS-CACHE-TICKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.owner_commitment),
            HashPart::Str(request.kind.as_str()),
            HashPart::Str(&request.range_proof_transcript_root),
            HashPart::Str(&request.cache_key_root),
            HashPart::Str(&request.ticket_nullifier),
        ],
        32,
    )
}

pub fn prover_reservation_id(request: &ProverReservationRequest, sequence: u64) -> String {
    domain_hash(
        "MONERO-L2-BPPLUS-CACHE-PROVER-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.ticket_id),
            HashPart::Str(&request.prover_commitment),
            HashPart::Str(&request.proving_key_root),
            HashPart::Str(&request.reservation_bid_root),
            HashPart::U64(request.reserved_height),
        ],
        32,
    )
}

pub fn pq_cache_attestation_id(request: &PqCacheAttestationRequest, sequence: u64) -> String {
    domain_hash(
        "MONERO-L2-BPPLUS-CACHE-PQ-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.ticket_id),
            HashPart::Str(&request.reservation_id),
            HashPart::Str(&request.attestor_commitment),
            HashPart::Str(&request.cache_attestation_root),
            HashPart::Str(&request.pq_signature_root),
            HashPart::U64(request.attested_height),
        ],
        32,
    )
}

pub fn batch_verification_hint_id(request: &BatchVerificationHintRequest, sequence: u64) -> String {
    domain_hash(
        "MONERO-L2-BPPLUS-CACHE-BATCH-HINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&id_list_root("ticket-ids", &request.ticket_ids)),
            HashPart::Str(&id_list_root("attestation-ids", &request.attestation_ids)),
            HashPart::Str(&request.batch_hint_root),
            HashPart::Str(&request.verifier_key_root),
            HashPart::U64(request.proof_count),
        ],
        32,
    )
}

pub fn low_fee_proof_rebate_id(request: &LowFeeProofRebateRequest, sequence: u64) -> String {
    domain_hash(
        "MONERO-L2-BPPLUS-CACHE-LOW-FEE-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.ticket_id),
            HashPart::Str(&request.reservation_id),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.rebate_commitment_root),
            HashPart::Str(&request.rebate_nullifier),
        ],
        32,
    )
}

pub fn privacy_redaction_budget_id(
    request: &PrivacyRedactionBudgetRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "MONERO-L2-BPPLUS-CACHE-REDACTION-BUDGET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.owner_commitment),
            HashPart::Str(&id_list_root("budget-ticket-ids", &request.ticket_ids)),
            HashPart::Str(&request.redaction_policy_root),
            HashPart::Str(&request.budget_nullifier),
        ],
        32,
    )
}

pub fn stale_proof_quarantine_id(request: &StaleProofQuarantineRequest, sequence: u64) -> String {
    domain_hash(
        "MONERO-L2-BPPLUS-CACHE-STALE-PROOF-QUARANTINE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.ticket_id),
            HashPart::Str(&request.subject_root),
            HashPart::Str(request.reason.as_str()),
            HashPart::Str(&request.evidence_root),
            HashPart::U64(request.reported_height),
        ],
        32,
    )
}

pub fn deterministic_public_record_id(
    request: &DeterministicPublicRecordRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "MONERO-L2-BPPLUS-CACHE-DETERMINISTIC-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.subject_id),
            HashPart::Str(request.audience.as_str()),
            HashPart::Str(&request.public_summary_root),
            HashPart::Str(&request.redacted_field_root),
        ],
        32,
    )
}

pub fn ticket_priority_score(
    kind: RangeProofCacheKind,
    privacy_set_size: u64,
    max_fee_micro_units: u64,
    requested_rebate_bps: u64,
) -> u64 {
    kind.complexity_weight()
        .saturating_add(privacy_set_size.min(1_048_576) / 1_024)
        .saturating_add(max_fee_micro_units.min(10_000_000) / 10_000)
        .saturating_add(requested_rebate_bps.saturating_mul(10))
}

pub fn prover_reservation_score(
    fee_micro_units: u64,
    max_latency_ms: u64,
    bond_micro_units: u64,
) -> u64 {
    20_000_u64
        .saturating_sub(
            fee_micro_units
                .min(10_000_000)
                .saturating_div(1_000)
                .saturating_add(max_latency_ms.min(10_000)),
        )
        .saturating_add(bond_micro_units.min(10_000_000).saturating_div(10_000))
}

pub fn proof_rebate_micro_units(config: &Config, fee_paid_micro_units: u64) -> u64 {
    fee_paid_micro_units
        .saturating_mul(config.target_rebate_bps)
        .saturating_div(MAX_BPS)
}

pub fn fee_cap_micro_units(max_user_fee_bps: u64) -> u64 {
    1_000_000_u64
        .saturating_mul(max_user_fee_bps)
        .saturating_div(MAX_BPS)
        .saturating_mul(20)
}

pub fn public_bucket(height: u64, bucket_size: u64) -> u64 {
    if bucket_size == 0 {
        height
    } else {
        height / bucket_size
    }
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

pub fn state_root_from_record(record: &Value) -> String {
    payload_root("MONERO-L2-BPPLUS-CACHE-MARKET-STATE-ROOT", record)
}

pub fn map_root<T: Serialize>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": serde_json::to_value(value).unwrap_or_else(|_| json!({"serialization": "failed"})),
            })
        })
        .collect::<Vec<_>>();
    public_record_root(domain, &leaves)
}

pub fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    public_record_root(domain, &leaves)
}

pub fn public_values<T: Serialize>(map: &BTreeMap<String, T>) -> Vec<Value> {
    map.values()
        .map(|value| {
            serde_json::to_value(value).unwrap_or_else(|_| json!({"serialization": "failed"}))
        })
        .collect()
}

pub fn id_list_root(domain: &str, ids: &[String]) -> String {
    public_record_root(
        &format!("MONERO-L2-BPPLUS-CACHE-ID-LIST-{domain}"),
        &ids.iter().map(|id| json!(id)).collect::<Vec<_>>(),
    )
}

fn demo_root(label: &str) -> String {
    payload_root(
        "MONERO-L2-BPPLUS-CACHE-DEMO-ROOT",
        &json!({ "label": label }),
    )
}

fn ensure_nonempty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_root(field: &str, value: &str) -> Result<()> {
    ensure_nonempty(field, value)?;
    if value.len() < 16 {
        return Err(format!("{field} must look like a commitment root"));
    }
    Ok(())
}

fn ensure_positive_u64(field: &str, value: u64) -> Result<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_positive_usize(field: &str, value: usize) -> Result<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(field: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{field} exceeds basis point maximum"))
    } else {
        Ok(())
    }
}

fn ensure_absent<T>(label: &str, map: &BTreeMap<String, T>, key: &str) -> Result<()> {
    if map.contains_key(key) {
        Err(format!("{label} {key} already exists"))
    } else {
        Ok(())
    }
}

fn ensure_unique_nonempty(field: &str, values: &[String]) -> Result<()> {
    if values.is_empty() {
        return Err(format!("{field} cannot be empty"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_nonempty(field, value)?;
        if !seen.insert(value) {
            return Err(format!("{field} contains duplicate value {value}"));
        }
    }
    Ok(())
}

fn ensure_capacity(label: &str, current: usize, max: usize) -> Result<()> {
    if current >= max {
        Err(format!("{label} capacity exhausted"))
    } else {
        Ok(())
    }
}

fn ensure_nullifier_available(nullifiers: &BTreeSet<String>, nullifier: &str) -> Result<()> {
    if nullifiers.contains(nullifier) {
        Err(format!("nullifier {nullifier} already consumed"))
    } else {
        Ok(())
    }
}
