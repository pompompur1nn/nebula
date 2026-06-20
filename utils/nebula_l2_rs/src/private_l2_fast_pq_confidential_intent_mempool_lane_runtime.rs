use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-pq-confidential-intent-mempool-lane-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_HEIGHT: u64 = 2_700_000;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_SENDER_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f+zk-sender-policy-attestation-v1";
pub const PQ_KEM_SUITE: &str = "ML-KEM-1024-threshold-orderflow-envelope-v1";
pub const SEALED_ORDERFLOW_AEAD_SUITE: &str = "XChaCha20-Poly1305-commitment-only-v1";
pub const NULLIFIER_FENCE_SCHEME: &str = "pq-confidential-intent-nullifier-fence-v1";
pub const ROUTE_HINT_SCHEME: &str = "private-defi-route-hint-commitment-v1";
pub const AUCTION_SCHEME: &str = "mev-resistant-sealed-orderflow-auction-v1";
pub const MICRO_BATCH_SCHEME: &str = "fast-pq-confidential-intent-microbatch-v1";
pub const PRECONFIRMATION_SCHEME: &str = "fast-pq-confidential-intent-preconfirmation-v1";
pub const SLASHING_EVIDENCE_SCHEME: &str = "pq-confidential-mempool-lane-slashing-v1";
pub const FEE_SPONSORSHIP_SCHEME: &str = "low-fee-confidential-intent-sponsor-v1";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_INTENT_TTL_BLOCKS: u64 = 10;
pub const DEFAULT_AUCTION_TTL_BLOCKS: u64 = 4;
pub const DEFAULT_PRECONFIRMATION_TTL_BLOCKS: u64 = 8;
pub const DEFAULT_MAX_PENDING_INTENTS: usize = 262_144;
pub const DEFAULT_MAX_NULLIFIER_FENCES: usize = 1_048_576;
pub const DEFAULT_MAX_ROUTE_HINTS: usize = 262_144;
pub const DEFAULT_MAX_SPONSORSHIPS: usize = 131_072;
pub const DEFAULT_MAX_MICROBATCHES: usize = 65_536;
pub const DEFAULT_MAX_AUCTIONS: usize = 65_536;
pub const DEFAULT_MAX_PRECONFIRMATIONS: usize = 262_144;
pub const DEFAULT_MAX_SLASHING_EVIDENCE: usize = 65_536;
pub const DEFAULT_BASE_FEE_MICRO_UNITS: u64 = 420;
pub const DEFAULT_PRIORITY_FEE_MICRO_UNITS: u64 = 80;
pub const DEFAULT_LOW_FEE_TARGET_MICRO_UNITS: u64 = 180;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 8_500;
pub const DEFAULT_MIN_AUCTION_BOND_MICRO_UNITS: u64 = 50_000;
pub const DEFAULT_MICROBATCH_MAX_WEIGHT: u64 = 4_096;
pub const DEFAULT_MICROBATCH_MAX_INTENTS: usize = 512;
pub const DEFAULT_QUORUM_THRESHOLD_BPS: u64 = 6_700;
pub const DEFAULT_ROUTE_REBATE_BPS: u64 = 2_500;
pub const DEFAULT_DEDUP_WINDOW_BLOCKS: u64 = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentKind {
    ConfidentialSwap,
    LiquidityProvision,
    LiquidityWithdrawal,
    LendingSupply,
    LendingBorrow,
    PerpetualMargin,
    BridgeExit,
    ProofAggregation,
    WalletTransfer,
    LiquidationBackstop,
    OracleBoundDefi,
    EmergencyCancel,
}

impl IntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfidentialSwap => "confidential_swap",
            Self::LiquidityProvision => "liquidity_provision",
            Self::LiquidityWithdrawal => "liquidity_withdrawal",
            Self::LendingSupply => "lending_supply",
            Self::LendingBorrow => "lending_borrow",
            Self::PerpetualMargin => "perpetual_margin",
            Self::BridgeExit => "bridge_exit",
            Self::ProofAggregation => "proof_aggregation",
            Self::WalletTransfer => "wallet_transfer",
            Self::LiquidationBackstop => "liquidation_backstop",
            Self::OracleBoundDefi => "oracle_bound_defi",
            Self::EmergencyCancel => "emergency_cancel",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyCancel => 1_200,
            Self::LiquidationBackstop => 1_050,
            Self::OracleBoundDefi => 980,
            Self::ConfidentialSwap => 940,
            Self::PerpetualMargin => 910,
            Self::BridgeExit => 870,
            Self::LiquidityProvision => 820,
            Self::LiquidityWithdrawal => 790,
            Self::LendingBorrow => 760,
            Self::LendingSupply => 720,
            Self::WalletTransfer => 640,
            Self::ProofAggregation => 520,
        }
    }

    pub fn base_weight(self) -> u64 {
        match self {
            Self::ProofAggregation => 2,
            Self::WalletTransfer => 3,
            Self::LendingSupply => 5,
            Self::LendingBorrow => 6,
            Self::LiquidityProvision => 7,
            Self::LiquidityWithdrawal => 7,
            Self::ConfidentialSwap => 8,
            Self::BridgeExit => 8,
            Self::PerpetualMargin => 9,
            Self::OracleBoundDefi => 10,
            Self::LiquidationBackstop => 11,
            Self::EmergencyCancel => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LatencyClass {
    Flash,
    Fast,
    Standard,
    Cheap,
    Backfill,
}

impl LatencyClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Flash => "flash",
            Self::Fast => "fast",
            Self::Standard => "standard",
            Self::Cheap => "cheap",
            Self::Backfill => "backfill",
        }
    }

    pub fn priority_boost(self) -> u64 {
        match self {
            Self::Flash => 400,
            Self::Fast => 260,
            Self::Standard => 140,
            Self::Cheap => 40,
            Self::Backfill => 0,
        }
    }

    pub fn fee_multiplier_bps(self) -> u64 {
        match self {
            Self::Flash => 14_000,
            Self::Fast => 11_500,
            Self::Standard => 10_000,
            Self::Cheap => 6_200,
            Self::Backfill => 4_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Submitted,
    Admitted,
    Batched,
    AuctionSealed,
    Preconfirmed,
    Included,
    Expired,
    Rejected,
    Slashed,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Admitted => "admitted",
            Self::Batched => "batched",
            Self::AuctionSealed => "auction_sealed",
            Self::Preconfirmed => "preconfirmed",
            Self::Included => "included",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
        }
    }

    pub fn is_pending(self) -> bool {
        matches!(self, Self::Submitted | Self::Admitted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Open,
    Sealed,
    Solved,
    Settled,
    Challenged,
    Expired,
}

impl AuctionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Solved => "solved",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreconfirmationStatus {
    Issued,
    Finalized,
    Reorged,
    Challenged,
    Expired,
}

impl PreconfirmationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Finalized => "finalized",
            Self::Reorged => "reorged",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    DuplicateNullifier,
    InvalidPqAttestation,
    EarlyReveal,
    CensoredWinningRoute,
    FeeSponsorDefault,
    PreconfirmationEquivocation,
    AuctionTranscriptMismatch,
    PrivacySetUnderflow,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::InvalidPqAttestation => "invalid_pq_attestation",
            Self::EarlyReveal => "early_reveal",
            Self::CensoredWinningRoute => "censored_winning_route",
            Self::FeeSponsorDefault => "fee_sponsor_default",
            Self::PreconfirmationEquivocation => "preconfirmation_equivocation",
            Self::AuctionTranscriptMismatch => "auction_transcript_mismatch",
            Self::PrivacySetUnderflow => "privacy_set_underflow",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub network: String,
    pub monero_network: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub intent_ttl_blocks: u64,
    pub auction_ttl_blocks: u64,
    pub preconfirmation_ttl_blocks: u64,
    pub max_pending_intents: usize,
    pub max_nullifier_fences: usize,
    pub max_route_hints: usize,
    pub max_sponsorships: usize,
    pub max_microbatches: usize,
    pub max_auctions: usize,
    pub max_preconfirmations: usize,
    pub max_slashing_evidence: usize,
    pub base_fee_micro_units: u64,
    pub priority_fee_micro_units: u64,
    pub low_fee_target_micro_units: u64,
    pub sponsor_cover_bps: u64,
    pub min_auction_bond_micro_units: u64,
    pub microbatch_max_weight: u64,
    pub microbatch_max_intents: usize,
    pub quorum_threshold_bps: u64,
    pub route_rebate_bps: u64,
    pub dedup_window_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            intent_ttl_blocks: DEFAULT_INTENT_TTL_BLOCKS,
            auction_ttl_blocks: DEFAULT_AUCTION_TTL_BLOCKS,
            preconfirmation_ttl_blocks: DEFAULT_PRECONFIRMATION_TTL_BLOCKS,
            max_pending_intents: DEFAULT_MAX_PENDING_INTENTS,
            max_nullifier_fences: DEFAULT_MAX_NULLIFIER_FENCES,
            max_route_hints: DEFAULT_MAX_ROUTE_HINTS,
            max_sponsorships: DEFAULT_MAX_SPONSORSHIPS,
            max_microbatches: DEFAULT_MAX_MICROBATCHES,
            max_auctions: DEFAULT_MAX_AUCTIONS,
            max_preconfirmations: DEFAULT_MAX_PRECONFIRMATIONS,
            max_slashing_evidence: DEFAULT_MAX_SLASHING_EVIDENCE,
            base_fee_micro_units: DEFAULT_BASE_FEE_MICRO_UNITS,
            priority_fee_micro_units: DEFAULT_PRIORITY_FEE_MICRO_UNITS,
            low_fee_target_micro_units: DEFAULT_LOW_FEE_TARGET_MICRO_UNITS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            min_auction_bond_micro_units: DEFAULT_MIN_AUCTION_BOND_MICRO_UNITS,
            microbatch_max_weight: DEFAULT_MICROBATCH_MAX_WEIGHT,
            microbatch_max_intents: DEFAULT_MICROBATCH_MAX_INTENTS,
            quorum_threshold_bps: DEFAULT_QUORUM_THRESHOLD_BPS,
            route_rebate_bps: DEFAULT_ROUTE_REBATE_BPS,
            dedup_window_blocks: DEFAULT_DEDUP_WINDOW_BLOCKS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "network": self.network,
            "monero_network": self.monero_network,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "auction_ttl_blocks": self.auction_ttl_blocks,
            "preconfirmation_ttl_blocks": self.preconfirmation_ttl_blocks,
            "max_pending_intents": self.max_pending_intents,
            "max_nullifier_fences": self.max_nullifier_fences,
            "max_route_hints": self.max_route_hints,
            "max_sponsorships": self.max_sponsorships,
            "max_microbatches": self.max_microbatches,
            "max_auctions": self.max_auctions,
            "max_preconfirmations": self.max_preconfirmations,
            "max_slashing_evidence": self.max_slashing_evidence,
            "base_fee_micro_units": self.base_fee_micro_units,
            "priority_fee_micro_units": self.priority_fee_micro_units,
            "low_fee_target_micro_units": self.low_fee_target_micro_units,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "min_auction_bond_micro_units": self.min_auction_bond_micro_units,
            "microbatch_max_weight": self.microbatch_max_weight,
            "microbatch_max_intents": self.microbatch_max_intents,
            "quorum_threshold_bps": self.quorum_threshold_bps,
            "route_rebate_bps": self.route_rebate_bps,
            "dedup_window_blocks": self.dedup_window_blocks,
            "hash_suite": HASH_SUITE,
            "pq_sender_attestation_suite": PQ_SENDER_ATTESTATION_SUITE,
            "pq_kem_suite": PQ_KEM_SUITE,
            "sealed_orderflow_aead_suite": SEALED_ORDERFLOW_AEAD_SUITE
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub admitted_intents: u64,
    pub rejected_intents: u64,
    pub expired_intents: u64,
    pub duplicate_nullifiers: u64,
    pub route_hints_registered: u64,
    pub sponsorships_registered: u64,
    pub microbatches_built: u64,
    pub auctions_sealed: u64,
    pub preconfirmations_issued: u64,
    pub slashing_evidence_opened: u64,
    pub sponsored_fee_micro_units: u64,
    pub user_fee_micro_units: u64,
    pub auction_bond_micro_units: u64,
}

impl Counters {
    pub fn empty() -> Self {
        Self {
            admitted_intents: 0,
            rejected_intents: 0,
            expired_intents: 0,
            duplicate_nullifiers: 0,
            route_hints_registered: 0,
            sponsorships_registered: 0,
            microbatches_built: 0,
            auctions_sealed: 0,
            preconfirmations_issued: 0,
            slashing_evidence_opened: 0,
            sponsored_fee_micro_units: 0,
            user_fee_micro_units: 0,
            auction_bond_micro_units: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "admitted_intents": self.admitted_intents,
            "rejected_intents": self.rejected_intents,
            "expired_intents": self.expired_intents,
            "duplicate_nullifiers": self.duplicate_nullifiers,
            "route_hints_registered": self.route_hints_registered,
            "sponsorships_registered": self.sponsorships_registered,
            "microbatches_built": self.microbatches_built,
            "auctions_sealed": self.auctions_sealed,
            "preconfirmations_issued": self.preconfirmations_issued,
            "slashing_evidence_opened": self.slashing_evidence_opened,
            "sponsored_fee_micro_units": self.sponsored_fee_micro_units,
            "user_fee_micro_units": self.user_fee_micro_units,
            "auction_bond_micro_units": self.auction_bond_micro_units
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub intent_root: String,
    pub nullifier_root: String,
    pub route_hint_root: String,
    pub sponsorship_root: String,
    pub microbatch_root: String,
    pub auction_root: String,
    pub preconfirmation_root: String,
    pub slashing_root: String,
    pub indexes_root: String,
    pub counters_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "intent_root": self.intent_root,
            "nullifier_root": self.nullifier_root,
            "route_hint_root": self.route_hint_root,
            "sponsorship_root": self.sponsorship_root,
            "microbatch_root": self.microbatch_root,
            "auction_root": self.auction_root,
            "preconfirmation_root": self.preconfirmation_root,
            "slashing_root": self.slashing_root,
            "indexes_root": self.indexes_root,
            "counters_root": self.counters_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSenderAttestation {
    pub attestation_id: String,
    pub sender_commitment: String,
    pub account_policy_root: String,
    pub pq_public_key_root: String,
    pub signature_root: String,
    pub transcript_root: String,
    pub security_bits: u16,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub committee_root: String,
}

impl PqSenderAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "sender_commitment": self.sender_commitment,
            "account_policy_root": self.account_policy_root,
            "pq_public_key_root": self.pq_public_key_root,
            "signature_root": self.signature_root,
            "transcript_root": self.transcript_root,
            "security_bits": self.security_bits,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "committee_root": self.committee_root,
            "suite": PQ_SENDER_ATTESTATION_SUITE
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedIntent {
    pub intent_id: String,
    pub kind: IntentKind,
    pub latency_class: LatencyClass,
    pub status: IntentStatus,
    pub sender_attestation: PqSenderAttestation,
    pub envelope_commitment: String,
    pub ciphertext_root: String,
    pub ephemeral_key_root: String,
    pub associated_data_root: String,
    pub nullifier: String,
    pub conflict_set_root: String,
    pub route_hint_id: String,
    pub sponsor_id: Option<String>,
    pub max_user_fee_micro_units: u64,
    pub priority_fee_micro_units: u64,
    pub privacy_set_size: u64,
    pub weight: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub admission_score: u64,
    pub batch_id: Option<String>,
    pub preconfirmation_id: Option<String>,
}

impl EncryptedIntent {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "kind": self.kind.as_str(),
            "latency_class": self.latency_class.as_str(),
            "status": self.status.as_str(),
            "sender_attestation": self.sender_attestation.public_record(),
            "envelope_commitment": self.envelope_commitment,
            "ciphertext_root": self.ciphertext_root,
            "ephemeral_key_root": self.ephemeral_key_root,
            "associated_data_root": self.associated_data_root,
            "nullifier": self.nullifier,
            "conflict_set_root": self.conflict_set_root,
            "route_hint_id": self.route_hint_id,
            "sponsor_id": self.sponsor_id,
            "max_user_fee_micro_units": self.max_user_fee_micro_units,
            "priority_fee_micro_units": self.priority_fee_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "weight": self.weight,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "admission_score": self.admission_score,
            "batch_id": self.batch_id,
            "preconfirmation_id": self.preconfirmation_id,
            "kem_suite": PQ_KEM_SUITE,
            "aead_suite": SEALED_ORDERFLOW_AEAD_SUITE
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateRouteHint {
    pub route_hint_id: String,
    pub hint_commitment: String,
    pub venue_root: String,
    pub asset_pair_root: String,
    pub solver_policy_root: String,
    pub liquidity_bucket_root: String,
    pub max_hops: u8,
    pub min_rebate_bps: u64,
    pub privacy_budget_bps: u64,
    pub created_at_height: u64,
}

impl PrivateRouteHint {
    pub fn public_record(&self) -> Value {
        json!({
            "route_hint_id": self.route_hint_id,
            "hint_commitment": self.hint_commitment,
            "venue_root": self.venue_root,
            "asset_pair_root": self.asset_pair_root,
            "solver_policy_root": self.solver_policy_root,
            "liquidity_bucket_root": self.liquidity_bucket_root,
            "max_hops": self.max_hops,
            "min_rebate_bps": self.min_rebate_bps,
            "privacy_budget_bps": self.privacy_budget_bps,
            "created_at_height": self.created_at_height,
            "scheme": ROUTE_HINT_SCHEME
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NullifierFence {
    pub fence_id: String,
    pub nullifier: String,
    pub intent_id: String,
    pub conflict_set_root: String,
    pub admitted_at_height: u64,
    pub expires_at_height: u64,
}

impl NullifierFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "nullifier": self.nullifier,
            "intent_id": self.intent_id,
            "conflict_set_root": self.conflict_set_root,
            "admitted_at_height": self.admitted_at_height,
            "expires_at_height": self.expires_at_height,
            "scheme": NULLIFIER_FENCE_SCHEME
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeSponsorship {
    pub sponsor_id: String,
    pub sponsor_commitment: String,
    pub credential_root: String,
    pub covered_intent_root: String,
    pub cover_bps: u64,
    pub budget_micro_units: u64,
    pub spent_micro_units: u64,
    pub min_privacy_set_size: u64,
    pub valid_until_height: u64,
}

impl FeeSponsorship {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "sponsor_commitment": self.sponsor_commitment,
            "credential_root": self.credential_root,
            "covered_intent_root": self.covered_intent_root,
            "cover_bps": self.cover_bps,
            "budget_micro_units": self.budget_micro_units,
            "spent_micro_units": self.spent_micro_units,
            "min_privacy_set_size": self.min_privacy_set_size,
            "valid_until_height": self.valid_until_height,
            "scheme": FEE_SPONSORSHIP_SCHEME
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BundleCommitment {
    pub bundle_id: String,
    pub intent_ids: Vec<String>,
    pub intent_root: String,
    pub route_hint_root: String,
    pub nullifier_root: String,
    pub total_weight: u64,
    pub total_user_fee_micro_units: u64,
    pub total_sponsored_fee_micro_units: u64,
    pub builder_commitment: String,
    pub built_at_height: u64,
    pub expires_at_height: u64,
}

impl BundleCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "bundle_id": self.bundle_id,
            "intent_ids": self.intent_ids,
            "intent_root": self.intent_root,
            "route_hint_root": self.route_hint_root,
            "nullifier_root": self.nullifier_root,
            "total_weight": self.total_weight,
            "total_user_fee_micro_units": self.total_user_fee_micro_units,
            "total_sponsored_fee_micro_units": self.total_sponsored_fee_micro_units,
            "builder_commitment": self.builder_commitment,
            "built_at_height": self.built_at_height,
            "expires_at_height": self.expires_at_height,
            "scheme": MICRO_BATCH_SCHEME
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedAuction {
    pub auction_id: String,
    pub status: AuctionStatus,
    pub bundle_id: String,
    pub sealed_bid_root: String,
    pub solver_set_root: String,
    pub fair_order_root: String,
    pub mev_burn_commitment: String,
    pub route_rebate_commitment: String,
    pub bond_micro_units: u64,
    pub sealed_at_height: u64,
    pub expires_at_height: u64,
}

impl SealedAuction {
    pub fn public_record(&self) -> Value {
        json!({
            "auction_id": self.auction_id,
            "status": self.status.as_str(),
            "bundle_id": self.bundle_id,
            "sealed_bid_root": self.sealed_bid_root,
            "solver_set_root": self.solver_set_root,
            "fair_order_root": self.fair_order_root,
            "mev_burn_commitment": self.mev_burn_commitment,
            "route_rebate_commitment": self.route_rebate_commitment,
            "bond_micro_units": self.bond_micro_units,
            "sealed_at_height": self.sealed_at_height,
            "expires_at_height": self.expires_at_height,
            "scheme": AUCTION_SCHEME
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreconfirmationReceipt {
    pub preconfirmation_id: String,
    pub status: PreconfirmationStatus,
    pub intent_id: String,
    pub bundle_id: String,
    pub auction_id: String,
    pub sequencer_committee_root: String,
    pub execution_claim_root: String,
    pub fee_claim_root: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl PreconfirmationReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "preconfirmation_id": self.preconfirmation_id,
            "status": self.status.as_str(),
            "intent_id": self.intent_id,
            "bundle_id": self.bundle_id,
            "auction_id": self.auction_id,
            "sequencer_committee_root": self.sequencer_committee_root,
            "execution_claim_root": self.execution_claim_root,
            "fee_claim_root": self.fee_claim_root,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "scheme": PRECONFIRMATION_SCHEME
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub kind: EvidenceKind,
    pub subject_id: String,
    pub transcript_root: String,
    pub witness_root: String,
    pub penalty_micro_units: u64,
    pub opened_at_height: u64,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "transcript_root": self.transcript_root,
            "witness_root": self.witness_root,
            "penalty_micro_units": self.penalty_micro_units,
            "opened_at_height": self.opened_at_height,
            "scheme": SLASHING_EVIDENCE_SCHEME
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub counters: Counters,
    pub intents: BTreeMap<String, EncryptedIntent>,
    pub nullifier_fences: BTreeMap<String, NullifierFence>,
    pub route_hints: BTreeMap<String, PrivateRouteHint>,
    pub sponsorships: BTreeMap<String, FeeSponsorship>,
    pub microbatches: BTreeMap<String, BundleCommitment>,
    pub auctions: BTreeMap<String, SealedAuction>,
    pub preconfirmations: BTreeMap<String, PreconfirmationReceipt>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub pending_by_score: BTreeSet<String>,
    pub intent_by_nullifier: BTreeMap<String, String>,
    pub intent_by_route_hint: BTreeMap<String, BTreeSet<String>>,
    pub intent_by_sponsor: BTreeMap<String, BTreeSet<String>>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            height: DEVNET_HEIGHT,
            counters: Counters::empty(),
            intents: BTreeMap::new(),
            nullifier_fences: BTreeMap::new(),
            route_hints: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            microbatches: BTreeMap::new(),
            auctions: BTreeMap::new(),
            preconfirmations: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            pending_by_score: BTreeSet::new(),
            intent_by_nullifier: BTreeMap::new(),
            intent_by_route_hint: BTreeMap::new(),
            intent_by_sponsor: BTreeMap::new(),
        };

        let hint = PrivateRouteHint {
            route_hint_id: route_hint_id("devnet-hint", "xmr-usdc", "stable-swap", 3),
            hint_commitment: commitment("devnet-route-hint", "low-fee-xmr-usdc"),
            venue_root: named_root("DEVNET-ROUTE-VENUES", &["darkpool", "stable-swap", "amm"]),
            asset_pair_root: named_root("DEVNET-ROUTE-ASSETS", &["xmr", "usdc"]),
            solver_policy_root: named_root("DEVNET-SOLVER-POLICY", &["pq", "private", "low-fee"]),
            liquidity_bucket_root: named_root("DEVNET-LIQUIDITY-BUCKET", &["deep", "fast"]),
            max_hops: 3,
            min_rebate_bps: state.config.route_rebate_bps,
            privacy_budget_bps: 120,
            created_at_height: DEVNET_HEIGHT,
        };
        let _ = state.register_route_hint(hint);

        let sponsorship = FeeSponsorship {
            sponsor_id: sponsor_id("devnet-sponsor", "confidential-swap", DEVNET_HEIGHT),
            sponsor_commitment: commitment("devnet-sponsor", "fee-vault"),
            credential_root: named_root("DEVNET-SPONSOR-CREDENTIAL", &["pq", "kyc-free", "bonded"]),
            covered_intent_root: named_root("DEVNET-SPONSOR-COVERED", &["swap", "wallet"]),
            cover_bps: state.config.sponsor_cover_bps,
            budget_micro_units: 12_000_000,
            spent_micro_units: 0,
            min_privacy_set_size: state.config.min_privacy_set_size,
            valid_until_height: DEVNET_HEIGHT + 2_000,
        };
        let _ = state.register_fee_sponsorship(sponsorship);

        let route_hint_id = state.route_hints.keys().next().cloned().unwrap_or_default();
        let sponsor_id = state.sponsorships.keys().next().cloned();
        let intent = sample_intent(
            IntentKind::ConfidentialSwap,
            LatencyClass::Fast,
            "devnet-sender-a",
            "devnet-nullifier-a",
            &route_hint_id,
            sponsor_id,
            DEVNET_HEIGHT,
        );
        if state.admit_intent(intent).is_ok() {
            let batch = state.build_microbatch(
                "devnet-builder",
                DEFAULT_MICROBATCH_MAX_INTENTS,
                DEVNET_HEIGHT + 1,
            );
            if let Ok(batch) = batch {
                let auction = state.seal_orderflow_auction(
                    &batch.bundle_id,
                    "devnet-solver-set",
                    "devnet-sealed-bids",
                    DEVNET_HEIGHT + 1,
                );
                if let Ok(auction) = auction {
                    let intent_id = batch.intent_ids.first().cloned().unwrap_or_default();
                    let _ = state.issue_preconfirmation(
                        &intent_id,
                        &batch.bundle_id,
                        &auction.auction_id,
                        "devnet-fast-sequencer-committee",
                        DEVNET_HEIGHT + 2,
                    );
                }
            }
        }
        state
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: domain_hash(
                "PRIVATE-L2-FAST-PQ-INTENT-MEMPOOL-CONFIG",
                &[HashPart::Json(&self.config.public_record())],
                32,
            ),
            intent_root: map_root(
                "PRIVATE-L2-FAST-PQ-INTENT-MEMPOOL-INTENTS",
                &self.intents,
                EncryptedIntent::public_record,
            ),
            nullifier_root: map_root(
                "PRIVATE-L2-FAST-PQ-INTENT-MEMPOOL-NULLIFIERS",
                &self.nullifier_fences,
                NullifierFence::public_record,
            ),
            route_hint_root: map_root(
                "PRIVATE-L2-FAST-PQ-INTENT-MEMPOOL-ROUTE-HINTS",
                &self.route_hints,
                PrivateRouteHint::public_record,
            ),
            sponsorship_root: map_root(
                "PRIVATE-L2-FAST-PQ-INTENT-MEMPOOL-SPONSORSHIPS",
                &self.sponsorships,
                FeeSponsorship::public_record,
            ),
            microbatch_root: map_root(
                "PRIVATE-L2-FAST-PQ-INTENT-MEMPOOL-MICROBATCHES",
                &self.microbatches,
                BundleCommitment::public_record,
            ),
            auction_root: map_root(
                "PRIVATE-L2-FAST-PQ-INTENT-MEMPOOL-AUCTIONS",
                &self.auctions,
                SealedAuction::public_record,
            ),
            preconfirmation_root: map_root(
                "PRIVATE-L2-FAST-PQ-INTENT-MEMPOOL-PRECONFIRMATIONS",
                &self.preconfirmations,
                PreconfirmationReceipt::public_record,
            ),
            slashing_root: map_root(
                "PRIVATE-L2-FAST-PQ-INTENT-MEMPOOL-SLASHING",
                &self.slashing_evidence,
                SlashingEvidence::public_record,
            ),
            indexes_root: self.indexes_root(),
            counters_root: domain_hash(
                "PRIVATE-L2-FAST-PQ-INTENT-MEMPOOL-COUNTERS",
                &[HashPart::Json(&self.counters.public_record())],
                32,
            ),
        }
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
            "counts": {
                "intents": self.intents.len(),
                "nullifier_fences": self.nullifier_fences.len(),
                "route_hints": self.route_hints.len(),
                "sponsorships": self.sponsorships.len(),
                "microbatches": self.microbatches.len(),
                "auctions": self.auctions.len(),
                "preconfirmations": self.preconfirmations.len(),
                "slashing_evidence": self.slashing_evidence.len()
            }
        })
    }

    pub fn register_route_hint(&mut self, hint: PrivateRouteHint) -> Result<String> {
        if self.route_hints.len() >= self.config.max_route_hints {
            return Err("route hint capacity exceeded".to_string());
        }
        if hint.min_rebate_bps > MAX_BPS || hint.privacy_budget_bps > MAX_BPS {
            return Err("route hint bps exceeds max".to_string());
        }
        let id = hint.route_hint_id.clone();
        self.route_hints.insert(id.clone(), hint);
        self.counters.route_hints_registered += 1;
        Ok(id)
    }

    pub fn register_fee_sponsorship(&mut self, sponsorship: FeeSponsorship) -> Result<String> {
        if self.sponsorships.len() >= self.config.max_sponsorships {
            return Err("fee sponsorship capacity exceeded".to_string());
        }
        if sponsorship.cover_bps > MAX_BPS {
            return Err("sponsorship cover bps exceeds max".to_string());
        }
        if sponsorship.min_privacy_set_size < self.config.min_privacy_set_size {
            return Err("sponsorship privacy floor too low".to_string());
        }
        let id = sponsorship.sponsor_id.clone();
        self.sponsorships.insert(id.clone(), sponsorship);
        self.counters.sponsorships_registered += 1;
        Ok(id)
    }

    pub fn admit_intent(&mut self, mut intent: EncryptedIntent) -> Result<String> {
        if self.intents.len() >= self.config.max_pending_intents {
            self.counters.rejected_intents += 1;
            return Err("intent capacity exceeded".to_string());
        }
        if intent.sender_attestation.security_bits < self.config.min_pq_security_bits {
            self.counters.rejected_intents += 1;
            return Err("insufficient pq sender security bits".to_string());
        }
        if intent.privacy_set_size < self.config.min_privacy_set_size {
            self.counters.rejected_intents += 1;
            return Err("privacy set underflow".to_string());
        }
        if intent.expires_at_height <= self.height {
            self.counters.rejected_intents += 1;
            return Err("intent already expired".to_string());
        }
        if self.intent_by_nullifier.contains_key(&intent.nullifier) {
            self.counters.duplicate_nullifiers += 1;
            self.counters.rejected_intents += 1;
            let evidence = slashing_evidence(
                EvidenceKind::DuplicateNullifier,
                &intent.intent_id,
                &intent.nullifier,
                self.config.base_fee_micro_units,
                self.height,
            );
            self.insert_slashing_evidence(evidence)?;
            return Err("duplicate nullifier".to_string());
        }
        if !self.route_hints.contains_key(&intent.route_hint_id) {
            self.counters.rejected_intents += 1;
            return Err("unknown private route hint".to_string());
        }
        if let Some(sponsor_id) = intent.sponsor_id.as_ref() {
            let sponsor = self
                .sponsorships
                .get(sponsor_id)
                .ok_or_else(|| "unknown fee sponsor".to_string())?;
            if sponsor.valid_until_height < self.height {
                self.counters.rejected_intents += 1;
                return Err("fee sponsor expired".to_string());
            }
        }
        intent.weight = intent.kind.base_weight() + intent.weight;
        intent.admission_score = admission_score(&intent);
        intent.status = IntentStatus::Admitted;
        let id = intent.intent_id.clone();
        let fence = NullifierFence {
            fence_id: nullifier_fence_id(&intent.nullifier, &id, self.height),
            nullifier: intent.nullifier.clone(),
            intent_id: id.clone(),
            conflict_set_root: intent.conflict_set_root.clone(),
            admitted_at_height: self.height,
            expires_at_height: self.height + self.config.dedup_window_blocks,
        };
        self.insert_nullifier_fence(fence)?;
        self.pending_by_score.insert(score_key(&intent));
        self.intent_by_nullifier
            .insert(intent.nullifier.clone(), id.clone());
        self.intent_by_route_hint
            .entry(intent.route_hint_id.clone())
            .or_default()
            .insert(id.clone());
        if let Some(sponsor_id) = intent.sponsor_id.clone() {
            self.intent_by_sponsor
                .entry(sponsor_id)
                .or_default()
                .insert(id.clone());
        }
        self.counters.user_fee_micro_units += intent.max_user_fee_micro_units;
        self.intents.insert(id.clone(), intent);
        self.counters.admitted_intents += 1;
        Ok(id)
    }

    pub fn build_microbatch(
        &mut self,
        builder_label: &str,
        max_intents: usize,
        height: u64,
    ) -> Result<BundleCommitment> {
        let limit = max_intents.min(self.config.microbatch_max_intents);
        if limit == 0 {
            return Err("microbatch limit is zero".to_string());
        }
        if self.microbatches.len() >= self.config.max_microbatches {
            return Err("microbatch capacity exceeded".to_string());
        }
        self.height = self.height.max(height);
        let mut selected = Vec::new();
        let mut total_weight = 0_u64;
        for key in self.pending_by_score.iter().rev() {
            let intent_id = key.rsplit(':').next().unwrap_or_default();
            if let Some(intent) = self.intents.get(intent_id) {
                if !intent.status.is_pending() || intent.expires_at_height <= height {
                    continue;
                }
                if selected.len() >= limit {
                    break;
                }
                if total_weight + intent.weight > self.config.microbatch_max_weight {
                    continue;
                }
                selected.push(intent_id.to_string());
                total_weight += intent.weight;
            }
        }
        if selected.is_empty() {
            return Err("no eligible intents for microbatch".to_string());
        }
        let intent_records = selected
            .iter()
            .filter_map(|intent_id| self.intents.get(intent_id))
            .map(EncryptedIntent::public_record)
            .collect::<Vec<_>>();
        let route_records = selected
            .iter()
            .filter_map(|intent_id| self.intents.get(intent_id))
            .filter_map(|intent| self.route_hints.get(&intent.route_hint_id))
            .map(PrivateRouteHint::public_record)
            .collect::<Vec<_>>();
        let nullifier_records = selected
            .iter()
            .filter_map(|intent_id| self.intents.get(intent_id))
            .filter_map(|intent| self.nullifier_fences.get(&intent.nullifier))
            .map(NullifierFence::public_record)
            .collect::<Vec<_>>();
        let user_fee = selected
            .iter()
            .filter_map(|intent_id| self.intents.get(intent_id))
            .map(|intent| intent.max_user_fee_micro_units)
            .sum::<u64>();
        let sponsored_fee = selected
            .iter()
            .filter_map(|intent_id| self.intents.get(intent_id))
            .map(|intent| self.sponsored_fee_for_intent(intent))
            .sum::<u64>();
        let bundle_id = microbatch_id(&selected, builder_label, height);
        let batch = BundleCommitment {
            bundle_id: bundle_id.clone(),
            intent_ids: selected.clone(),
            intent_root: merkle_root("PRIVATE-L2-FAST-PQ-BATCH-INTENTS", &intent_records),
            route_hint_root: merkle_root("PRIVATE-L2-FAST-PQ-BATCH-ROUTES", &route_records),
            nullifier_root: merkle_root("PRIVATE-L2-FAST-PQ-BATCH-NULLIFIERS", &nullifier_records),
            total_weight,
            total_user_fee_micro_units: user_fee,
            total_sponsored_fee_micro_units: sponsored_fee,
            builder_commitment: commitment("PRIVATE-L2-FAST-PQ-BUILDER", builder_label),
            built_at_height: height,
            expires_at_height: height + self.config.auction_ttl_blocks,
        };
        for intent_id in selected {
            if let Some(intent) = self.intents.get_mut(&intent_id) {
                self.pending_by_score.remove(&score_key(intent));
                intent.status = IntentStatus::Batched;
                intent.batch_id = Some(bundle_id.clone());
            }
        }
        self.counters.sponsored_fee_micro_units += sponsored_fee;
        self.counters.microbatches_built += 1;
        self.microbatches.insert(bundle_id.clone(), batch.clone());
        Ok(batch)
    }

    pub fn seal_orderflow_auction(
        &mut self,
        bundle_id: &str,
        solver_set_label: &str,
        sealed_bid_label: &str,
        height: u64,
    ) -> Result<SealedAuction> {
        if self.auctions.len() >= self.config.max_auctions {
            return Err("auction capacity exceeded".to_string());
        }
        let batch = self
            .microbatches
            .get(bundle_id)
            .ok_or_else(|| "unknown microbatch".to_string())?;
        if batch.expires_at_height <= height {
            return Err("microbatch expired before auction seal".to_string());
        }
        let fair_order_root = fair_order_root(&batch.intent_ids);
        let auction_id = auction_id(bundle_id, &fair_order_root, height);
        let auction = SealedAuction {
            auction_id: auction_id.clone(),
            status: AuctionStatus::Sealed,
            bundle_id: bundle_id.to_string(),
            sealed_bid_root: named_root("PRIVATE-L2-FAST-PQ-SEALED-BIDS", &[sealed_bid_label]),
            solver_set_root: named_root("PRIVATE-L2-FAST-PQ-SOLVER-SET", &[solver_set_label]),
            fair_order_root,
            mev_burn_commitment: commitment("PRIVATE-L2-FAST-PQ-MEV-BURN", bundle_id),
            route_rebate_commitment: commitment("PRIVATE-L2-FAST-PQ-ROUTE-REBATE", bundle_id),
            bond_micro_units: self.config.min_auction_bond_micro_units,
            sealed_at_height: height,
            expires_at_height: height + self.config.auction_ttl_blocks,
        };
        for intent_id in &batch.intent_ids {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = IntentStatus::AuctionSealed;
            }
        }
        self.counters.auction_bond_micro_units += auction.bond_micro_units;
        self.counters.auctions_sealed += 1;
        self.auctions.insert(auction_id, auction.clone());
        Ok(auction)
    }

    pub fn issue_preconfirmation(
        &mut self,
        intent_id: &str,
        bundle_id: &str,
        auction_id: &str,
        committee_label: &str,
        height: u64,
    ) -> Result<PreconfirmationReceipt> {
        if self.preconfirmations.len() >= self.config.max_preconfirmations {
            return Err("preconfirmation capacity exceeded".to_string());
        }
        let auction = self
            .auctions
            .get(auction_id)
            .ok_or_else(|| "unknown sealed auction".to_string())?;
        if auction.bundle_id != bundle_id {
            return Err("auction does not bind bundle".to_string());
        }
        if auction.expires_at_height <= height {
            return Err("auction expired before preconfirmation".to_string());
        }
        let intent = self
            .intents
            .get(intent_id)
            .ok_or_else(|| "unknown intent".to_string())?;
        if intent.batch_id.as_deref() != Some(bundle_id) {
            return Err("intent does not bind bundle".to_string());
        }
        let preconfirmation_id = preconfirmation_id(intent_id, bundle_id, auction_id, height);
        let receipt = PreconfirmationReceipt {
            preconfirmation_id: preconfirmation_id.clone(),
            status: PreconfirmationStatus::Issued,
            intent_id: intent_id.to_string(),
            bundle_id: bundle_id.to_string(),
            auction_id: auction_id.to_string(),
            sequencer_committee_root: named_root(
                "PRIVATE-L2-FAST-PQ-PRECONFIRMATION-COMMITTEE",
                &[committee_label],
            ),
            execution_claim_root: named_root(
                "PRIVATE-L2-FAST-PQ-PRECONFIRMATION-EXECUTION",
                &[intent_id, bundle_id],
            ),
            fee_claim_root: named_root(
                "PRIVATE-L2-FAST-PQ-PRECONFIRMATION-FEE",
                &[intent_id, auction_id],
            ),
            issued_at_height: height,
            expires_at_height: height + self.config.preconfirmation_ttl_blocks,
        };
        if let Some(intent) = self.intents.get_mut(intent_id) {
            intent.status = IntentStatus::Preconfirmed;
            intent.preconfirmation_id = Some(preconfirmation_id.clone());
        }
        self.preconfirmations
            .insert(preconfirmation_id, receipt.clone());
        self.counters.preconfirmations_issued += 1;
        Ok(receipt)
    }

    pub fn evict_expired_intents(&mut self, height: u64) -> Vec<String> {
        self.height = self.height.max(height);
        let expired = self
            .intents
            .iter()
            .filter(|(_, intent)| intent.status.is_pending() && intent.expires_at_height <= height)
            .map(|(intent_id, _)| intent_id.clone())
            .collect::<Vec<_>>();
        for intent_id in &expired {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                self.pending_by_score.remove(&score_key(intent));
                intent.status = IntentStatus::Expired;
                self.counters.expired_intents += 1;
            }
        }
        let expired_fences = self
            .nullifier_fences
            .iter()
            .filter(|(_, fence)| fence.expires_at_height <= height)
            .map(|(nullifier, _)| nullifier.clone())
            .collect::<Vec<_>>();
        for nullifier in expired_fences {
            self.nullifier_fences.remove(&nullifier);
            self.intent_by_nullifier.remove(&nullifier);
        }
        expired
    }

    pub fn reject_intent(
        &mut self,
        intent_id: &str,
        evidence_kind: Option<EvidenceKind>,
        height: u64,
    ) -> Result<String> {
        self.height = self.height.max(height);
        let transcript_label = if let Some(intent) = self.intents.get_mut(intent_id) {
            self.pending_by_score.remove(&score_key(intent));
            intent.status = IntentStatus::Rejected;
            self.counters.rejected_intents += 1;
            intent.nullifier.clone()
        } else {
            return Err("unknown intent".to_string());
        };
        if let Some(kind) = evidence_kind {
            self.open_slashing_evidence(
                kind,
                intent_id,
                &transcript_label,
                "intent-rejection-witness",
                self.config.base_fee_micro_units,
                height,
            )
        } else {
            Ok(intent_id.to_string())
        }
    }

    pub fn settle_orderflow_auction(
        &mut self,
        auction_id: &str,
        settlement_label: &str,
        height: u64,
    ) -> Result<Value> {
        self.height = self.height.max(height);
        let bundle_id = {
            let auction = self
                .auctions
                .get_mut(auction_id)
                .ok_or_else(|| "unknown auction".to_string())?;
            if auction.expires_at_height <= height {
                auction.status = AuctionStatus::Expired;
                return Err("auction expired before settlement".to_string());
            }
            auction.status = AuctionStatus::Settled;
            auction.bundle_id.clone()
        };
        let batch = self
            .microbatches
            .get(&bundle_id)
            .ok_or_else(|| "auction bundle missing".to_string())?;
        for intent_id in &batch.intent_ids {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = IntentStatus::Included;
            }
        }
        Ok(json!({
            "auction_id": auction_id,
            "bundle_id": bundle_id,
            "settlement_root": named_root("PRIVATE-L2-FAST-PQ-AUCTION-SETTLEMENT", &[settlement_label]),
            "settled_at_height": height,
            "intent_count": batch.intent_ids.len(),
            "total_user_fee_micro_units": batch.total_user_fee_micro_units,
            "total_sponsored_fee_micro_units": batch.total_sponsored_fee_micro_units
        }))
    }

    pub fn finalize_preconfirmation(
        &mut self,
        preconfirmation_id: &str,
        height: u64,
    ) -> Result<PreconfirmationReceipt> {
        self.height = self.height.max(height);
        let receipt = self
            .preconfirmations
            .get_mut(preconfirmation_id)
            .ok_or_else(|| "unknown preconfirmation".to_string())?;
        if receipt.expires_at_height <= height {
            receipt.status = PreconfirmationStatus::Expired;
            return Err("preconfirmation expired".to_string());
        }
        receipt.status = PreconfirmationStatus::Finalized;
        Ok(receipt.clone())
    }

    pub fn challenge_preconfirmation(
        &mut self,
        preconfirmation_id: &str,
        evidence_kind: EvidenceKind,
        witness_label: &str,
        height: u64,
    ) -> Result<String> {
        self.height = self.height.max(height);
        let subject = {
            let receipt = self
                .preconfirmations
                .get_mut(preconfirmation_id)
                .ok_or_else(|| "unknown preconfirmation".to_string())?;
            receipt.status = PreconfirmationStatus::Challenged;
            receipt.intent_id.clone()
        };
        self.open_slashing_evidence(
            evidence_kind,
            &subject,
            preconfirmation_id,
            witness_label,
            self.config.min_auction_bond_micro_units,
            height,
        )
    }

    pub fn lane_fee_quote(
        &self,
        kind: IntentKind,
        latency_class: LatencyClass,
        weight: u64,
        sponsor_id: Option<&str>,
    ) -> Value {
        let effective_weight = weight + kind.base_weight();
        let gross_fee = self
            .config
            .base_fee_micro_units
            .saturating_mul(effective_weight)
            .saturating_mul(latency_class.fee_multiplier_bps())
            / MAX_BPS
            + self.config.priority_fee_micro_units;
        let sponsor_cover = sponsor_id
            .and_then(|id| self.sponsorships.get(id))
            .map(|sponsor| gross_fee.saturating_mul(sponsor.cover_bps) / MAX_BPS)
            .unwrap_or(0);
        json!({
            "kind": kind.as_str(),
            "latency_class": latency_class.as_str(),
            "effective_weight": effective_weight,
            "gross_fee_micro_units": gross_fee,
            "sponsor_cover_micro_units": sponsor_cover,
            "user_fee_micro_units": gross_fee.saturating_sub(sponsor_cover),
            "low_fee_target_micro_units": self.config.low_fee_target_micro_units
        })
    }

    pub fn route_pressure_record(&self, route_hint_id: &str) -> Value {
        let intent_ids = self
            .intent_by_route_hint
            .get(route_hint_id)
            .cloned()
            .unwrap_or_default();
        let pending_weight = intent_ids
            .iter()
            .filter_map(|intent_id| self.intents.get(intent_id))
            .filter(|intent| intent.status.is_pending())
            .map(|intent| intent.weight)
            .sum::<u64>();
        let pending_fees = intent_ids
            .iter()
            .filter_map(|intent_id| self.intents.get(intent_id))
            .filter(|intent| intent.status.is_pending())
            .map(|intent| intent.max_user_fee_micro_units)
            .sum::<u64>();
        json!({
            "route_hint_id": route_hint_id,
            "intent_count": intent_ids.len(),
            "pending_weight": pending_weight,
            "pending_user_fee_micro_units": pending_fees,
            "pressure_root": domain_hash(
                "PRIVATE-L2-FAST-PQ-ROUTE-PRESSURE",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(route_hint_id),
                    HashPart::U64(pending_weight),
                    HashPart::U64(pending_fees)
                ],
                32
            )
        })
    }

    pub fn sponsor_utilization_record(&self, sponsor_id: &str) -> Value {
        let intent_ids = self
            .intent_by_sponsor
            .get(sponsor_id)
            .cloned()
            .unwrap_or_default();
        let reserved = intent_ids
            .iter()
            .filter_map(|intent_id| self.intents.get(intent_id))
            .map(|intent| self.sponsored_fee_for_intent(intent))
            .sum::<u64>();
        let sponsor = self.sponsorships.get(sponsor_id);
        json!({
            "sponsor_id": sponsor_id,
            "intent_count": intent_ids.len(),
            "reserved_micro_units": reserved,
            "budget_micro_units": sponsor.map(|s| s.budget_micro_units).unwrap_or(0),
            "spent_micro_units": sponsor.map(|s| s.spent_micro_units).unwrap_or(0),
            "valid_until_height": sponsor.map(|s| s.valid_until_height).unwrap_or(0)
        })
    }

    pub fn sealed_orderflow_digest(&self, bundle_id: &str) -> Result<String> {
        let batch = self
            .microbatches
            .get(bundle_id)
            .ok_or_else(|| "unknown microbatch".to_string())?;
        Ok(domain_hash(
            "PRIVATE-L2-FAST-PQ-SEALED-ORDERFLOW-DIGEST",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&batch.bundle_id),
                HashPart::Str(&batch.intent_root),
                HashPart::Str(&batch.route_hint_root),
                HashPart::Str(&batch.nullifier_root),
                HashPart::U64(batch.total_weight),
            ],
            32,
        ))
    }

    pub fn open_slashing_evidence(
        &mut self,
        kind: EvidenceKind,
        subject_id: &str,
        transcript_label: &str,
        witness_label: &str,
        penalty_micro_units: u64,
        height: u64,
    ) -> Result<String> {
        let evidence = SlashingEvidence {
            evidence_id: evidence_id(kind, subject_id, transcript_label, height),
            kind,
            subject_id: subject_id.to_string(),
            transcript_root: named_root("PRIVATE-L2-FAST-PQ-SLASH-TRANSCRIPT", &[transcript_label]),
            witness_root: named_root("PRIVATE-L2-FAST-PQ-SLASH-WITNESS", &[witness_label]),
            penalty_micro_units,
            opened_at_height: height,
        };
        let id = evidence.evidence_id.clone();
        self.insert_slashing_evidence(evidence)?;
        Ok(id)
    }

    fn insert_nullifier_fence(&mut self, fence: NullifierFence) -> Result<()> {
        if self.nullifier_fences.len() >= self.config.max_nullifier_fences {
            return Err("nullifier fence capacity exceeded".to_string());
        }
        self.nullifier_fences.insert(fence.nullifier.clone(), fence);
        Ok(())
    }

    fn insert_slashing_evidence(&mut self, evidence: SlashingEvidence) -> Result<()> {
        if self.slashing_evidence.len() >= self.config.max_slashing_evidence {
            return Err("slashing evidence capacity exceeded".to_string());
        }
        self.slashing_evidence
            .insert(evidence.evidence_id.clone(), evidence);
        self.counters.slashing_evidence_opened += 1;
        Ok(())
    }

    fn sponsored_fee_for_intent(&self, intent: &EncryptedIntent) -> u64 {
        intent
            .sponsor_id
            .as_ref()
            .and_then(|sponsor_id| self.sponsorships.get(sponsor_id))
            .map(|sponsor| {
                intent
                    .max_user_fee_micro_units
                    .saturating_mul(sponsor.cover_bps)
                    / MAX_BPS
            })
            .unwrap_or(0)
    }

    fn indexes_root(&self) -> String {
        let pending = self
            .pending_by_score
            .iter()
            .map(|key| json!({"score_key": key}))
            .collect::<Vec<_>>();
        let nullifiers = self
            .intent_by_nullifier
            .iter()
            .map(|(nullifier, intent_id)| json!({"nullifier": nullifier, "intent_id": intent_id}))
            .collect::<Vec<_>>();
        let routes = self
            .intent_by_route_hint
            .iter()
            .map(|(route_hint_id, intent_ids)| {
                json!({"route_hint_id": route_hint_id, "intent_ids": intent_ids.iter().cloned().collect::<Vec<_>>()})
            })
            .collect::<Vec<_>>();
        let sponsors = self
            .intent_by_sponsor
            .iter()
            .map(|(sponsor_id, intent_ids)| {
                json!({"sponsor_id": sponsor_id, "intent_ids": intent_ids.iter().cloned().collect::<Vec<_>>()})
            })
            .collect::<Vec<_>>();
        let record = json!({
            "pending_root": merkle_root("PRIVATE-L2-FAST-PQ-INDEX-PENDING", &pending),
            "nullifier_root": merkle_root("PRIVATE-L2-FAST-PQ-INDEX-NULLIFIER", &nullifiers),
            "route_root": merkle_root("PRIVATE-L2-FAST-PQ-INDEX-ROUTE", &routes),
            "sponsor_root": merkle_root("PRIVATE-L2-FAST-PQ-INDEX-SPONSOR", &sponsors)
        });
        domain_hash(
            "PRIVATE-L2-FAST-PQ-INTENT-MEMPOOL-INDEXES",
            &[HashPart::Json(&record)],
            32,
        )
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
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-INTENT-MEMPOOL-LANE-STATE",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn intent_id(
    kind: IntentKind,
    latency_class: LatencyClass,
    sender_commitment: &str,
    envelope_commitment: &str,
    nullifier: &str,
    submitted_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(latency_class.as_str()),
            HashPart::Str(sender_commitment),
            HashPart::Str(envelope_commitment),
            HashPart::Str(nullifier),
            HashPart::U64(submitted_at_height),
        ],
        32,
    )
}

pub fn attestation_id(
    sender_commitment: &str,
    account_policy_root: &str,
    pq_public_key_root: &str,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-SENDER-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sender_commitment),
            HashPart::Str(account_policy_root),
            HashPart::Str(pq_public_key_root),
            HashPart::U64(issued_at_height),
        ],
        32,
    )
}

pub fn route_hint_id(
    owner_label: &str,
    asset_pair_label: &str,
    venue_label: &str,
    max_hops: u8,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-ROUTE-HINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_label),
            HashPart::Str(asset_pair_label),
            HashPart::Str(venue_label),
            HashPart::U64(max_hops as u64),
        ],
        32,
    )
}

pub fn sponsor_id(sponsor_label: &str, policy_label: &str, valid_from_height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-SPONSOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_label),
            HashPart::Str(policy_label),
            HashPart::U64(valid_from_height),
        ],
        32,
    )
}

pub fn nullifier_fence_id(nullifier: &str, intent_id: &str, admitted_at_height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-NULLIFIER-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(nullifier),
            HashPart::Str(intent_id),
            HashPart::U64(admitted_at_height),
        ],
        32,
    )
}

pub fn microbatch_id(intent_ids: &[String], builder_label: &str, height: u64) -> String {
    let records = intent_ids
        .iter()
        .map(|intent_id| json!({"intent_id": intent_id}))
        .collect::<Vec<_>>();
    let root = merkle_root("PRIVATE-L2-FAST-PQ-MICROBATCH-ID-INTENTS", &records);
    domain_hash(
        "PRIVATE-L2-FAST-PQ-MICROBATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&root),
            HashPart::Str(builder_label),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn auction_id(bundle_id: &str, fair_order_root: &str, sealed_at_height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-AUCTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bundle_id),
            HashPart::Str(fair_order_root),
            HashPart::U64(sealed_at_height),
        ],
        32,
    )
}

pub fn preconfirmation_id(
    intent_id: &str,
    bundle_id: &str,
    auction_id: &str,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-PRECONFIRMATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(bundle_id),
            HashPart::Str(auction_id),
            HashPart::U64(issued_at_height),
        ],
        32,
    )
}

pub fn evidence_id(
    kind: EvidenceKind,
    subject_id: &str,
    transcript_label: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(transcript_label),
            HashPart::U64(opened_at_height),
        ],
        32,
    )
}

pub fn commitment(domain: &str, label: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(label)], 32)
}

pub fn named_root(domain: &str, labels: &[&str]) -> String {
    let records = labels
        .iter()
        .map(|label| json!({"label": label}))
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let records = map
        .iter()
        .map(|(key, value)| json!({"key": key, "value": record(value)}))
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

fn fair_order_root(intent_ids: &[String]) -> String {
    let mut ordered = intent_ids.to_vec();
    ordered.sort();
    let records = ordered
        .iter()
        .enumerate()
        .map(|(position, intent_id)| json!({"position": position, "intent_id": intent_id}))
        .collect::<Vec<_>>();
    merkle_root("PRIVATE-L2-FAST-PQ-FAIR-ORDER", &records)
}

fn admission_score(intent: &EncryptedIntent) -> u64 {
    intent.kind.priority_weight()
        + intent.latency_class.priority_boost()
        + intent.priority_fee_micro_units.min(10_000)
        + intent.privacy_set_size.min(1_000_000) / 1_024
}

fn score_key(intent: &EncryptedIntent) -> String {
    format!(
        "{:020}:{:020}:{}",
        admission_score(intent),
        u64::MAX.saturating_sub(intent.submitted_at_height),
        intent.intent_id
    )
}

fn slashing_evidence(
    kind: EvidenceKind,
    subject_id: &str,
    transcript_label: &str,
    penalty_micro_units: u64,
    height: u64,
) -> SlashingEvidence {
    SlashingEvidence {
        evidence_id: evidence_id(kind, subject_id, transcript_label, height),
        kind,
        subject_id: subject_id.to_string(),
        transcript_root: named_root(
            "PRIVATE-L2-FAST-PQ-AUTO-SLASH-TRANSCRIPT",
            &[transcript_label],
        ),
        witness_root: named_root("PRIVATE-L2-FAST-PQ-AUTO-SLASH-WITNESS", &[subject_id]),
        penalty_micro_units,
        opened_at_height: height,
    }
}

fn sample_attestation(sender_label: &str, height: u64) -> PqSenderAttestation {
    let sender_commitment = commitment("DEVNET-PQ-SENDER", sender_label);
    let account_policy_root = named_root("DEVNET-PQ-ACCOUNT-POLICY", &["session", "defi", "fast"]);
    let pq_public_key_root = named_root("DEVNET-PQ-PUBLIC-KEY", &[sender_label, "ml-dsa-87"]);
    PqSenderAttestation {
        attestation_id: attestation_id(
            &sender_commitment,
            &account_policy_root,
            &pq_public_key_root,
            height,
        ),
        sender_commitment,
        account_policy_root,
        pq_public_key_root,
        signature_root: named_root("DEVNET-PQ-SIGNATURE", &[sender_label]),
        transcript_root: named_root("DEVNET-PQ-ATTESTATION-TRANSCRIPT", &[sender_label]),
        security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        issued_at_height: height,
        expires_at_height: height + 1_000,
        committee_root: named_root(
            "DEVNET-PQ-SENDER-COMMITTEE",
            &["committee-a", "committee-b"],
        ),
    }
}

fn sample_intent(
    kind: IntentKind,
    latency_class: LatencyClass,
    sender_label: &str,
    nullifier_label: &str,
    route_hint_id: &str,
    sponsor_id: Option<String>,
    height: u64,
) -> EncryptedIntent {
    let attestation = sample_attestation(sender_label, height);
    let nullifier = commitment("DEVNET-PQ-INTENT-NULLIFIER", nullifier_label);
    let envelope_commitment = commitment("DEVNET-PQ-INTENT-ENVELOPE", sender_label);
    let id = intent_id(
        kind,
        latency_class,
        &attestation.sender_commitment,
        &envelope_commitment,
        &nullifier,
        height,
    );
    EncryptedIntent {
        intent_id: id,
        kind,
        latency_class,
        status: IntentStatus::Submitted,
        sender_attestation: attestation,
        envelope_commitment,
        ciphertext_root: named_root("DEVNET-PQ-INTENT-CIPHERTEXT", &[sender_label, "ciphertext"]),
        ephemeral_key_root: named_root("DEVNET-PQ-INTENT-EPHEMERAL", &[sender_label, "kem"]),
        associated_data_root: named_root("DEVNET-PQ-INTENT-AD", &[sender_label, "ad"]),
        nullifier,
        conflict_set_root: named_root("DEVNET-PQ-INTENT-CONFLICT", &[nullifier_label]),
        route_hint_id: route_hint_id.to_string(),
        sponsor_id,
        max_user_fee_micro_units: DEFAULT_BASE_FEE_MICRO_UNITS + DEFAULT_PRIORITY_FEE_MICRO_UNITS,
        priority_fee_micro_units: DEFAULT_PRIORITY_FEE_MICRO_UNITS,
        privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE * 2,
        weight: 1,
        submitted_at_height: height,
        expires_at_height: height + DEFAULT_INTENT_TTL_BLOCKS,
        admission_score: 0,
        batch_id: None,
        preconfirmation_id: None,
    }
}
