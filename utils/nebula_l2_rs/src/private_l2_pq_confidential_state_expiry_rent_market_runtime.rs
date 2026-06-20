use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_STATE_EXPIRY_RENT_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-state-expiry-rent-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_STATE_EXPIRY_RENT_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_OWNER_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-private-state-owner-attestation-v1";
pub const ENCRYPTED_STATE_LEASE_SCHEME: &str =
    "ML-KEM-1024+XChaCha20-Poly1305+view-tagged-state-lease-v1";
pub const STORAGE_RENT_BID_SCHEME: &str = "sealed-private-storage-rent-bid-root-v1";
pub const SPONSOR_VOUCHER_SCHEME: &str = "low-fee-private-state-rent-sponsor-voucher-v1";
pub const COMPACT_STATE_PROOF_SCHEME: &str = "recursive-compact-private-state-proof-v1";
pub const EVICTION_RECEIPT_SCHEME: &str = "private-contract-state-eviction-receipt-v1";
pub const RENEWAL_BATCH_SCHEME: &str = "privacy-preserving-state-lease-renewal-batch-v1";
pub const NULLIFIER_FENCE_SCHEME: &str = "monero-l2-private-state-expiry-nullifier-fence-v1";
pub const SLASHING_EVIDENCE_SCHEME: &str = "pq-keeper-fault-slashing-evidence-root-v1";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_HEIGHT: u64 = 1_388_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_LEASE_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_LEASE_BLOCKS: u64 = 2_592_000;
pub const DEFAULT_RENEWAL_WINDOW_BLOCKS: u64 = 10_080;
pub const DEFAULT_EVICTION_GRACE_BLOCKS: u64 = 2_880;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_VOUCHER_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_BID_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_PROOF_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 10;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 8_800;
pub const DEFAULT_MIN_KEEPER_BOND_UNITS: u64 = 1_000_000;
pub const DEFAULT_MIN_RENT_PRICE_MICRO_UNITS: u64 = 1;
pub const DEFAULT_MAX_LANES: usize = 262_144;
pub const DEFAULT_MAX_LEASES: usize = 2_097_152;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_RENT_BIDS: usize = 4_194_304;
pub const DEFAULT_MAX_VOUCHERS: usize = 4_194_304;
pub const DEFAULT_MAX_PROOFS: usize = 4_194_304;
pub const DEFAULT_MAX_RENEWAL_BATCHES: usize = 1_048_576;
pub const DEFAULT_MAX_EVICTION_RECEIPTS: usize = 2_097_152;
pub const DEFAULT_MAX_CHALLENGES: usize = 1_048_576;
pub const DEFAULT_MAX_SLASHING_EVIDENCE: usize = 1_048_576;
pub const DEFAULT_MAX_FENCES: usize = 4_194_304;
pub const DEFAULT_MAX_EVENTS: usize = 8_388_608;

macro_rules! ensure {
    ($condition:expr, $message:expr) => {
        if !$condition {
            return Err($message.to_string());
        }
    };
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneKind {
    ContractHot,
    ContractWarm,
    ContractCold,
    DefiVault,
    AmmPool,
    LendingPool,
    PerpMargin,
    OracleCache,
    BridgeExit,
    AccountSession,
    RollupCheckpoint,
    Custom,
}
impl LaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractHot => "contract_hot",
            Self::ContractWarm => "contract_warm",
            Self::ContractCold => "contract_cold",
            Self::DefiVault => "defi_vault",
            Self::AmmPool => "amm_pool",
            Self::LendingPool => "lending_pool",
            Self::PerpMargin => "perp_margin",
            Self::OracleCache => "oracle_cache",
            Self::BridgeExit => "bridge_exit",
            Self::AccountSession => "account_session",
            Self::RollupCheckpoint => "rollup_checkpoint",
            Self::Custom => "custom",
        }
    }
    pub fn priority_weight_bps(self) -> u64 {
        match self {
            Self::BridgeExit => 10_000,
            Self::PerpMargin => 9_700,
            Self::AmmPool => 9_500,
            Self::LendingPool => 9_300,
            Self::DefiVault => 9_000,
            Self::ContractHot => 8_800,
            Self::OracleCache => 8_400,
            Self::AccountSession => 8_000,
            Self::ContractWarm => 7_600,
            Self::ContractCold => 6_900,
            Self::RollupCheckpoint => 6_700,
            Self::Custom => 6_400,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Proposed,
    Open,
    Congested,
    RenewalOnly,
    EvictionOnly,
    Paused,
    Closed,
    Slashed,
}
impl LaneStatus {
    pub fn accepts_new_leases(self) -> bool {
        matches!(self, Self::Open | Self::Congested)
    }
    pub fn accepts_renewals(self) -> bool {
        matches!(self, Self::Open | Self::Congested | Self::RenewalOnly)
    }
    pub fn accepts_evictions(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Congested | Self::EvictionOnly | Self::RenewalOnly
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseStatus {
    Registered,
    Active,
    RenewalPending,
    Renewed,
    Expiring,
    EvictionPending,
    Evicted,
    Restored,
    Challenged,
    Slashed,
    Expired,
}
impl LeaseStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Registered
                | Self::Active
                | Self::RenewalPending
                | Self::Renewed
                | Self::Expiring
                | Self::Restored
        )
    }
    pub fn evictable(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Renewed | Self::Expiring | Self::EvictionPending
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    OwnerIdentity,
    OwnerSessionKey,
    ContractCapability,
    LeaseAuthorization,
    RenewalAuthorization,
    EvictionAuthorization,
    KeeperCapability,
    SponsorCapability,
    PrivacySetMembership,
    RecoveryGuardian,
}
impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OwnerIdentity => "owner_identity",
            Self::OwnerSessionKey => "owner_session_key",
            Self::ContractCapability => "contract_capability",
            Self::LeaseAuthorization => "lease_authorization",
            Self::RenewalAuthorization => "renewal_authorization",
            Self::EvictionAuthorization => "eviction_authorization",
            Self::KeeperCapability => "keeper_capability",
            Self::SponsorCapability => "sponsor_capability",
            Self::PrivacySetMembership => "privacy_set_membership",
            Self::RecoveryGuardian => "recovery_guardian",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    WeakQuorum,
    StrongQuorum,
    Rejected,
    Superseded,
    Slashed,
}
impl AttestationStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Accepted | Self::WeakQuorum | Self::StrongQuorum)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Open,
    Matched,
    Reserved,
    PartiallyFilled,
    Filled,
    Outbid,
    Expired,
    Cancelled,
    Slashed,
}
impl BidStatus {
    pub fn matchable(self) -> bool {
        matches!(self, Self::Open | Self::PartiallyFilled | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VoucherStatus {
    Issued,
    Reserved,
    PartiallyConsumed,
    Consumed,
    Refunded,
    Expired,
    Slashed,
}
impl VoucherStatus {
    pub fn spendable(self) -> bool {
        matches!(
            self,
            Self::Issued | Self::Reserved | Self::PartiallyConsumed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofStatus {
    Submitted,
    LeaseMatched,
    BatchQueued,
    Verified,
    Settled,
    Rejected,
    Expired,
    Challenged,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RenewalBatchStatus {
    Proposed,
    ProofsLinked,
    Sponsored,
    Settled,
    PartiallySettled,
    Rejected,
    Expired,
    Challenged,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvictionStatus {
    Proposed,
    GraceOpen,
    ReceiptPublished,
    Challenged,
    Finalized,
    Reversed,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    EvidenceLinked,
    Accepted,
    Rejected,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceStatus {
    Open,
    Spent,
    Tombstoned,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultKind {
    InvalidEviction,
    MissingCiphertext,
    ExpiredProof,
    DuplicateNullifier,
    UnderfundedRent,
    FalseAvailability,
    WithheldRenewal,
    SponsorDoubleSpend,
    KeeperEquivocation,
    ChallengeCensorship,
}
impl FaultKind {
    pub fn slash_weight_bps(self) -> u64 {
        match self {
            Self::KeeperEquivocation => 10_000,
            Self::DuplicateNullifier => 9_800,
            Self::InvalidEviction => 9_600,
            Self::SponsorDoubleSpend => 9_200,
            Self::FalseAvailability => 8_900,
            Self::MissingCiphertext => 8_500,
            Self::WithheldRenewal => 8_000,
            Self::ChallengeCensorship => 7_800,
            Self::ExpiredProof => 7_200,
            Self::UnderfundedRent => 6_800,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidEviction => "invalid_eviction",
            Self::MissingCiphertext => "missing_ciphertext",
            Self::ExpiredProof => "expired_proof",
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::UnderfundedRent => "underfunded_rent",
            Self::FalseAvailability => "false_availability",
            Self::WithheldRenewal => "withheld_renewal",
            Self::SponsorDoubleSpend => "sponsor_double_spend",
            Self::KeeperEquivocation => "keeper_equivocation",
            Self::ChallengeCensorship => "challenge_censorship",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingStatus {
    Submitted,
    EvidenceAccepted,
    KeeperSlashed,
    SponsorSlashed,
    Rejected,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeEventKind {
    LaneOpened,
    OwnerAttested,
    LeaseRegistered,
    RentBidOpened,
    VoucherReserved,
    CompactProofSubmitted,
    RenewalBatchSettled,
    EvictionReceiptPublished,
    EvictionChallenged,
    KeeperSlashed,
    NullifierFenced,
    RuntimeRootPublished,
}
impl RuntimeEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LaneOpened => "lane_opened",
            Self::OwnerAttested => "owner_attested",
            Self::LeaseRegistered => "lease_registered",
            Self::RentBidOpened => "rent_bid_opened",
            Self::VoucherReserved => "voucher_reserved",
            Self::CompactProofSubmitted => "compact_proof_submitted",
            Self::RenewalBatchSettled => "renewal_batch_settled",
            Self::EvictionReceiptPublished => "eviction_receipt_published",
            Self::EvictionChallenged => "eviction_challenged",
            Self::KeeperSlashed => "keeper_slashed",
            Self::NullifierFenced => "nullifier_fenced",
            Self::RuntimeRootPublished => "runtime_root_published",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_owner_attestation_suite: String,
    pub encrypted_state_lease_scheme: String,
    pub storage_rent_bid_scheme: String,
    pub sponsor_voucher_scheme: String,
    pub compact_state_proof_scheme: String,
    pub eviction_receipt_scheme: String,
    pub renewal_batch_scheme: String,
    pub nullifier_fence_scheme: String,
    pub slashing_evidence_scheme: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_lease_blocks: u64,
    pub max_lease_blocks: u64,
    pub renewal_window_blocks: u64,
    pub eviction_grace_blocks: u64,
    pub challenge_window_blocks: u64,
    pub voucher_ttl_blocks: u64,
    pub bid_ttl_blocks: u64,
    pub proof_ttl_blocks: u64,
    pub max_user_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub min_keeper_bond_units: u64,
    pub min_rent_price_micro_units: u64,
    pub max_lanes: usize,
    pub max_leases: usize,
    pub max_attestations: usize,
    pub max_rent_bids: usize,
    pub max_vouchers: usize,
    pub max_proofs: usize,
    pub max_renewal_batches: usize,
    pub max_eviction_receipts: usize,
    pub max_challenges: usize,
    pub max_slashing_evidence: usize,
    pub max_fences: usize,
    pub max_events: usize,
    pub devnet_height: u64,
    pub devnet_monero_network: String,
    pub devnet_l2_network: String,
}
impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "pq_owner_attestation_suite": self.pq_owner_attestation_suite,
            "encrypted_state_lease_scheme": self.encrypted_state_lease_scheme,
            "storage_rent_bid_scheme": self.storage_rent_bid_scheme,
            "sponsor_voucher_scheme": self.sponsor_voucher_scheme,
            "compact_state_proof_scheme": self.compact_state_proof_scheme,
            "eviction_receipt_scheme": self.eviction_receipt_scheme,
            "renewal_batch_scheme": self.renewal_batch_scheme,
            "nullifier_fence_scheme": self.nullifier_fence_scheme,
            "slashing_evidence_scheme": self.slashing_evidence_scheme,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_lease_blocks": self.min_lease_blocks,
            "max_lease_blocks": self.max_lease_blocks,
            "renewal_window_blocks": self.renewal_window_blocks,
            "eviction_grace_blocks": self.eviction_grace_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "voucher_ttl_blocks": self.voucher_ttl_blocks,
            "bid_ttl_blocks": self.bid_ttl_blocks,
            "proof_ttl_blocks": self.proof_ttl_blocks,
            "max_user_fee_bps": self.max_user_fee_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "min_keeper_bond_units": self.min_keeper_bond_units,
            "min_rent_price_micro_units": self.min_rent_price_micro_units,
            "max_lanes": self.max_lanes,
            "max_leases": self.max_leases,
            "max_attestations": self.max_attestations,
            "max_rent_bids": self.max_rent_bids,
            "max_vouchers": self.max_vouchers,
            "max_proofs": self.max_proofs,
            "max_renewal_batches": self.max_renewal_batches,
            "max_eviction_receipts": self.max_eviction_receipts,
            "max_challenges": self.max_challenges,
            "max_slashing_evidence": self.max_slashing_evidence,
            "max_fences": self.max_fences,
            "max_events": self.max_events,
            "devnet_height": self.devnet_height,
            "devnet_monero_network": self.devnet_monero_network,
            "devnet_l2_network": self.devnet_l2_network,
        })
    }

    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_owner_attestation_suite: PQ_OWNER_ATTESTATION_SUITE.to_string(),
            encrypted_state_lease_scheme: ENCRYPTED_STATE_LEASE_SCHEME.to_string(),
            storage_rent_bid_scheme: STORAGE_RENT_BID_SCHEME.to_string(),
            sponsor_voucher_scheme: SPONSOR_VOUCHER_SCHEME.to_string(),
            compact_state_proof_scheme: COMPACT_STATE_PROOF_SCHEME.to_string(),
            eviction_receipt_scheme: EVICTION_RECEIPT_SCHEME.to_string(),
            renewal_batch_scheme: RENEWAL_BATCH_SCHEME.to_string(),
            nullifier_fence_scheme: NULLIFIER_FENCE_SCHEME.to_string(),
            slashing_evidence_scheme: SLASHING_EVIDENCE_SCHEME.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_lease_blocks: DEFAULT_MIN_LEASE_BLOCKS,
            max_lease_blocks: DEFAULT_MAX_LEASE_BLOCKS,
            renewal_window_blocks: DEFAULT_RENEWAL_WINDOW_BLOCKS,
            eviction_grace_blocks: DEFAULT_EVICTION_GRACE_BLOCKS,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            voucher_ttl_blocks: DEFAULT_VOUCHER_TTL_BLOCKS,
            bid_ttl_blocks: DEFAULT_BID_TTL_BLOCKS,
            proof_ttl_blocks: DEFAULT_PROOF_TTL_BLOCKS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            min_keeper_bond_units: DEFAULT_MIN_KEEPER_BOND_UNITS,
            min_rent_price_micro_units: DEFAULT_MIN_RENT_PRICE_MICRO_UNITS,
            max_lanes: DEFAULT_MAX_LANES,
            max_leases: DEFAULT_MAX_LEASES,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_rent_bids: DEFAULT_MAX_RENT_BIDS,
            max_vouchers: DEFAULT_MAX_VOUCHERS,
            max_proofs: DEFAULT_MAX_PROOFS,
            max_renewal_batches: DEFAULT_MAX_RENEWAL_BATCHES,
            max_eviction_receipts: DEFAULT_MAX_EVICTION_RECEIPTS,
            max_challenges: DEFAULT_MAX_CHALLENGES,
            max_slashing_evidence: DEFAULT_MAX_SLASHING_EVIDENCE,
            max_fences: DEFAULT_MAX_FENCES,
            max_events: DEFAULT_MAX_EVENTS,
            devnet_height: DEVNET_HEIGHT,
            devnet_monero_network: DEVNET_MONERO_NETWORK.to_string(),
            devnet_l2_network: DEVNET_L2_NETWORK.to_string(),
        }
    }
    pub fn validate(&self) -> Result<()> {
        require_non_empty("chain_id", &self.chain_id)?;
        ensure!(self.chain_id == CHAIN_ID, "config chain_id mismatch");
        ensure!(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol version mismatch"
        );
        ensure!(
            self.schema_version == SCHEMA_VERSION,
            "schema version mismatch"
        );
        ensure!(self.hash_suite == HASH_SUITE, "hash suite mismatch");
        ensure!(
            self.min_pq_security_bits >= 192,
            "min pq security bits too low"
        );
        require_positive_u64("min_privacy_set_size", self.min_privacy_set_size)?;
        ensure!(
            self.batch_privacy_set_size >= self.min_privacy_set_size,
            "batch privacy set below minimum"
        );
        require_positive_u64("min_lease_blocks", self.min_lease_blocks)?;
        ensure!(
            self.max_lease_blocks >= self.min_lease_blocks,
            "max lease below min lease"
        );
        require_positive_u64("renewal_window_blocks", self.renewal_window_blocks)?;
        require_positive_u64("eviction_grace_blocks", self.eviction_grace_blocks)?;
        require_positive_u64("challenge_window_blocks", self.challenge_window_blocks)?;
        require_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        require_bps("sponsor_cover_bps", self.sponsor_cover_bps)?;
        require_positive_usize("max_lanes", self.max_lanes)?;
        require_positive_usize("max_leases", self.max_leases)?;
        require_positive_usize("max_events", self.max_events)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StateLane {
    pub lane_id: String,
    pub lane_kind: LaneKind,
    pub status: LaneStatus,
    pub operator_commitment: String,
    pub keeper_committee_root: String,
    pub encrypted_metadata_root: String,
    pub pricing_oracle_root: String,
    pub capacity_bytes: u64,
    pub reserved_bytes: u64,
    pub active_leases: u64,
    pub min_rent_price_micro_units: u64,
    pub sponsor_cover_bps: u64,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub opened_at_height: u64,
    pub updated_at_height: u64,
}
impl StateLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind,
            "status": self.status,
            "operator_commitment": self.operator_commitment,
            "keeper_committee_root": self.keeper_committee_root,
            "encrypted_metadata_root": self.encrypted_metadata_root,
            "pricing_oracle_root": self.pricing_oracle_root,
            "capacity_bytes": self.capacity_bytes,
            "reserved_bytes": self.reserved_bytes,
            "active_leases": self.active_leases,
            "min_rent_price_micro_units": self.min_rent_price_micro_units,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "pq_security_bits": self.pq_security_bits,
            "privacy_set_size": self.privacy_set_size,
            "opened_at_height": self.opened_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }

    pub fn free_bytes(&self) -> u64 {
        self.capacity_bytes.saturating_sub(self.reserved_bytes)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqOwnerAttestation {
    pub attestation_id: String,
    pub lane_id: String,
    pub owner_commitment: String,
    pub contract_commitment: String,
    pub kind: AttestationKind,
    pub status: AttestationStatus,
    pub pq_key_root: String,
    pub signature_root: String,
    pub capability_root: String,
    pub nullifier_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub accepted_at_height: Option<u64>,
}
impl PqOwnerAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "lane_id": self.lane_id,
            "owner_commitment": self.owner_commitment,
            "contract_commitment": self.contract_commitment,
            "kind": self.kind,
            "status": self.status,
            "pq_key_root": self.pq_key_root,
            "signature_root": self.signature_root,
            "capability_root": self.capability_root,
            "nullifier_root": self.nullifier_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "accepted_at_height": self.accepted_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptedStateLease {
    pub lease_id: String,
    pub lane_id: String,
    pub owner_attestation_id: String,
    pub contract_commitment: String,
    pub encrypted_state_root: String,
    pub encrypted_index_root: String,
    pub ciphertext_commitment_root: String,
    pub view_tag_root: String,
    pub rent_bid_id: Option<String>,
    pub sponsor_voucher_id: Option<String>,
    pub status: LeaseStatus,
    pub size_bytes: u64,
    pub rent_price_micro_units: u64,
    pub rent_paid_micro_units: u64,
    pub sponsor_paid_micro_units: u64,
    pub lease_start_height: u64,
    pub lease_expiry_height: u64,
    pub renewal_deadline_height: u64,
    pub eviction_eligible_height: u64,
    pub last_proof_height: u64,
    pub nullifier_root: String,
    pub renewal_count: u64,
}
impl EncryptedStateLease {
    pub fn public_record(&self) -> Value {
        json!({
            "lease_id": self.lease_id,
            "lane_id": self.lane_id,
            "owner_attestation_id": self.owner_attestation_id,
            "contract_commitment": self.contract_commitment,
            "encrypted_state_root": self.encrypted_state_root,
            "encrypted_index_root": self.encrypted_index_root,
            "ciphertext_commitment_root": self.ciphertext_commitment_root,
            "view_tag_root": self.view_tag_root,
            "rent_bid_id": self.rent_bid_id,
            "sponsor_voucher_id": self.sponsor_voucher_id,
            "status": self.status,
            "size_bytes": self.size_bytes,
            "rent_price_micro_units": self.rent_price_micro_units,
            "rent_paid_micro_units": self.rent_paid_micro_units,
            "sponsor_paid_micro_units": self.sponsor_paid_micro_units,
            "lease_start_height": self.lease_start_height,
            "lease_expiry_height": self.lease_expiry_height,
            "renewal_deadline_height": self.renewal_deadline_height,
            "eviction_eligible_height": self.eviction_eligible_height,
            "last_proof_height": self.last_proof_height,
            "nullifier_root": self.nullifier_root,
            "renewal_count": self.renewal_count,
        })
    }

    pub fn rent_due_for_extension(&self, extension_blocks: u64) -> u64 {
        self.size_bytes
            .saturating_mul(self.rent_price_micro_units)
            .saturating_mul(extension_blocks)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StorageRentBid {
    pub bid_id: String,
    pub lane_id: String,
    pub bidder_commitment: String,
    pub encrypted_bid_root: String,
    pub bid_nullifier_root: String,
    pub status: BidStatus,
    pub max_price_micro_units: u64,
    pub reserved_bytes: u64,
    pub remaining_bytes: u64,
    pub prepaid_micro_units: u64,
    pub matched_lease_ids: BTreeSet<String>,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}
impl StorageRentBid {
    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "lane_id": self.lane_id,
            "bidder_commitment": self.bidder_commitment,
            "encrypted_bid_root": self.encrypted_bid_root,
            "bid_nullifier_root": self.bid_nullifier_root,
            "status": self.status,
            "max_price_micro_units": self.max_price_micro_units,
            "reserved_bytes": self.reserved_bytes,
            "remaining_bytes": self.remaining_bytes,
            "prepaid_micro_units": self.prepaid_micro_units,
            "matched_lease_ids": self.matched_lease_ids,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsorVoucher {
    pub voucher_id: String,
    pub sponsor_commitment: String,
    pub beneficiary_commitment: String,
    pub lane_id: String,
    pub lease_id: Option<String>,
    pub status: VoucherStatus,
    pub voucher_root: String,
    pub nullifier_root: String,
    pub max_fee_bps: u64,
    pub cover_bps: u64,
    pub reserved_micro_units: u64,
    pub consumed_micro_units: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}
impl SponsorVoucher {
    pub fn public_record(&self) -> Value {
        json!({
            "voucher_id": self.voucher_id,
            "sponsor_commitment": self.sponsor_commitment,
            "beneficiary_commitment": self.beneficiary_commitment,
            "lane_id": self.lane_id,
            "lease_id": self.lease_id,
            "status": self.status,
            "voucher_root": self.voucher_root,
            "nullifier_root": self.nullifier_root,
            "max_fee_bps": self.max_fee_bps,
            "cover_bps": self.cover_bps,
            "reserved_micro_units": self.reserved_micro_units,
            "consumed_micro_units": self.consumed_micro_units,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn remaining_micro_units(&self) -> u64 {
        self.reserved_micro_units
            .saturating_sub(self.consumed_micro_units)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CompactStateProof {
    pub proof_id: String,
    pub lease_id: String,
    pub lane_id: String,
    pub prover_commitment: String,
    pub status: ProofStatus,
    pub compact_proof_root: String,
    pub state_transition_root: String,
    pub availability_root: String,
    pub nullifier_root: String,
    pub proof_size_bytes: u64,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub verified_at_height: Option<u64>,
}
impl CompactStateProof {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "lease_id": self.lease_id,
            "lane_id": self.lane_id,
            "prover_commitment": self.prover_commitment,
            "status": self.status,
            "compact_proof_root": self.compact_proof_root,
            "state_transition_root": self.state_transition_root,
            "availability_root": self.availability_root,
            "nullifier_root": self.nullifier_root,
            "proof_size_bytes": self.proof_size_bytes,
            "pq_security_bits": self.pq_security_bits,
            "privacy_set_size": self.privacy_set_size,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "verified_at_height": self.verified_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RenewalBatch {
    pub batch_id: String,
    pub lane_id: String,
    pub keeper_commitment: String,
    pub status: RenewalBatchStatus,
    pub lease_ids: BTreeSet<String>,
    pub proof_ids: BTreeSet<String>,
    pub voucher_ids: BTreeSet<String>,
    pub renewal_root: String,
    pub rent_payment_root: String,
    pub nullifier_root: String,
    pub total_bytes: u64,
    pub total_rent_micro_units: u64,
    pub sponsor_micro_units: u64,
    pub extension_blocks: u64,
    pub proposed_at_height: u64,
    pub settled_at_height: Option<u64>,
}
impl RenewalBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "keeper_commitment": self.keeper_commitment,
            "status": self.status,
            "lease_ids": self.lease_ids,
            "proof_ids": self.proof_ids,
            "voucher_ids": self.voucher_ids,
            "renewal_root": self.renewal_root,
            "rent_payment_root": self.rent_payment_root,
            "nullifier_root": self.nullifier_root,
            "total_bytes": self.total_bytes,
            "total_rent_micro_units": self.total_rent_micro_units,
            "sponsor_micro_units": self.sponsor_micro_units,
            "extension_blocks": self.extension_blocks,
            "proposed_at_height": self.proposed_at_height,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EvictionReceipt {
    pub receipt_id: String,
    pub lease_id: String,
    pub lane_id: String,
    pub keeper_commitment: String,
    pub status: EvictionStatus,
    pub eviction_root: String,
    pub final_state_root: String,
    pub ciphertext_tombstone_root: String,
    pub reason_code: String,
    pub rent_due_micro_units: u64,
    pub keeper_bond_units: u64,
    pub proposed_at_height: u64,
    pub grace_ends_at_height: u64,
    pub finalized_at_height: Option<u64>,
}
impl EvictionReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "lease_id": self.lease_id,
            "lane_id": self.lane_id,
            "keeper_commitment": self.keeper_commitment,
            "status": self.status,
            "eviction_root": self.eviction_root,
            "final_state_root": self.final_state_root,
            "ciphertext_tombstone_root": self.ciphertext_tombstone_root,
            "reason_code": self.reason_code,
            "rent_due_micro_units": self.rent_due_micro_units,
            "keeper_bond_units": self.keeper_bond_units,
            "proposed_at_height": self.proposed_at_height,
            "grace_ends_at_height": self.grace_ends_at_height,
            "finalized_at_height": self.finalized_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EvictionChallenge {
    pub challenge_id: String,
    pub receipt_id: String,
    pub lease_id: String,
    pub challenger_commitment: String,
    pub status: ChallengeStatus,
    pub evidence_root: String,
    pub counter_proof_root: String,
    pub nullifier_root: String,
    pub bond_units: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub resolved_at_height: Option<u64>,
}
impl EvictionChallenge {
    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "receipt_id": self.receipt_id,
            "lease_id": self.lease_id,
            "challenger_commitment": self.challenger_commitment,
            "status": self.status,
            "evidence_root": self.evidence_root,
            "counter_proof_root": self.counter_proof_root,
            "nullifier_root": self.nullifier_root,
            "bond_units": self.bond_units,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "resolved_at_height": self.resolved_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub target_commitment: String,
    pub lane_id: String,
    pub related_receipt_id: Option<String>,
    pub related_challenge_id: Option<String>,
    pub fault_kind: FaultKind,
    pub status: SlashingStatus,
    pub evidence_root: String,
    pub fraud_proof_root: String,
    pub slash_amount_units: u64,
    pub reporter_commitment: String,
    pub submitted_at_height: u64,
    pub resolved_at_height: Option<u64>,
}
impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "target_commitment": self.target_commitment,
            "lane_id": self.lane_id,
            "related_receipt_id": self.related_receipt_id,
            "related_challenge_id": self.related_challenge_id,
            "fault_kind": self.fault_kind,
            "status": self.status,
            "evidence_root": self.evidence_root,
            "fraud_proof_root": self.fraud_proof_root,
            "slash_amount_units": self.slash_amount_units,
            "reporter_commitment": self.reporter_commitment,
            "submitted_at_height": self.submitted_at_height,
            "resolved_at_height": self.resolved_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NullifierFence {
    pub fence_id: String,
    pub lane_id: String,
    pub subject_id: String,
    pub status: FenceStatus,
    pub nullifier_root: String,
    pub privacy_epoch: u64,
    pub opened_at_height: u64,
    pub spent_at_height: Option<u64>,
}
impl NullifierFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "lane_id": self.lane_id,
            "subject_id": self.subject_id,
            "status": self.status,
            "nullifier_root": self.nullifier_root,
            "privacy_epoch": self.privacy_epoch,
            "opened_at_height": self.opened_at_height,
            "spent_at_height": self.spent_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub kind: RuntimeEventKind,
    pub subject_id: String,
    pub payload_root: String,
    pub lane_id: Option<String>,
    pub height: u64,
    pub sequence: u64,
}
impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "lane_id": self.lane_id,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Counters {
    pub lanes: u64,
    pub leases: u64,
    pub attestations: u64,
    pub rent_bids: u64,
    pub vouchers: u64,
    pub proofs: u64,
    pub renewal_batches: u64,
    pub eviction_receipts: u64,
    pub challenges: u64,
    pub slashing_evidence: u64,
    pub fences: u64,
    pub events: u64,
    pub active_leases: u64,
    pub evicted_leases: u64,
    pub challenged_evictions: u64,
    pub slashed_keepers: u64,
    pub sponsored_micro_units: u64,
    pub rent_collected_micro_units: u64,
    pub bytes_leased: u64,
    pub bytes_evicted: u64,
}
impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "lanes": self.lanes,
            "leases": self.leases,
            "attestations": self.attestations,
            "rent_bids": self.rent_bids,
            "vouchers": self.vouchers,
            "proofs": self.proofs,
            "renewal_batches": self.renewal_batches,
            "eviction_receipts": self.eviction_receipts,
            "challenges": self.challenges,
            "slashing_evidence": self.slashing_evidence,
            "fences": self.fences,
            "events": self.events,
            "active_leases": self.active_leases,
            "evicted_leases": self.evicted_leases,
            "challenged_evictions": self.challenged_evictions,
            "slashed_keepers": self.slashed_keepers,
            "sponsored_micro_units": self.sponsored_micro_units,
            "rent_collected_micro_units": self.rent_collected_micro_units,
            "bytes_leased": self.bytes_leased,
            "bytes_evicted": self.bytes_evicted,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub lanes_root: String,
    pub leases_root: String,
    pub attestations_root: String,
    pub rent_bids_root: String,
    pub vouchers_root: String,
    pub proofs_root: String,
    pub renewal_batches_root: String,
    pub eviction_receipts_root: String,
    pub challenges_root: String,
    pub slashing_evidence_root: String,
    pub fences_root: String,
    pub events_root: String,
    pub active_leases_root: String,
    pub evicted_leases_root: String,
    pub challenged_receipts_root: String,
}
impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "lanes_root": self.lanes_root,
            "leases_root": self.leases_root,
            "attestations_root": self.attestations_root,
            "rent_bids_root": self.rent_bids_root,
            "vouchers_root": self.vouchers_root,
            "proofs_root": self.proofs_root,
            "renewal_batches_root": self.renewal_batches_root,
            "eviction_receipts_root": self.eviction_receipts_root,
            "challenges_root": self.challenges_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "fences_root": self.fences_root,
            "events_root": self.events_root,
            "active_leases_root": self.active_leases_root,
            "evicted_leases_root": self.evicted_leases_root,
            "challenged_receipts_root": self.challenged_receipts_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub lanes: BTreeMap<String, StateLane>,
    pub leases: BTreeMap<String, EncryptedStateLease>,
    pub attestations: BTreeMap<String, PqOwnerAttestation>,
    pub rent_bids: BTreeMap<String, StorageRentBid>,
    pub vouchers: BTreeMap<String, SponsorVoucher>,
    pub proofs: BTreeMap<String, CompactStateProof>,
    pub renewal_batches: BTreeMap<String, RenewalBatch>,
    pub eviction_receipts: BTreeMap<String, EvictionReceipt>,
    pub challenges: BTreeMap<String, EvictionChallenge>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub fences: BTreeMap<String, NullifierFence>,
    pub events: BTreeMap<String, RuntimeEvent>,
    pub active_leases: BTreeSet<String>,
    pub evicted_leases: BTreeSet<String>,
    pub challenged_receipts: BTreeSet<String>,
}
impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            lanes: BTreeMap::new(),
            leases: BTreeMap::new(),
            attestations: BTreeMap::new(),
            rent_bids: BTreeMap::new(),
            vouchers: BTreeMap::new(),
            proofs: BTreeMap::new(),
            renewal_batches: BTreeMap::new(),
            eviction_receipts: BTreeMap::new(),
            challenges: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            fences: BTreeMap::new(),
            events: BTreeMap::new(),
            active_leases: BTreeSet::new(),
            evicted_leases: BTreeSet::new(),
            challenged_receipts: BTreeSet::new(),
        })
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).expect("valid devnet expiry rent config");
        let h = state.config.devnet_height;
        let lane_id =
            deterministic_lane_id("devnet-hot-contract-state", LaneKind::ContractHot, h, 0);
        let attestation_id = owner_attestation_id(
            &lane_id,
            "devnet-owner",
            AttestationKind::OwnerIdentity,
            h,
            0,
        );
        let bid_id = rent_bid_id(
            &lane_id,
            "devnet-bidder",
            "devnet-bid-nullifier-root-0000000000",
            h,
            0,
        );
        let voucher_id = sponsor_voucher_id("devnet-sponsor", &lane_id, "devnet-beneficiary", h, 0);
        let lease_id = encrypted_state_lease_id(
            &lane_id,
            "devnet-contract",
            "devnet-encrypted-state-root-0000000000",
            h,
            0,
        );
        let proof_id =
            compact_state_proof_id(&lease_id, "devnet-transition-root-0000000000000", h + 1, 0);
        state
            .open_lane(StateLane {
                lane_id: lane_id.clone(),
                lane_kind: LaneKind::ContractHot,
                status: LaneStatus::Proposed,
                operator_commitment: "devnet-operator".to_string(),
                keeper_committee_root: "devnet-keeper-committee-root-0000000000".to_string(),
                encrypted_metadata_root: "devnet-encrypted-metadata-root-000000000".to_string(),
                pricing_oracle_root: "devnet-pricing-oracle-root-0000000000".to_string(),
                capacity_bytes: 64 * 1024 * 1024,
                reserved_bytes: 0,
                active_leases: 0,
                min_rent_price_micro_units: 2,
                sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
                pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
                opened_at_height: h,
                updated_at_height: h,
            })
            .expect("devnet lane");
        state
            .accept_owner_attestation(PqOwnerAttestation {
                attestation_id: attestation_id.clone(),
                lane_id: lane_id.clone(),
                owner_commitment: "devnet-owner".to_string(),
                contract_commitment: "devnet-contract".to_string(),
                kind: AttestationKind::OwnerIdentity,
                status: AttestationStatus::Submitted,
                pq_key_root: "devnet-owner-pq-key-root-0000000000000".to_string(),
                signature_root: "devnet-owner-signature-root-000000000".to_string(),
                capability_root: "devnet-owner-capability-root-00000000".to_string(),
                nullifier_root: "devnet-owner-nullifier-root-000000000".to_string(),
                privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
                pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                valid_from_height: h,
                valid_until_height: h + 86_400,
                accepted_at_height: None,
            })
            .expect("devnet attestation");
        state
            .bid_rent(StorageRentBid {
                bid_id: bid_id.clone(),
                lane_id: lane_id.clone(),
                bidder_commitment: "devnet-bidder".to_string(),
                encrypted_bid_root: "devnet-encrypted-bid-root-00000000000".to_string(),
                bid_nullifier_root: "devnet-bid-nullifier-root-0000000000".to_string(),
                status: BidStatus::Open,
                max_price_micro_units: 4,
                reserved_bytes: 8192,
                remaining_bytes: 8192,
                prepaid_micro_units: 8192 * 4 * DEFAULT_MIN_LEASE_BLOCKS,
                matched_lease_ids: BTreeSet::new(),
                created_at_height: h,
                expires_at_height: h + DEFAULT_BID_TTL_BLOCKS,
            })
            .expect("devnet bid");
        state
            .reserve_sponsor_voucher(SponsorVoucher {
                voucher_id: voucher_id.clone(),
                sponsor_commitment: "devnet-sponsor".to_string(),
                beneficiary_commitment: "devnet-beneficiary".to_string(),
                lane_id: lane_id.clone(),
                lease_id: None,
                status: VoucherStatus::Issued,
                voucher_root: "devnet-voucher-root-0000000000000000".to_string(),
                nullifier_root: "devnet-voucher-nullifier-root-00000000".to_string(),
                max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
                cover_bps: DEFAULT_SPONSOR_COVER_BPS,
                reserved_micro_units: 128_000,
                consumed_micro_units: 0,
                issued_at_height: h,
                expires_at_height: h + DEFAULT_VOUCHER_TTL_BLOCKS,
            })
            .expect("devnet voucher");
        state
            .register_leased_state(EncryptedStateLease {
                lease_id: lease_id.clone(),
                lane_id: lane_id.clone(),
                owner_attestation_id: attestation_id,
                contract_commitment: "devnet-contract".to_string(),
                encrypted_state_root: "devnet-encrypted-state-root-0000000000".to_string(),
                encrypted_index_root: "devnet-encrypted-index-root-0000000000".to_string(),
                ciphertext_commitment_root: "devnet-ciphertext-commitment-root-000000".to_string(),
                view_tag_root: "devnet-view-tag-root-00000000000000".to_string(),
                rent_bid_id: Some(bid_id),
                sponsor_voucher_id: Some(voucher_id.clone()),
                status: LeaseStatus::Registered,
                size_bytes: 8192,
                rent_price_micro_units: 3,
                rent_paid_micro_units: 0,
                sponsor_paid_micro_units: 0,
                lease_start_height: h,
                lease_expiry_height: h + DEFAULT_MIN_LEASE_BLOCKS,
                renewal_deadline_height: h + DEFAULT_MIN_LEASE_BLOCKS - 32,
                eviction_eligible_height: h
                    + DEFAULT_MIN_LEASE_BLOCKS
                    + DEFAULT_EVICTION_GRACE_BLOCKS,
                last_proof_height: h,
                nullifier_root: "devnet-lease-nullifier-root-0000000000".to_string(),
                renewal_count: 0,
            })
            .expect("devnet lease");
        state
            .submit_compact_state_proof(CompactStateProof {
                proof_id: proof_id.clone(),
                lease_id: lease_id.clone(),
                lane_id: lane_id.clone(),
                prover_commitment: "devnet-prover".to_string(),
                status: ProofStatus::Submitted,
                compact_proof_root: "devnet-compact-proof-root-00000000000".to_string(),
                state_transition_root: "devnet-transition-root-0000000000000".to_string(),
                availability_root: "devnet-availability-root-00000000000".to_string(),
                nullifier_root: "devnet-proof-nullifier-root-0000000000".to_string(),
                proof_size_bytes: 512,
                pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
                submitted_at_height: h + 1,
                expires_at_height: h + 1 + DEFAULT_PROOF_TTL_BLOCKS,
                verified_at_height: None,
            })
            .expect("devnet proof");
        state
            .renew_state(RenewalBatch {
                batch_id: renewal_batch_id(
                    &lane_id,
                    "devnet-renewal-root-00000000000000",
                    h + 2,
                    0,
                ),
                lane_id: lane_id.clone(),
                keeper_commitment: "devnet-keeper".to_string(),
                status: RenewalBatchStatus::Proposed,
                lease_ids: BTreeSet::from([lease_id.clone()]),
                proof_ids: BTreeSet::from([proof_id]),
                voucher_ids: BTreeSet::from([voucher_id]),
                renewal_root: "devnet-renewal-root-00000000000000".to_string(),
                rent_payment_root: "devnet-rent-payment-root-0000000000".to_string(),
                nullifier_root: "devnet-renewal-nullifier-root-0000000".to_string(),
                total_bytes: 8192,
                total_rent_micro_units: 8192 * 3 * DEFAULT_MIN_LEASE_BLOCKS,
                sponsor_micro_units: 128_000,
                extension_blocks: DEFAULT_MIN_LEASE_BLOCKS,
                proposed_at_height: h + 2,
                settled_at_height: None,
            })
            .expect("devnet renewal");
        state
    }

    pub fn counters(&self) -> Counters {
        Counters {
            lanes: self.lanes.len() as u64,
            leases: self.leases.len() as u64,
            attestations: self.attestations.len() as u64,
            rent_bids: self.rent_bids.len() as u64,
            vouchers: self.vouchers.len() as u64,
            proofs: self.proofs.len() as u64,
            renewal_batches: self.renewal_batches.len() as u64,
            eviction_receipts: self.eviction_receipts.len() as u64,
            challenges: self.challenges.len() as u64,
            slashing_evidence: self.slashing_evidence.len() as u64,
            fences: self.fences.len() as u64,
            events: self.events.len() as u64,
            active_leases: self.active_leases.len() as u64,
            evicted_leases: self.evicted_leases.len() as u64,
            challenged_evictions: self.challenged_receipts.len() as u64,
            slashed_keepers: self
                .slashing_evidence
                .values()
                .filter(|e| {
                    matches!(
                        e.status,
                        SlashingStatus::KeeperSlashed | SlashingStatus::SponsorSlashed
                    )
                })
                .count() as u64,
            sponsored_micro_units: self.vouchers.values().map(|v| v.consumed_micro_units).sum(),
            rent_collected_micro_units: self.leases.values().map(|l| l.rent_paid_micro_units).sum(),
            bytes_leased: self
                .leases
                .values()
                .filter(|l| l.status.live())
                .map(|l| l.size_bytes)
                .sum(),
            bytes_evicted: self
                .evicted_leases
                .iter()
                .filter_map(|id| self.leases.get(id))
                .map(|l| l.size_bytes)
                .sum(),
        }
    }

    pub fn roots(&self) -> Roots {
        Roots {
            lanes_root: map_root("private-l2-state-expiry-rent-lanes", &self.lanes),
            leases_root: map_root("private-l2-state-expiry-rent-leases", &self.leases),
            attestations_root: map_root(
                "private-l2-state-expiry-rent-attestations",
                &self.attestations,
            ),
            rent_bids_root: map_root("private-l2-state-expiry-rent-bids", &self.rent_bids),
            vouchers_root: map_root("private-l2-state-expiry-rent-vouchers", &self.vouchers),
            proofs_root: map_root("private-l2-state-expiry-rent-proofs", &self.proofs),
            renewal_batches_root: map_root(
                "private-l2-state-expiry-rent-renewal-batches",
                &self.renewal_batches,
            ),
            eviction_receipts_root: map_root(
                "private-l2-state-expiry-rent-eviction-receipts",
                &self.eviction_receipts,
            ),
            challenges_root: map_root("private-l2-state-expiry-rent-challenges", &self.challenges),
            slashing_evidence_root: map_root(
                "private-l2-state-expiry-rent-slashing",
                &self.slashing_evidence,
            ),
            fences_root: map_root("private-l2-state-expiry-rent-fences", &self.fences),
            events_root: map_root("private-l2-state-expiry-rent-events", &self.events),
            active_leases_root: set_root(
                "private-l2-state-expiry-rent-active-leases",
                &self.active_leases,
            ),
            evicted_leases_root: set_root(
                "private-l2-state-expiry-rent-evicted-leases",
                &self.evicted_leases,
            ),
            challenged_receipts_root: set_root(
                "private-l2-state-expiry-rent-challenged-receipts",
                &self.challenged_receipts,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "config": self.config.public_record(), "counters": self.counters().public_record(), "roots": self.roots().public_record(), "state_root": self.state_root() })
    }
    pub fn state_root(&self) -> String {
        let roots = self.roots().public_record();
        let counters = self.counters().public_record();
        domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-STATE-EXPIRY-RENT-MARKET-STATE-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&self.config.public_record()),
                HashPart::Json(&counters),
                HashPart::Json(&roots),
            ],
            32,
        )
    }

    pub fn open_lane(&mut self, mut lane: StateLane) -> Result<()> {
        ensure_capacity("lanes", self.lanes.len(), self.config.max_lanes)?;
        require_non_empty("lane_id", &lane.lane_id)?;
        require_non_empty("operator_commitment", &lane.operator_commitment)?;
        require_root("keeper_committee_root", &lane.keeper_committee_root)?;
        require_root("encrypted_metadata_root", &lane.encrypted_metadata_root)?;
        require_root("pricing_oracle_root", &lane.pricing_oracle_root)?;
        require_positive_u64("capacity_bytes", lane.capacity_bytes)?;
        require_bps("sponsor_cover_bps", lane.sponsor_cover_bps)?;
        ensure!(
            lane.reserved_bytes <= lane.capacity_bytes,
            "reserved bytes exceed capacity"
        );
        ensure!(
            lane.pq_security_bits >= self.config.min_pq_security_bits,
            "lane pq security below minimum"
        );
        ensure!(
            lane.privacy_set_size >= self.config.min_privacy_set_size,
            "lane privacy set below minimum"
        );
        ensure!(
            !self.lanes.contains_key(&lane.lane_id),
            "lane already exists"
        );
        lane.status = LaneStatus::Open;
        let lane_id = lane.lane_id.clone();
        let payload_root = public_record_root(&lane.public_record());
        self.lanes.insert(lane_id.clone(), lane);
        self.push_event(
            RuntimeEventKind::LaneOpened,
            &lane_id,
            &payload_root,
            Some(lane_id.clone()),
            self.config.devnet_height,
        )?;
        Ok(())
    }
    pub fn accept_owner_attestation(&mut self, mut a: PqOwnerAttestation) -> Result<()> {
        ensure_capacity(
            "attestations",
            self.attestations.len(),
            self.config.max_attestations,
        )?;
        require_non_empty("attestation_id", &a.attestation_id)?;
        require_root("pq_key_root", &a.pq_key_root)?;
        require_root("signature_root", &a.signature_root)?;
        require_root("capability_root", &a.capability_root)?;
        require_root("nullifier_root", &a.nullifier_root)?;
        ensure!(
            self.lanes.contains_key(&a.lane_id),
            "unknown attestation lane"
        );
        ensure!(
            a.valid_until_height > a.valid_from_height,
            "attestation validity window is empty"
        );
        ensure!(
            a.pq_security_bits >= self.config.min_pq_security_bits,
            "attestation pq security below minimum"
        );
        ensure!(
            a.privacy_set_size >= self.config.min_privacy_set_size,
            "attestation privacy set below minimum"
        );
        ensure!(
            !self.attestations.contains_key(&a.attestation_id),
            "attestation already exists"
        );
        self.open_nullifier_fence(
            &a.lane_id,
            &a.attestation_id,
            &a.nullifier_root,
            a.valid_from_height,
        )?;
        a.status = AttestationStatus::Accepted;
        a.accepted_at_height = Some(a.valid_from_height);
        let id = a.attestation_id.clone();
        let lane_id = a.lane_id.clone();
        let payload_root = public_record_root(&a.public_record());
        self.attestations.insert(id.clone(), a);
        self.push_event(
            RuntimeEventKind::OwnerAttested,
            &id,
            &payload_root,
            Some(lane_id),
            self.config.devnet_height,
        )?;
        Ok(())
    }
    pub fn bid_rent(&mut self, bid: StorageRentBid) -> Result<()> {
        ensure_capacity("rent_bids", self.rent_bids.len(), self.config.max_rent_bids)?;
        require_non_empty("bid_id", &bid.bid_id)?;
        require_root("encrypted_bid_root", &bid.encrypted_bid_root)?;
        require_root("bid_nullifier_root", &bid.bid_nullifier_root)?;
        let lane = self
            .lanes
            .get(&bid.lane_id)
            .ok_or_else(|| "unknown bid lane".to_string())?;
        ensure!(
            lane.status.accepts_new_leases(),
            "lane does not accept rent bids"
        );
        ensure!(
            bid.expires_at_height <= bid.created_at_height + self.config.bid_ttl_blocks,
            "bid ttl exceeds runtime limit"
        );
        ensure!(
            bid.max_price_micro_units >= lane.min_rent_price_micro_units,
            "bid price below lane minimum"
        );
        ensure!(
            bid.remaining_bytes <= bid.reserved_bytes && bid.reserved_bytes > 0,
            "invalid bid byte reservation"
        );
        ensure!(bid.prepaid_micro_units > 0, "bid must escrow prepaid rent");
        ensure!(
            !self.rent_bids.contains_key(&bid.bid_id),
            "rent bid already exists"
        );
        self.open_nullifier_fence(
            &bid.lane_id,
            &bid.bid_id,
            &bid.bid_nullifier_root,
            bid.created_at_height,
        )?;
        let id = bid.bid_id.clone();
        let lane_id = bid.lane_id.clone();
        let payload_root = public_record_root(&bid.public_record());
        self.rent_bids.insert(id.clone(), bid);
        self.push_event(
            RuntimeEventKind::RentBidOpened,
            &id,
            &payload_root,
            Some(lane_id),
            self.config.devnet_height,
        )?;
        Ok(())
    }
    pub fn reserve_sponsor_voucher(&mut self, mut v: SponsorVoucher) -> Result<()> {
        ensure_capacity("vouchers", self.vouchers.len(), self.config.max_vouchers)?;
        require_non_empty("voucher_id", &v.voucher_id)?;
        require_root("voucher_root", &v.voucher_root)?;
        require_root("nullifier_root", &v.nullifier_root)?;
        ensure!(self.lanes.contains_key(&v.lane_id), "unknown voucher lane");
        require_bps("max_fee_bps", v.max_fee_bps)?;
        require_bps("cover_bps", v.cover_bps)?;
        ensure!(
            v.max_fee_bps <= self.config.max_user_fee_bps,
            "voucher fee cap above runtime low-fee target"
        );
        ensure!(
            v.cover_bps <= self.config.sponsor_cover_bps,
            "voucher cover above runtime cap"
        );
        ensure!(
            v.reserved_micro_units > 0 && v.consumed_micro_units <= v.reserved_micro_units,
            "invalid voucher reserve"
        );
        ensure!(
            v.expires_at_height <= v.issued_at_height + self.config.voucher_ttl_blocks,
            "voucher ttl exceeds runtime limit"
        );
        ensure!(
            !self.vouchers.contains_key(&v.voucher_id),
            "voucher already exists"
        );
        self.open_nullifier_fence(
            &v.lane_id,
            &v.voucher_id,
            &v.nullifier_root,
            v.issued_at_height,
        )?;
        v.status = VoucherStatus::Reserved;
        let id = v.voucher_id.clone();
        let lane_id = v.lane_id.clone();
        let payload_root = public_record_root(&v.public_record());
        self.vouchers.insert(id.clone(), v);
        self.push_event(
            RuntimeEventKind::VoucherReserved,
            &id,
            &payload_root,
            Some(lane_id),
            self.config.devnet_height,
        )?;
        Ok(())
    }
    pub fn register_leased_state(&mut self, mut lease: EncryptedStateLease) -> Result<()> {
        ensure_capacity("leases", self.leases.len(), self.config.max_leases)?;
        require_non_empty("lease_id", &lease.lease_id)?;
        require_root("encrypted_state_root", &lease.encrypted_state_root)?;
        require_root("encrypted_index_root", &lease.encrypted_index_root)?;
        require_root(
            "ciphertext_commitment_root",
            &lease.ciphertext_commitment_root,
        )?;
        require_root("view_tag_root", &lease.view_tag_root)?;
        require_root("nullifier_root", &lease.nullifier_root)?;
        ensure!(
            !self.leases.contains_key(&lease.lease_id),
            "lease already exists"
        );
        let lane = self
            .lanes
            .get(&lease.lane_id)
            .ok_or_else(|| "unknown lease lane".to_string())?;
        ensure!(
            lane.status.accepts_new_leases(),
            "lane does not accept new leases"
        );
        ensure!(
            lane.free_bytes() >= lease.size_bytes,
            "lane capacity exhausted"
        );
        let att = self
            .attestations
            .get(&lease.owner_attestation_id)
            .ok_or_else(|| "unknown owner attestation".to_string())?;
        ensure!(att.status.usable(), "owner attestation is not usable");
        ensure!(
            att.lane_id == lease.lane_id && att.contract_commitment == lease.contract_commitment,
            "attestation mismatch"
        );
        let duration = lease
            .lease_expiry_height
            .saturating_sub(lease.lease_start_height);
        ensure!(
            duration >= self.config.min_lease_blocks && duration <= self.config.max_lease_blocks,
            "lease duration outside limits"
        );
        ensure!(
            lease.eviction_eligible_height
                >= lease.lease_expiry_height + self.config.eviction_grace_blocks,
            "eviction eligibility before grace period"
        );
        if let Some(bid_id) = &lease.rent_bid_id {
            let bid = self
                .rent_bids
                .get_mut(bid_id)
                .ok_or_else(|| "unknown rent bid".to_string())?;
            ensure!(
                bid.status.matchable()
                    && bid.remaining_bytes >= lease.size_bytes
                    && bid.max_price_micro_units >= lease.rent_price_micro_units,
                "rent bid cannot cover lease"
            );
            bid.remaining_bytes -= lease.size_bytes;
            bid.matched_lease_ids.insert(lease.lease_id.clone());
            bid.status = if bid.remaining_bytes == 0 {
                BidStatus::Filled
            } else {
                BidStatus::PartiallyFilled
            };
        }
        if let Some(voucher_id) = &lease.sponsor_voucher_id {
            let voucher = self
                .vouchers
                .get_mut(voucher_id)
                .ok_or_else(|| "unknown sponsor voucher".to_string())?;
            ensure!(
                voucher.status.spendable() && voucher.lane_id == lease.lane_id,
                "voucher cannot sponsor lease"
            );
            voucher.lease_id = Some(lease.lease_id.clone());
            voucher.status = VoucherStatus::PartiallyConsumed;
        }
        self.open_nullifier_fence(
            &lease.lane_id,
            &lease.lease_id,
            &lease.nullifier_root,
            lease.lease_start_height,
        )?;
        lease.status = LeaseStatus::Active;
        let lane_id = lease.lane_id.clone();
        let lease_id = lease.lease_id.clone();
        let payload_root = public_record_root(&lease.public_record());
        self.leases.insert(lease_id.clone(), lease);
        self.active_leases.insert(lease_id.clone());
        if let Some(lane) = self.lanes.get_mut(&lane_id) {
            lane.reserved_bytes = lane
                .reserved_bytes
                .saturating_add(self.leases[&lease_id].size_bytes);
            lane.active_leases = lane.active_leases.saturating_add(1);
            lane.updated_at_height = self.leases[&lease_id].lease_start_height;
        }
        self.push_event(
            RuntimeEventKind::LeaseRegistered,
            &lease_id,
            &payload_root,
            Some(lane_id),
            self.config.devnet_height,
        )?;
        Ok(())
    }
    pub fn submit_compact_state_proof(&mut self, mut proof: CompactStateProof) -> Result<()> {
        ensure_capacity("proofs", self.proofs.len(), self.config.max_proofs)?;
        require_root("compact_proof_root", &proof.compact_proof_root)?;
        require_root("state_transition_root", &proof.state_transition_root)?;
        require_root("availability_root", &proof.availability_root)?;
        require_root("nullifier_root", &proof.nullifier_root)?;
        ensure!(
            !self.proofs.contains_key(&proof.proof_id),
            "proof already exists"
        );
        let lease = self
            .leases
            .get(&proof.lease_id)
            .ok_or_else(|| "unknown proof lease".to_string())?;
        ensure!(
            lease.lane_id == proof.lane_id && lease.status.live(),
            "proof lease invalid"
        );
        ensure!(
            proof.expires_at_height <= proof.submitted_at_height + self.config.proof_ttl_blocks,
            "proof ttl exceeds runtime limit"
        );
        ensure!(
            proof.pq_security_bits >= self.config.min_pq_security_bits
                && proof.privacy_set_size >= self.config.min_privacy_set_size,
            "proof security below minimum"
        );
        self.open_nullifier_fence(
            &proof.lane_id,
            &proof.proof_id,
            &proof.nullifier_root,
            proof.submitted_at_height,
        )?;
        proof.status = ProofStatus::Verified;
        proof.verified_at_height = Some(proof.submitted_at_height);
        let id = proof.proof_id.clone();
        let lane_id = proof.lane_id.clone();
        let lease_id = proof.lease_id.clone();
        let payload_root = public_record_root(&proof.public_record());
        self.proofs.insert(id.clone(), proof);
        if let Some(lease) = self.leases.get_mut(&lease_id) {
            lease.last_proof_height = self.proofs[&id].submitted_at_height;
        }
        self.push_event(
            RuntimeEventKind::CompactProofSubmitted,
            &id,
            &payload_root,
            Some(lane_id),
            self.config.devnet_height,
        )?;
        Ok(())
    }
    pub fn renew_state(&mut self, mut batch: RenewalBatch) -> Result<()> {
        ensure_capacity(
            "renewal_batches",
            self.renewal_batches.len(),
            self.config.max_renewal_batches,
        )?;
        require_root("renewal_root", &batch.renewal_root)?;
        require_root("rent_payment_root", &batch.rent_payment_root)?;
        require_root("nullifier_root", &batch.nullifier_root)?;
        ensure!(
            !self.renewal_batches.contains_key(&batch.batch_id),
            "renewal batch already exists"
        );
        let lane = self
            .lanes
            .get(&batch.lane_id)
            .ok_or_else(|| "unknown renewal lane".to_string())?;
        ensure!(
            lane.status.accepts_renewals(),
            "lane does not accept renewals"
        );
        ensure!(
            !batch.lease_ids.is_empty(),
            "renewal batch must include leases"
        );
        ensure!(
            batch.extension_blocks >= self.config.min_lease_blocks
                && batch.extension_blocks <= self.config.max_lease_blocks,
            "renewal extension outside limits"
        );
        let mut total_bytes = 0;
        let mut expected_rent = 0;
        for lease_id in &batch.lease_ids {
            let lease = self
                .leases
                .get(lease_id)
                .ok_or_else(|| format!("unknown lease {lease_id}"))?;
            ensure!(
                lease.lane_id == batch.lane_id && lease.status.live(),
                "renewal lease invalid"
            );
            total_bytes += lease.size_bytes;
            expected_rent += lease.rent_due_for_extension(batch.extension_blocks);
        }
        ensure!(
            batch.total_bytes == total_bytes,
            "renewal total bytes mismatch"
        );
        ensure!(
            batch.total_rent_micro_units >= expected_rent,
            "renewal rent underfunded"
        );
        for proof_id in &batch.proof_ids {
            let proof = self
                .proofs
                .get(proof_id)
                .ok_or_else(|| format!("unknown renewal proof {proof_id}"))?;
            ensure!(
                matches!(proof.status, ProofStatus::Verified | ProofStatus::Settled),
                "renewal proof not verified"
            );
            ensure!(
                batch.lease_ids.contains(&proof.lease_id),
                "renewal proof lease not in batch"
            );
        }
        let sponsor_available: u64 = batch
            .voucher_ids
            .iter()
            .map(|id| {
                self.vouchers
                    .get(id)
                    .map(SponsorVoucher::remaining_micro_units)
                    .unwrap_or(0)
            })
            .sum();
        ensure!(
            batch.sponsor_micro_units <= sponsor_available,
            "renewal sponsor amount exceeds vouchers"
        );
        self.open_nullifier_fence(
            &batch.lane_id,
            &batch.batch_id,
            &batch.nullifier_root,
            batch.proposed_at_height,
        )?;
        for lease_id in &batch.lease_ids {
            if let Some(lease) = self.leases.get_mut(lease_id) {
                lease.status = LeaseStatus::Renewed;
                lease.lease_expiry_height += batch.extension_blocks;
                lease.renewal_deadline_height = lease.lease_expiry_height.saturating_sub(
                    self.config
                        .renewal_window_blocks
                        .min(batch.extension_blocks),
                );
                lease.eviction_eligible_height =
                    lease.lease_expiry_height + self.config.eviction_grace_blocks;
                lease.rent_paid_micro_units += lease.rent_due_for_extension(batch.extension_blocks);
                lease.renewal_count += 1;
            }
        }
        let mut remaining = batch.sponsor_micro_units;
        for id in &batch.voucher_ids {
            if remaining == 0 {
                break;
            }
            if let Some(v) = self.vouchers.get_mut(id) {
                let spend = v.remaining_micro_units().min(remaining);
                v.consumed_micro_units += spend;
                remaining -= spend;
                v.status = if v.remaining_micro_units() == 0 {
                    VoucherStatus::Consumed
                } else {
                    VoucherStatus::PartiallyConsumed
                };
            }
        }
        for id in &batch.proof_ids {
            if let Some(p) = self.proofs.get_mut(id) {
                p.status = ProofStatus::Settled;
            }
        }
        batch.status = RenewalBatchStatus::Settled;
        batch.settled_at_height = Some(batch.proposed_at_height);
        let id = batch.batch_id.clone();
        let lane_id = batch.lane_id.clone();
        let payload_root = public_record_root(&batch.public_record());
        self.renewal_batches.insert(id.clone(), batch);
        self.push_event(
            RuntimeEventKind::RenewalBatchSettled,
            &id,
            &payload_root,
            Some(lane_id),
            self.config.devnet_height,
        )?;
        Ok(())
    }
    pub fn publish_eviction_receipt(&mut self, mut receipt: EvictionReceipt) -> Result<()> {
        ensure_capacity(
            "eviction_receipts",
            self.eviction_receipts.len(),
            self.config.max_eviction_receipts,
        )?;
        require_root("eviction_root", &receipt.eviction_root)?;
        require_root("final_state_root", &receipt.final_state_root)?;
        require_root(
            "ciphertext_tombstone_root",
            &receipt.ciphertext_tombstone_root,
        )?;
        ensure!(
            !self.eviction_receipts.contains_key(&receipt.receipt_id),
            "eviction receipt already exists"
        );
        let lane = self
            .lanes
            .get(&receipt.lane_id)
            .ok_or_else(|| "unknown eviction lane".to_string())?;
        ensure!(
            lane.status.accepts_evictions(),
            "lane does not accept evictions"
        );
        let lease = self
            .leases
            .get(&receipt.lease_id)
            .ok_or_else(|| "unknown eviction lease".to_string())?;
        ensure!(
            lease.lane_id == receipt.lane_id && lease.status.evictable(),
            "lease is not evictable"
        );
        ensure!(
            receipt.proposed_at_height >= lease.eviction_eligible_height,
            "eviction before eligibility height"
        );
        ensure!(
            receipt.grace_ends_at_height
                >= receipt.proposed_at_height + self.config.challenge_window_blocks,
            "eviction challenge window too short"
        );
        ensure!(
            receipt.keeper_bond_units >= self.config.min_keeper_bond_units,
            "keeper bond below minimum"
        );
        receipt.status = EvictionStatus::ReceiptPublished;
        let id = receipt.receipt_id.clone();
        let lane_id = receipt.lane_id.clone();
        let lease_id = receipt.lease_id.clone();
        let payload_root = public_record_root(&receipt.public_record());
        self.eviction_receipts.insert(id.clone(), receipt);
        if let Some(lease) = self.leases.get_mut(&lease_id) {
            lease.status = LeaseStatus::EvictionPending;
        }
        self.push_event(
            RuntimeEventKind::EvictionReceiptPublished,
            &id,
            &payload_root,
            Some(lane_id),
            self.config.devnet_height,
        )?;
        Ok(())
    }
    pub fn finalize_eviction(&mut self, receipt_id: &str, height: u64) -> Result<()> {
        let receipt = self
            .eviction_receipts
            .get_mut(receipt_id)
            .ok_or_else(|| "unknown eviction receipt".to_string())?;
        ensure!(
            matches!(
                receipt.status,
                EvictionStatus::ReceiptPublished | EvictionStatus::GraceOpen
            ),
            "receipt cannot be finalized"
        );
        ensure!(
            height >= receipt.grace_ends_at_height,
            "eviction challenge window still open"
        );
        ensure!(
            !self.challenged_receipts.contains(receipt_id),
            "challenged receipt cannot finalize"
        );
        receipt.status = EvictionStatus::Finalized;
        receipt.finalized_at_height = Some(height);
        if let Some(lease) = self.leases.get_mut(&receipt.lease_id) {
            lease.status = LeaseStatus::Evicted;
            self.active_leases.remove(&lease.lease_id);
            self.evicted_leases.insert(lease.lease_id.clone());
            if let Some(lane) = self.lanes.get_mut(&lease.lane_id) {
                lane.reserved_bytes = lane.reserved_bytes.saturating_sub(lease.size_bytes);
                lane.active_leases = lane.active_leases.saturating_sub(1);
                lane.updated_at_height = height;
            }
        }
        Ok(())
    }
    pub fn challenge_eviction(&mut self, mut c: EvictionChallenge) -> Result<()> {
        ensure_capacity(
            "challenges",
            self.challenges.len(),
            self.config.max_challenges,
        )?;
        require_root("evidence_root", &c.evidence_root)?;
        require_root("counter_proof_root", &c.counter_proof_root)?;
        require_root("nullifier_root", &c.nullifier_root)?;
        ensure!(
            !self.challenges.contains_key(&c.challenge_id),
            "challenge already exists"
        );
        let (lane_id, receipt_id) = {
            let receipt = self
                .eviction_receipts
                .get_mut(&c.receipt_id)
                .ok_or_else(|| "unknown challenge receipt".to_string())?;
            ensure!(receipt.lease_id == c.lease_id, "challenge lease mismatch");
            ensure!(
                matches!(
                    receipt.status,
                    EvictionStatus::ReceiptPublished | EvictionStatus::GraceOpen
                ),
                "receipt is not challengeable"
            );
            ensure!(
                c.opened_at_height <= receipt.grace_ends_at_height,
                "challenge after grace window"
            );
            receipt.status = EvictionStatus::Challenged;
            (receipt.lane_id.clone(), receipt.receipt_id.clone())
        };
        self.open_nullifier_fence(
            &lane_id,
            &c.challenge_id,
            &c.nullifier_root,
            c.opened_at_height,
        )?;
        if let Some(lease) = self.leases.get_mut(&c.lease_id) {
            lease.status = LeaseStatus::Challenged;
        }
        c.status = ChallengeStatus::EvidenceLinked;
        let id = c.challenge_id.clone();
        let payload_root = public_record_root(&c.public_record());
        self.challenged_receipts.insert(receipt_id);
        self.challenges.insert(id.clone(), c);
        self.push_event(
            RuntimeEventKind::EvictionChallenged,
            &id,
            &payload_root,
            Some(lane_id),
            self.config.devnet_height,
        )?;
        Ok(())
    }
    pub fn slash_faulty_keeper(&mut self, mut e: SlashingEvidence) -> Result<()> {
        ensure_capacity(
            "slashing_evidence",
            self.slashing_evidence.len(),
            self.config.max_slashing_evidence,
        )?;
        require_root("evidence_root", &e.evidence_root)?;
        require_root("fraud_proof_root", &e.fraud_proof_root)?;
        ensure!(self.lanes.contains_key(&e.lane_id), "unknown slashing lane");
        ensure!(
            !self.slashing_evidence.contains_key(&e.evidence_id),
            "slashing evidence already exists"
        );
        ensure!(
            e.slash_amount_units
                >= self
                    .config
                    .min_keeper_bond_units
                    .saturating_mul(e.fault_kind.slash_weight_bps())
                    / MAX_BPS,
            "slash amount below weighted minimum"
        );
        if let Some(receipt_id) = &e.related_receipt_id {
            let receipt = self
                .eviction_receipts
                .get_mut(receipt_id)
                .ok_or_else(|| "unknown slashing receipt".to_string())?;
            receipt.status = EvictionStatus::Slashed;
            if let Some(lease) = self.leases.get_mut(&receipt.lease_id) {
                lease.status = LeaseStatus::Restored;
                self.active_leases.insert(lease.lease_id.clone());
                self.evicted_leases.remove(&lease.lease_id);
            }
        }
        if let Some(challenge_id) = &e.related_challenge_id {
            let challenge = self
                .challenges
                .get_mut(challenge_id)
                .ok_or_else(|| "unknown slashing challenge".to_string())?;
            challenge.status = ChallengeStatus::Accepted;
            challenge.resolved_at_height = Some(e.submitted_at_height);
        }
        e.status = SlashingStatus::KeeperSlashed;
        e.resolved_at_height = Some(e.submitted_at_height);
        let id = e.evidence_id.clone();
        let lane_id = e.lane_id.clone();
        let payload_root = public_record_root(&e.public_record());
        self.slashing_evidence.insert(id.clone(), e);
        self.push_event(
            RuntimeEventKind::KeeperSlashed,
            &id,
            &payload_root,
            Some(lane_id),
            self.config.devnet_height,
        )?;
        Ok(())
    }
    pub fn public_record_for_subject(&self, subject_id: &str) -> Option<Value> {
        self.lanes
            .get(subject_id)
            .map(StateLane::public_record)
            .or_else(|| {
                self.leases
                    .get(subject_id)
                    .map(EncryptedStateLease::public_record)
            })
            .or_else(|| {
                self.attestations
                    .get(subject_id)
                    .map(PqOwnerAttestation::public_record)
            })
            .or_else(|| {
                self.rent_bids
                    .get(subject_id)
                    .map(StorageRentBid::public_record)
            })
            .or_else(|| {
                self.vouchers
                    .get(subject_id)
                    .map(SponsorVoucher::public_record)
            })
            .or_else(|| {
                self.proofs
                    .get(subject_id)
                    .map(CompactStateProof::public_record)
            })
            .or_else(|| {
                self.renewal_batches
                    .get(subject_id)
                    .map(RenewalBatch::public_record)
            })
            .or_else(|| {
                self.eviction_receipts
                    .get(subject_id)
                    .map(EvictionReceipt::public_record)
            })
            .or_else(|| {
                self.challenges
                    .get(subject_id)
                    .map(EvictionChallenge::public_record)
            })
            .or_else(|| {
                self.slashing_evidence
                    .get(subject_id)
                    .map(SlashingEvidence::public_record)
            })
            .or_else(|| {
                self.fences
                    .get(subject_id)
                    .map(NullifierFence::public_record)
            })
            .or_else(|| self.events.get(subject_id).map(RuntimeEvent::public_record))
    }
    pub fn publish_runtime_root_event(&mut self, height: u64) -> Result<String> {
        let root = self.state_root();
        self.push_event(
            RuntimeEventKind::RuntimeRootPublished,
            &root,
            &root,
            None,
            height,
        )
    }
    fn open_nullifier_fence(
        &mut self,
        lane_id: &str,
        subject_id: &str,
        nullifier_root: &str,
        height: u64,
    ) -> Result<()> {
        ensure_capacity("fences", self.fences.len(), self.config.max_fences)?;
        require_root("nullifier_root", nullifier_root)?;
        let id = nullifier_fence_id(lane_id, subject_id, nullifier_root, height);
        if let Some(f) = self.fences.get(&id) {
            ensure!(
                f.status != FenceStatus::Spent,
                "nullifier fence already spent"
            );
            return Ok(());
        }
        let fence = NullifierFence {
            fence_id: id.clone(),
            lane_id: lane_id.to_string(),
            subject_id: subject_id.to_string(),
            status: FenceStatus::Open,
            nullifier_root: nullifier_root.to_string(),
            privacy_epoch: height,
            opened_at_height: height,
            spent_at_height: None,
        };
        let payload_root = public_record_root(&fence.public_record());
        self.fences.insert(id.clone(), fence);
        self.push_event(
            RuntimeEventKind::NullifierFenced,
            &id,
            &payload_root,
            Some(lane_id.to_string()),
            height,
        )?;
        Ok(())
    }
    fn push_event(
        &mut self,
        kind: RuntimeEventKind,
        subject_id: &str,
        payload_root: &str,
        lane_id: Option<String>,
        height: u64,
    ) -> Result<String> {
        ensure_capacity("events", self.events.len(), self.config.max_events)?;
        let sequence = self.events.len() as u64;
        let id = runtime_event_id(kind, subject_id, payload_root, height, sequence);
        let event = RuntimeEvent {
            event_id: id.clone(),
            kind,
            subject_id: subject_id.to_string(),
            payload_root: payload_root.to_string(),
            lane_id,
            height,
            sequence,
        };
        self.events.insert(id.clone(), event);
        Ok(id)
    }
}
pub fn public_record_root(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-STATE-EXPIRY-RENT-MARKET-PUBLIC-RECORD-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}
pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-STATE-EXPIRY-RENT-MARKET-STATE-ROOT-FROM-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}
pub fn deterministic_lane_id(
    label: &str,
    lane_kind: LaneKind,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-STATE-EXPIRY-RENT-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(lane_kind.as_str()),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}
pub fn owner_attestation_id(
    lane_id: &str,
    owner_commitment: &str,
    kind: AttestationKind,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-STATE-EXPIRY-RENT-OWNER-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(owner_commitment),
            HashPart::Str(kind.as_str()),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}
pub fn encrypted_state_lease_id(
    lane_id: &str,
    contract_commitment: &str,
    encrypted_state_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-STATE-EXPIRY-RENT-LEASE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(contract_commitment),
            HashPart::Str(encrypted_state_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}
pub fn rent_bid_id(
    lane_id: &str,
    bidder_commitment: &str,
    bid_nullifier_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-STATE-EXPIRY-RENT-BID-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(bidder_commitment),
            HashPart::Str(bid_nullifier_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}
pub fn sponsor_voucher_id(
    sponsor_commitment: &str,
    lane_id: &str,
    beneficiary_commitment: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-STATE-EXPIRY-RENT-SPONSOR-VOUCHER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(lane_id),
            HashPart::Str(beneficiary_commitment),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}
pub fn compact_state_proof_id(
    lease_id: &str,
    state_transition_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-STATE-EXPIRY-RENT-COMPACT-PROOF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lease_id),
            HashPart::Str(state_transition_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}
pub fn renewal_batch_id(lane_id: &str, renewal_root: &str, height: u64, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-STATE-EXPIRY-RENT-RENEWAL-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(renewal_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}
pub fn eviction_receipt_id(
    lease_id: &str,
    eviction_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-STATE-EXPIRY-RENT-EVICTION-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lease_id),
            HashPart::Str(eviction_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}
pub fn eviction_challenge_id(
    receipt_id: &str,
    challenger_commitment: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-STATE-EXPIRY-RENT-EVICTION-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(receipt_id),
            HashPart::Str(challenger_commitment),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}
pub fn slashing_evidence_id(
    target_commitment: &str,
    fault_kind: FaultKind,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-STATE-EXPIRY-RENT-SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(target_commitment),
            HashPart::Str(fault_kind.as_str()),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}
pub fn nullifier_fence_id(
    lane_id: &str,
    subject_id: &str,
    nullifier_root: &str,
    privacy_epoch: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-STATE-EXPIRY-RENT-NULLIFIER-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(subject_id),
            HashPart::Str(nullifier_root),
            HashPart::U64(privacy_epoch),
        ],
        32,
    )
}
pub fn runtime_event_id(
    kind: RuntimeEventKind,
    subject_id: &str,
    payload_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-STATE-EXPIRY-RENT-RUNTIME-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}
fn map_root<T: Serialize>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| json!({"id": key, "record": value}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}
fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| Value::String(value.clone()))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}
fn require_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{field} must not be empty"))
    } else {
        Ok(())
    }
}
fn require_root(field: &str, value: &str) -> Result<()> {
    require_non_empty(field, value)?;
    if value.len() < 32 {
        return Err(format!("{field} must be a domain-separated root"));
    }
    Ok(())
}
fn require_bps(field: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{field} cannot exceed {MAX_BPS}"))
    } else {
        Ok(())
    }
}
fn require_positive_u64(field: &str, value: u64) -> Result<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}
fn require_positive_usize(field: &str, value: usize) -> Result<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}
fn ensure_capacity(name: &str, current: usize, max: usize) -> Result<()> {
    if current >= max {
        Err(format!("{name} capacity exhausted"))
    } else {
        Ok(())
    }
}
