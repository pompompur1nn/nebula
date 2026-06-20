use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialTokenLaunchpadRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-token-launchpad-runtime-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s-token-launchpad-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_NOTE_SCHEME: &str =
    "private-l2-shielded-sale-note-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_NULLIFIER_SCHEME: &str =
    "private-l2-shielded-sale-nullifier-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_VESTING_SCHEME: &str =
    "private-l2-confidential-linear-vesting-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_SPONSOR_SCHEME: &str =
    "roots-only-low-fee-launchpad-sponsor-reservation-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_SETTLEMENT_SCHEME: &str =
    "private-l2-confidential-token-launch-settlement-receipt-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEVNET_HEIGHT: u64 = 512_000;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_MONERO_NETWORK: &str =
    "monero-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_L2_NETWORK: &str =
    "nebula-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_FEE_ASSET_ID: &str =
    "piconero-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_COLLATERAL_ASSET_ID: &str =
    "wxmr-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_LOW_FEE_LANE: &str =
    "private-l2-confidential-token-launchpad";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_MAX_LAUNCHES: usize = 262_144;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_MAX_SPONSOR_RESERVATIONS: usize =
    1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_MAX_SALE_NOTES: usize = 4_194_304;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_MAX_VESTING_BATCHES: usize =
    1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_MAX_PQ_ATTESTATIONS: usize =
    1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_MAX_SETTLEMENT_RECEIPTS: usize =
    524_288;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 =
    16_384;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 =
    262_144;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_MAX_SPONSOR_FEE_BPS: u64 = 8;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_SALE_NOTE_TTL_BLOCKS: u64 = 36;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 72;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 24;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchKind {
    PrivateSale,
    Community,
    LiquidityBootstrap,
    FairAirdrop,
    GovernanceDistribution,
    DefiVaultShare,
    ContractBound,
}

impl LaunchKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateSale => "private_sale",
            Self::Community => "community",
            Self::LiquidityBootstrap => "liquidity_bootstrap",
            Self::FairAirdrop => "fair_airdrop",
            Self::GovernanceDistribution => "governance_distribution",
            Self::DefiVaultShare => "defi_vault_share",
            Self::ContractBound => "contract_bound",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchStatus {
    Registered,
    SponsorReserved,
    SaleOpen,
    Vesting,
    SettlementReady,
    Settled,
    Paused,
    Cancelled,
    Failed,
}

impl LaunchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::SponsorReserved => "sponsor_reserved",
            Self::SaleOpen => "sale_open",
            Self::Vesting => "vesting",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Paused => "paused",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        }
    }

    pub fn accepts_sale_notes(self) -> bool {
        matches!(
            self,
            Self::Registered | Self::SponsorReserved | Self::SaleOpen
        )
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Cancelled | Self::Failed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorReservationStatus {
    Reserved,
    Consumed,
    Released,
    Expired,
    Slashed,
}

impl SponsorReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SaleNoteStatus {
    Pending,
    PqAuthorized,
    SponsorCovered,
    VestingQueued,
    Unlocked,
    Settled,
    Rejected,
    Expired,
}

impl SaleNoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::PqAuthorized => "pq_authorized",
            Self::SponsorCovered => "sponsor_covered",
            Self::VestingQueued => "vesting_queued",
            Self::Unlocked => "unlocked",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn vestable(self) -> bool {
        matches!(
            self,
            Self::Pending | Self::PqAuthorized | Self::SponsorCovered
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAttestationKind {
    IssuerAuthorization,
    InvestorCredential,
    ContractBytecode,
    DeFiHook,
    SettlementBatch,
}

impl PqAttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IssuerAuthorization => "issuer_authorization",
            Self::InvestorCredential => "investor_credential",
            Self::ContractBytecode => "contract_bytecode",
            Self::DeFiHook => "defi_hook",
            Self::SettlementBatch => "settlement_batch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Accepted,
    Watch,
    Quarantined,
    Rejected,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Watch => "watch",
            Self::Quarantined => "quarantined",
            Self::Rejected => "rejected",
        }
    }

    pub fn allows_progress(self) -> bool {
        matches!(self, Self::Accepted | Self::Watch)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VestingBatchStatus {
    Queued,
    UnlockReady,
    Unlocked,
    Settled,
    Disputed,
    Expired,
}

impl VestingBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::UnlockReady => "unlock_ready",
            Self::Unlocked => "unlocked",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub collateral_asset_id: String,
    pub low_fee_lane: String,
    pub hash_suite: String,
    pub pq_authorization_suite: String,
    pub note_scheme: String,
    pub nullifier_scheme: String,
    pub vesting_scheme: String,
    pub sponsor_scheme: String,
    pub settlement_scheme: String,
    pub max_launches: usize,
    pub max_sponsor_reservations: usize,
    pub max_sale_notes: usize,
    pub max_vesting_batches: usize,
    pub max_pq_attestations: usize,
    pub max_settlement_receipts: usize,
    pub min_privacy_set_size: u64,
    pub min_batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_sponsor_fee_bps: u64,
    pub sale_note_ttl_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub require_low_fee_sponsor: bool,
    pub require_pq_attestation: bool,
    pub require_defi_hook_root: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            monero_network: PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_MONERO_NETWORK
                .to_string(),
            l2_network: PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_L2_NETWORK
                .to_string(),
            fee_asset_id: PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_FEE_ASSET_ID
                .to_string(),
            collateral_asset_id:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_COLLATERAL_ASSET_ID
                    .to_string(),
            low_fee_lane: PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_LOW_FEE_LANE
                .to_string(),
            hash_suite: PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_HASH_SUITE.to_string(),
            pq_authorization_suite: PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_PQ_AUTH_SUITE
                .to_string(),
            note_scheme: PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_NOTE_SCHEME.to_string(),
            nullifier_scheme: PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_NULLIFIER_SCHEME
                .to_string(),
            vesting_scheme: PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_VESTING_SCHEME
                .to_string(),
            sponsor_scheme: PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_SPONSOR_SCHEME
                .to_string(),
            settlement_scheme: PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_SETTLEMENT_SCHEME
                .to_string(),
            max_launches: PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_MAX_LAUNCHES,
            max_sponsor_reservations:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_MAX_SPONSOR_RESERVATIONS,
            max_sale_notes: PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_MAX_SALE_NOTES,
            max_vesting_batches:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_MAX_VESTING_BATCHES,
            max_pq_attestations:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_MAX_PQ_ATTESTATIONS,
            max_settlement_receipts:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_MAX_SETTLEMENT_RECEIPTS,
            min_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_batch_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            max_sponsor_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_MAX_SPONSOR_FEE_BPS,
            sale_note_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_SALE_NOTE_TTL_BLOCKS,
            sponsor_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_SPONSOR_TTL_BLOCKS,
            settlement_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            require_low_fee_sponsor: true,
            require_pq_attestation: true,
            require_defi_hook_root: true,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub launches: u64,
    pub sponsor_reservations: u64,
    pub sale_notes: u64,
    pub vesting_batches: u64,
    pub pq_attestations: u64,
    pub settlement_receipts: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub launch_root: String,
    pub sponsor_reservation_root: String,
    pub sale_note_root: String,
    pub nullifier_root: String,
    pub vesting_root: String,
    pub pq_attestation_root: String,
    pub settlement_receipt_root: String,
}

impl Roots {
    pub fn state_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-TOKEN-LAUNCHPAD-ROOTS",
            &json!(self),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterShieldedLaunchRequest {
    pub issuer_commitment: String,
    pub launch_kind: LaunchKind,
    pub token_metadata_root: String,
    pub confidential_supply_root: String,
    pub sale_policy_root: String,
    pub vesting_policy_root: String,
    pub defi_hook_root: String,
    pub contract_init_root: String,
    pub pq_authorization_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub registered_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchRecord {
    pub launch_id: String,
    pub issuer_commitment: String,
    pub launch_kind: LaunchKind,
    pub status: LaunchStatus,
    pub token_metadata_root: String,
    pub confidential_supply_root: String,
    pub sale_policy_root: String,
    pub vesting_policy_root: String,
    pub defi_hook_root: String,
    pub contract_init_root: String,
    pub pq_authorization_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub registered_at_height: u64,
    pub updated_at_height: u64,
}

impl LaunchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "launch_id": self.launch_id,
            "issuer_commitment": self.issuer_commitment,
            "launch_kind": self.launch_kind.as_str(),
            "status": self.status.as_str(),
            "token_metadata_root": self.token_metadata_root,
            "confidential_supply_root": self.confidential_supply_root,
            "sale_policy_root": self.sale_policy_root,
            "vesting_policy_root": self.vesting_policy_root,
            "defi_hook_root": self.defi_hook_root,
            "contract_init_root": self.contract_init_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "registered_at_height": self.registered_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveSponsorCapacityRequest {
    pub launch_id: String,
    pub sponsor_commitment: String,
    pub capacity_commitment_root: String,
    pub fee_quote_root: String,
    pub max_sponsor_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_authorization_root: String,
    pub reserved_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorReservationRecord {
    pub reservation_id: String,
    pub launch_id: String,
    pub sponsor_commitment: String,
    pub capacity_commitment_root: String,
    pub fee_quote_root: String,
    pub max_sponsor_fee_bps: u64,
    pub status: SponsorReservationStatus,
    pub privacy_set_size: u64,
    pub pq_authorization_root: String,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl SponsorReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "launch_id": self.launch_id,
            "sponsor_commitment": self.sponsor_commitment,
            "capacity_commitment_root": self.capacity_commitment_root,
            "fee_quote_root": self.fee_quote_root,
            "max_sponsor_fee_bps": self.max_sponsor_fee_bps,
            "status": self.status.as_str(),
            "privacy_set_size": self.privacy_set_size,
            "pq_authorization_root": self.pq_authorization_root,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptPrivateSaleNoteRequest {
    pub launch_id: String,
    pub buyer_commitment: String,
    pub sale_note_root: String,
    pub amount_commitment_root: String,
    pub payment_commitment_root: String,
    pub credential_root: String,
    pub nullifier: String,
    pub sponsor_reservation_id: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub submitted_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateSaleNoteRecord {
    pub sale_note_id: String,
    pub launch_id: String,
    pub buyer_commitment: String,
    pub sale_note_root: String,
    pub amount_commitment_root: String,
    pub payment_commitment_root: String,
    pub credential_root: String,
    pub nullifier: String,
    pub sponsor_reservation_id: String,
    pub status: SaleNoteStatus,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivateSaleNoteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "sale_note_id": self.sale_note_id,
            "launch_id": self.launch_id,
            "buyer_commitment": self.buyer_commitment,
            "sale_note_root": self.sale_note_root,
            "amount_commitment_root": self.amount_commitment_root,
            "payment_commitment_root": self.payment_commitment_root,
            "credential_root": self.credential_root,
            "nullifier": self.nullifier,
            "sponsor_reservation_id": self.sponsor_reservation_id,
            "status": self.status.as_str(),
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueVestingUnlockBatchRequest {
    pub launch_id: String,
    pub sale_note_ids: Vec<String>,
    pub unlock_commitment_root: String,
    pub vesting_witness_root: String,
    pub recursive_proof_root: String,
    pub privacy_set_size: u64,
    pub queued_at_height: u64,
    pub unlock_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VestingUnlockBatchRecord {
    pub vesting_batch_id: String,
    pub launch_id: String,
    pub sale_note_ids: Vec<String>,
    pub unlock_commitment_root: String,
    pub vesting_witness_root: String,
    pub recursive_proof_root: String,
    pub status: VestingBatchStatus,
    pub privacy_set_size: u64,
    pub queued_at_height: u64,
    pub unlock_at_height: u64,
}

impl VestingUnlockBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "vesting_batch_id": self.vesting_batch_id,
            "launch_id": self.launch_id,
            "sale_note_ids": self.sale_note_ids,
            "unlock_commitment_root": self.unlock_commitment_root,
            "vesting_witness_root": self.vesting_witness_root,
            "recursive_proof_root": self.recursive_proof_root,
            "status": self.status.as_str(),
            "privacy_set_size": self.privacy_set_size,
            "queued_at_height": self.queued_at_height,
            "unlock_at_height": self.unlock_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishPqAttestationRequest {
    pub launch_id: String,
    pub subject_id: String,
    pub kind: PqAttestationKind,
    pub attestor_commitment: String,
    pub attestation_root: String,
    pub signature_root: String,
    pub verdict: AttestationVerdict,
    pub pq_security_bits: u16,
    pub attested_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAttestationRecord {
    pub attestation_id: String,
    pub launch_id: String,
    pub subject_id: String,
    pub kind: PqAttestationKind,
    pub attestor_commitment: String,
    pub attestation_root: String,
    pub signature_root: String,
    pub verdict: AttestationVerdict,
    pub pq_security_bits: u16,
    pub attested_at_height: u64,
}

impl PqAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "launch_id": self.launch_id,
            "subject_id": self.subject_id,
            "kind": self.kind.as_str(),
            "attestor_commitment": self.attestor_commitment,
            "attestation_root": self.attestation_root,
            "signature_root": self.signature_root,
            "verdict": self.verdict.as_str(),
            "pq_security_bits": self.pq_security_bits,
            "attested_at_height": self.attested_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueSettlementReceiptRequest {
    pub launch_id: String,
    pub vesting_batch_id: String,
    pub settlement_tx_root: String,
    pub token_state_root_after: String,
    pub liquidity_pool_root_after: String,
    pub settlement_proof_root: String,
    pub pq_attestation_id: String,
    pub settled_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceiptRecord {
    pub settlement_receipt_id: String,
    pub launch_id: String,
    pub vesting_batch_id: String,
    pub settlement_tx_root: String,
    pub token_state_root_after: String,
    pub liquidity_pool_root_after: String,
    pub settlement_proof_root: String,
    pub pq_attestation_id: String,
    pub settled_at_height: u64,
    pub expires_at_height: u64,
}

impl SettlementReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_receipt_id": self.settlement_receipt_id,
            "launch_id": self.launch_id,
            "vesting_batch_id": self.vesting_batch_id,
            "settlement_tx_root": self.settlement_tx_root,
            "token_state_root_after": self.token_state_root_after,
            "liquidity_pool_root_after": self.liquidity_pool_root_after,
            "settlement_proof_root": self.settlement_proof_root,
            "pq_attestation_id": self.pq_attestation_id,
            "settled_at_height": self.settled_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Runtime {
    pub config: Config,
    pub counters: Counters,
    pub launches: BTreeMap<String, LaunchRecord>,
    pub sponsor_reservations: BTreeMap<String, SponsorReservationRecord>,
    pub sale_notes: BTreeMap<String, PrivateSaleNoteRecord>,
    pub vesting_batches: BTreeMap<String, VestingUnlockBatchRecord>,
    pub pq_attestations: BTreeMap<String, PqAttestationRecord>,
    pub settlement_receipts: BTreeMap<String, SettlementReceiptRecord>,
    pub nullifiers: BTreeSet<String>,
}

impl Default for Runtime {
    fn default() -> Self {
        Self::devnet()
    }
}

impl Runtime {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            counters: Counters::default(),
            launches: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            sale_notes: BTreeMap::new(),
            vesting_batches: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
        }
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet())
    }

    pub fn register_shielded_token_launch(
        &mut self,
        request: RegisterShieldedLaunchRequest,
    ) -> PrivateL2ConfidentialTokenLaunchpadRuntimeResult<LaunchRecord> {
        if self.launches.len() >= self.config.max_launches {
            return Err("launch registry capacity exhausted".to_string());
        }
        require_non_empty("issuer commitment", &request.issuer_commitment)?;
        require_non_empty("token metadata root", &request.token_metadata_root)?;
        require_non_empty(
            "confidential supply root",
            &request.confidential_supply_root,
        )?;
        require_non_empty("sale policy root", &request.sale_policy_root)?;
        require_non_empty("vesting policy root", &request.vesting_policy_root)?;
        require_non_empty("contract init root", &request.contract_init_root)?;
        require_non_empty("PQ authorization root", &request.pq_authorization_root)?;
        if self.config.require_defi_hook_root {
            require_non_empty("DeFi hook root", &request.defi_hook_root)?;
        }
        require_privacy_and_pq(
            request.privacy_set_size,
            request.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        if request.max_user_fee_bps > self.config.max_user_fee_bps {
            return Err("launch user fee cap exceeds configured low-fee bound".to_string());
        }

        self.counters.launches += 1;
        let launch_id = launch_id(&request, self.counters.launches);
        let record = LaunchRecord {
            launch_id: launch_id.clone(),
            issuer_commitment: request.issuer_commitment,
            launch_kind: request.launch_kind,
            status: LaunchStatus::Registered,
            token_metadata_root: request.token_metadata_root,
            confidential_supply_root: request.confidential_supply_root,
            sale_policy_root: request.sale_policy_root,
            vesting_policy_root: request.vesting_policy_root,
            defi_hook_root: request.defi_hook_root,
            contract_init_root: request.contract_init_root,
            pq_authorization_root: request.pq_authorization_root,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            max_user_fee_bps: request.max_user_fee_bps,
            registered_at_height: request.registered_at_height,
            updated_at_height: request.registered_at_height,
        };
        self.launches.insert(launch_id, record.clone());
        Ok(record)
    }

    pub fn reserve_low_fee_sponsor_capacity(
        &mut self,
        request: ReserveSponsorCapacityRequest,
    ) -> PrivateL2ConfidentialTokenLaunchpadRuntimeResult<SponsorReservationRecord> {
        if self.sponsor_reservations.len() >= self.config.max_sponsor_reservations {
            return Err("sponsor reservation capacity exhausted".to_string());
        }
        let launch = self
            .launches
            .get_mut(&request.launch_id)
            .ok_or_else(|| "launch not found for sponsor reservation".to_string())?;
        if launch.status.terminal() {
            return Err("terminal launch cannot reserve sponsor capacity".to_string());
        }
        require_non_empty("sponsor commitment", &request.sponsor_commitment)?;
        require_non_empty(
            "capacity commitment root",
            &request.capacity_commitment_root,
        )?;
        require_non_empty("fee quote root", &request.fee_quote_root)?;
        require_non_empty("PQ authorization root", &request.pq_authorization_root)?;
        if request.max_sponsor_fee_bps > self.config.max_sponsor_fee_bps {
            return Err("sponsor fee cap exceeds configured low-fee bound".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("sponsor reservation privacy set below configured threshold".to_string());
        }

        self.counters.sponsor_reservations += 1;
        let reservation_id = sponsor_reservation_id(&request, self.counters.sponsor_reservations);
        let record = SponsorReservationRecord {
            reservation_id: reservation_id.clone(),
            launch_id: request.launch_id,
            sponsor_commitment: request.sponsor_commitment,
            capacity_commitment_root: request.capacity_commitment_root,
            fee_quote_root: request.fee_quote_root,
            max_sponsor_fee_bps: request.max_sponsor_fee_bps,
            status: SponsorReservationStatus::Reserved,
            privacy_set_size: request.privacy_set_size,
            pq_authorization_root: request.pq_authorization_root,
            reserved_at_height: request.reserved_at_height,
            expires_at_height: request
                .reserved_at_height
                .saturating_add(self.config.sponsor_ttl_blocks),
        };
        launch.status = LaunchStatus::SponsorReserved;
        launch.updated_at_height = request.reserved_at_height;
        self.sponsor_reservations
            .insert(reservation_id, record.clone());
        Ok(record)
    }

    pub fn accept_private_sale_note(
        &mut self,
        request: AcceptPrivateSaleNoteRequest,
    ) -> PrivateL2ConfidentialTokenLaunchpadRuntimeResult<PrivateSaleNoteRecord> {
        if self.sale_notes.len() >= self.config.max_sale_notes {
            return Err("private sale note capacity exhausted".to_string());
        }
        if self.nullifiers.contains(&request.nullifier) {
            return Err("private sale note nullifier already spent".to_string());
        }
        let launch = self
            .launches
            .get_mut(&request.launch_id)
            .ok_or_else(|| "launch not found for private sale note".to_string())?;
        if !launch.status.accepts_sale_notes() {
            return Err("launch is not accepting private sale notes".to_string());
        }
        require_non_empty("buyer commitment", &request.buyer_commitment)?;
        require_non_empty("sale note root", &request.sale_note_root)?;
        require_non_empty("amount commitment root", &request.amount_commitment_root)?;
        require_non_empty("payment commitment root", &request.payment_commitment_root)?;
        require_non_empty("credential root", &request.credential_root)?;
        require_non_empty("note nullifier", &request.nullifier)?;
        if self.config.require_low_fee_sponsor {
            let reservation = self
                .sponsor_reservations
                .get_mut(&request.sponsor_reservation_id)
                .ok_or_else(|| "required sponsor reservation not found".to_string())?;
            if reservation.launch_id != request.launch_id {
                return Err("sponsor reservation belongs to a different launch".to_string());
            }
            if reservation.status != SponsorReservationStatus::Reserved {
                return Err("sponsor reservation is not available".to_string());
            }
            if reservation.expires_at_height <= request.submitted_at_height {
                reservation.status = SponsorReservationStatus::Expired;
                return Err("sponsor reservation expired before sale note".to_string());
            }
            reservation.status = SponsorReservationStatus::Consumed;
        }
        if request.max_fee_bps > launch.max_user_fee_bps {
            return Err("private sale note fee cap exceeds launch limit".to_string());
        }
        require_privacy_and_pq(
            request.privacy_set_size,
            request.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;

        self.counters.sale_notes += 1;
        let sale_note_id = private_sale_note_id(&request, self.counters.sale_notes);
        let status = if self.config.require_low_fee_sponsor {
            SaleNoteStatus::SponsorCovered
        } else {
            SaleNoteStatus::Pending
        };
        let record = PrivateSaleNoteRecord {
            sale_note_id: sale_note_id.clone(),
            launch_id: request.launch_id,
            buyer_commitment: request.buyer_commitment,
            sale_note_root: request.sale_note_root,
            amount_commitment_root: request.amount_commitment_root,
            payment_commitment_root: request.payment_commitment_root,
            credential_root: request.credential_root,
            nullifier: request.nullifier.clone(),
            sponsor_reservation_id: request.sponsor_reservation_id,
            status,
            max_fee_bps: request.max_fee_bps,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            submitted_at_height: request.submitted_at_height,
            expires_at_height: request
                .submitted_at_height
                .saturating_add(self.config.sale_note_ttl_blocks),
        };
        launch.status = LaunchStatus::SaleOpen;
        launch.updated_at_height = record.submitted_at_height;
        self.nullifiers.insert(request.nullifier);
        self.sale_notes.insert(sale_note_id, record.clone());
        Ok(record)
    }

    pub fn queue_vesting_unlock_batch(
        &mut self,
        request: QueueVestingUnlockBatchRequest,
    ) -> PrivateL2ConfidentialTokenLaunchpadRuntimeResult<VestingUnlockBatchRecord> {
        if self.vesting_batches.len() >= self.config.max_vesting_batches {
            return Err("vesting unlock batch capacity exhausted".to_string());
        }
        if request.sale_note_ids.is_empty() {
            return Err("vesting unlock batch must include sale notes".to_string());
        }
        require_non_empty("unlock commitment root", &request.unlock_commitment_root)?;
        require_non_empty("vesting witness root", &request.vesting_witness_root)?;
        require_non_empty("recursive proof root", &request.recursive_proof_root)?;
        if request.privacy_set_size < self.config.min_batch_privacy_set_size {
            return Err("vesting batch privacy set below configured batch threshold".to_string());
        }
        let launch = self
            .launches
            .get_mut(&request.launch_id)
            .ok_or_else(|| "launch not found for vesting batch".to_string())?;
        if launch.status.terminal() {
            return Err("terminal launch cannot queue vesting batch".to_string());
        }

        for sale_note_id in &request.sale_note_ids {
            let note = self
                .sale_notes
                .get_mut(sale_note_id)
                .ok_or_else(|| "sale note not found for vesting batch".to_string())?;
            if note.launch_id != request.launch_id {
                return Err("vesting batch sale note belongs to another launch".to_string());
            }
            if !note.status.vestable() {
                return Err("sale note is not eligible for vesting".to_string());
            }
            if note.expires_at_height <= request.queued_at_height {
                note.status = SaleNoteStatus::Expired;
                return Err("sale note expired before vesting batch".to_string());
            }
            note.status = SaleNoteStatus::VestingQueued;
        }

        self.counters.vesting_batches += 1;
        let vesting_batch_id = vesting_unlock_batch_id(&request, self.counters.vesting_batches);
        let status = if request.unlock_at_height <= request.queued_at_height {
            VestingBatchStatus::UnlockReady
        } else {
            VestingBatchStatus::Queued
        };
        let record = VestingUnlockBatchRecord {
            vesting_batch_id: vesting_batch_id.clone(),
            launch_id: request.launch_id,
            sale_note_ids: request.sale_note_ids,
            unlock_commitment_root: request.unlock_commitment_root,
            vesting_witness_root: request.vesting_witness_root,
            recursive_proof_root: request.recursive_proof_root,
            status,
            privacy_set_size: request.privacy_set_size,
            queued_at_height: request.queued_at_height,
            unlock_at_height: request.unlock_at_height,
        };
        launch.status = LaunchStatus::Vesting;
        launch.updated_at_height = record.queued_at_height;
        self.vesting_batches
            .insert(vesting_batch_id, record.clone());
        Ok(record)
    }

    pub fn unlock_vesting_batch(
        &mut self,
        vesting_batch_id: &str,
        unlocked_at_height: u64,
    ) -> PrivateL2ConfidentialTokenLaunchpadRuntimeResult<VestingUnlockBatchRecord> {
        let batch = self
            .vesting_batches
            .get_mut(vesting_batch_id)
            .ok_or_else(|| "vesting batch not found".to_string())?;
        if unlocked_at_height < batch.unlock_at_height {
            return Err("vesting batch unlock height not reached".to_string());
        }
        batch.status = VestingBatchStatus::Unlocked;
        for sale_note_id in &batch.sale_note_ids {
            if let Some(note) = self.sale_notes.get_mut(sale_note_id) {
                note.status = SaleNoteStatus::Unlocked;
            }
        }
        if let Some(launch) = self.launches.get_mut(&batch.launch_id) {
            launch.status = LaunchStatus::SettlementReady;
            launch.updated_at_height = unlocked_at_height;
        }
        Ok(batch.clone())
    }

    pub fn publish_pq_authorization_attestation(
        &mut self,
        request: PublishPqAttestationRequest,
    ) -> PrivateL2ConfidentialTokenLaunchpadRuntimeResult<PqAttestationRecord> {
        if self.pq_attestations.len() >= self.config.max_pq_attestations {
            return Err("PQ attestation capacity exhausted".to_string());
        }
        self.launches
            .get(&request.launch_id)
            .ok_or_else(|| "launch not found for PQ attestation".to_string())?;
        require_non_empty("attestation subject", &request.subject_id)?;
        require_non_empty("attestor commitment", &request.attestor_commitment)?;
        require_non_empty("attestation root", &request.attestation_root)?;
        require_non_empty("signature root", &request.signature_root)?;
        if request.pq_security_bits < self.config.min_pq_security_bits {
            return Err("PQ attestation security bits below configured minimum".to_string());
        }

        self.counters.pq_attestations += 1;
        let attestation_id = pq_attestation_id(&request, self.counters.pq_attestations);
        let record = PqAttestationRecord {
            attestation_id: attestation_id.clone(),
            launch_id: request.launch_id.clone(),
            subject_id: request.subject_id.clone(),
            kind: request.kind,
            attestor_commitment: request.attestor_commitment,
            attestation_root: request.attestation_root,
            signature_root: request.signature_root,
            verdict: request.verdict,
            pq_security_bits: request.pq_security_bits,
            attested_at_height: request.attested_at_height,
        };
        if request.verdict.allows_progress() {
            if let Some(note) = self.sale_notes.get_mut(&request.subject_id) {
                note.status = SaleNoteStatus::PqAuthorized;
            }
        }
        self.pq_attestations.insert(attestation_id, record.clone());
        Ok(record)
    }

    pub fn issue_settlement_receipt(
        &mut self,
        request: IssueSettlementReceiptRequest,
    ) -> PrivateL2ConfidentialTokenLaunchpadRuntimeResult<SettlementReceiptRecord> {
        if self.settlement_receipts.len() >= self.config.max_settlement_receipts {
            return Err("settlement receipt capacity exhausted".to_string());
        }
        require_non_empty("settlement tx root", &request.settlement_tx_root)?;
        require_non_empty("token state root after", &request.token_state_root_after)?;
        require_non_empty(
            "liquidity pool root after",
            &request.liquidity_pool_root_after,
        )?;
        require_non_empty("settlement proof root", &request.settlement_proof_root)?;
        let attestation = self
            .pq_attestations
            .get(&request.pq_attestation_id)
            .ok_or_else(|| "settlement PQ attestation not found".to_string())?;
        if self.config.require_pq_attestation && !attestation.verdict.allows_progress() {
            return Err("settlement PQ attestation does not allow progress".to_string());
        }
        let batch = self
            .vesting_batches
            .get_mut(&request.vesting_batch_id)
            .ok_or_else(|| "vesting batch not found for settlement".to_string())?;
        if batch.launch_id != request.launch_id {
            return Err("vesting batch belongs to a different launch".to_string());
        }
        if batch.status != VestingBatchStatus::Unlocked {
            return Err("vesting batch must be unlocked before settlement".to_string());
        }

        self.counters.settlement_receipts += 1;
        let settlement_receipt_id =
            settlement_receipt_id(&request, self.counters.settlement_receipts);
        let record = SettlementReceiptRecord {
            settlement_receipt_id: settlement_receipt_id.clone(),
            launch_id: request.launch_id.clone(),
            vesting_batch_id: request.vesting_batch_id,
            settlement_tx_root: request.settlement_tx_root,
            token_state_root_after: request.token_state_root_after,
            liquidity_pool_root_after: request.liquidity_pool_root_after,
            settlement_proof_root: request.settlement_proof_root,
            pq_attestation_id: request.pq_attestation_id,
            settled_at_height: request.settled_at_height,
            expires_at_height: request
                .settled_at_height
                .saturating_add(self.config.settlement_ttl_blocks),
        };
        batch.status = VestingBatchStatus::Settled;
        for sale_note_id in &batch.sale_note_ids {
            if let Some(note) = self.sale_notes.get_mut(sale_note_id) {
                note.status = SaleNoteStatus::Settled;
            }
        }
        if let Some(launch) = self.launches.get_mut(&request.launch_id) {
            launch.status = LaunchStatus::Settled;
            launch.updated_at_height = record.settled_at_height;
        }
        self.settlement_receipts
            .insert(settlement_receipt_id, record.clone());
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            launch_root: merkle_json_root(
                "PRIVATE-L2-CONFIDENTIAL-TOKEN-LAUNCHPAD-LAUNCH-ROOT",
                self.launches.values().map(LaunchRecord::public_record),
            ),
            sponsor_reservation_root: merkle_json_root(
                "PRIVATE-L2-CONFIDENTIAL-TOKEN-LAUNCHPAD-SPONSOR-ROOT",
                self.sponsor_reservations
                    .values()
                    .map(SponsorReservationRecord::public_record),
            ),
            sale_note_root: merkle_json_root(
                "PRIVATE-L2-CONFIDENTIAL-TOKEN-LAUNCHPAD-SALE-NOTE-ROOT",
                self.sale_notes
                    .values()
                    .map(PrivateSaleNoteRecord::public_record),
            ),
            nullifier_root: merkle_json_root(
                "PRIVATE-L2-CONFIDENTIAL-TOKEN-LAUNCHPAD-NULLIFIER-ROOT",
                self.nullifiers
                    .iter()
                    .map(|nullifier| json!({ "nullifier": nullifier })),
            ),
            vesting_root: merkle_json_root(
                "PRIVATE-L2-CONFIDENTIAL-TOKEN-LAUNCHPAD-VESTING-ROOT",
                self.vesting_batches
                    .values()
                    .map(VestingUnlockBatchRecord::public_record),
            ),
            pq_attestation_root: merkle_json_root(
                "PRIVATE-L2-CONFIDENTIAL-TOKEN-LAUNCHPAD-PQ-ATTESTATION-ROOT",
                self.pq_attestations
                    .values()
                    .map(PqAttestationRecord::public_record),
            ),
            settlement_receipt_root: merkle_json_root(
                "PRIVATE-L2-CONFIDENTIAL-TOKEN-LAUNCHPAD-SETTLEMENT-RECEIPT-ROOT",
                self.settlement_receipts
                    .values()
                    .map(SettlementReceiptRecord::public_record),
            ),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "config": self.config,
            "counters": self.counters,
            "roots": roots,
            "roots_state_root": roots.state_root(),
            "launch_count": self.launches.len(),
            "sponsor_reservation_count": self.sponsor_reservations.len(),
            "sale_note_count": self.sale_notes.len(),
            "vesting_batch_count": self.vesting_batches.len(),
            "pq_attestation_count": self.pq_attestations.len(),
            "settlement_receipt_count": self.settlement_receipts.len(),
            "nullifier_count": self.nullifiers.len(),
        })
    }

    pub fn state_root(&self) -> String {
        private_l2_confidential_token_launchpad_runtime_state_root_from_record(
            &self.public_record_without_state_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }
}

pub fn launch_id(request: &RegisterShieldedLaunchRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-LAUNCHPAD-LAUNCH-ID",
        &json!({
            "counter": counter,
            "issuer_commitment": request.issuer_commitment,
            "launch_kind": request.launch_kind.as_str(),
            "token_metadata_root": request.token_metadata_root,
            "confidential_supply_root": request.confidential_supply_root,
            "sale_policy_root": request.sale_policy_root,
            "vesting_policy_root": request.vesting_policy_root,
            "defi_hook_root": request.defi_hook_root,
            "contract_init_root": request.contract_init_root,
            "pq_authorization_root": request.pq_authorization_root,
            "registered_at_height": request.registered_at_height,
        }),
    )
}

pub fn sponsor_reservation_id(request: &ReserveSponsorCapacityRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-LAUNCHPAD-SPONSOR-RESERVATION-ID",
        &json!({
            "counter": counter,
            "launch_id": request.launch_id,
            "sponsor_commitment": request.sponsor_commitment,
            "capacity_commitment_root": request.capacity_commitment_root,
            "fee_quote_root": request.fee_quote_root,
            "pq_authorization_root": request.pq_authorization_root,
            "reserved_at_height": request.reserved_at_height,
        }),
    )
}

pub fn private_sale_note_id(request: &AcceptPrivateSaleNoteRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-LAUNCHPAD-SALE-NOTE-ID",
        &json!({
            "counter": counter,
            "launch_id": request.launch_id,
            "buyer_commitment": request.buyer_commitment,
            "sale_note_root": request.sale_note_root,
            "amount_commitment_root": request.amount_commitment_root,
            "payment_commitment_root": request.payment_commitment_root,
            "credential_root": request.credential_root,
            "nullifier": request.nullifier,
            "submitted_at_height": request.submitted_at_height,
        }),
    )
}

pub fn vesting_unlock_batch_id(request: &QueueVestingUnlockBatchRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-LAUNCHPAD-VESTING-BATCH-ID",
        &json!({
            "counter": counter,
            "launch_id": request.launch_id,
            "sale_note_ids": request.sale_note_ids,
            "unlock_commitment_root": request.unlock_commitment_root,
            "vesting_witness_root": request.vesting_witness_root,
            "recursive_proof_root": request.recursive_proof_root,
            "queued_at_height": request.queued_at_height,
            "unlock_at_height": request.unlock_at_height,
        }),
    )
}

pub fn pq_attestation_id(request: &PublishPqAttestationRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-LAUNCHPAD-PQ-ATTESTATION-ID",
        &json!({
            "counter": counter,
            "launch_id": request.launch_id,
            "subject_id": request.subject_id,
            "kind": request.kind.as_str(),
            "attestor_commitment": request.attestor_commitment,
            "attestation_root": request.attestation_root,
            "signature_root": request.signature_root,
            "verdict": request.verdict.as_str(),
            "attested_at_height": request.attested_at_height,
        }),
    )
}

pub fn settlement_receipt_id(request: &IssueSettlementReceiptRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-LAUNCHPAD-SETTLEMENT-RECEIPT-ID",
        &json!({
            "counter": counter,
            "launch_id": request.launch_id,
            "vesting_batch_id": request.vesting_batch_id,
            "settlement_tx_root": request.settlement_tx_root,
            "token_state_root_after": request.token_state_root_after,
            "liquidity_pool_root_after": request.liquidity_pool_root_after,
            "settlement_proof_root": request.settlement_proof_root,
            "pq_attestation_id": request.pq_attestation_id,
            "settled_at_height": request.settled_at_height,
        }),
    )
}

pub fn private_l2_confidential_token_launchpad_runtime_state_root_from_record(
    record: &Value,
) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-LAUNCHPAD-RUNTIME-STATE-ROOT",
        record,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn payload_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!(
            "{}:{}:{}",
            PRIVATE_L2_CONFIDENTIAL_TOKEN_LAUNCHPAD_RUNTIME_PROTOCOL_VERSION, CHAIN_ID, domain
        ),
        parts,
        32,
    )
}

fn merkle_json_root(domain: &str, records: impl Iterator<Item = Value>) -> String {
    let leaves = records
        .map(|record| Value::String(payload_root(domain, &record)))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn require_non_empty(
    label: &str,
    value: &str,
) -> PrivateL2ConfidentialTokenLaunchpadRuntimeResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn require_privacy_and_pq(
    privacy_set_size: u64,
    pq_security_bits: u16,
    min_privacy_set_size: u64,
    min_pq_security_bits: u16,
) -> PrivateL2ConfidentialTokenLaunchpadRuntimeResult<()> {
    if privacy_set_size < min_privacy_set_size {
        return Err("launchpad privacy set is below configured anonymity threshold".to_string());
    }
    if pq_security_bits < min_pq_security_bits {
        return Err(
            "launchpad PQ authorization security bits below configured minimum".to_string(),
        );
    }
    Ok(())
}
