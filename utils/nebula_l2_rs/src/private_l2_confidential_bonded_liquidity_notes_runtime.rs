use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialBondedLiquidityNotesRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-bonded-liquidity-notes-runtime-v1";
pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s-bonded-liquidity-notes-v1";
pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_VAULT_SCHEME: &str =
    "private-l2-confidential-bonded-liquidity-note-vault-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEPOSIT_SCHEME: &str =
    "encrypted-private-defi-liquidity-deposit-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_QUOTE_SCHEME: &str =
    "confidential-tokenized-liquidity-bond-quote-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_ATTESTATION_SCHEME: &str =
    "pq-custodian-liquidity-position-attestation-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_SPONSOR_SCHEME: &str =
    "low-fee-confidential-liquidity-sponsor-reservation-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_REDEMPTION_SCHEME: &str =
    "batched-confidential-bonded-liquidity-redemption-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_RECEIPT_SCHEME: &str =
    "roots-only-confidential-bonded-liquidity-receipt-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_REBATE_SCHEME: &str =
    "private-defi-low-fee-liquidity-rebate-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_SLASHING_SCHEME: &str =
    "pq-custodian-slashing-dispute-receipt-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEVNET_HEIGHT: u64 = 918_000;
pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_MONERO_NETWORK: &str =
    "monero-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_LOW_FEE_LANE: &str =
    "devnet-private-l2-bonded-liquidity-low-fee";
pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_MAX_VAULTS: usize =
    262_144;
pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_MAX_DEPOSITS: usize =
    8_388_608;
pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_MAX_QUOTES: usize =
    4_194_304;
pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_MAX_ATTESTATIONS: usize =
    4_194_304;
pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_MAX_SPONSOR_RESERVATIONS: usize =
    4_194_304;
pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_MAX_REDEMPTION_BATCHES:
    usize = 1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_MAX_RECEIPTS: usize =
    8_388_608;
pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_MAX_REBATES: usize =
    4_194_304;
pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_MAX_SLASHING_RECEIPTS:
    usize = 1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 =
    8_192;
pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE:
    u64 = 65_536;
pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 =
    256;
pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 14;
pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_TARGET_REBATE_BPS: u64 = 7;
pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_MIN_BOND_COLLATERAL_BPS:
    u64 = 12_500;
pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_MAX_QUOTE_SPREAD_BPS: u64 =
    45;
pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 36;
pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS:
    u64 = 72;
pub const PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_REDEMPTION_TTL_BLOCKS:
    u64 = 48;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityVaultKind {
    AmmLp,
    StableSwapLp,
    LendingReceipt,
    PerpetualLp,
    BridgeInventory,
    TokenizedVaultShare,
    RwaLiquidityNote,
    Custom,
}

impl LiquidityVaultKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AmmLp => "amm_lp",
            Self::StableSwapLp => "stable_swap_lp",
            Self::LendingReceipt => "lending_receipt",
            Self::PerpetualLp => "perpetual_lp",
            Self::BridgeInventory => "bridge_inventory",
            Self::TokenizedVaultShare => "tokenized_vault_share",
            Self::RwaLiquidityNote => "rwa_liquidity_note",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Draft,
    Active,
    DepositOnly,
    RedemptionOnly,
    Paused,
    SlashingOnly,
    Retired,
}

impl VaultStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::DepositOnly => "deposit_only",
            Self::RedemptionOnly => "redemption_only",
            Self::Paused => "paused",
            Self::SlashingOnly => "slashing_only",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_deposits(self) -> bool {
        matches!(self, Self::Active | Self::DepositOnly)
    }

    pub fn accepts_redemptions(self) -> bool {
        matches!(self, Self::Active | Self::RedemptionOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DepositStatus {
    Submitted,
    Encrypted,
    Attested,
    Bonded,
    Tokenized,
    Redeeming,
    Redeemed,
    Rejected,
    Slashed,
}

impl DepositStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Encrypted => "encrypted",
            Self::Attested => "attested",
            Self::Bonded => "bonded",
            Self::Tokenized => "tokenized",
            Self::Redeeming => "redeeming",
            Self::Redeemed => "redeemed",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted
                | Self::Encrypted
                | Self::Attested
                | Self::Bonded
                | Self::Tokenized
                | Self::Redeeming
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Requested,
    Quoted,
    Accepted,
    Expired,
    Cancelled,
    Rejected,
}

impl QuoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Quoted => "quoted",
            Self::Accepted => "accepted",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Rejected => "rejected",
        }
    }

    pub fn can_accept(self) -> bool {
        matches!(self, Self::Quoted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodianVerdict {
    Backed,
    OverCollateralized,
    Watch,
    RedemptionOnly,
    Slashable,
    Rejected,
}

impl CustodianVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Backed => "backed",
            Self::OverCollateralized => "over_collateralized",
            Self::Watch => "watch",
            Self::RedemptionOnly => "redemption_only",
            Self::Slashable => "slashable",
            Self::Rejected => "rejected",
        }
    }

    pub fn allows_bond(self) -> bool {
        matches!(self, Self::Backed | Self::OverCollateralized | Self::Watch)
    }

    pub fn slashable(self) -> bool {
        matches!(self, Self::Slashable)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorReservationStatus {
    Reserved,
    Consumed,
    RebateQueued,
    Refunded,
    Expired,
    Slashed,
}

impl SponsorReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::RebateQueued => "rebate_queued",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedemptionBatchStatus {
    Proposed,
    Proving,
    SettlementReady,
    Settled,
    PartiallySettled,
    Disputed,
    Expired,
}

impl RedemptionBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Proving => "proving",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::PartiallySettled => "partially_settled",
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
    VaultOpened,
    DepositAccepted,
    QuoteAccepted,
    CustodianAttested,
    SponsorReserved,
    RedemptionSettled,
    RebatePaid,
    SlashingResolved,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VaultOpened => "vault_opened",
            Self::DepositAccepted => "deposit_accepted",
            Self::QuoteAccepted => "quote_accepted",
            Self::CustodianAttested => "custodian_attested",
            Self::SponsorReserved => "sponsor_reserved",
            Self::RedemptionSettled => "redemption_settled",
            Self::RebatePaid => "rebate_paid",
            Self::SlashingResolved => "slashing_resolved",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeVerdict {
    CustodianFault,
    UserFault,
    SponsorFault,
    Inconclusive,
    FraudProofAccepted,
    FraudProofRejected,
}

impl DisputeVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CustodianFault => "custodian_fault",
            Self::UserFault => "user_fault",
            Self::SponsorFault => "sponsor_fault",
            Self::Inconclusive => "inconclusive",
            Self::FraudProofAccepted => "fraud_proof_accepted",
            Self::FraudProofRejected => "fraud_proof_rejected",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub devnet_height: u64,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub monero_network: String,
    pub low_fee_lane: String,
    pub max_vaults: usize,
    pub max_deposits: usize,
    pub max_quotes: usize,
    pub max_attestations: usize,
    pub max_sponsor_reservations: usize,
    pub max_redemption_batches: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub max_slashing_receipts: usize,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub min_bond_collateral_bps: u64,
    pub max_quote_spread_bps: u64,
    pub quote_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub redemption_ttl_blocks: u64,
}
impl Config {
    pub fn devnet() -> Self {
        Self { chain_id: CHAIN_ID.to_string(), protocol_version: PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_PROTOCOL_VERSION.to_string(), schema_version: PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_SCHEMA_VERSION, devnet_height: PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEVNET_HEIGHT, hash_suite: PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_HASH_SUITE.to_string(), pq_auth_suite: PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_PQ_AUTH_SUITE.to_string(), monero_network: PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_MONERO_NETWORK.to_string(), low_fee_lane: PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_LOW_FEE_LANE.to_string(), max_vaults: PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_MAX_VAULTS, max_deposits: PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_MAX_DEPOSITS, max_quotes: PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_MAX_QUOTES, max_attestations: PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_MAX_ATTESTATIONS, max_sponsor_reservations: PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_MAX_SPONSOR_RESERVATIONS, max_redemption_batches: PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_MAX_REDEMPTION_BATCHES, max_receipts: PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_MAX_RECEIPTS, max_rebates: PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_MAX_REBATES, max_slashing_receipts: PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_MAX_SLASHING_RECEIPTS, min_privacy_set_size: PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE, batch_privacy_set_size: PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE, min_pq_security_bits: PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS, max_user_fee_bps: PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_MAX_USER_FEE_BPS, target_rebate_bps: PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_TARGET_REBATE_BPS, min_bond_collateral_bps: PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_MIN_BOND_COLLATERAL_BPS, max_quote_spread_bps: PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_MAX_QUOTE_SPREAD_BPS, quote_ttl_blocks: PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS, reservation_ttl_blocks: PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS, redemption_ttl_blocks: PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEFAULT_REDEMPTION_TTL_BLOCKS }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub next_vault: u64,
    pub next_deposit: u64,
    pub next_quote: u64,
    pub next_attestation: u64,
    pub next_sponsor_reservation: u64,
    pub next_redemption_batch: u64,
    pub next_receipt: u64,
    pub next_rebate: u64,
    pub next_slashing_receipt: u64,
    pub consumed_nullifier_counter: u64,
}
impl Counters {
    pub fn devnet() -> Self {
        Self {
            next_vault: 1,
            next_deposit: 1,
            next_quote: 1,
            next_attestation: 1,
            next_sponsor_reservation: 1,
            next_redemption_batch: 1,
            next_receipt: 1,
            next_rebate: 1,
            next_slashing_receipt: 1,
            consumed_nullifier_counter: 0,
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterNoteVaultRequest {
    pub vault_kind: LiquidityVaultKind,
    pub vault_commitment: String,
    pub operator_commitment: String,
    pub custodian_committee_root: String,
    pub asset_registry_root: String,
    pub fee_policy_root: String,
    pub vault_nullifier: String,
    pub min_deposit_privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub created_height: u64,
}
impl RegisterNoteVaultRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitEncryptedDepositRequest {
    pub vault_id: String,
    pub depositor_commitment: String,
    pub encrypted_liquidity_note_root: String,
    pub tokenized_position_commitment: String,
    pub amount_ciphertext: String,
    pub asset_blinding_root: String,
    pub deposit_nullifier: String,
    pub sponsor_reservation_id: Option<String>,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub submitted_height: u64,
}
impl SubmitEncryptedDepositRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestBondQuoteRequest {
    pub vault_id: String,
    pub deposit_id: String,
    pub quote_commitment: String,
    pub bonded_position_root: String,
    pub liquidity_token_root: String,
    pub max_spread_bps: u64,
    pub bond_collateral_bps: u64,
    pub quote_nullifier: String,
    pub expires_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}
impl RequestBondQuoteRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishPqCustodianAttestationRequest {
    pub vault_id: String,
    pub deposit_id: String,
    pub quote_id: Option<String>,
    pub verdict: CustodianVerdict,
    pub pq_attestation_root: String,
    pub custodian_set_root: String,
    pub reserve_proof_root: String,
    pub position_valuation_root: String,
    pub attestation_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub attested_height: u64,
}
impl PublishPqCustodianAttestationRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveLowFeeSponsorRequest {
    pub vault_id: String,
    pub sponsor_commitment: String,
    pub fee_budget_root: String,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub reservation_nullifier: String,
    pub expires_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}
impl ReserveLowFeeSponsorRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildRedemptionBatchRequest {
    pub vault_id: String,
    pub deposit_ids: Vec<String>,
    pub quote_ids: Vec<String>,
    pub output_note_root: String,
    pub redemption_proof_root: String,
    pub recursive_batch_proof_root: String,
    pub redemption_nullifier: String,
    pub settlement_deadline_height: u64,
    pub batch_privacy_set_size: u64,
    pub pq_security_bits: u16,
}
impl BuildRedemptionBatchRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishSettlementReceiptRequest {
    pub receipt_kind: ReceiptKind,
    pub subject_id: String,
    pub vault_id: String,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub fee_paid_bps: u64,
    pub receipt_nullifier: String,
    pub published_height: u64,
}
impl PublishSettlementReceiptRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishFeeRebateRequest {
    pub receipt_id: String,
    pub reservation_ids: Vec<String>,
    pub rebate_pool_root: String,
    pub rebate_output_root: String,
    pub sponsor_refund_root: String,
    pub rebate_bps: u64,
    pub rebate_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}
impl PublishFeeRebateRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishSlashDisputeReceiptRequest {
    pub vault_id: String,
    pub deposit_ids: Vec<String>,
    pub custodian_attestation_ids: Vec<String>,
    pub verdict: DisputeVerdict,
    pub slashed_bond_root: String,
    pub challenger_reward_root: String,
    pub fraud_or_dispute_proof_root: String,
    pub dispute_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub resolved_height: u64,
}
impl PublishSlashDisputeReceiptRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondedLiquidityNoteVault {
    pub note_vault_id: String,
    pub request: RegisterNoteVaultRequest,
    pub status: VaultStatus,
    pub note_vault_root: String,
}
impl BondedLiquidityNoteVault {
    pub fn public_record(&self) -> Value {
        json!({"note_vault_id": self.note_vault_id, "request": self.request.public_record(), "status": self.status.as_str(), "note_vault_root": self.note_vault_root})
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedBondedDeposit {
    pub encrypted_deposit_id: String,
    pub request: SubmitEncryptedDepositRequest,
    pub status: DepositStatus,
    pub encrypted_deposit_root: String,
}
impl EncryptedBondedDeposit {
    pub fn public_record(&self) -> Value {
        json!({"encrypted_deposit_id": self.encrypted_deposit_id, "request": self.request.public_record(), "status": self.status.as_str(), "encrypted_deposit_root": self.encrypted_deposit_root})
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialBondQuote {
    pub bond_quote_id: String,
    pub request: RequestBondQuoteRequest,
    pub status: QuoteStatus,
    pub bond_quote_root: String,
}
impl ConfidentialBondQuote {
    pub fn public_record(&self) -> Value {
        json!({"bond_quote_id": self.bond_quote_id, "request": self.request.public_record(), "status": self.status.as_str(), "bond_quote_root": self.bond_quote_root})
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCustodianAttestation {
    pub custodian_attestation_id: String,
    pub request: PublishPqCustodianAttestationRequest,
    pub status: CustodianVerdict,
    pub custodian_attestation_root: String,
}
impl PqCustodianAttestation {
    pub fn public_record(&self) -> Value {
        json!({"custodian_attestation_id": self.custodian_attestation_id, "request": self.request.public_record(), "status": self.status.as_str(), "custodian_attestation_root": self.custodian_attestation_root})
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSponsorReservation {
    pub sponsor_reservation_id: String,
    pub request: ReserveLowFeeSponsorRequest,
    pub status: SponsorReservationStatus,
    pub sponsor_reservation_root: String,
}
impl LowFeeSponsorReservation {
    pub fn public_record(&self) -> Value {
        json!({"sponsor_reservation_id": self.sponsor_reservation_id, "request": self.request.public_record(), "status": self.status.as_str(), "sponsor_reservation_root": self.sponsor_reservation_root})
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialRedemptionBatch {
    pub redemption_batch_id: String,
    pub request: BuildRedemptionBatchRequest,
    pub status: RedemptionBatchStatus,
    pub redemption_batch_root: String,
}
impl ConfidentialRedemptionBatch {
    pub fn public_record(&self) -> Value {
        json!({"redemption_batch_id": self.redemption_batch_id, "request": self.request.public_record(), "status": self.status.as_str(), "redemption_batch_root": self.redemption_batch_root})
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondedLiquidityReceipt {
    pub settlement_receipt_id: String,
    pub request: PublishSettlementReceiptRequest,
    pub status: ReceiptKind,
    pub settlement_receipt_root: String,
}
impl BondedLiquidityReceipt {
    pub fn public_record(&self) -> Value {
        json!({"settlement_receipt_id": self.settlement_receipt_id, "request": self.request.public_record(), "status": self.status.as_str(), "settlement_receipt_root": self.settlement_receipt_root})
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeRebateReceipt {
    pub fee_rebate_id: String,
    pub request: PublishFeeRebateRequest,
    pub status: ReceiptKind,
    pub fee_rebate_root: String,
}
impl LowFeeRebateReceipt {
    pub fn public_record(&self) -> Value {
        json!({"fee_rebate_id": self.fee_rebate_id, "request": self.request.public_record(), "status": self.status.as_str(), "fee_rebate_root": self.fee_rebate_root})
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingDisputeReceipt {
    pub slash_dispute_receipt_id: String,
    pub request: PublishSlashDisputeReceiptRequest,
    pub status: DisputeVerdict,
    pub slash_dispute_receipt_root: String,
}
impl SlashingDisputeReceipt {
    pub fn public_record(&self) -> Value {
        json!({"slash_dispute_receipt_id": self.slash_dispute_receipt_id, "request": self.request.public_record(), "status": self.status.as_str(), "slash_dispute_receipt_root": self.slash_dispute_receipt_root})
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub note_vault_root: String,
    pub encrypted_deposit_root: String,
    pub bond_quote_root: String,
    pub custodian_attestation_root: String,
    pub sponsor_reservation_root: String,
    pub redemption_batch_root: String,
    pub settlement_receipt_root: String,
    pub fee_rebate_root: String,
    pub slash_dispute_receipt_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub note_vaults: BTreeMap<String, BondedLiquidityNoteVault>,
    pub encrypted_deposits: BTreeMap<String, EncryptedBondedDeposit>,
    pub bond_quotes: BTreeMap<String, ConfidentialBondQuote>,
    pub custodian_attestations: BTreeMap<String, PqCustodianAttestation>,
    pub sponsor_reservations: BTreeMap<String, LowFeeSponsorReservation>,
    pub redemption_batches: BTreeMap<String, ConfidentialRedemptionBatch>,
    pub settlement_receipts: BTreeMap<String, BondedLiquidityReceipt>,
    pub fee_rebates: BTreeMap<String, LowFeeRebateReceipt>,
    pub slash_dispute_receipts: BTreeMap<String, SlashingDisputeReceipt>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        Self::new(
            Config::devnet(),
            Counters::devnet(),
            PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEVNET_HEIGHT,
        )
    }

    pub fn new(config: Config, counters: Counters, current_height: u64) -> Self {
        Self {
            config,
            counters,
            current_height,
            note_vaults: BTreeMap::new(),
            encrypted_deposits: BTreeMap::new(),
            bond_quotes: BTreeMap::new(),
            custodian_attestations: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            redemption_batches: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            slash_dispute_receipts: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        }
    }

    pub fn roots(&self) -> Roots {
        let note_vault_root = public_record_root(
            PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_VAULT_SCHEME,
            &self
                .note_vaults
                .values()
                .map(BondedLiquidityNoteVault::public_record)
                .collect::<Vec<_>>(),
        );
        let encrypted_deposit_root = public_record_root(
            PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_DEPOSIT_SCHEME,
            &self
                .encrypted_deposits
                .values()
                .map(EncryptedBondedDeposit::public_record)
                .collect::<Vec<_>>(),
        );
        let bond_quote_root = public_record_root(
            PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_QUOTE_SCHEME,
            &self
                .bond_quotes
                .values()
                .map(ConfidentialBondQuote::public_record)
                .collect::<Vec<_>>(),
        );
        let custodian_attestation_root = public_record_root(
            PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_ATTESTATION_SCHEME,
            &self
                .custodian_attestations
                .values()
                .map(PqCustodianAttestation::public_record)
                .collect::<Vec<_>>(),
        );
        let sponsor_reservation_root = public_record_root(
            PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_SPONSOR_SCHEME,
            &self
                .sponsor_reservations
                .values()
                .map(LowFeeSponsorReservation::public_record)
                .collect::<Vec<_>>(),
        );
        let redemption_batch_root = public_record_root(
            PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_REDEMPTION_SCHEME,
            &self
                .redemption_batches
                .values()
                .map(ConfidentialRedemptionBatch::public_record)
                .collect::<Vec<_>>(),
        );
        let settlement_receipt_root = public_record_root(
            PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_RECEIPT_SCHEME,
            &self
                .settlement_receipts
                .values()
                .map(BondedLiquidityReceipt::public_record)
                .collect::<Vec<_>>(),
        );
        let fee_rebate_root = public_record_root(
            PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_REBATE_SCHEME,
            &self
                .fee_rebates
                .values()
                .map(LowFeeRebateReceipt::public_record)
                .collect::<Vec<_>>(),
        );
        let slash_dispute_receipt_root = public_record_root(
            PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_SLASHING_SCHEME,
            &self
                .slash_dispute_receipts
                .values()
                .map(SlashingDisputeReceipt::public_record)
                .collect::<Vec<_>>(),
        );
        let nullifier_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-NULLIFIER-ROOT",
            &self
                .consumed_nullifiers
                .iter()
                .map(|nullifier| json!(nullifier))
                .collect::<Vec<_>>(),
        );
        let state_root = state_root_from_record(&json!({
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "current_height": self.current_height,
            "note_vault_root": note_vault_root,
            "encrypted_deposit_root": encrypted_deposit_root,
            "bond_quote_root": bond_quote_root,
            "custodian_attestation_root": custodian_attestation_root,
            "sponsor_reservation_root": sponsor_reservation_root,
            "redemption_batch_root": redemption_batch_root,
            "settlement_receipt_root": settlement_receipt_root,
            "fee_rebate_root": fee_rebate_root,
            "slash_dispute_receipt_root": slash_dispute_receipt_root,
            "nullifier_root": nullifier_root,
        }));
        Roots {
            note_vault_root,
            encrypted_deposit_root,
            bond_quote_root,
            custodian_attestation_root,
            sponsor_reservation_root,
            redemption_batch_root,
            settlement_receipt_root,
            fee_rebate_root,
            slash_dispute_receipt_root,
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
            "note_vault_ids": self.note_vaults.keys().cloned().collect::<Vec<_>>(),
            "encrypted_deposit_ids": self.encrypted_deposits.keys().cloned().collect::<Vec<_>>(),
            "bond_quote_ids": self.bond_quotes.keys().cloned().collect::<Vec<_>>(),
            "custodian_attestation_ids": self.custodian_attestations.keys().cloned().collect::<Vec<_>>(),
            "sponsor_reservation_ids": self.sponsor_reservations.keys().cloned().collect::<Vec<_>>(),
            "redemption_batch_ids": self.redemption_batches.keys().cloned().collect::<Vec<_>>(),
            "settlement_receipt_ids": self.settlement_receipts.keys().cloned().collect::<Vec<_>>(),
            "fee_rebate_ids": self.fee_rebates.keys().cloned().collect::<Vec<_>>(),
            "slash_dispute_receipt_ids": self.slash_dispute_receipts.keys().cloned().collect::<Vec<_>>(),
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

    pub fn consume_nullifier_for_devnet_fixture(
        &mut self,
        nullifier: &str,
    ) -> PrivateL2ConfidentialBondedLiquidityNotesRuntimeResult<()> {
        self.consume_nullifier(nullifier)
    }

    fn consume_nullifier(
        &mut self,
        nullifier: &str,
    ) -> PrivateL2ConfidentialBondedLiquidityNotesRuntimeResult<()> {
        let nullifier_hash = payload_id(
            "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-NULLIFIER-ID",
            &[HashPart::Str(nullifier)],
        );
        require(
            self.consumed_nullifiers.insert(nullifier_hash),
            "confidential bonded liquidity note nullifier replay detected",
        )?;
        self.counters.consumed_nullifier_counter =
            self.counters.consumed_nullifier_counter.saturating_add(1);
        Ok(())
    }
}

pub type Runtime = State;

pub fn note_vault_id(request: &RegisterNoteVaultRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-NOTE-VAULT-ID",
        &[
            HashPart::Str(request.vault_kind.as_str()),
            HashPart::Str(&request.vault_commitment),
            HashPart::Str(&request.operator_commitment),
            HashPart::Str(&request.vault_nullifier),
            HashPart::Int(sequence as i128),
        ],
    )
}
pub fn encrypted_deposit_id(request: &SubmitEncryptedDepositRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-ENCRYPTED-DEPOSIT-ID",
        &[
            HashPart::Str(&request.vault_id),
            HashPart::Str(&request.depositor_commitment),
            HashPart::Str(&request.encrypted_liquidity_note_root),
            HashPart::Str(&request.deposit_nullifier),
            HashPart::Int(sequence as i128),
        ],
    )
}
pub fn bond_quote_id(request: &RequestBondQuoteRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-BOND-QUOTE-ID",
        &[
            HashPart::Str(&request.vault_id),
            HashPart::Str(&request.deposit_id),
            HashPart::Str(&request.quote_commitment),
            HashPart::Str(&request.quote_nullifier),
            HashPart::Int(sequence as i128),
        ],
    )
}
pub fn custodian_attestation_id(
    request: &PublishPqCustodianAttestationRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-CUSTODIAN-ATTESTATION-ID",
        &[
            HashPart::Str(&request.vault_id),
            HashPart::Str(&request.deposit_id),
            HashPart::Str(request.verdict.as_str()),
            HashPart::Str(&request.pq_attestation_root),
            HashPart::Str(&request.attestation_nullifier),
            HashPart::Int(sequence as i128),
        ],
    )
}
pub fn sponsor_reservation_id(request: &ReserveLowFeeSponsorRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-SPONSOR-RESERVATION-ID",
        &[
            HashPart::Str(&request.vault_id),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.fee_budget_root),
            HashPart::Str(&request.reservation_nullifier),
            HashPart::Int(sequence as i128),
        ],
    )
}
pub fn redemption_batch_id(request: &BuildRedemptionBatchRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-REDEMPTION-BATCH-ID",
        &[
            HashPart::Str(&request.vault_id),
            HashPart::Json(&json!(request.deposit_ids)),
            HashPart::Json(&json!(request.quote_ids)),
            HashPart::Str(&request.recursive_batch_proof_root),
            HashPart::Str(&request.redemption_nullifier),
            HashPart::Int(sequence as i128),
        ],
    )
}
pub fn settlement_receipt_id(request: &PublishSettlementReceiptRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(request.receipt_kind.as_str()),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.settlement_tx_root),
            HashPart::Str(&request.state_root_after),
            HashPart::Str(&request.receipt_nullifier),
            HashPart::Int(sequence as i128),
        ],
    )
}
pub fn fee_rebate_id(request: &PublishFeeRebateRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-FEE-REBATE-ID",
        &[
            HashPart::Str(&request.receipt_id),
            HashPart::Json(&json!(request.reservation_ids)),
            HashPart::Str(&request.rebate_output_root),
            HashPart::Str(&request.rebate_nullifier),
            HashPart::Int(sequence as i128),
        ],
    )
}
pub fn slash_dispute_receipt_id(
    request: &PublishSlashDisputeReceiptRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-SLASH-DISPUTE-RECEIPT-ID",
        &[
            HashPart::Str(&request.vault_id),
            HashPart::Json(&json!(request.deposit_ids)),
            HashPart::Str(request.verdict.as_str()),
            HashPart::Str(&request.fraud_or_dispute_proof_root),
            HashPart::Str(&request.dispute_nullifier),
            HashPart::Int(sequence as i128),
        ],
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_PROTOCOL_VERSION),
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
            PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_PROTOCOL_VERSION,
            CHAIN_ID,
            domain
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
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-STATE-ROOT",
        record,
    )
}
fn require(
    condition: bool,
    message: &str,
) -> PrivateL2ConfidentialBondedLiquidityNotesRuntimeResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
fn require_non_empty(
    label: &str,
    value: &str,
) -> PrivateL2ConfidentialBondedLiquidityNotesRuntimeResult<()> {
    require(
        !value.trim().is_empty(),
        &format!("{label} must not be empty"),
    )
}
fn require_root(
    label: &str,
    value: &str,
) -> PrivateL2ConfidentialBondedLiquidityNotesRuntimeResult<()> {
    require_non_empty(label, value)?;
    require(
        value.len() >= 16,
        &format!("{label} must look like a commitment/root"),
    )
}
fn require_bps(
    label: &str,
    value: u64,
) -> PrivateL2ConfidentialBondedLiquidityNotesRuntimeResult<()> {
    require(
        value <= PRIVATE_L2_CONFIDENTIAL_BONDED_LIQUIDITY_NOTES_RUNTIME_MAX_BPS,
        &format!("{label} exceeds basis point maximum"),
    )
}
fn require_privacy_and_pq(
    privacy_set_size: u64,
    pq_security_bits: u16,
    min_privacy_set_size: u64,
    min_pq_security_bits: u16,
) -> PrivateL2ConfidentialBondedLiquidityNotesRuntimeResult<()> {
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
) -> PrivateL2ConfidentialBondedLiquidityNotesRuntimeResult<()> {
    let unique = values.iter().collect::<BTreeSet<_>>();
    require(
        unique.len() == values.len(),
        &format!("{label} must be unique"),
    )
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainCatalogEntry {
    pub lane: String,
    pub purpose: String,
    pub domain: String,
    pub privacy_priority: bool,
    pub pq_required: bool,
    pub low_fee_priority: bool,
}
impl DomainCatalogEntry {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

pub fn domain_catalog() -> Vec<DomainCatalogEntry> {
    vec![
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0001".to_string(),
            purpose: "encrypted_deposit".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(1)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0002".to_string(),
            purpose: "bond_quote".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(2)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0003".to_string(),
            purpose: "pq_custodian_attestation".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(3)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0004".to_string(),
            purpose: "sponsor_reservation".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(4)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0005".to_string(),
            purpose: "redemption_batch".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(5)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0006".to_string(),
            purpose: "receipt".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(6)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0007".to_string(),
            purpose: "rebate".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(7)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0008".to_string(),
            purpose: "slashing_dispute".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(8)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0009".to_string(),
            purpose: "nullifier".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(9)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0010".to_string(),
            purpose: "note_vault".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(10)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0011".to_string(),
            purpose: "encrypted_deposit".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(11)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0012".to_string(),
            purpose: "bond_quote".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(12)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0013".to_string(),
            purpose: "pq_custodian_attestation".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(13)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0014".to_string(),
            purpose: "sponsor_reservation".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(14)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0015".to_string(),
            purpose: "redemption_batch".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(15)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0016".to_string(),
            purpose: "receipt".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(16)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0017".to_string(),
            purpose: "rebate".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(17)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0018".to_string(),
            purpose: "slashing_dispute".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(18)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0019".to_string(),
            purpose: "nullifier".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(19)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0020".to_string(),
            purpose: "note_vault".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(20)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0021".to_string(),
            purpose: "encrypted_deposit".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(21)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0022".to_string(),
            purpose: "bond_quote".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(22)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0023".to_string(),
            purpose: "pq_custodian_attestation".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(23)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0024".to_string(),
            purpose: "sponsor_reservation".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(24)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0025".to_string(),
            purpose: "redemption_batch".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(25)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0026".to_string(),
            purpose: "receipt".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(26)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0027".to_string(),
            purpose: "rebate".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(27)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0028".to_string(),
            purpose: "slashing_dispute".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(28)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0029".to_string(),
            purpose: "nullifier".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(29)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0030".to_string(),
            purpose: "note_vault".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(30)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0031".to_string(),
            purpose: "encrypted_deposit".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(31)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0032".to_string(),
            purpose: "bond_quote".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(32)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0033".to_string(),
            purpose: "pq_custodian_attestation".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(33)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0034".to_string(),
            purpose: "sponsor_reservation".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(34)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0035".to_string(),
            purpose: "redemption_batch".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(35)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0036".to_string(),
            purpose: "receipt".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(36)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0037".to_string(),
            purpose: "rebate".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(37)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0038".to_string(),
            purpose: "slashing_dispute".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(38)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0039".to_string(),
            purpose: "nullifier".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(39)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0040".to_string(),
            purpose: "note_vault".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(40)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0041".to_string(),
            purpose: "encrypted_deposit".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(41)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0042".to_string(),
            purpose: "bond_quote".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(42)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0043".to_string(),
            purpose: "pq_custodian_attestation".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(43)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0044".to_string(),
            purpose: "sponsor_reservation".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(44)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0045".to_string(),
            purpose: "redemption_batch".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(45)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0046".to_string(),
            purpose: "receipt".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(46)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0047".to_string(),
            purpose: "rebate".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(47)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0048".to_string(),
            purpose: "slashing_dispute".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(48)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0049".to_string(),
            purpose: "nullifier".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(49)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0050".to_string(),
            purpose: "note_vault".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(50)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0051".to_string(),
            purpose: "encrypted_deposit".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(51)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0052".to_string(),
            purpose: "bond_quote".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(52)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0053".to_string(),
            purpose: "pq_custodian_attestation".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(53)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0054".to_string(),
            purpose: "sponsor_reservation".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(54)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0055".to_string(),
            purpose: "redemption_batch".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(55)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0056".to_string(),
            purpose: "receipt".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(56)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0057".to_string(),
            purpose: "rebate".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(57)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0058".to_string(),
            purpose: "slashing_dispute".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(58)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0059".to_string(),
            purpose: "nullifier".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(59)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0060".to_string(),
            purpose: "note_vault".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(60)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0061".to_string(),
            purpose: "encrypted_deposit".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(61)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0062".to_string(),
            purpose: "bond_quote".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(62)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0063".to_string(),
            purpose: "pq_custodian_attestation".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(63)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0064".to_string(),
            purpose: "sponsor_reservation".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(64)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0065".to_string(),
            purpose: "redemption_batch".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(65)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0066".to_string(),
            purpose: "receipt".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(66)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0067".to_string(),
            purpose: "rebate".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(67)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0068".to_string(),
            purpose: "slashing_dispute".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(68)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0069".to_string(),
            purpose: "nullifier".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(69)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0070".to_string(),
            purpose: "note_vault".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(70)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0071".to_string(),
            purpose: "encrypted_deposit".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(71)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0072".to_string(),
            purpose: "bond_quote".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(72)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0073".to_string(),
            purpose: "pq_custodian_attestation".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(73)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0074".to_string(),
            purpose: "sponsor_reservation".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(74)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0075".to_string(),
            purpose: "redemption_batch".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(75)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0076".to_string(),
            purpose: "receipt".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(76)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0077".to_string(),
            purpose: "rebate".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(77)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0078".to_string(),
            purpose: "slashing_dispute".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(78)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0079".to_string(),
            purpose: "nullifier".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(79)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0080".to_string(),
            purpose: "note_vault".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(80)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0081".to_string(),
            purpose: "encrypted_deposit".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(81)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0082".to_string(),
            purpose: "bond_quote".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(82)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0083".to_string(),
            purpose: "pq_custodian_attestation".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(83)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0084".to_string(),
            purpose: "sponsor_reservation".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(84)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0085".to_string(),
            purpose: "redemption_batch".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(85)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0086".to_string(),
            purpose: "receipt".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(86)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0087".to_string(),
            purpose: "rebate".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(87)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0088".to_string(),
            purpose: "slashing_dispute".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(88)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0089".to_string(),
            purpose: "nullifier".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(89)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0090".to_string(),
            purpose: "note_vault".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(90)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0091".to_string(),
            purpose: "encrypted_deposit".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(91)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0092".to_string(),
            purpose: "bond_quote".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(92)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0093".to_string(),
            purpose: "pq_custodian_attestation".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(93)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0094".to_string(),
            purpose: "sponsor_reservation".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(94)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0095".to_string(),
            purpose: "redemption_batch".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(95)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0096".to_string(),
            purpose: "receipt".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(96)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0097".to_string(),
            purpose: "rebate".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(97)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0098".to_string(),
            purpose: "slashing_dispute".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(98)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0099".to_string(),
            purpose: "nullifier".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(99)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0100".to_string(),
            purpose: "note_vault".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(100)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0101".to_string(),
            purpose: "encrypted_deposit".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(101)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0102".to_string(),
            purpose: "bond_quote".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(102)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0103".to_string(),
            purpose: "pq_custodian_attestation".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(103)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0104".to_string(),
            purpose: "sponsor_reservation".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(104)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0105".to_string(),
            purpose: "redemption_batch".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(105)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0106".to_string(),
            purpose: "receipt".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(106)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0107".to_string(),
            purpose: "rebate".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(107)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0108".to_string(),
            purpose: "slashing_dispute".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(108)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0109".to_string(),
            purpose: "nullifier".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(109)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0110".to_string(),
            purpose: "note_vault".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(110)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0111".to_string(),
            purpose: "encrypted_deposit".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(111)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0112".to_string(),
            purpose: "bond_quote".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(112)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0113".to_string(),
            purpose: "pq_custodian_attestation".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(113)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0114".to_string(),
            purpose: "sponsor_reservation".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(114)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0115".to_string(),
            purpose: "redemption_batch".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(115)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0116".to_string(),
            purpose: "receipt".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(116)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0117".to_string(),
            purpose: "rebate".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(117)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0118".to_string(),
            purpose: "slashing_dispute".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(118)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0119".to_string(),
            purpose: "nullifier".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(119)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0120".to_string(),
            purpose: "note_vault".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(120)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: false,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0121".to_string(),
            purpose: "encrypted_deposit".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(121)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
        DomainCatalogEntry {
            lane: "bonded-liquidity-lane-0122".to_string(),
            purpose: "bond_quote".to_string(),
            domain: payload_id(
                "PRIVATE-L2-CONFIDENTIAL-BONDED-LIQUIDITY-NOTES-DOMAIN-CATALOG",
                &[HashPart::Int(122)],
            ),
            privacy_priority: true,
            pq_required: true,
            low_fee_priority: true,
        },
    ]
}
