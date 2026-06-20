use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2PrivateWithdrawalNoteBurnRuntimeResult<T> = Result<T, String>;

pub const MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-private-withdrawal-note-burn-runtime-v1";
pub const PROTOCOL_VERSION: &str = MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_PROTOCOL_VERSION;
pub const MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-withdrawal-auth-v1";
pub const MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_BURN_SCHEME: &str =
    "monero-l2-private-withdrawal-note-burn-v1";
pub const MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_LIQUIDITY_SCHEME: &str =
    "roots-only-monero-liquidity-solvency-attestation-v1";
pub const MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_RECEIPT_SCHEME: &str =
    "private-withdrawal-burn-and-settlement-receipt-root-v1";
pub const MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_SPONSOR_SCHEME: &str =
    "low-fee-sponsored-private-withdrawal-note-burn-v1";
pub const MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_NULLIFIER_SCHEME: &str =
    "monero-l2-private-withdrawal-nullifier-replay-fence-v1";
pub const MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_REPLAY_DOMAIN: &str =
    "monero-l2-private-withdrawal-note-burn-devnet";
pub const MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_DEVNET_HEIGHT: u64 = 336_000;
pub const MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_DEVNET_MONERO_NETWORK: &str =
    "monero-devnet";
pub const MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_DEVNET_FEE_ASSET_ID: &str =
    "piconero-devnet";
pub const MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_MAX_BPS: u64 = 10_000;
pub const MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_DEFAULT_REQUEST_TTL_BLOCKS: u64 = 96;
pub const MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 24;
pub const MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 144;
pub const MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 =
    65_536;
pub const MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_DEFAULT_MIN_LIQUIDITY_BPS: u64 = 10_000;
pub const MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_DEFAULT_TARGET_SOLVENCY_BPS: u64 = 11_000;
pub const MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 30;
pub const MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_DEFAULT_LOW_FEE_BPS: u64 = 5;
pub const MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_DEFAULT_SPONSOR_COVER_BPS: u64 = 8_500;
pub const MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_MAX_WITHDRAWALS: usize = 1_048_576;
pub const MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_MAX_AUTHORIZATIONS: usize = 1_048_576;
pub const MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_MAX_ATTESTATIONS: usize = 1_048_576;
pub const MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_MAX_RESERVATIONS: usize = 1_048_576;
pub const MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_MAX_RECEIPTS: usize = 1_048_576;
pub const MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_MAX_BATCHES: usize = 262_144;
pub const MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_MAX_PUBLIC_RECORDS: usize = 2_097_152;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalLane {
    SponsoredLowFee,
    Standard,
    FastExit,
    DefiExit,
    Emergency,
}

impl WithdrawalLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SponsoredLowFee => "sponsored_low_fee",
            Self::Standard => "standard",
            Self::FastExit => "fast_exit",
            Self::DefiExit => "defi_exit",
            Self::Emergency => "emergency",
        }
    }

    pub fn user_fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::SponsoredLowFee => config.low_fee_bps,
            Self::Standard => config.max_user_fee_bps.saturating_mul(2) / 3,
            Self::FastExit | Self::Emergency => config.max_user_fee_bps,
            Self::DefiExit => config.max_user_fee_bps.saturating_mul(3) / 4,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAuthorizationStatus {
    Submitted,
    Accepted,
    Replayed,
    Revoked,
    Expired,
}

impl PqAuthorizationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Replayed => "replayed",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Submitted | Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalRequestStatus {
    Submitted,
    Authorized,
    LiquidityAttested,
    SponsorReserved,
    Burned,
    Batched,
    Settled,
    Rejected,
    Expired,
}

impl WithdrawalRequestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Authorized => "authorized",
            Self::LiquidityAttested => "liquidity_attested",
            Self::SponsorReserved => "sponsor_reserved",
            Self::Burned => "burned",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted
                | Self::Authorized
                | Self::LiquidityAttested
                | Self::SponsorReserved
                | Self::Burned
                | Self::Batched
        )
    }

    pub fn burnable(self) -> bool {
        matches!(
            self,
            Self::Authorized | Self::LiquidityAttested | Self::SponsorReserved
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityAttestationStatus {
    Pending,
    Accepted,
    Superseded,
    Challenged,
    Rejected,
}

impl LiquidityAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Superseded => "superseded",
            Self::Challenged => "challenged",
            Self::Rejected => "rejected",
        }
    }

    pub fn acceptable(self) -> bool {
        matches!(self, Self::Pending | Self::Accepted)
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

    pub fn live(self) -> bool {
        matches!(self, Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BurnReceiptStatus {
    Issued,
    Batched,
    Settled,
    Reorged,
    Expired,
}

impl BurnReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Reorged => "reorged",
            Self::Expired => "expired",
        }
    }

    pub fn batchable(self) -> bool {
        matches!(self, Self::Issued)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalBatchStatus {
    Open,
    Proved,
    Submitted,
    Settled,
    Rejected,
}

impl WithdrawalBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Proved => "proved",
            Self::Submitted => "submitted",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
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
    pub asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_authorization_suite: String,
    pub burn_scheme: String,
    pub liquidity_scheme: String,
    pub receipt_scheme: String,
    pub sponsor_scheme: String,
    pub nullifier_scheme: String,
    pub replay_domain: String,
    pub request_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub min_liquidity_bps: u64,
    pub target_solvency_bps: u64,
    pub max_user_fee_bps: u64,
    pub low_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub max_withdrawals: usize,
    pub max_authorizations: usize,
    pub max_attestations: usize,
    pub max_reservations: usize,
    pub max_receipts: usize,
    pub max_batches: usize,
    pub max_public_records: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            monero_network: MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_DEVNET_MONERO_NETWORK
                .to_string(),
            l2_network: MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_DEVNET_L2_NETWORK
                .to_string(),
            asset_id: MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_DEVNET_FEE_ASSET_ID
                .to_string(),
            hash_suite: MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_HASH_SUITE.to_string(),
            pq_authorization_suite: MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_PQ_AUTH_SUITE
                .to_string(),
            burn_scheme: MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_BURN_SCHEME.to_string(),
            liquidity_scheme: MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_LIQUIDITY_SCHEME
                .to_string(),
            receipt_scheme: MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_RECEIPT_SCHEME
                .to_string(),
            sponsor_scheme: MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_SPONSOR_SCHEME
                .to_string(),
            nullifier_scheme: MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_NULLIFIER_SCHEME
                .to_string(),
            replay_domain: MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_REPLAY_DOMAIN.to_string(),
            request_ttl_blocks:
                MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_DEFAULT_REQUEST_TTL_BLOCKS,
            reservation_ttl_blocks:
                MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
            settlement_ttl_blocks:
                MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            min_privacy_set_size:
                MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            min_liquidity_bps:
                MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_DEFAULT_MIN_LIQUIDITY_BPS,
            target_solvency_bps:
                MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_DEFAULT_TARGET_SOLVENCY_BPS,
            max_user_fee_bps:
                MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            low_fee_bps: MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_DEFAULT_LOW_FEE_BPS,
            sponsor_cover_bps:
                MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_DEFAULT_SPONSOR_COVER_BPS,
            max_withdrawals: MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_MAX_WITHDRAWALS,
            max_authorizations: MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_MAX_AUTHORIZATIONS,
            max_attestations: MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_MAX_ATTESTATIONS,
            max_reservations: MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_MAX_RESERVATIONS,
            max_receipts: MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_MAX_RECEIPTS,
            max_batches: MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_MAX_BATCHES,
            max_public_records: MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_MAX_PUBLIC_RECORDS,
        }
    }

    pub fn validate(&self) -> MoneroL2PrivateWithdrawalNoteBurnRuntimeResult<()> {
        require(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol version mismatch",
        )?;
        require(self.schema_version == 1, "schema version mismatch")?;
        require(self.chain_id == CHAIN_ID, "config chain id mismatch")?;
        required("monero_network", &self.monero_network)?;
        required("l2_network", &self.l2_network)?;
        required("asset_id", &self.asset_id)?;
        required("fee_asset_id", &self.fee_asset_id)?;
        require(
            self.min_pq_security_bits
                >= MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            "minimum PQ security bits too low",
        )?;
        require(
            self.min_liquidity_bps >= MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_MAX_BPS,
            "liquidity proof must cover withdrawals",
        )?;
        require(
            self.target_solvency_bps >= self.min_liquidity_bps,
            "target solvency below minimum liquidity",
        )?;
        require(
            self.max_user_fee_bps <= MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_MAX_BPS,
            "max user fee bps too high",
        )?;
        require(
            self.low_fee_bps <= self.max_user_fee_bps,
            "low fee bps exceeds max user fee bps",
        )?;
        require(
            self.sponsor_cover_bps <= MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_MAX_BPS,
            "sponsor cover bps too high",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "pq_authorization_suite": self.pq_authorization_suite,
            "burn_scheme": self.burn_scheme,
            "liquidity_scheme": self.liquidity_scheme,
            "receipt_scheme": self.receipt_scheme,
            "sponsor_scheme": self.sponsor_scheme,
            "nullifier_scheme": self.nullifier_scheme,
            "replay_domain": self.replay_domain,
            "request_ttl_blocks": self.request_ttl_blocks,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_liquidity_bps": self.min_liquidity_bps,
            "target_solvency_bps": self.target_solvency_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "low_fee_bps": self.low_fee_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "max_withdrawals": self.max_withdrawals,
            "max_authorizations": self.max_authorizations,
            "max_attestations": self.max_attestations,
            "max_reservations": self.max_reservations,
            "max_receipts": self.max_receipts,
            "max_batches": self.max_batches,
            "max_public_records": self.max_public_records,
        })
    }

    pub fn state_root(&self) -> String {
        record_hash(
            "MONERO-L2-PRIVATE-WITHDRAWAL-NOTE-BURN-CONFIG",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub private_withdrawals_submitted: u64,
    pub pq_authorizations_accepted: u64,
    pub liquidity_attestations_accepted: u64,
    pub sponsor_reservations_created: u64,
    pub withdrawal_notes_burned: u64,
    pub burn_receipts_issued: u64,
    pub withdrawal_batches_settled: u64,
    pub replay_fences_consumed: u64,
    pub nullifiers_consumed: u64,
    pub sponsored_withdrawals: u64,
    pub total_private_amount: u128,
    pub total_public_fee: u128,
    pub total_sponsor_fee: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "private_withdrawals_submitted": self.private_withdrawals_submitted,
            "pq_authorizations_accepted": self.pq_authorizations_accepted,
            "liquidity_attestations_accepted": self.liquidity_attestations_accepted,
            "sponsor_reservations_created": self.sponsor_reservations_created,
            "withdrawal_notes_burned": self.withdrawal_notes_burned,
            "burn_receipts_issued": self.burn_receipts_issued,
            "withdrawal_batches_settled": self.withdrawal_batches_settled,
            "replay_fences_consumed": self.replay_fences_consumed,
            "nullifiers_consumed": self.nullifiers_consumed,
            "sponsored_withdrawals": self.sponsored_withdrawals,
            "total_private_amount": self.total_private_amount,
            "total_public_fee": self.total_public_fee,
            "total_sponsor_fee": self.total_sponsor_fee,
        })
    }

    pub fn state_root(&self) -> String {
        record_hash(
            "MONERO-L2-PRIVATE-WITHDRAWAL-NOTE-BURN-COUNTERS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub withdrawal_root: String,
    pub live_withdrawal_root: String,
    pub pq_authorization_root: String,
    pub liquidity_attestation_root: String,
    pub sponsor_reservation_root: String,
    pub burn_receipt_root: String,
    pub unsettled_receipt_root: String,
    pub withdrawal_batch_root: String,
    pub consumed_nullifier_root: String,
    pub replay_fence_root: String,
    pub liquidity_privacy_root: String,
    pub withdrawal_output_root: String,
    pub sponsor_root: String,
    pub event_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "withdrawal_root": self.withdrawal_root,
            "live_withdrawal_root": self.live_withdrawal_root,
            "pq_authorization_root": self.pq_authorization_root,
            "liquidity_attestation_root": self.liquidity_attestation_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "burn_receipt_root": self.burn_receipt_root,
            "unsettled_receipt_root": self.unsettled_receipt_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
            "replay_fence_root": self.replay_fence_root,
            "liquidity_privacy_root": self.liquidity_privacy_root,
            "withdrawal_output_root": self.withdrawal_output_root,
            "sponsor_root": self.sponsor_root,
            "event_root": self.event_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_hash(
            "MONERO-L2-PRIVATE-WITHDRAWAL-NOTE-BURN-ROOTS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitPrivateWithdrawalBurnRequest {
    pub lane: WithdrawalLane,
    pub note_commitment_root: String,
    pub withdrawal_nullifier: String,
    pub amount: u128,
    pub destination_stealth_address_root: String,
    pub destination_view_tag_root: String,
    pub encrypted_withdrawal_memo_root: String,
    pub change_note_root: String,
    pub fee_commitment_root: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl SubmitPrivateWithdrawalBurnRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "note_commitment_root": self.note_commitment_root,
            "withdrawal_nullifier": self.withdrawal_nullifier,
            "amount": self.amount,
            "destination_stealth_address_root": self.destination_stealth_address_root,
            "destination_view_tag_root": self.destination_view_tag_root,
            "encrypted_withdrawal_memo_root": self.encrypted_withdrawal_memo_root,
            "change_note_root": self.change_note_root,
            "fee_commitment_root": self.fee_commitment_root,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizeWithdrawalBurnRequest {
    pub withdrawal_id: String,
    pub pq_authorization_root: String,
    pub pq_authorization_nullifier: String,
    pub pq_transcript_root: String,
    pub authorizer_commitment: String,
    pub pq_security_bits: u16,
    pub authorized_at_height: u64,
    pub expires_at_height: u64,
}

impl AuthorizeWithdrawalBurnRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "withdrawal_id": self.withdrawal_id,
            "pq_authorization_root": self.pq_authorization_root,
            "pq_authorization_nullifier": self.pq_authorization_nullifier,
            "pq_transcript_root": self.pq_transcript_root,
            "authorizer_commitment": self.authorizer_commitment,
            "pq_security_bits": self.pq_security_bits,
            "authorized_at_height": self.authorized_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestWithdrawalLiquidityRequest {
    pub withdrawal_id: String,
    pub liquidity_attestor_id: String,
    pub liquidity_pool_root: String,
    pub solvency_snapshot_root: String,
    pub withdrawal_liability_root: String,
    pub liquidity_privacy_root: String,
    pub monero_output_capacity_root: String,
    pub available_liquidity_bps: u64,
    pub solvency_bps: u64,
    pub pq_attestation_root: String,
    pub attested_at_height: u64,
}

impl AttestWithdrawalLiquidityRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "withdrawal_id": self.withdrawal_id,
            "liquidity_attestor_id": self.liquidity_attestor_id,
            "liquidity_pool_root": self.liquidity_pool_root,
            "solvency_snapshot_root": self.solvency_snapshot_root,
            "withdrawal_liability_root": self.withdrawal_liability_root,
            "liquidity_privacy_root": self.liquidity_privacy_root,
            "monero_output_capacity_root": self.monero_output_capacity_root,
            "available_liquidity_bps": self.available_liquidity_bps,
            "solvency_bps": self.solvency_bps,
            "pq_attestation_root": self.pq_attestation_root,
            "attested_at_height": self.attested_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveLowFeeWithdrawalSponsorRequest {
    pub withdrawal_id: String,
    pub sponsor_commitment: String,
    pub sponsor_budget_root: String,
    pub sponsor_receipt_root: String,
    pub reserved_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub pq_reservation_root: String,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl ReserveLowFeeWithdrawalSponsorRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "withdrawal_id": self.withdrawal_id,
            "sponsor_commitment": self.sponsor_commitment,
            "sponsor_budget_root": self.sponsor_budget_root,
            "sponsor_receipt_root": self.sponsor_receipt_root,
            "reserved_fee_bps": self.reserved_fee_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "pq_reservation_root": self.pq_reservation_root,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurnWithdrawalNoteRequest {
    pub withdrawal_id: String,
    pub authorization_id: String,
    pub attestation_id: String,
    pub sponsor_reservation_id: Option<String>,
    pub burn_proof_root: String,
    pub burned_note_root: String,
    pub output_commitment_root: String,
    pub fee_commitment_root: String,
    pub receipt_nullifier: String,
    pub replay_fence: String,
    pub burned_at_height: u64,
}

impl BurnWithdrawalNoteRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "withdrawal_id": self.withdrawal_id,
            "authorization_id": self.authorization_id,
            "attestation_id": self.attestation_id,
            "sponsor_reservation_id": self.sponsor_reservation_id,
            "burn_proof_root": self.burn_proof_root,
            "burned_note_root": self.burned_note_root,
            "output_commitment_root": self.output_commitment_root,
            "fee_commitment_root": self.fee_commitment_root,
            "receipt_nullifier": self.receipt_nullifier,
            "replay_fence": self.replay_fence,
            "burned_at_height": self.burned_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleWithdrawalBatchRequest {
    pub batch_coordinator_id: String,
    pub receipt_ids: Vec<String>,
    pub settlement_root: String,
    pub recursive_proof_root: String,
    pub monero_anchor_root: String,
    pub monero_tx_root: String,
    pub liquidity_snapshot_root: String,
    pub withdrawal_output_root: String,
    pub pq_aggregate_authorization_root: String,
    pub replay_fence: String,
    pub privacy_set_size: u64,
    pub settled_at_height: u64,
}

impl SettleWithdrawalBatchRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_coordinator_id": self.batch_coordinator_id,
            "receipt_ids": self.receipt_ids,
            "settlement_root": self.settlement_root,
            "recursive_proof_root": self.recursive_proof_root,
            "monero_anchor_root": self.monero_anchor_root,
            "monero_tx_root": self.monero_tx_root,
            "liquidity_snapshot_root": self.liquidity_snapshot_root,
            "withdrawal_output_root": self.withdrawal_output_root,
            "pq_aggregate_authorization_root": self.pq_aggregate_authorization_root,
            "replay_fence": self.replay_fence,
            "privacy_set_size": self.privacy_set_size,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateWithdrawalBurnRecord {
    pub withdrawal_id: String,
    pub lane: WithdrawalLane,
    pub note_commitment_root: String,
    pub withdrawal_nullifier: String,
    pub amount: u128,
    pub destination_stealth_address_root: String,
    pub destination_view_tag_root: String,
    pub encrypted_withdrawal_memo_root: String,
    pub change_note_root: String,
    pub fee_commitment_root: String,
    pub max_fee_bps: u64,
    pub user_fee: u128,
    pub privacy_set_size: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub status: WithdrawalRequestStatus,
    pub authorization_id: Option<String>,
    pub attestation_id: Option<String>,
    pub sponsor_reservation_id: Option<String>,
    pub burn_receipt_id: Option<String>,
    pub batch_id: Option<String>,
}

impl PrivateWithdrawalBurnRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "withdrawal_id": self.withdrawal_id,
            "lane": self.lane.as_str(),
            "note_commitment_root": self.note_commitment_root,
            "withdrawal_nullifier": self.withdrawal_nullifier,
            "amount": self.amount,
            "destination_stealth_address_root": self.destination_stealth_address_root,
            "destination_view_tag_root": self.destination_view_tag_root,
            "encrypted_withdrawal_memo_root": self.encrypted_withdrawal_memo_root,
            "change_note_root": self.change_note_root,
            "fee_commitment_root": self.fee_commitment_root,
            "max_fee_bps": self.max_fee_bps,
            "user_fee": self.user_fee,
            "privacy_set_size": self.privacy_set_size,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "authorization_id": self.authorization_id,
            "attestation_id": self.attestation_id,
            "sponsor_reservation_id": self.sponsor_reservation_id,
            "burn_receipt_id": self.burn_receipt_id,
            "batch_id": self.batch_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqWithdrawalAuthorizationRecord {
    pub authorization_id: String,
    pub withdrawal_id: String,
    pub pq_authorization_root: String,
    pub pq_authorization_nullifier: String,
    pub pq_transcript_root: String,
    pub authorizer_commitment: String,
    pub pq_security_bits: u16,
    pub authorized_at_height: u64,
    pub expires_at_height: u64,
    pub status: PqAuthorizationStatus,
}

impl PqWithdrawalAuthorizationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "authorization_id": self.authorization_id,
            "withdrawal_id": self.withdrawal_id,
            "pq_authorization_root": self.pq_authorization_root,
            "pq_authorization_nullifier": self.pq_authorization_nullifier,
            "pq_transcript_root": self.pq_transcript_root,
            "authorizer_commitment": self.authorizer_commitment,
            "pq_security_bits": self.pq_security_bits,
            "authorized_at_height": self.authorized_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquiditySolvencyAttestationRecord {
    pub attestation_id: String,
    pub withdrawal_id: String,
    pub liquidity_attestor_id: String,
    pub liquidity_pool_root: String,
    pub solvency_snapshot_root: String,
    pub withdrawal_liability_root: String,
    pub liquidity_privacy_root: String,
    pub monero_output_capacity_root: String,
    pub available_liquidity_bps: u64,
    pub solvency_bps: u64,
    pub pq_attestation_root: String,
    pub attested_at_height: u64,
    pub status: LiquidityAttestationStatus,
}

impl LiquiditySolvencyAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "withdrawal_id": self.withdrawal_id,
            "liquidity_attestor_id": self.liquidity_attestor_id,
            "liquidity_pool_root": self.liquidity_pool_root,
            "solvency_snapshot_root": self.solvency_snapshot_root,
            "withdrawal_liability_root": self.withdrawal_liability_root,
            "liquidity_privacy_root": self.liquidity_privacy_root,
            "monero_output_capacity_root": self.monero_output_capacity_root,
            "available_liquidity_bps": self.available_liquidity_bps,
            "solvency_bps": self.solvency_bps,
            "pq_attestation_root": self.pq_attestation_root,
            "attested_at_height": self.attested_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSponsorReservationRecord {
    pub reservation_id: String,
    pub withdrawal_id: String,
    pub sponsor_commitment: String,
    pub sponsor_budget_root: String,
    pub sponsor_receipt_root: String,
    pub reserved_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub sponsor_fee: u128,
    pub pq_reservation_root: String,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
    pub status: SponsorReservationStatus,
}

impl LowFeeSponsorReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "withdrawal_id": self.withdrawal_id,
            "sponsor_commitment": self.sponsor_commitment,
            "sponsor_budget_root": self.sponsor_budget_root,
            "sponsor_receipt_root": self.sponsor_receipt_root,
            "reserved_fee_bps": self.reserved_fee_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "sponsor_fee": self.sponsor_fee,
            "pq_reservation_root": self.pq_reservation_root,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurnReceiptRecord {
    pub receipt_id: String,
    pub withdrawal_id: String,
    pub authorization_id: String,
    pub attestation_id: String,
    pub sponsor_reservation_id: Option<String>,
    pub burn_proof_root: String,
    pub burned_note_root: String,
    pub output_commitment_root: String,
    pub fee_commitment_root: String,
    pub receipt_nullifier: String,
    pub replay_fence: String,
    pub amount: u128,
    pub user_fee: u128,
    pub sponsor_fee: u128,
    pub burned_at_height: u64,
    pub status: BurnReceiptStatus,
    pub batch_id: Option<String>,
}

impl BurnReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "withdrawal_id": self.withdrawal_id,
            "authorization_id": self.authorization_id,
            "attestation_id": self.attestation_id,
            "sponsor_reservation_id": self.sponsor_reservation_id,
            "burn_proof_root": self.burn_proof_root,
            "burned_note_root": self.burned_note_root,
            "output_commitment_root": self.output_commitment_root,
            "fee_commitment_root": self.fee_commitment_root,
            "receipt_nullifier": self.receipt_nullifier,
            "replay_fence": self.replay_fence,
            "amount": self.amount,
            "user_fee": self.user_fee,
            "sponsor_fee": self.sponsor_fee,
            "burned_at_height": self.burned_at_height,
            "status": self.status.as_str(),
            "batch_id": self.batch_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalBatchRecord {
    pub batch_id: String,
    pub batch_coordinator_id: String,
    pub receipt_ids: Vec<String>,
    pub settlement_root: String,
    pub recursive_proof_root: String,
    pub monero_anchor_root: String,
    pub monero_tx_root: String,
    pub liquidity_snapshot_root: String,
    pub withdrawal_output_root: String,
    pub pq_aggregate_authorization_root: String,
    pub replay_fence: String,
    pub privacy_set_size: u64,
    pub total_amount: u128,
    pub total_user_fee: u128,
    pub total_sponsor_fee: u128,
    pub settled_at_height: u64,
    pub status: WithdrawalBatchStatus,
}

impl WithdrawalBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "batch_coordinator_id": self.batch_coordinator_id,
            "receipt_ids": self.receipt_ids,
            "settlement_root": self.settlement_root,
            "recursive_proof_root": self.recursive_proof_root,
            "monero_anchor_root": self.monero_anchor_root,
            "monero_tx_root": self.monero_tx_root,
            "liquidity_snapshot_root": self.liquidity_snapshot_root,
            "withdrawal_output_root": self.withdrawal_output_root,
            "pq_aggregate_authorization_root": self.pq_aggregate_authorization_root,
            "replay_fence": self.replay_fence,
            "privacy_set_size": self.privacy_set_size,
            "total_amount": self.total_amount,
            "total_user_fee": self.total_user_fee,
            "total_sponsor_fee": self.total_sponsor_fee,
            "settled_at_height": self.settled_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayFenceRecord {
    pub replay_fence: String,
    pub domain: String,
    pub consumed_by: String,
    pub consumed_at_height: u64,
}

impl ReplayFenceRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "replay_fence": self.replay_fence,
            "domain": self.domain,
            "consumed_by": self.consumed_by,
            "consumed_at_height": self.consumed_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub withdrawals: BTreeMap<String, PrivateWithdrawalBurnRecord>,
    pub pq_authorizations: BTreeMap<String, PqWithdrawalAuthorizationRecord>,
    pub liquidity_attestations: BTreeMap<String, LiquiditySolvencyAttestationRecord>,
    pub sponsor_reservations: BTreeMap<String, LowFeeSponsorReservationRecord>,
    pub burn_receipts: BTreeMap<String, BurnReceiptRecord>,
    pub batches: BTreeMap<String, WithdrawalBatchRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub replay_fences: BTreeMap<String, ReplayFenceRecord>,
    pub events: Vec<Value>,
}

impl State {
    pub fn devnet() -> Self {
        Self::with_config(Config::devnet()).expect("devnet withdrawal note burn config is valid")
    }

    pub fn with_config(config: Config) -> MoneroL2PrivateWithdrawalNoteBurnRuntimeResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            current_height: MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_DEVNET_HEIGHT,
            withdrawals: BTreeMap::new(),
            pq_authorizations: BTreeMap::new(),
            liquidity_attestations: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            burn_receipts: BTreeMap::new(),
            batches: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            replay_fences: BTreeMap::new(),
            events: Vec::new(),
        })
    }

    pub fn submit_private_withdrawal_burn(
        &mut self,
        request: SubmitPrivateWithdrawalBurnRequest,
    ) -> MoneroL2PrivateWithdrawalNoteBurnRuntimeResult<PrivateWithdrawalBurnRecord> {
        self.config.validate()?;
        require(
            self.withdrawals.len() < self.config.max_withdrawals,
            "private withdrawal capacity reached",
        )?;
        required("note_commitment_root", &request.note_commitment_root)?;
        required("withdrawal_nullifier", &request.withdrawal_nullifier)?;
        required(
            "destination_stealth_address_root",
            &request.destination_stealth_address_root,
        )?;
        required(
            "destination_view_tag_root",
            &request.destination_view_tag_root,
        )?;
        required(
            "encrypted_withdrawal_memo_root",
            &request.encrypted_withdrawal_memo_root,
        )?;
        required("change_note_root", &request.change_note_root)?;
        required("fee_commitment_root", &request.fee_commitment_root)?;
        require(request.amount > 0, "withdrawal amount must be positive")?;
        require(
            request.max_fee_bps <= self.config.max_user_fee_bps,
            "withdrawal max fee exceeds runtime cap",
        )?;
        require(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "withdrawal privacy set below runtime minimum",
        )?;
        require(
            request.expires_at_height > request.submitted_at_height,
            "withdrawal expiry must be after submission height",
        )?;
        require(
            !self
                .consumed_nullifiers
                .contains(&request.withdrawal_nullifier),
            "withdrawal nullifier already consumed",
        )?;

        let withdrawal_id = private_withdrawal_burn_id(&request);
        require(
            !self.withdrawals.contains_key(&withdrawal_id),
            "private withdrawal already exists",
        )?;

        let user_fee = fee_amount(request.amount, request.lane.user_fee_bps(&self.config))
            .min(fee_amount(request.amount, request.max_fee_bps));
        let record = PrivateWithdrawalBurnRecord {
            withdrawal_id: withdrawal_id.clone(),
            lane: request.lane,
            note_commitment_root: request.note_commitment_root,
            withdrawal_nullifier: request.withdrawal_nullifier,
            amount: request.amount,
            destination_stealth_address_root: request.destination_stealth_address_root,
            destination_view_tag_root: request.destination_view_tag_root,
            encrypted_withdrawal_memo_root: request.encrypted_withdrawal_memo_root,
            change_note_root: request.change_note_root,
            fee_commitment_root: request.fee_commitment_root,
            max_fee_bps: request.max_fee_bps,
            user_fee,
            privacy_set_size: request.privacy_set_size,
            submitted_at_height: request.submitted_at_height,
            expires_at_height: request.expires_at_height,
            status: WithdrawalRequestStatus::Submitted,
            authorization_id: None,
            attestation_id: None,
            sponsor_reservation_id: None,
            burn_receipt_id: None,
            batch_id: None,
        };

        self.consumed_nullifiers
            .insert(record.withdrawal_nullifier.clone());
        self.withdrawals
            .insert(withdrawal_id.clone(), record.clone());
        self.counters.private_withdrawals_submitted += 1;
        self.counters.nullifiers_consumed += 1;
        self.counters.total_private_amount = self
            .counters
            .total_private_amount
            .saturating_add(record.amount);
        self.counters.total_public_fee = self.counters.total_public_fee.saturating_add(user_fee);
        self.push_event(
            "private_withdrawal_burn_submitted",
            &withdrawal_id,
            record.public_record(),
        );
        Ok(record)
    }

    pub fn authorize_withdrawal_burn(
        &mut self,
        request: AuthorizeWithdrawalBurnRequest,
    ) -> MoneroL2PrivateWithdrawalNoteBurnRuntimeResult<PqWithdrawalAuthorizationRecord> {
        self.config.validate()?;
        require(
            self.pq_authorizations.len() < self.config.max_authorizations,
            "withdrawal authorization capacity reached",
        )?;
        required("withdrawal_id", &request.withdrawal_id)?;
        required("pq_authorization_root", &request.pq_authorization_root)?;
        required(
            "pq_authorization_nullifier",
            &request.pq_authorization_nullifier,
        )?;
        required("pq_transcript_root", &request.pq_transcript_root)?;
        required("authorizer_commitment", &request.authorizer_commitment)?;
        require(
            request.pq_security_bits >= self.config.min_pq_security_bits,
            "withdrawal authorization PQ security bits below runtime minimum",
        )?;
        require(
            request.expires_at_height > request.authorized_at_height,
            "authorization expiry must be after authorization height",
        )?;
        require(
            !self
                .consumed_nullifiers
                .contains(&request.pq_authorization_nullifier),
            "PQ authorization nullifier already consumed",
        )?;
        let withdrawal = self
            .withdrawals
            .get_mut(&request.withdrawal_id)
            .ok_or_else(|| "withdrawal missing for PQ authorization".to_string())?;
        require(withdrawal.status.live(), "withdrawal is not live")?;

        let authorization_id = pq_withdrawal_authorization_id(
            &request.withdrawal_id,
            &request.pq_authorization_root,
            &request.pq_authorization_nullifier,
        );
        require(
            !self.pq_authorizations.contains_key(&authorization_id),
            "PQ withdrawal authorization already exists",
        )?;

        let record = PqWithdrawalAuthorizationRecord {
            authorization_id: authorization_id.clone(),
            withdrawal_id: request.withdrawal_id.clone(),
            pq_authorization_root: request.pq_authorization_root,
            pq_authorization_nullifier: request.pq_authorization_nullifier,
            pq_transcript_root: request.pq_transcript_root,
            authorizer_commitment: request.authorizer_commitment,
            pq_security_bits: request.pq_security_bits,
            authorized_at_height: request.authorized_at_height,
            expires_at_height: request.expires_at_height,
            status: PqAuthorizationStatus::Accepted,
        };

        withdrawal.status = WithdrawalRequestStatus::Authorized;
        withdrawal.authorization_id = Some(authorization_id.clone());
        self.consumed_nullifiers
            .insert(record.pq_authorization_nullifier.clone());
        self.pq_authorizations
            .insert(authorization_id.clone(), record.clone());
        self.counters.pq_authorizations_accepted += 1;
        self.counters.nullifiers_consumed += 1;
        self.push_event(
            "withdrawal_pq_authorized",
            &authorization_id,
            record.public_record(),
        );
        Ok(record)
    }

    pub fn attest_withdrawal_liquidity(
        &mut self,
        request: AttestWithdrawalLiquidityRequest,
    ) -> MoneroL2PrivateWithdrawalNoteBurnRuntimeResult<LiquiditySolvencyAttestationRecord> {
        self.config.validate()?;
        require(
            self.liquidity_attestations.len() < self.config.max_attestations,
            "liquidity attestation capacity reached",
        )?;
        required("withdrawal_id", &request.withdrawal_id)?;
        required("liquidity_attestor_id", &request.liquidity_attestor_id)?;
        required("liquidity_pool_root", &request.liquidity_pool_root)?;
        required("solvency_snapshot_root", &request.solvency_snapshot_root)?;
        required(
            "withdrawal_liability_root",
            &request.withdrawal_liability_root,
        )?;
        required("liquidity_privacy_root", &request.liquidity_privacy_root)?;
        required(
            "monero_output_capacity_root",
            &request.monero_output_capacity_root,
        )?;
        required("pq_attestation_root", &request.pq_attestation_root)?;
        require(
            request.available_liquidity_bps >= self.config.min_liquidity_bps,
            "available liquidity below runtime minimum",
        )?;
        require(
            request.solvency_bps >= self.config.target_solvency_bps,
            "solvency below runtime target",
        )?;
        let withdrawal = self
            .withdrawals
            .get_mut(&request.withdrawal_id)
            .ok_or_else(|| "withdrawal missing for liquidity attestation".to_string())?;
        require(withdrawal.status.live(), "withdrawal is not live")?;
        require(
            withdrawal.authorization_id.is_some(),
            "withdrawal requires PQ authorization before liquidity attestation",
        )?;

        let attestation_id = withdrawal_liquidity_attestation_id(&request);
        require(
            !self.liquidity_attestations.contains_key(&attestation_id),
            "liquidity attestation already exists",
        )?;
        let record = LiquiditySolvencyAttestationRecord {
            attestation_id: attestation_id.clone(),
            withdrawal_id: request.withdrawal_id.clone(),
            liquidity_attestor_id: request.liquidity_attestor_id,
            liquidity_pool_root: request.liquidity_pool_root,
            solvency_snapshot_root: request.solvency_snapshot_root,
            withdrawal_liability_root: request.withdrawal_liability_root,
            liquidity_privacy_root: request.liquidity_privacy_root,
            monero_output_capacity_root: request.monero_output_capacity_root,
            available_liquidity_bps: request.available_liquidity_bps,
            solvency_bps: request.solvency_bps,
            pq_attestation_root: request.pq_attestation_root,
            attested_at_height: request.attested_at_height,
            status: LiquidityAttestationStatus::Accepted,
        };

        withdrawal.status = WithdrawalRequestStatus::LiquidityAttested;
        withdrawal.attestation_id = Some(attestation_id.clone());
        self.liquidity_attestations
            .insert(attestation_id.clone(), record.clone());
        self.counters.liquidity_attestations_accepted += 1;
        self.push_event(
            "withdrawal_liquidity_attested",
            &attestation_id,
            record.public_record(),
        );
        Ok(record)
    }

    pub fn reserve_low_fee_withdrawal_sponsor(
        &mut self,
        request: ReserveLowFeeWithdrawalSponsorRequest,
    ) -> MoneroL2PrivateWithdrawalNoteBurnRuntimeResult<LowFeeSponsorReservationRecord> {
        self.config.validate()?;
        require(
            self.sponsor_reservations.len() < self.config.max_reservations,
            "sponsor reservation capacity reached",
        )?;
        required("withdrawal_id", &request.withdrawal_id)?;
        required("sponsor_commitment", &request.sponsor_commitment)?;
        required("sponsor_budget_root", &request.sponsor_budget_root)?;
        required("sponsor_receipt_root", &request.sponsor_receipt_root)?;
        required("pq_reservation_root", &request.pq_reservation_root)?;
        require(
            request.reserved_fee_bps <= self.config.low_fee_bps,
            "reserved fee exceeds low-fee cap",
        )?;
        require(
            request.sponsor_cover_bps <= self.config.sponsor_cover_bps,
            "sponsor cover exceeds runtime cap",
        )?;
        require(
            request.expires_at_height > request.reserved_at_height,
            "sponsor reservation expiry must be after reservation height",
        )?;
        let withdrawal = self
            .withdrawals
            .get_mut(&request.withdrawal_id)
            .ok_or_else(|| "withdrawal missing for sponsor reservation".to_string())?;
        require(withdrawal.status.live(), "withdrawal is not live")?;
        require(
            matches!(
                withdrawal.lane,
                WithdrawalLane::SponsoredLowFee | WithdrawalLane::Emergency
            ),
            "withdrawal lane is not eligible for low-fee sponsorship",
        )?;

        let reservation_id = low_fee_withdrawal_sponsor_reservation_id(&request);
        require(
            !self.sponsor_reservations.contains_key(&reservation_id),
            "sponsor reservation already exists",
        )?;
        let sponsor_fee = fee_amount(withdrawal.amount, request.sponsor_cover_bps);
        let record = LowFeeSponsorReservationRecord {
            reservation_id: reservation_id.clone(),
            withdrawal_id: request.withdrawal_id.clone(),
            sponsor_commitment: request.sponsor_commitment,
            sponsor_budget_root: request.sponsor_budget_root,
            sponsor_receipt_root: request.sponsor_receipt_root,
            reserved_fee_bps: request.reserved_fee_bps,
            sponsor_cover_bps: request.sponsor_cover_bps,
            sponsor_fee,
            pq_reservation_root: request.pq_reservation_root,
            reserved_at_height: request.reserved_at_height,
            expires_at_height: request.expires_at_height,
            status: SponsorReservationStatus::Reserved,
        };

        withdrawal.status = WithdrawalRequestStatus::SponsorReserved;
        withdrawal.sponsor_reservation_id = Some(reservation_id.clone());
        self.sponsor_reservations
            .insert(reservation_id.clone(), record.clone());
        self.counters.sponsor_reservations_created += 1;
        self.counters.sponsored_withdrawals += 1;
        self.counters.total_sponsor_fee =
            self.counters.total_sponsor_fee.saturating_add(sponsor_fee);
        self.push_event(
            "low_fee_withdrawal_sponsor_reserved",
            &reservation_id,
            record.public_record(),
        );
        Ok(record)
    }

    pub fn burn_withdrawal_note(
        &mut self,
        request: BurnWithdrawalNoteRequest,
    ) -> MoneroL2PrivateWithdrawalNoteBurnRuntimeResult<BurnReceiptRecord> {
        self.config.validate()?;
        require(
            self.burn_receipts.len() < self.config.max_receipts,
            "burn receipt capacity reached",
        )?;
        required("withdrawal_id", &request.withdrawal_id)?;
        required("authorization_id", &request.authorization_id)?;
        required("attestation_id", &request.attestation_id)?;
        required("burn_proof_root", &request.burn_proof_root)?;
        required("burned_note_root", &request.burned_note_root)?;
        required("output_commitment_root", &request.output_commitment_root)?;
        required("fee_commitment_root", &request.fee_commitment_root)?;
        required("receipt_nullifier", &request.receipt_nullifier)?;
        required("replay_fence", &request.replay_fence)?;
        require(
            !self
                .consumed_nullifiers
                .contains(&request.receipt_nullifier),
            "receipt nullifier already consumed",
        )?;
        require(
            !self.replay_fences.contains_key(&request.replay_fence),
            "burn replay fence already consumed",
        )?;

        let withdrawal = self
            .withdrawals
            .get_mut(&request.withdrawal_id)
            .ok_or_else(|| "withdrawal missing for burn".to_string())?;
        require(withdrawal.status.burnable(), "withdrawal is not burnable")?;
        require(
            withdrawal.authorization_id.as_deref() == Some(&request.authorization_id),
            "authorization does not match withdrawal",
        )?;
        require(
            withdrawal.attestation_id.as_deref() == Some(&request.attestation_id),
            "liquidity attestation does not match withdrawal",
        )?;

        let authorization = self
            .pq_authorizations
            .get(&request.authorization_id)
            .ok_or_else(|| "PQ authorization missing for burn".to_string())?;
        require(
            authorization.status.usable(),
            "PQ authorization is not usable",
        )?;
        let attestation = self
            .liquidity_attestations
            .get(&request.attestation_id)
            .ok_or_else(|| "liquidity attestation missing for burn".to_string())?;
        require(
            attestation.status.acceptable(),
            "liquidity attestation is not acceptable",
        )?;

        let mut sponsor_fee = 0_u128;
        if let Some(reservation_id) = &request.sponsor_reservation_id {
            require(
                withdrawal.sponsor_reservation_id.as_ref() == Some(reservation_id),
                "sponsor reservation does not match withdrawal",
            )?;
            let reservation = self
                .sponsor_reservations
                .get(reservation_id)
                .ok_or_else(|| "sponsor reservation missing for burn".to_string())?;
            require(reservation.status.live(), "sponsor reservation is not live")?;
            sponsor_fee = reservation.sponsor_fee;
        }

        let receipt_id = withdrawal_burn_receipt_id(&request);
        require(
            !self.burn_receipts.contains_key(&receipt_id),
            "burn receipt already exists",
        )?;
        let record = BurnReceiptRecord {
            receipt_id: receipt_id.clone(),
            withdrawal_id: request.withdrawal_id.clone(),
            authorization_id: request.authorization_id,
            attestation_id: request.attestation_id,
            sponsor_reservation_id: request.sponsor_reservation_id.clone(),
            burn_proof_root: request.burn_proof_root,
            burned_note_root: request.burned_note_root,
            output_commitment_root: request.output_commitment_root,
            fee_commitment_root: request.fee_commitment_root,
            receipt_nullifier: request.receipt_nullifier.clone(),
            replay_fence: request.replay_fence.clone(),
            amount: withdrawal.amount,
            user_fee: withdrawal.user_fee,
            sponsor_fee,
            burned_at_height: request.burned_at_height,
            status: BurnReceiptStatus::Issued,
            batch_id: None,
        };

        withdrawal.status = WithdrawalRequestStatus::Burned;
        withdrawal.burn_receipt_id = Some(receipt_id.clone());
        if let Some(reservation_id) = &request.sponsor_reservation_id {
            if let Some(reservation) = self.sponsor_reservations.get_mut(reservation_id) {
                reservation.status = SponsorReservationStatus::Consumed;
            }
        }
        self.consumed_nullifiers.insert(request.receipt_nullifier);
        self.replay_fences.insert(
            request.replay_fence.clone(),
            ReplayFenceRecord {
                replay_fence: request.replay_fence,
                domain: self.config.replay_domain.clone(),
                consumed_by: receipt_id.clone(),
                consumed_at_height: request.burned_at_height,
            },
        );
        self.burn_receipts
            .insert(receipt_id.clone(), record.clone());
        self.counters.withdrawal_notes_burned += 1;
        self.counters.burn_receipts_issued += 1;
        self.counters.nullifiers_consumed += 1;
        self.counters.replay_fences_consumed += 1;
        self.push_event(
            "withdrawal_note_burned",
            &receipt_id,
            record.public_record(),
        );
        Ok(record)
    }

    pub fn settle_withdrawal_batch(
        &mut self,
        request: SettleWithdrawalBatchRequest,
    ) -> MoneroL2PrivateWithdrawalNoteBurnRuntimeResult<WithdrawalBatchRecord> {
        self.config.validate()?;
        require(
            self.batches.len() < self.config.max_batches,
            "withdrawal batch capacity reached",
        )?;
        required("batch_coordinator_id", &request.batch_coordinator_id)?;
        required("settlement_root", &request.settlement_root)?;
        required("recursive_proof_root", &request.recursive_proof_root)?;
        required("monero_anchor_root", &request.monero_anchor_root)?;
        required("monero_tx_root", &request.monero_tx_root)?;
        required("liquidity_snapshot_root", &request.liquidity_snapshot_root)?;
        required("withdrawal_output_root", &request.withdrawal_output_root)?;
        required(
            "pq_aggregate_authorization_root",
            &request.pq_aggregate_authorization_root,
        )?;
        required("replay_fence", &request.replay_fence)?;
        require(
            !request.receipt_ids.is_empty(),
            "withdrawal batch requires at least one receipt",
        )?;
        require(
            request.privacy_set_size >= self.config.batch_privacy_set_size,
            "withdrawal batch privacy set below runtime minimum",
        )?;
        require(
            !self.replay_fences.contains_key(&request.replay_fence),
            "batch replay fence already consumed",
        )?;
        let unique_receipts = request.receipt_ids.iter().collect::<BTreeSet<_>>();
        require(
            unique_receipts.len() == request.receipt_ids.len(),
            "batch receipt ids must be unique",
        )?;

        let batch_id = withdrawal_batch_id(&request);
        require(
            !self.batches.contains_key(&batch_id),
            "withdrawal batch already exists",
        )?;

        let mut total_amount = 0_u128;
        let mut total_user_fee = 0_u128;
        let mut total_sponsor_fee = 0_u128;
        for receipt_id in &request.receipt_ids {
            let receipt = self
                .burn_receipts
                .get(receipt_id)
                .ok_or_else(|| format!("burn receipt not found: {receipt_id}"))?;
            require(receipt.status.batchable(), "burn receipt is not batchable")?;
            require(receipt.batch_id.is_none(), "burn receipt already batched")?;
            total_amount = total_amount.saturating_add(receipt.amount);
            total_user_fee = total_user_fee.saturating_add(receipt.user_fee);
            total_sponsor_fee = total_sponsor_fee.saturating_add(receipt.sponsor_fee);
        }

        let record = WithdrawalBatchRecord {
            batch_id: batch_id.clone(),
            batch_coordinator_id: request.batch_coordinator_id,
            receipt_ids: request.receipt_ids.clone(),
            settlement_root: request.settlement_root,
            recursive_proof_root: request.recursive_proof_root,
            monero_anchor_root: request.monero_anchor_root,
            monero_tx_root: request.monero_tx_root,
            liquidity_snapshot_root: request.liquidity_snapshot_root,
            withdrawal_output_root: request.withdrawal_output_root,
            pq_aggregate_authorization_root: request.pq_aggregate_authorization_root,
            replay_fence: request.replay_fence.clone(),
            privacy_set_size: request.privacy_set_size,
            total_amount,
            total_user_fee,
            total_sponsor_fee,
            settled_at_height: request.settled_at_height,
            status: WithdrawalBatchStatus::Settled,
        };

        for receipt_id in &request.receipt_ids {
            let receipt = self
                .burn_receipts
                .get_mut(receipt_id)
                .ok_or_else(|| format!("burn receipt not found: {receipt_id}"))?;
            receipt.status = BurnReceiptStatus::Settled;
            receipt.batch_id = Some(batch_id.clone());
            let withdrawal = self
                .withdrawals
                .get_mut(&receipt.withdrawal_id)
                .ok_or_else(|| "private withdrawal missing for receipt".to_string())?;
            withdrawal.status = WithdrawalRequestStatus::Settled;
            withdrawal.batch_id = Some(batch_id.clone());
        }

        self.replay_fences.insert(
            request.replay_fence.clone(),
            ReplayFenceRecord {
                replay_fence: request.replay_fence,
                domain: self.config.replay_domain.clone(),
                consumed_by: batch_id.clone(),
                consumed_at_height: request.settled_at_height,
            },
        );
        self.batches.insert(batch_id.clone(), record.clone());
        self.counters.withdrawal_batches_settled += 1;
        self.counters.replay_fences_consumed += 1;
        self.push_event(
            "withdrawal_batch_settled",
            &batch_id,
            record.public_record(),
        );
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        let withdrawal_records = self
            .withdrawals
            .values()
            .map(PrivateWithdrawalBurnRecord::public_record)
            .collect::<Vec<_>>();
        let live_withdrawal_records = self
            .withdrawals
            .values()
            .filter(|withdrawal| withdrawal.status.live())
            .map(PrivateWithdrawalBurnRecord::public_record)
            .collect::<Vec<_>>();
        let pq_authorization_records = self
            .pq_authorizations
            .values()
            .map(PqWithdrawalAuthorizationRecord::public_record)
            .collect::<Vec<_>>();
        let liquidity_attestation_records = self
            .liquidity_attestations
            .values()
            .map(LiquiditySolvencyAttestationRecord::public_record)
            .collect::<Vec<_>>();
        let sponsor_reservation_records = self
            .sponsor_reservations
            .values()
            .map(LowFeeSponsorReservationRecord::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .burn_receipts
            .values()
            .map(BurnReceiptRecord::public_record)
            .collect::<Vec<_>>();
        let unsettled_receipt_records = self
            .burn_receipts
            .values()
            .filter(|receipt| receipt.status.batchable())
            .map(BurnReceiptRecord::public_record)
            .collect::<Vec<_>>();
        let batch_records = self
            .batches
            .values()
            .map(WithdrawalBatchRecord::public_record)
            .collect::<Vec<_>>();
        let nullifier_records = self
            .consumed_nullifiers
            .iter()
            .map(|nullifier| json!({ "nullifier": nullifier }))
            .collect::<Vec<_>>();
        let replay_records = self
            .replay_fences
            .values()
            .map(ReplayFenceRecord::public_record)
            .collect::<Vec<_>>();
        let liquidity_privacy_records = self
            .liquidity_attestations
            .values()
            .map(|attestation| {
                json!({
                    "attestation_id": attestation.attestation_id,
                    "liquidity_privacy_root": attestation.liquidity_privacy_root,
                    "solvency_snapshot_root": attestation.solvency_snapshot_root,
                    "withdrawal_liability_root": attestation.withdrawal_liability_root,
                })
            })
            .collect::<Vec<_>>();
        let withdrawal_output_records = self
            .withdrawals
            .values()
            .map(|withdrawal| {
                json!({
                    "withdrawal_id": withdrawal.withdrawal_id,
                    "destination_stealth_address_root": withdrawal.destination_stealth_address_root,
                    "destination_view_tag_root": withdrawal.destination_view_tag_root,
                    "change_note_root": withdrawal.change_note_root,
                })
            })
            .chain(self.burn_receipts.values().map(|receipt| {
                json!({
                    "receipt_id": receipt.receipt_id,
                    "output_commitment_root": receipt.output_commitment_root,
                })
            }))
            .collect::<Vec<_>>();
        let sponsor_records = self
            .sponsor_reservations
            .values()
            .map(|reservation| {
                json!({
                    "reservation_id": reservation.reservation_id,
                    "withdrawal_id": reservation.withdrawal_id,
                    "sponsor_budget_root": reservation.sponsor_budget_root,
                    "sponsor_receipt_root": reservation.sponsor_receipt_root,
                    "sponsor_fee": reservation.sponsor_fee,
                })
            })
            .collect::<Vec<_>>();

        Roots {
            config_root: self.config.state_root(),
            counters_root: self.counters.state_root(),
            withdrawal_root: merkle_root(
                "MONERO-L2-PRIVATE-WITHDRAWAL-NOTE-BURN-WITHDRAWALS",
                &withdrawal_records,
            ),
            live_withdrawal_root: merkle_root(
                "MONERO-L2-PRIVATE-WITHDRAWAL-NOTE-BURN-LIVE-WITHDRAWALS",
                &live_withdrawal_records,
            ),
            pq_authorization_root: merkle_root(
                "MONERO-L2-PRIVATE-WITHDRAWAL-NOTE-BURN-PQ-AUTHORIZATIONS",
                &pq_authorization_records,
            ),
            liquidity_attestation_root: merkle_root(
                "MONERO-L2-PRIVATE-WITHDRAWAL-NOTE-BURN-LIQUIDITY-ATTESTATIONS",
                &liquidity_attestation_records,
            ),
            sponsor_reservation_root: merkle_root(
                "MONERO-L2-PRIVATE-WITHDRAWAL-NOTE-BURN-SPONSOR-RESERVATIONS",
                &sponsor_reservation_records,
            ),
            burn_receipt_root: merkle_root(
                "MONERO-L2-PRIVATE-WITHDRAWAL-NOTE-BURN-RECEIPTS",
                &receipt_records,
            ),
            unsettled_receipt_root: merkle_root(
                "MONERO-L2-PRIVATE-WITHDRAWAL-NOTE-BURN-UNSETTLED-RECEIPTS",
                &unsettled_receipt_records,
            ),
            withdrawal_batch_root: merkle_root(
                "MONERO-L2-PRIVATE-WITHDRAWAL-NOTE-BURN-BATCHES",
                &batch_records,
            ),
            consumed_nullifier_root: merkle_root(
                "MONERO-L2-PRIVATE-WITHDRAWAL-NOTE-BURN-CONSUMED-NULLIFIERS",
                &nullifier_records,
            ),
            replay_fence_root: merkle_root(
                "MONERO-L2-PRIVATE-WITHDRAWAL-NOTE-BURN-REPLAY-FENCES",
                &replay_records,
            ),
            liquidity_privacy_root: merkle_root(
                "MONERO-L2-PRIVATE-WITHDRAWAL-NOTE-BURN-LIQUIDITY-PRIVACY",
                &liquidity_privacy_records,
            ),
            withdrawal_output_root: merkle_root(
                "MONERO-L2-PRIVATE-WITHDRAWAL-NOTE-BURN-OUTPUTS",
                &withdrawal_output_records,
            ),
            sponsor_root: merkle_root(
                "MONERO-L2-PRIVATE-WITHDRAWAL-NOTE-BURN-SPONSORS",
                &sponsor_records,
            ),
            event_root: merkle_root(
                "MONERO-L2-PRIVATE-WITHDRAWAL-NOTE-BURN-EVENTS",
                &self.events,
            ),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": CHAIN_ID,
            "config_root": roots.config_root,
            "counters_root": roots.counters_root,
            "roots_root": roots.state_root(),
            "roots": roots.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        set_json_field(&mut record, "state_root", json!(self.state_root()));
        record
    }

    pub fn state_root(&self) -> String {
        record_hash(
            "MONERO-L2-PRIVATE-WITHDRAWAL-NOTE-BURN-STATE",
            &self.public_record_without_state_root(),
        )
    }

    fn push_event(&mut self, kind: &str, record_id: &str, payload: Value) {
        if self.events.len() >= self.config.max_public_records {
            return;
        }
        let event_id = domain_hash(
            "MONERO-L2-PRIVATE-WITHDRAWAL-NOTE-BURN-EVENT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(kind),
                HashPart::Str(record_id),
                HashPart::Int(self.events.len() as i128),
            ],
            32,
        );
        self.events.push(json!({
            "event_id": event_id,
            "kind": kind,
            "record_id": record_id,
            "payload_root": record_hash("MONERO-L2-PRIVATE-WITHDRAWAL-NOTE-BURN-EVENT-PAYLOAD", &payload),
        }));
    }
}

pub fn monero_l2_private_withdrawal_note_burn_runtime_devnet() -> State {
    State::devnet()
}

pub fn monero_l2_private_withdrawal_note_burn_runtime_state_root(state: &State) -> String {
    state.state_root()
}

pub fn monero_l2_private_withdrawal_note_burn_runtime_public_record(state: &State) -> Value {
    state.public_record()
}

pub fn private_withdrawal_burn_id(request: &SubmitPrivateWithdrawalBurnRequest) -> String {
    domain_hash(
        "MONERO-L2-PRIVATE-WITHDRAWAL-NOTE-BURN-WITHDRAWAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.lane.as_str()),
            HashPart::Str(&request.note_commitment_root),
            HashPart::Str(&request.withdrawal_nullifier),
            HashPart::Str(&request.destination_stealth_address_root),
            HashPart::Str(&request.change_note_root),
            HashPart::Int(request.submitted_at_height as i128),
        ],
        32,
    )
}

pub fn pq_withdrawal_authorization_id(
    withdrawal_id: &str,
    pq_authorization_root: &str,
    pq_authorization_nullifier: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PRIVATE-WITHDRAWAL-NOTE-BURN-PQ-AUTHORIZATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(withdrawal_id),
            HashPart::Str(pq_authorization_root),
            HashPart::Str(pq_authorization_nullifier),
        ],
        32,
    )
}

pub fn withdrawal_liquidity_attestation_id(request: &AttestWithdrawalLiquidityRequest) -> String {
    domain_hash(
        "MONERO-L2-PRIVATE-WITHDRAWAL-NOTE-BURN-LIQUIDITY-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.withdrawal_id),
            HashPart::Str(&request.liquidity_attestor_id),
            HashPart::Str(&request.liquidity_pool_root),
            HashPart::Str(&request.solvency_snapshot_root),
            HashPart::Str(&request.pq_attestation_root),
            HashPart::Int(request.attested_at_height as i128),
        ],
        32,
    )
}

pub fn low_fee_withdrawal_sponsor_reservation_id(
    request: &ReserveLowFeeWithdrawalSponsorRequest,
) -> String {
    domain_hash(
        "MONERO-L2-PRIVATE-WITHDRAWAL-NOTE-BURN-SPONSOR-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.withdrawal_id),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.sponsor_budget_root),
            HashPart::Str(&request.sponsor_receipt_root),
            HashPart::Str(&request.pq_reservation_root),
        ],
        32,
    )
}

pub fn withdrawal_burn_receipt_id(request: &BurnWithdrawalNoteRequest) -> String {
    domain_hash(
        "MONERO-L2-PRIVATE-WITHDRAWAL-NOTE-BURN-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.withdrawal_id),
            HashPart::Str(&request.authorization_id),
            HashPart::Str(&request.attestation_id),
            HashPart::Str(&request.burned_note_root),
            HashPart::Str(&request.receipt_nullifier),
            HashPart::Str(&request.replay_fence),
        ],
        32,
    )
}

pub fn withdrawal_batch_id(request: &SettleWithdrawalBatchRequest) -> String {
    let receipt_root = id_merkle_root(
        "MONERO-L2-PRIVATE-WITHDRAWAL-NOTE-BURN-BATCH-RECEIPT-IDS",
        &request.receipt_ids,
    );
    domain_hash(
        "MONERO-L2-PRIVATE-WITHDRAWAL-NOTE-BURN-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.batch_coordinator_id),
            HashPart::Str(&receipt_root),
            HashPart::Str(&request.settlement_root),
            HashPart::Str(&request.recursive_proof_root),
            HashPart::Str(&request.monero_tx_root),
            HashPart::Str(&request.replay_fence),
        ],
        32,
    )
}

fn fee_amount(amount: u128, fee_bps: u64) -> u128 {
    amount.saturating_mul(fee_bps as u128)
        / MONERO_L2_PRIVATE_WITHDRAWAL_NOTE_BURN_RUNTIME_MAX_BPS as u128
}

fn id_merkle_root(domain: &str, ids: &[String]) -> String {
    let leaves = ids.iter().map(|id| json!({ "id": id })).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn record_hash(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

fn required(field: &str, value: &str) -> MoneroL2PrivateWithdrawalNoteBurnRuntimeResult<()> {
    require(!value.is_empty(), &format!("{field} is required"))
}

fn require(condition: bool, message: &str) -> MoneroL2PrivateWithdrawalNoteBurnRuntimeResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn set_json_field(record: &mut Value, key: &str, value: Value) {
    if let Value::Object(fields) = record {
        fields.insert(key.to_string(), value);
    }
}
