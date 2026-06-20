use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialTokenStreamingRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-token-streaming-runtime-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s-token-streaming-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_STREAM_SCHEME: &str =
    "private-l2-confidential-token-stream-commitment-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_CLIFF_SCHEME: &str =
    "private-l2-confidential-token-stream-cliff-schedule-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_RELEASE_NOTE_SCHEME: &str =
    "private-l2-confidential-token-stream-encrypted-release-note-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_ATTESTATION_SCHEME: &str =
    "private-l2-confidential-token-stream-payer-receiver-attestation-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_SPONSOR_SCHEME: &str =
    "roots-only-low-fee-token-streaming-sponsor-reservation-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_SETTLEMENT_SCHEME: &str =
    "private-l2-confidential-token-streaming-settlement-batch-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_RECEIPT_SCHEME: &str =
    "private-l2-confidential-token-streaming-receipt-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_REBATE_SCHEME: &str =
    "private-l2-confidential-token-streaming-fee-rebate-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_NULLIFIER_SCHEME: &str =
    "private-l2-confidential-token-streaming-nullifier-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEVNET_HEIGHT: u64 = 864_000;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_MONERO_NETWORK: &str =
    "monero-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_L2_NETWORK: &str =
    "nebula-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_FEE_ASSET_ID: &str =
    "piconero-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_STREAM_ASSET_ID: &str =
    "wxmr-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_LOW_FEE_LANE: &str =
    "private-l2-confidential-token-streaming";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_MAX_STREAMS: usize = 2_097_152;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_MAX_CLIFF_SCHEDULES: usize =
    2_097_152;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_MAX_RELEASE_NOTES: usize =
    8_388_608;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_MAX_ATTESTATIONS: usize =
    4_194_304;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_MAX_SPONSOR_RESERVATIONS: usize =
    4_194_304;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_MAX_SETTLEMENT_BATCHES: usize =
    1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_MAX_RECEIPTS: usize = 8_388_608;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_MAX_REBATES: usize = 4_194_304;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_MAX_BATCH_ITEMS: usize = 65_536;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 =
    16_384;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 =
    262_144;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 10;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_MAX_SPONSOR_FEE_BPS: u64 = 6;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_TARGET_REBATE_BPS: u64 = 8;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_STREAM_TTL_BLOCKS: u64 = 7_200;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_RELEASE_NOTE_TTL_BLOCKS: u64 = 48;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 96;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS: u64 = 24;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_MAX_BPS: u64 = 10_000;
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamKind {
    Payroll,
    Subscription,
    ContributorGrant,
    Vesting,
    ProtocolIncentive,
    RevenueShare,
    DaoStipend,
    ContractBound,
}
impl StreamKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Payroll => "payroll",
            Self::Subscription => "subscription",
            Self::ContributorGrant => "contributor_grant",
            Self::Vesting => "vesting",
            Self::ProtocolIncentive => "protocol_incentive",
            Self::RevenueShare => "revenue_share",
            Self::DaoStipend => "dao_stipend",
            Self::ContractBound => "contract_bound",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamStatus {
    Draft,
    PayerAttested,
    ReceiverAttested,
    SponsorReserved,
    Active,
    Paused,
    CliffLocked,
    ReleaseQueued,
    Settling,
    Settled,
    Cancelled,
    Expired,
    Disputed,
}
impl StreamStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::PayerAttested => "payer_attested",
            Self::ReceiverAttested => "receiver_attested",
            Self::SponsorReserved => "sponsor_reserved",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::CliffLocked => "cliff_locked",
            Self::ReleaseQueued => "release_queued",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }
    pub fn accepts_release_notes(self) -> bool {
        matches!(
            self,
            Self::PayerAttested
                | Self::ReceiverAttested
                | Self::SponsorReserved
                | Self::Active
                | Self::Paused
                | Self::CliffLocked
                | Self::ReleaseQueued
        )
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Cancelled | Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CliffKind {
    None,
    BlockHeight,
    Timestamp,
    Milestone,
    AttestedEvent,
    Hybrid,
}
impl CliffKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::BlockHeight => "block_height",
            Self::Timestamp => "timestamp",
            Self::Milestone => "milestone",
            Self::AttestedEvent => "attested_event",
            Self::Hybrid => "hybrid",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseCadence {
    Continuous,
    PerBlock,
    Hourly,
    Daily,
    Weekly,
    Monthly,
    Milestone,
    ManualBatch,
}
impl ReleaseCadence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Continuous => "continuous",
            Self::PerBlock => "per_block",
            Self::Hourly => "hourly",
            Self::Daily => "daily",
            Self::Weekly => "weekly",
            Self::Monthly => "monthly",
            Self::Milestone => "milestone",
            Self::ManualBatch => "manual_batch",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationParty {
    Payer,
    Receiver,
    Sponsor,
    PayrollAdmin,
    SubscriptionMerchant,
    ComplianceOracle,
    ContractHook,
}
impl AttestationParty {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Payer => "payer",
            Self::Receiver => "receiver",
            Self::Sponsor => "sponsor",
            Self::PayrollAdmin => "payroll_admin",
            Self::SubscriptionMerchant => "subscription_merchant",
            Self::ComplianceOracle => "compliance_oracle",
            Self::ContractHook => "contract_hook",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Accepted,
    AcceptedWithDisclosure,
    Watch,
    Hold,
    Rejected,
    Revoked,
}
impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::AcceptedWithDisclosure => "accepted_with_disclosure",
            Self::Watch => "watch",
            Self::Hold => "hold",
            Self::Rejected => "rejected",
            Self::Revoked => "revoked",
        }
    }
    pub fn allows_activation(self) -> bool {
        matches!(
            self,
            Self::Accepted | Self::AcceptedWithDisclosure | Self::Watch
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementBatchStatus {
    Proposed,
    Aggregating,
    Submitted,
    Settled,
    PartiallySettled,
    Disputed,
    Cancelled,
}
impl SettlementBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Aggregating => "aggregating",
            Self::Submitted => "submitted",
            Self::Settled => "settled",
            Self::PartiallySettled => "partially_settled",
            Self::Disputed => "disputed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    StreamOpened,
    CliffScheduled,
    ReleaseNoteAccepted,
    AttestationAccepted,
    SponsorReserved,
    BatchSettled,
    RebatePaid,
    StreamClosed,
}
impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StreamOpened => "stream_opened",
            Self::CliffScheduled => "cliff_scheduled",
            Self::ReleaseNoteAccepted => "release_note_accepted",
            Self::AttestationAccepted => "attestation_accepted",
            Self::SponsorReserved => "sponsor_reserved",
            Self::BatchSettled => "batch_settled",
            Self::RebatePaid => "rebate_paid",
            Self::StreamClosed => "stream_closed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Queued,
    Paid,
    Donated,
    Expired,
    Cancelled,
}
impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Paid => "paid",
            Self::Donated => "donated",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub devnet_height: u64,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub monero_network: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub default_stream_asset_id: String,
    pub low_fee_lane: String,
    pub max_streams: usize,
    pub max_cliff_schedules: usize,
    pub max_release_notes: usize,
    pub max_attestations: usize,
    pub max_sponsor_reservations: usize,
    pub max_settlement_batches: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub max_batch_items: usize,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_sponsor_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub stream_ttl_blocks: u64,
    pub release_note_ttl_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_SCHEMA_VERSION,
            devnet_height: PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEVNET_HEIGHT,
            hash_suite: PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_HASH_SUITE.to_string(),
            pq_auth_suite: PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_PQ_AUTH_SUITE
                .to_string(),
            monero_network: PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_MONERO_NETWORK
                .to_string(),
            l2_network: PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_L2_NETWORK
                .to_string(),
            fee_asset_id: PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_FEE_ASSET_ID
                .to_string(),
            default_stream_asset_id:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_STREAM_ASSET_ID.to_string(),
            low_fee_lane: PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_LOW_FEE_LANE
                .to_string(),
            max_streams: PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_MAX_STREAMS,
            max_cliff_schedules:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_MAX_CLIFF_SCHEDULES,
            max_release_notes:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_MAX_RELEASE_NOTES,
            max_attestations:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_MAX_ATTESTATIONS,
            max_sponsor_reservations:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_MAX_SPONSOR_RESERVATIONS,
            max_settlement_batches:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_MAX_SETTLEMENT_BATCHES,
            max_receipts: PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_MAX_RECEIPTS,
            max_rebates: PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_MAX_REBATES,
            max_batch_items:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_MAX_BATCH_ITEMS,
            min_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            max_sponsor_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_MAX_SPONSOR_FEE_BPS,
            target_rebate_bps:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            stream_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_STREAM_TTL_BLOCKS,
            release_note_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_RELEASE_NOTE_TTL_BLOCKS,
            sponsor_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_SPONSOR_TTL_BLOCKS,
            batch_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_token_streaming_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "devnet_height": self.devnet_height,
            "hash_suite": self.hash_suite,
            "pq_auth_suite": self.pq_auth_suite,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "default_stream_asset_id": self.default_stream_asset_id,
            "low_fee_lane": self.low_fee_lane,
            "max_streams": self.max_streams,
            "max_cliff_schedules": self.max_cliff_schedules,
            "max_release_notes": self.max_release_notes,
            "max_attestations": self.max_attestations,
            "max_sponsor_reservations": self.max_sponsor_reservations,
            "max_settlement_batches": self.max_settlement_batches,
            "max_receipts": self.max_receipts,
            "max_rebates": self.max_rebates,
            "max_batch_items": self.max_batch_items,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_sponsor_fee_bps": self.max_sponsor_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "stream_ttl_blocks": self.stream_ttl_blocks,
            "release_note_ttl_blocks": self.release_note_ttl_blocks,
            "sponsor_ttl_blocks": self.sponsor_ttl_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-CONFIG",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub streams_opened: u64,
    pub cliff_schedules_registered: u64,
    pub release_notes_submitted: u64,
    pub attestations_recorded: u64,
    pub sponsor_reservations: u64,
    pub settlement_batches: u64,
    pub receipts_published: u64,
    pub rebates_published: u64,
    pub nullifiers_seen: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_token_streaming_counters",
            "streams_opened": self.streams_opened,
            "cliff_schedules_registered": self.cliff_schedules_registered,
            "release_notes_submitted": self.release_notes_submitted,
            "attestations_recorded": self.attestations_recorded,
            "sponsor_reservations": self.sponsor_reservations,
            "settlement_batches": self.settlement_batches,
            "receipts_published": self.receipts_published,
            "rebates_published": self.rebates_published,
            "nullifiers_seen": self.nullifiers_seen,
        })
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenStreamRequest {
    pub stream_kind: StreamKind,
    pub asset_id: String,
    pub payer_commitment: String,
    pub receiver_commitment: String,
    pub stream_commitment_root: String,
    pub amount_commitment_root: String,
    pub rate_commitment_root: String,
    pub start_height: u64,
    pub end_height: u64,
    pub cadence: ReleaseCadence,
    pub privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub payer_view_key_root: String,
    pub receiver_view_key_root: String,
    pub metadata_commitment_root: String,
    pub policy_root: String,
    pub pq_open_authorization_root: String,
    pub expiry_height: u64,
}
impl OpenStreamRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "stream_kind": self.stream_kind.as_str(),
            "asset_id": self.asset_id,
            "payer_commitment": self.payer_commitment,
            "receiver_commitment": self.receiver_commitment,
            "stream_commitment_root": self.stream_commitment_root,
            "amount_commitment_root": self.amount_commitment_root,
            "rate_commitment_root": self.rate_commitment_root,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "cadence": self.cadence.as_str(),
            "privacy_set_size": self.privacy_set_size,
            "max_user_fee_bps": self.max_user_fee_bps,
            "payer_view_key_root": self.payer_view_key_root,
            "receiver_view_key_root": self.receiver_view_key_root,
            "metadata_commitment_root": self.metadata_commitment_root,
            "policy_root": self.policy_root,
            "pq_open_authorization_root": self.pq_open_authorization_root,
            "expiry_height": self.expiry_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterCliffScheduleRequest {
    pub stream_id: String,
    pub cliff_kind: CliffKind,
    pub cliff_commitment_root: String,
    pub unlock_height: u64,
    pub milestone_root: String,
    pub withheld_amount_root: String,
    pub encrypted_terms_root: String,
    pub proof_root: String,
    pub pq_schedule_root: String,
}
impl RegisterCliffScheduleRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "stream_id": self.stream_id,
            "cliff_kind": self.cliff_kind.as_str(),
            "cliff_commitment_root": self.cliff_commitment_root,
            "unlock_height": self.unlock_height,
            "milestone_root": self.milestone_root,
            "withheld_amount_root": self.withheld_amount_root,
            "encrypted_terms_root": self.encrypted_terms_root,
            "proof_root": self.proof_root,
            "pq_schedule_root": self.pq_schedule_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitReleaseNoteRequest {
    pub stream_id: String,
    pub release_note_ciphertext_root: String,
    pub release_amount_commitment_root: String,
    pub release_window_start: u64,
    pub release_window_end: u64,
    pub input_note_root: String,
    pub output_note_root: String,
    pub nullifier_root: String,
    pub receiver_hint_root: String,
    pub fee_commitment_root: String,
    pub proof_root: String,
    pub pq_release_root: String,
    pub expiry_height: u64,
}
impl SubmitReleaseNoteRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "stream_id": self.stream_id,
            "release_note_ciphertext_root": self.release_note_ciphertext_root,
            "release_amount_commitment_root": self.release_amount_commitment_root,
            "release_window_start": self.release_window_start,
            "release_window_end": self.release_window_end,
            "input_note_root": self.input_note_root,
            "output_note_root": self.output_note_root,
            "nullifier_root": self.nullifier_root,
            "receiver_hint_root": self.receiver_hint_root,
            "fee_commitment_root": self.fee_commitment_root,
            "proof_root": self.proof_root,
            "pq_release_root": self.pq_release_root,
            "expiry_height": self.expiry_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttestStreamPartyRequest {
    pub stream_id: String,
    pub party: AttestationParty,
    pub verdict: AttestationVerdict,
    pub attestor_commitment: String,
    pub selective_disclosure_root: String,
    pub risk_score_bps: u64,
    pub credential_root: String,
    pub pq_attestation_root: String,
    pub expires_at_height: u64,
}
impl AttestStreamPartyRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "stream_id": self.stream_id,
            "party": self.party.as_str(),
            "verdict": self.verdict.as_str(),
            "attestor_commitment": self.attestor_commitment,
            "selective_disclosure_root": self.selective_disclosure_root,
            "risk_score_bps": self.risk_score_bps,
            "credential_root": self.credential_root,
            "pq_attestation_root": self.pq_attestation_root,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveStreamSponsorRequest {
    pub stream_id: String,
    pub sponsor_commitment: String,
    pub budget_root: String,
    pub fee_asset_id: String,
    pub reserved_fee_bps: u64,
    pub rebate_commitment_root: String,
    pub reservation_proof_root: String,
    pub pq_reservation_root: String,
    pub expires_at_height: u64,
}
impl ReserveStreamSponsorRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "stream_id": self.stream_id,
            "sponsor_commitment": self.sponsor_commitment,
            "budget_root": self.budget_root,
            "fee_asset_id": self.fee_asset_id,
            "reserved_fee_bps": self.reserved_fee_bps,
            "rebate_commitment_root": self.rebate_commitment_root,
            "reservation_proof_root": self.reservation_proof_root,
            "pq_reservation_root": self.pq_reservation_root,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuildStreamSettlementBatchRequest {
    pub operator_commitment: String,
    pub stream_ids: Vec<String>,
    pub release_note_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub aggregate_input_root: String,
    pub aggregate_output_root: String,
    pub aggregate_nullifier_root: String,
    pub aggregate_release_root: String,
    pub batch_fee_root: String,
    pub rebate_root: String,
    pub proof_aggregation_root: String,
    pub pq_batch_root: String,
    pub privacy_set_size: u64,
    pub expires_at_height: u64,
}
impl BuildStreamSettlementBatchRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "operator_commitment": self.operator_commitment,
            "stream_ids": self.stream_ids,
            "release_note_ids": self.release_note_ids,
            "reservation_ids": self.reservation_ids,
            "aggregate_input_root": self.aggregate_input_root,
            "aggregate_output_root": self.aggregate_output_root,
            "aggregate_nullifier_root": self.aggregate_nullifier_root,
            "aggregate_release_root": self.aggregate_release_root,
            "batch_fee_root": self.batch_fee_root,
            "rebate_root": self.rebate_root,
            "proof_aggregation_root": self.proof_aggregation_root,
            "pq_batch_root": self.pq_batch_root,
            "privacy_set_size": self.privacy_set_size,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishStreamReceiptRequest {
    pub batch_id: String,
    pub receipt_kind: ReceiptKind,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub fee_receipt_root: String,
    pub rebate_receipt_root: String,
    pub pq_settlement_root: String,
    pub settled_at_height: u64,
}
impl PublishStreamReceiptRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "receipt_kind": self.receipt_kind.as_str(),
            "settlement_tx_root": self.settlement_tx_root,
            "settlement_proof_root": self.settlement_proof_root,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "fee_receipt_root": self.fee_receipt_root,
            "rebate_receipt_root": self.rebate_receipt_root,
            "pq_settlement_root": self.pq_settlement_root,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishStreamRebateRequest {
    pub stream_id: String,
    pub reservation_id: String,
    pub recipient_commitment: String,
    pub rebate_status: RebateStatus,
    pub rebate_asset_id: String,
    pub rebate_commitment_root: String,
    pub sponsor_fee_bps: u64,
    pub proof_root: String,
    pub pq_rebate_root: String,
    pub paid_at_height: u64,
}
impl PublishStreamRebateRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "stream_id": self.stream_id,
            "reservation_id": self.reservation_id,
            "recipient_commitment": self.recipient_commitment,
            "rebate_status": self.rebate_status.as_str(),
            "rebate_asset_id": self.rebate_asset_id,
            "rebate_commitment_root": self.rebate_commitment_root,
            "sponsor_fee_bps": self.sponsor_fee_bps,
            "proof_root": self.proof_root,
            "pq_rebate_root": self.pq_rebate_root,
            "paid_at_height": self.paid_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StreamRecord {
    pub stream_id: String,
    pub request: OpenStreamRequest,
    pub status: StreamStatus,
    pub opened_at_height: u64,
    pub sequence: u64,
    pub record_root: String,
}
impl StreamRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "stream_record",
            "stream_id": self.stream_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "sequence": self.sequence,
            "record_root": self.record_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CliffScheduleRecord {
    pub cliff_schedule_id: String,
    pub request: RegisterCliffScheduleRequest,
    pub status: StreamStatus,
    pub registered_at_height: u64,
    pub sequence: u64,
    pub record_root: String,
}
impl CliffScheduleRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "cliff_schedule_record",
            "cliff_schedule_id": self.cliff_schedule_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "registered_at_height": self.registered_at_height,
            "sequence": self.sequence,
            "record_root": self.record_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseNoteRecord {
    pub release_note_id: String,
    pub request: SubmitReleaseNoteRequest,
    pub status: StreamStatus,
    pub submitted_at_height: u64,
    pub sequence: u64,
    pub record_root: String,
}
impl ReleaseNoteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "release_note_record",
            "release_note_id": self.release_note_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "sequence": self.sequence,
            "record_root": self.record_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StreamAttestationRecord {
    pub attestation_id: String,
    pub request: AttestStreamPartyRequest,
    pub verdict: AttestationVerdict,
    pub attested_at_height: u64,
    pub sequence: u64,
    pub record_root: String,
}
impl StreamAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "stream_attestation_record",
            "attestation_id": self.attestation_id,
            "request": self.request.public_record(),
            "verdict": self.verdict.as_str(),
            "attested_at_height": self.attested_at_height,
            "sequence": self.sequence,
            "record_root": self.record_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StreamSponsorReservationRecord {
    pub reservation_id: String,
    pub request: ReserveStreamSponsorRequest,
    pub status: SponsorReservationStatus,
    pub reserved_at_height: u64,
    pub sequence: u64,
    pub record_root: String,
}
impl StreamSponsorReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "stream_sponsor_reservation_record",
            "reservation_id": self.reservation_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "reserved_at_height": self.reserved_at_height,
            "sequence": self.sequence,
            "record_root": self.record_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StreamSettlementBatchRecord {
    pub batch_id: String,
    pub request: BuildStreamSettlementBatchRequest,
    pub status: SettlementBatchStatus,
    pub built_at_height: u64,
    pub sequence: u64,
    pub record_root: String,
}
impl StreamSettlementBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "stream_settlement_batch_record",
            "batch_id": self.batch_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "built_at_height": self.built_at_height,
            "sequence": self.sequence,
            "record_root": self.record_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StreamReceiptRecord {
    pub receipt_id: String,
    pub request: PublishStreamReceiptRequest,
    pub kind: ReceiptKind,
    pub published_at_height: u64,
    pub sequence: u64,
    pub record_root: String,
}
impl StreamReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "stream_receipt_record",
            "receipt_id": self.receipt_id,
            "request": self.request.public_record(),
            "kind": self.kind.as_str(),
            "published_at_height": self.published_at_height,
            "sequence": self.sequence,
            "record_root": self.record_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StreamRebateRecord {
    pub rebate_id: String,
    pub request: PublishStreamRebateRequest,
    pub status: RebateStatus,
    pub published_at_height: u64,
    pub sequence: u64,
    pub record_root: String,
}
impl StreamRebateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "stream_rebate_record",
            "rebate_id": self.rebate_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "published_at_height": self.published_at_height,
            "sequence": self.sequence,
            "record_root": self.record_root,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub stream_root: String,
    pub cliff_schedule_root: String,
    pub release_note_root: String,
    pub attestation_root: String,
    pub sponsor_reservation_root: String,
    pub settlement_batch_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub nullifier_root: String,
    pub active_stream_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "stream_root": self.stream_root,
            "cliff_schedule_root": self.cliff_schedule_root,
            "release_note_root": self.release_note_root,
            "attestation_root": self.attestation_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "settlement_batch_root": self.settlement_batch_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
            "nullifier_root": self.nullifier_root,
            "active_stream_root": self.active_stream_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub streams: BTreeMap<String, StreamRecord>,
    pub cliff_schedules: BTreeMap<String, CliffScheduleRecord>,
    pub release_notes: BTreeMap<String, ReleaseNoteRecord>,
    pub attestations: BTreeMap<String, StreamAttestationRecord>,
    pub sponsor_reservations: BTreeMap<String, StreamSponsorReservationRecord>,
    pub settlement_batches: BTreeMap<String, StreamSettlementBatchRecord>,
    pub receipts: BTreeMap<String, StreamReceiptRecord>,
    pub rebates: BTreeMap<String, StreamRebateRecord>,
    pub seen_nullifier_roots: BTreeSet<String>,
    pub active_stream_ids: BTreeSet<String>,
    pub public_records: Vec<Value>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(
            Config::default(),
            PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_DEVNET_HEIGHT,
        )
    }
}

impl State {
    pub fn new(config: Config, current_height: u64) -> Self {
        Self {
            config,
            counters: Counters::default(),
            current_height,
            streams: BTreeMap::new(),
            cliff_schedules: BTreeMap::new(),
            release_notes: BTreeMap::new(),
            attestations: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            seen_nullifier_roots: BTreeSet::new(),
            active_stream_ids: BTreeSet::new(),
            public_records: Vec::new(),
        }
    }

    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn advance_to_height(
        &mut self,
        height: u64,
    ) -> PrivateL2ConfidentialTokenStreamingRuntimeResult<()> {
        if height < self.current_height {
            return Err("cannot rewind confidential token streaming runtime height".to_string());
        }
        self.current_height = height;
        Ok(())
    }
    pub fn open_stream(
        &mut self,
        request: OpenStreamRequest,
    ) -> PrivateL2ConfidentialTokenStreamingRuntimeResult<StreamRecord> {
        self.require_stream_capacity()?;
        require_nonempty("asset_id", &request.asset_id)?;
        require_nonempty("payer_commitment", &request.payer_commitment)?;
        require_nonempty("receiver_commitment", &request.receiver_commitment)?;
        require_nonempty("stream_commitment_root", &request.stream_commitment_root)?;
        require_nonempty("amount_commitment_root", &request.amount_commitment_root)?;
        require_nonempty("rate_commitment_root", &request.rate_commitment_root)?;
        require_nonempty(
            "pq_open_authorization_root",
            &request.pq_open_authorization_root,
        )?;
        require_fee_bps(
            "max_user_fee_bps",
            request.max_user_fee_bps,
            self.config.max_user_fee_bps,
        )?;
        if request.end_height <= request.start_height {
            return Err("stream end_height must be greater than start_height".to_string());
        }
        if request.expiry_height <= self.current_height {
            return Err("stream expiry_height must be in the future".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("stream privacy set is below runtime minimum".to_string());
        }
        let sequence = self.counters.streams_opened + 1;
        let stream_id = stream_id(&request, sequence);
        if self.streams.contains_key(&stream_id) {
            return Err(format!("stream {stream_id} already exists"));
        }
        let record_root = payload_root(
            "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-STREAM-RECORD",
            &request.public_record(),
        );
        let record = StreamRecord {
            stream_id: stream_id.clone(),
            request,
            status: StreamStatus::Draft,
            opened_at_height: self.current_height,
            sequence,
            record_root,
        };
        self.counters.streams_opened = sequence;
        self.active_stream_ids.insert(stream_id.clone());
        self.public_records.push(record.public_record());
        self.streams.insert(stream_id, record.clone());
        Ok(record)
    }

    pub fn register_cliff_schedule(
        &mut self,
        request: RegisterCliffScheduleRequest,
    ) -> PrivateL2ConfidentialTokenStreamingRuntimeResult<CliffScheduleRecord> {
        self.require_cliff_capacity()?;
        self.require_stream_exists(&request.stream_id)?;
        require_nonempty("cliff_commitment_root", &request.cliff_commitment_root)?;
        require_nonempty("encrypted_terms_root", &request.encrypted_terms_root)?;
        require_nonempty("proof_root", &request.proof_root)?;
        require_nonempty("pq_schedule_root", &request.pq_schedule_root)?;
        let sequence = self.counters.cliff_schedules_registered + 1;
        let cliff_schedule_id = cliff_schedule_id(&request, sequence);
        let record_root = payload_root(
            "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-CLIFF-RECORD",
            &request.public_record(),
        );
        let record = CliffScheduleRecord {
            cliff_schedule_id: cliff_schedule_id.clone(),
            request,
            status: StreamStatus::CliffLocked,
            registered_at_height: self.current_height,
            sequence,
            record_root,
        };
        self.counters.cliff_schedules_registered = sequence;
        self.public_records.push(record.public_record());
        self.cliff_schedules
            .insert(cliff_schedule_id, record.clone());
        Ok(record)
    }

    pub fn submit_release_note(
        &mut self,
        request: SubmitReleaseNoteRequest,
    ) -> PrivateL2ConfidentialTokenStreamingRuntimeResult<ReleaseNoteRecord> {
        self.require_release_note_capacity()?;
        self.require_stream_accepts_release_notes(&request.stream_id)?;
        require_nonempty(
            "release_note_ciphertext_root",
            &request.release_note_ciphertext_root,
        )?;
        require_nonempty(
            "release_amount_commitment_root",
            &request.release_amount_commitment_root,
        )?;
        require_nonempty("input_note_root", &request.input_note_root)?;
        require_nonempty("output_note_root", &request.output_note_root)?;
        require_nonempty("nullifier_root", &request.nullifier_root)?;
        require_nonempty("proof_root", &request.proof_root)?;
        require_nonempty("pq_release_root", &request.pq_release_root)?;
        if request.release_window_end <= request.release_window_start {
            return Err("release note window end must be greater than start".to_string());
        }
        if request.expiry_height <= self.current_height {
            return Err("release note expiry_height must be in the future".to_string());
        }
        if self.seen_nullifier_roots.contains(&request.nullifier_root) {
            return Err("release note nullifier root has already been seen".to_string());
        }
        let sequence = self.counters.release_notes_submitted + 1;
        let release_note_id = release_note_id(&request, sequence);
        let record_root = payload_root(
            "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-RELEASE-NOTE-RECORD",
            &request.public_record(),
        );
        let nullifier = request.nullifier_root.clone();
        let record = ReleaseNoteRecord {
            release_note_id: release_note_id.clone(),
            request,
            status: StreamStatus::ReleaseQueued,
            submitted_at_height: self.current_height,
            sequence,
            record_root,
        };
        self.counters.release_notes_submitted = sequence;
        self.counters.nullifiers_seen += 1;
        self.seen_nullifier_roots.insert(nullifier);
        self.public_records.push(record.public_record());
        self.release_notes.insert(release_note_id, record.clone());
        Ok(record)
    }

    pub fn attest_stream_party(
        &mut self,
        request: AttestStreamPartyRequest,
    ) -> PrivateL2ConfidentialTokenStreamingRuntimeResult<StreamAttestationRecord> {
        self.require_attestation_capacity()?;
        self.require_stream_exists(&request.stream_id)?;
        require_nonempty("attestor_commitment", &request.attestor_commitment)?;
        require_nonempty("credential_root", &request.credential_root)?;
        require_nonempty("pq_attestation_root", &request.pq_attestation_root)?;
        require_bps("risk_score_bps", request.risk_score_bps)?;
        if request.expires_at_height <= self.current_height {
            return Err("attestation expires_at_height must be in the future".to_string());
        }
        if !request.verdict.allows_activation() {
            return Err("attestation verdict does not allow stream activation".to_string());
        }
        let sequence = self.counters.attestations_recorded + 1;
        let attestation_id = stream_attestation_id(&request, sequence);
        let record_root = payload_root(
            "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-ATTESTATION-RECORD",
            &request.public_record(),
        );
        let verdict = request.verdict;
        let record = StreamAttestationRecord {
            attestation_id: attestation_id.clone(),
            request,
            verdict,
            attested_at_height: self.current_height,
            sequence,
            record_root,
        };
        self.counters.attestations_recorded = sequence;
        self.public_records.push(record.public_record());
        self.attestations.insert(attestation_id, record.clone());
        Ok(record)
    }

    pub fn reserve_stream_sponsor(
        &mut self,
        request: ReserveStreamSponsorRequest,
    ) -> PrivateL2ConfidentialTokenStreamingRuntimeResult<StreamSponsorReservationRecord> {
        self.require_reservation_capacity()?;
        self.require_stream_exists(&request.stream_id)?;
        require_nonempty("sponsor_commitment", &request.sponsor_commitment)?;
        require_nonempty("budget_root", &request.budget_root)?;
        require_nonempty("fee_asset_id", &request.fee_asset_id)?;
        require_nonempty("reservation_proof_root", &request.reservation_proof_root)?;
        require_nonempty("pq_reservation_root", &request.pq_reservation_root)?;
        require_fee_bps(
            "reserved_fee_bps",
            request.reserved_fee_bps,
            self.config.max_sponsor_fee_bps,
        )?;
        if request.expires_at_height <= self.current_height {
            return Err("sponsor reservation expires_at_height must be in the future".to_string());
        }
        let sequence = self.counters.sponsor_reservations + 1;
        let reservation_id = sponsor_reservation_id(&request, sequence);
        let record_root = payload_root(
            "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-SPONSOR-RECORD",
            &request.public_record(),
        );
        let record = StreamSponsorReservationRecord {
            reservation_id: reservation_id.clone(),
            request,
            status: SponsorReservationStatus::Reserved,
            reserved_at_height: self.current_height,
            sequence,
            record_root,
        };
        self.counters.sponsor_reservations = sequence;
        self.public_records.push(record.public_record());
        self.sponsor_reservations
            .insert(reservation_id, record.clone());
        Ok(record)
    }

    pub fn build_settlement_batch(
        &mut self,
        request: BuildStreamSettlementBatchRequest,
    ) -> PrivateL2ConfidentialTokenStreamingRuntimeResult<StreamSettlementBatchRecord> {
        self.require_batch_capacity()?;
        require_unique("stream_ids", &request.stream_ids)?;
        require_unique("release_note_ids", &request.release_note_ids)?;
        require_unique("reservation_ids", &request.reservation_ids)?;
        if request.release_note_ids.is_empty() {
            return Err("settlement batch must include release notes".to_string());
        }
        if request.release_note_ids.len() > self.config.max_batch_items {
            return Err("settlement batch exceeds max batch items".to_string());
        }
        if request.privacy_set_size < self.config.batch_privacy_set_size {
            return Err("batch privacy set is below runtime minimum".to_string());
        }
        if request.expires_at_height <= self.current_height {
            return Err("settlement batch expires_at_height must be in the future".to_string());
        }
        require_nonempty("operator_commitment", &request.operator_commitment)?;
        require_nonempty("aggregate_input_root", &request.aggregate_input_root)?;
        require_nonempty("aggregate_output_root", &request.aggregate_output_root)?;
        require_nonempty(
            "aggregate_nullifier_root",
            &request.aggregate_nullifier_root,
        )?;
        require_nonempty("aggregate_release_root", &request.aggregate_release_root)?;
        require_nonempty("proof_aggregation_root", &request.proof_aggregation_root)?;
        require_nonempty("pq_batch_root", &request.pq_batch_root)?;
        for id in &request.stream_ids {
            self.require_stream_exists(id)?;
        }
        for id in &request.release_note_ids {
            self.require_release_note_exists(id)?;
        }
        for id in &request.reservation_ids {
            self.require_reservation_exists(id)?;
        }
        let sequence = self.counters.settlement_batches + 1;
        let batch_id = settlement_batch_id(&request, sequence);
        let record_root = payload_root(
            "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-BATCH-RECORD",
            &request.public_record(),
        );
        let record = StreamSettlementBatchRecord {
            batch_id: batch_id.clone(),
            request,
            status: SettlementBatchStatus::Proposed,
            built_at_height: self.current_height,
            sequence,
            record_root,
        };
        self.counters.settlement_batches = sequence;
        self.public_records.push(record.public_record());
        self.settlement_batches.insert(batch_id, record.clone());
        Ok(record)
    }

    pub fn publish_receipt(
        &mut self,
        request: PublishStreamReceiptRequest,
    ) -> PrivateL2ConfidentialTokenStreamingRuntimeResult<StreamReceiptRecord> {
        self.require_receipt_capacity()?;
        self.require_batch_exists(&request.batch_id)?;
        require_nonempty("settlement_tx_root", &request.settlement_tx_root)?;
        require_nonempty("settlement_proof_root", &request.settlement_proof_root)?;
        require_nonempty("state_root_before", &request.state_root_before)?;
        require_nonempty("state_root_after", &request.state_root_after)?;
        require_nonempty("pq_settlement_root", &request.pq_settlement_root)?;
        let sequence = self.counters.receipts_published + 1;
        let receipt_id = stream_receipt_id(&request, sequence);
        let record_root = payload_root(
            "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-RECEIPT-RECORD",
            &request.public_record(),
        );
        let kind = request.receipt_kind;
        let record = StreamReceiptRecord {
            receipt_id: receipt_id.clone(),
            request,
            kind,
            published_at_height: self.current_height,
            sequence,
            record_root,
        };
        self.counters.receipts_published = sequence;
        self.public_records.push(record.public_record());
        self.receipts.insert(receipt_id, record.clone());
        Ok(record)
    }

    pub fn publish_rebate(
        &mut self,
        request: PublishStreamRebateRequest,
    ) -> PrivateL2ConfidentialTokenStreamingRuntimeResult<StreamRebateRecord> {
        self.require_rebate_capacity()?;
        self.require_stream_exists(&request.stream_id)?;
        self.require_reservation_exists(&request.reservation_id)?;
        require_nonempty("recipient_commitment", &request.recipient_commitment)?;
        require_nonempty("rebate_asset_id", &request.rebate_asset_id)?;
        require_nonempty("rebate_commitment_root", &request.rebate_commitment_root)?;
        require_nonempty("proof_root", &request.proof_root)?;
        require_nonempty("pq_rebate_root", &request.pq_rebate_root)?;
        require_fee_bps(
            "sponsor_fee_bps",
            request.sponsor_fee_bps,
            self.config.max_sponsor_fee_bps,
        )?;
        let sequence = self.counters.rebates_published + 1;
        let rebate_id = stream_rebate_id(&request, sequence);
        let record_root = payload_root(
            "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-REBATE-RECORD",
            &request.public_record(),
        );
        let status = request.rebate_status;
        let record = StreamRebateRecord {
            rebate_id: rebate_id.clone(),
            request,
            status,
            published_at_height: self.current_height,
            sequence,
            record_root,
        };
        self.counters.rebates_published = sequence;
        self.public_records.push(record.public_record());
        self.rebates.insert(rebate_id, record.clone());
        Ok(record)
    }
    pub fn roots(&self) -> Roots {
        let stream_records = self
            .streams
            .values()
            .map(StreamRecord::public_record)
            .collect::<Vec<_>>();
        let cliff_records = self
            .cliff_schedules
            .values()
            .map(CliffScheduleRecord::public_record)
            .collect::<Vec<_>>();
        let release_records = self
            .release_notes
            .values()
            .map(ReleaseNoteRecord::public_record)
            .collect::<Vec<_>>();
        let attestation_records = self
            .attestations
            .values()
            .map(StreamAttestationRecord::public_record)
            .collect::<Vec<_>>();
        let reservation_records = self
            .sponsor_reservations
            .values()
            .map(StreamSponsorReservationRecord::public_record)
            .collect::<Vec<_>>();
        let batch_records = self
            .settlement_batches
            .values()
            .map(StreamSettlementBatchRecord::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .receipts
            .values()
            .map(StreamReceiptRecord::public_record)
            .collect::<Vec<_>>();
        let rebate_records = self
            .rebates
            .values()
            .map(StreamRebateRecord::public_record)
            .collect::<Vec<_>>();
        let nullifier_records = self
            .seen_nullifier_roots
            .iter()
            .map(|root| json!({ "nullifier_root": root }))
            .collect::<Vec<_>>();
        Roots {
            stream_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-STREAM",
                &stream_records,
            ),
            cliff_schedule_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-CLIFF",
                &cliff_records,
            ),
            release_note_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-RELEASE-NOTE",
                &release_records,
            ),
            attestation_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-ATTESTATION",
                &attestation_records,
            ),
            sponsor_reservation_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-SPONSOR",
                &reservation_records,
            ),
            settlement_batch_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-BATCH",
                &batch_records,
            ),
            receipt_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-RECEIPT",
                &receipt_records,
            ),
            rebate_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-REBATE",
                &rebate_records,
            ),
            nullifier_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-NULLIFIER",
                &nullifier_records,
            ),
            active_stream_root: id_list_root(
                "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-ACTIVE-STREAM",
                self.active_stream_ids.iter(),
            ),
            public_record_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-PUBLIC-RECORD",
                &self.public_records,
            ),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_token_streaming_runtime",
            "protocol_version": PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_SCHEMA_VERSION,
            "hash_suite": PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_HASH_SUITE,
            "pq_auth_suite": PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_PQ_AUTH_SUITE,
            "stream_scheme": PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_STREAM_SCHEME,
            "cliff_scheme": PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_CLIFF_SCHEME,
            "release_note_scheme": PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_RELEASE_NOTE_SCHEME,
            "attestation_scheme": PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_ATTESTATION_SCHEME,
            "sponsor_scheme": PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_SPONSOR_SCHEME,
            "settlement_scheme": PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_SETTLEMENT_SCHEME,
            "receipt_scheme": PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_RECEIPT_SCHEME,
            "rebate_scheme": PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_REBATE_SCHEME,
            "nullifier_scheme": PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_NULLIFIER_SCHEME,
            "config": self.config.public_record(),
            "config_root": self.config.state_root(),
            "counters": self.counters.public_record(),
            "current_height": self.current_height,
            "roots": self.roots().public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let record = self.public_record_without_state_root();
        let state_root = root_from_record("PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-STATE", &record);
        json!({ "state_root": state_root, "record": record })
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-STATE",
            &self.public_record_without_state_root(),
        )
    }

    fn require_stream_exists(
        &self,
        stream_id: &str,
    ) -> PrivateL2ConfidentialTokenStreamingRuntimeResult<()> {
        require_nonempty("stream_id", stream_id)?;
        if !self.streams.contains_key(stream_id) {
            return Err(format!("stream {stream_id} does not exist"));
        }
        Ok(())
    }
    fn require_stream_accepts_release_notes(
        &self,
        stream_id: &str,
    ) -> PrivateL2ConfidentialTokenStreamingRuntimeResult<()> {
        self.require_stream_exists(stream_id)?;
        let stream = self
            .streams
            .get(stream_id)
            .expect("stream existence checked");
        if !stream.status.accepts_release_notes() {
            return Err(format!("stream {stream_id} does not accept release notes"));
        }
        Ok(())
    }
    fn require_release_note_exists(
        &self,
        release_note_id: &str,
    ) -> PrivateL2ConfidentialTokenStreamingRuntimeResult<()> {
        require_nonempty("release_note_id", release_note_id)?;
        if !self.release_notes.contains_key(release_note_id) {
            return Err(format!("release note {release_note_id} does not exist"));
        }
        Ok(())
    }
    fn require_reservation_exists(
        &self,
        reservation_id: &str,
    ) -> PrivateL2ConfidentialTokenStreamingRuntimeResult<()> {
        require_nonempty("reservation_id", reservation_id)?;
        if !self.sponsor_reservations.contains_key(reservation_id) {
            return Err(format!(
                "sponsor reservation {reservation_id} does not exist"
            ));
        }
        Ok(())
    }
    fn require_batch_exists(
        &self,
        batch_id: &str,
    ) -> PrivateL2ConfidentialTokenStreamingRuntimeResult<()> {
        require_nonempty("batch_id", batch_id)?;
        if !self.settlement_batches.contains_key(batch_id) {
            return Err(format!("settlement batch {batch_id} does not exist"));
        }
        Ok(())
    }
    fn require_stream_capacity(&self) -> PrivateL2ConfidentialTokenStreamingRuntimeResult<()> {
        if self.streams.len() >= self.config.max_streams {
            return Err("stream capacity exhausted".to_string());
        }
        Ok(())
    }
    fn require_cliff_capacity(&self) -> PrivateL2ConfidentialTokenStreamingRuntimeResult<()> {
        if self.cliff_schedules.len() >= self.config.max_cliff_schedules {
            return Err("cliff schedule capacity exhausted".to_string());
        }
        Ok(())
    }
    fn require_release_note_capacity(
        &self,
    ) -> PrivateL2ConfidentialTokenStreamingRuntimeResult<()> {
        if self.release_notes.len() >= self.config.max_release_notes {
            return Err("release note capacity exhausted".to_string());
        }
        Ok(())
    }
    fn require_attestation_capacity(&self) -> PrivateL2ConfidentialTokenStreamingRuntimeResult<()> {
        if self.attestations.len() >= self.config.max_attestations {
            return Err("attestation capacity exhausted".to_string());
        }
        Ok(())
    }
    fn require_reservation_capacity(&self) -> PrivateL2ConfidentialTokenStreamingRuntimeResult<()> {
        if self.sponsor_reservations.len() >= self.config.max_sponsor_reservations {
            return Err("sponsor reservation capacity exhausted".to_string());
        }
        Ok(())
    }
    fn require_batch_capacity(&self) -> PrivateL2ConfidentialTokenStreamingRuntimeResult<()> {
        if self.settlement_batches.len() >= self.config.max_settlement_batches {
            return Err("settlement batch capacity exhausted".to_string());
        }
        Ok(())
    }
    fn require_receipt_capacity(&self) -> PrivateL2ConfidentialTokenStreamingRuntimeResult<()> {
        if self.receipts.len() >= self.config.max_receipts {
            return Err("receipt capacity exhausted".to_string());
        }
        Ok(())
    }
    fn require_rebate_capacity(&self) -> PrivateL2ConfidentialTokenStreamingRuntimeResult<()> {
        if self.rebates.len() >= self.config.max_rebates {
            return Err("rebate capacity exhausted".to_string());
        }
        Ok(())
    }
}
pub type Runtime = State;

pub fn stream_id(request: &OpenStreamRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-STREAM-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}
pub fn cliff_schedule_id(request: &RegisterCliffScheduleRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-CLIFF-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}
pub fn release_note_id(request: &SubmitReleaseNoteRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-RELEASE-NOTE-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}
pub fn stream_attestation_id(request: &AttestStreamPartyRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-ATTESTATION-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}
pub fn sponsor_reservation_id(request: &ReserveStreamSponsorRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-SPONSOR-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}
pub fn settlement_batch_id(request: &BuildStreamSettlementBatchRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-BATCH-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}
pub fn stream_receipt_id(request: &PublishStreamReceiptRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-RECEIPT-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}
pub fn stream_rebate_id(request: &PublishStreamRebateRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-REBATE-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}
pub fn payload_root(domain: &str, payload: &Value) -> String {
    root_from_record(domain, payload)
}
pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    let leaves = records
        .iter()
        .enumerate()
        .map(|(index, record)| {
            Value::String(root_from_record(
                domain,
                &json!({ "index": index, "record": record }),
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}
pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-STATE-ROOT", record)
}
fn payload_id(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}
fn record_root<I>(domain: &str, records: I) -> String
where
    I: Iterator<Item = Value>,
{
    public_record_root(domain, &records.collect::<Vec<_>>())
}
fn id_list_root<'a, I>(domain: &str, ids: I) -> String
where
    I: Iterator<Item = &'a String>,
{
    let leaves = ids
        .enumerate()
        .map(|(index, id)| {
            Value::String(domain_hash(
                domain,
                &[HashPart::Int(index as i128), HashPart::Str(id)],
                32,
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}
fn require_nonempty(
    field: &str,
    value: &str,
) -> PrivateL2ConfidentialTokenStreamingRuntimeResult<()> {
    if value.is_empty() {
        return Err(format!("{field} cannot be empty"));
    }
    Ok(())
}
fn require_bps(field: &str, value: u64) -> PrivateL2ConfidentialTokenStreamingRuntimeResult<()> {
    if value > PRIVATE_L2_CONFIDENTIAL_TOKEN_STREAMING_RUNTIME_MAX_BPS {
        return Err(format!("{field} exceeds 10000 bps"));
    }
    Ok(())
}
fn require_fee_bps(
    field: &str,
    value: u64,
    maximum: u64,
) -> PrivateL2ConfidentialTokenStreamingRuntimeResult<()> {
    require_bps(field, value)?;
    if value > maximum {
        return Err(format!("{field} exceeds runtime maximum of {maximum} bps"));
    }
    Ok(())
}
fn require_unique(
    field: &str,
    values: &[String],
) -> PrivateL2ConfidentialTokenStreamingRuntimeResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if value.is_empty() {
            return Err(format!("{field} cannot contain empty ids"));
        }
        if !seen.insert(value) {
            return Err(format!("{field} contains duplicate id {value}"));
        }
    }
    Ok(())
}
pub fn stream_commitment_root(record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-STREAM-COMMITMENT",
        record,
    )
}
pub fn cliff_commitment_root(record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-CLIFF-COMMITMENT",
        record,
    )
}
pub fn encrypted_release_note_root(record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-ENCRYPTED-RELEASE-NOTE",
        record,
    )
}
pub fn payer_attestation_root(record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-PAYER-ATTESTATION",
        record,
    )
}
pub fn receiver_attestation_root(record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-RECEIVER-ATTESTATION",
        record,
    )
}
pub fn sponsor_reservation_root(record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-SPONSOR-RESERVATION",
        record,
    )
}
pub fn settlement_receipt_root(record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-SETTLEMENT-RECEIPT",
        record,
    )
}
pub fn fee_rebate_root(record: &Value) -> String {
    root_from_record("PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-FEE-REBATE", record)
}
pub fn nullifier_commitment_root(record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-NULLIFIER-COMMITMENT",
        record,
    )
}
pub fn payroll_lane_root(record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-PAYROLL-LANE",
        record,
    )
}
pub fn subscription_lane_root(record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-SUBSCRIPTION-LANE",
        record,
    )
}
pub fn low_fee_lane_root(record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-LOW-FEE-LANE",
        record,
    )
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PayrollCycleView {
    pub stream_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl PayrollCycleView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "payroll_cycle_view",
            "stream_id": self.stream_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-PAYROLLCYCLEVIEW",
            &self.public_record(),
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PayrollEmployeeView {
    pub stream_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl PayrollEmployeeView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "payroll_employee_view",
            "stream_id": self.stream_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-PAYROLLEMPLOYEEVIEW",
            &self.public_record(),
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PayrollEmployerView {
    pub stream_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl PayrollEmployerView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "payroll_employer_view",
            "stream_id": self.stream_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-PAYROLLEMPLOYERVIEW",
            &self.public_record(),
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubscriptionMerchantView {
    pub stream_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl SubscriptionMerchantView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "subscription_merchant_view",
            "stream_id": self.stream_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-SUBSCRIPTIONMERCHANTVIEW",
            &self.public_record(),
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubscriptionSubscriberView {
    pub stream_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl SubscriptionSubscriberView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "subscription_subscriber_view",
            "stream_id": self.stream_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-SUBSCRIPTIONSUBSCRIBERVIEW",
            &self.public_record(),
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubscriptionRenewalView {
    pub stream_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl SubscriptionRenewalView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "subscription_renewal_view",
            "stream_id": self.stream_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-SUBSCRIPTIONRENEWALVIEW",
            &self.public_record(),
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GrantVestingView {
    pub stream_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl GrantVestingView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "grant_vesting_view",
            "stream_id": self.stream_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-GRANTVESTINGVIEW",
            &self.public_record(),
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RevenueShareView {
    pub stream_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl RevenueShareView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "revenue_share_view",
            "stream_id": self.stream_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-REVENUESHAREVIEW",
            &self.public_record(),
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DaoStipendView {
    pub stream_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl DaoStipendView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "dao_stipend_view",
            "stream_id": self.stream_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-DAOSTIPENDVIEW",
            &self.public_record(),
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractHookView {
    pub stream_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl ContractHookView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "contract_hook_view",
            "stream_id": self.stream_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-CONTRACTHOOKVIEW",
            &self.public_record(),
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StreamLiquidityView {
    pub stream_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl StreamLiquidityView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "stream_liquidity_view",
            "stream_id": self.stream_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-STREAMLIQUIDITYVIEW",
            &self.public_record(),
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeSponsorBudgetView {
    pub stream_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl FeeSponsorBudgetView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_sponsor_budget_view",
            "stream_id": self.stream_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-FEESPONSORBUDGETVIEW",
            &self.public_record(),
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofAggregationView {
    pub stream_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl ProofAggregationView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_aggregation_view",
            "stream_id": self.stream_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-PROOFAGGREGATIONVIEW",
            &self.public_record(),
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedMemoView {
    pub stream_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl EncryptedMemoView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_memo_view",
            "stream_id": self.stream_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-ENCRYPTEDMEMOVIEW",
            &self.public_record(),
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SelectiveDisclosureView {
    pub stream_id: String,
    pub asset_id: String,
    pub commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub effective_height: u64,
    pub expires_at_height: u64,
}

impl SelectiveDisclosureView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "selective_disclosure_view",
            "stream_id": self.stream_id,
            "asset_id": self.asset_id,
            "commitment_root": self.commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-TOKEN-STREAMING-SELECTIVEDISCLOSUREVIEW",
            &self.public_record(),
        )
    }
}
