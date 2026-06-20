use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialContractStateChannelRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-state-channel-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-state-channel-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_ENCRYPTION_SUITE: &str =
    "ML-KEM-1024+XChaCha20-Poly1305+view-tagged-state-delta-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_PROOF_SUITE: &str =
    "zk-pq-confidential-contract-channel-proof-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEVNET_HEIGHT: u64 = 812_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_MAX_CHANNELS: usize =
    1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_MAX_PARTICIPANTS:
    usize = 8_388_608;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_MAX_ATTESTATIONS:
    usize = 8_388_608;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_MAX_STATE_UPDATES:
    usize = 33_554_432;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_MAX_DISPUTES: usize =
    4_194_304;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_MAX_RESERVATIONS:
    usize = 8_388_608;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_MAX_BATCHES: usize =
    2_097_152;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_MAX_RECEIPTS: usize =
    33_554_432;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_MAX_REBATES: usize =
    16_777_216;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_MIN_PRIVACY_SET: usize =
    256;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_BATCH_PRIVACY_SET:
    usize = 2_048;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS:
    u16 = 256;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_DISPUTE_WINDOW_BLOCKS:
    u64 = 180;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_UPDATE_TTL_BLOCKS: u64 =
    96;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS:
    u64 = 72;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS:
    u64 = 48;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 =
    12;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_TARGET_REBATE_BPS: u64 =
    8;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_SPONSOR_RESERVE_UNITS:
    u64 = 500_000_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelKind {
    PrivatePayment,
    ContractCall,
    DefiIntent,
    AmmSwap,
    LendingPosition,
    PerpetualMargin,
    OptionsExercise,
    BridgeExit,
    GovernanceVote,
    VaultStrategy,
    Custom,
}

impl ChannelKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivatePayment => "private_payment",
            Self::ContractCall => "contract_call",
            Self::DefiIntent => "defi_intent",
            Self::AmmSwap => "amm_swap",
            Self::LendingPosition => "lending_position",
            Self::PerpetualMargin => "perpetual_margin",
            Self::OptionsExercise => "options_exercise",
            Self::BridgeExit => "bridge_exit",
            Self::GovernanceVote => "governance_vote",
            Self::VaultStrategy => "vault_strategy",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelStatus {
    Proposed,
    Open,
    Updating,
    Settling,
    Disputed,
    Finalized,
    Cancelled,
    Expired,
    Slashed,
}

impl ChannelStatus {
    pub fn accepts_updates(self) -> bool {
        matches!(self, Self::Open | Self::Updating)
    }

    pub fn accepts_disputes(self) -> bool {
        matches!(self, Self::Open | Self::Updating | Self::Settling)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ParticipantRole {
    Initiator,
    Counterparty,
    Watcher,
    Sponsor,
    Solver,
    Oracle,
    Sequencer,
    RecoveryGuardian,
}

impl ParticipantRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Initiator => "initiator",
            Self::Counterparty => "counterparty",
            Self::Watcher => "watcher",
            Self::Sponsor => "sponsor",
            Self::Solver => "solver",
            Self::Oracle => "oracle",
            Self::Sequencer => "sequencer",
            Self::RecoveryGuardian => "recovery_guardian",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ParticipantStatus {
    Invited,
    Attested,
    Active,
    Rotating,
    Suspended,
    Exited,
    Slashed,
}

impl ParticipantStatus {
    pub fn can_sign(self) -> bool {
        matches!(self, Self::Attested | Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    PqIdentity,
    PqSessionKey,
    ContractCapability,
    LiquidityCapability,
    WatcherCapability,
    SponsorCapability,
    PrivacySetMembership,
    EmergencyRecovery,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqIdentity => "pq_identity",
            Self::PqSessionKey => "pq_session_key",
            Self::ContractCapability => "contract_capability",
            Self::LiquidityCapability => "liquidity_capability",
            Self::WatcherCapability => "watcher_capability",
            Self::SponsorCapability => "sponsor_capability",
            Self::PrivacySetMembership => "privacy_set_membership",
            Self::EmergencyRecovery => "emergency_recovery",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateKind {
    OpenState,
    ContractCall,
    TokenTransfer,
    SwapFill,
    MarginMove,
    OracleRefresh,
    NettingStep,
    FeeReprice,
    CloseIntent,
    EmergencyExit,
}

impl UpdateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OpenState => "open_state",
            Self::ContractCall => "contract_call",
            Self::TokenTransfer => "token_transfer",
            Self::SwapFill => "swap_fill",
            Self::MarginMove => "margin_move",
            Self::OracleRefresh => "oracle_refresh",
            Self::NettingStep => "netting_step",
            Self::FeeReprice => "fee_reprice",
            Self::CloseIntent => "close_intent",
            Self::EmergencyExit => "emergency_exit",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateStatus {
    Proposed,
    Attested,
    Encrypted,
    Applied,
    Superseded,
    Rejected,
    Expired,
    Disputed,
}

impl UpdateStatus {
    pub fn can_settle(self) -> bool {
        matches!(self, Self::Attested | Self::Encrypted | Self::Applied)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeKind {
    StaleState,
    InvalidSignature,
    InvalidTransition,
    MissingWitness,
    FeeOvercharge,
    PrivacyLeak,
    SponsorDefault,
    SequencerCensorship,
    EmergencyPause,
}

impl DisputeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaleState => "stale_state",
            Self::InvalidSignature => "invalid_signature",
            Self::InvalidTransition => "invalid_transition",
            Self::MissingWitness => "missing_witness",
            Self::FeeOvercharge => "fee_overcharge",
            Self::PrivacyLeak => "privacy_leak",
            Self::SponsorDefault => "sponsor_default",
            Self::SequencerCensorship => "sequencer_censorship",
            Self::EmergencyPause => "emergency_pause",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeStatus {
    Open,
    EvidencePosted,
    Countered,
    Resolved,
    TimedOut,
    Slashed,
    Cancelled,
}

impl DisputeStatus {
    pub fn active(self) -> bool {
        matches!(self, Self::Open | Self::EvidencePosted | Self::Countered)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorReservationStatus {
    Reserved,
    Locked,
    Consumed,
    RebateQueued,
    Refunded,
    Expired,
    Slashed,
}

impl SponsorReservationStatus {
    pub fn spendable(self) -> bool {
        matches!(self, Self::Reserved | Self::Locked)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementBatchStatus {
    Proposed,
    Proving,
    Published,
    Finalized,
    PartiallyFinalized,
    Disputed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    ChannelOpened,
    ParticipantAttested,
    StateUpdated,
    DisputeOpened,
    DisputeResolved,
    SponsorReserved,
    SettlementPublished,
    RebatePublished,
    NullifierFenceRaised,
    PrivacyFenceAudited,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ChannelOpened => "channel_opened",
            Self::ParticipantAttested => "participant_attested",
            Self::StateUpdated => "state_updated",
            Self::DisputeOpened => "dispute_opened",
            Self::DisputeResolved => "dispute_resolved",
            Self::SponsorReserved => "sponsor_reserved",
            Self::SettlementPublished => "settlement_published",
            Self::RebatePublished => "rebate_published",
            Self::NullifierFenceRaised => "nullifier_fence_raised",
            Self::PrivacyFenceAudited => "privacy_fence_audited",
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
    pub encryption_suite: String,
    pub proof_suite: String,
    pub max_channels: usize,
    pub max_participants: usize,
    pub max_attestations: usize,
    pub max_state_updates: usize,
    pub max_disputes: usize,
    pub max_sponsor_reservations: usize,
    pub max_batches: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub min_privacy_set: usize,
    pub batch_privacy_set: usize,
    pub min_pq_security_bits: u16,
    pub dispute_window_blocks: u64,
    pub update_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub sponsor_reserve_units: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_PROTOCOL_VERSION
                    .to_string(),
            schema_version:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_SCHEMA_VERSION,
            devnet_height: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEVNET_HEIGHT,
            hash_suite: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_HASH_SUITE
                .to_string(),
            pq_auth_suite:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_PQ_AUTH_SUITE
                    .to_string(),
            encryption_suite:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_ENCRYPTION_SUITE
                    .to_string(),
            proof_suite: PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_PROOF_SUITE
                .to_string(),
            max_channels:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_MAX_CHANNELS,
            max_participants:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_MAX_PARTICIPANTS,
            max_attestations:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_MAX_ATTESTATIONS,
            max_state_updates:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_MAX_STATE_UPDATES,
            max_disputes:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_MAX_DISPUTES,
            max_sponsor_reservations:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_batches:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_MAX_BATCHES,
            max_receipts:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_MAX_RECEIPTS,
            max_rebates:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_MAX_REBATES,
            min_privacy_set:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
            batch_privacy_set:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_BATCH_PRIVACY_SET,
            min_pq_security_bits:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            dispute_window_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_DISPUTE_WINDOW_BLOCKS,
            update_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_UPDATE_TTL_BLOCKS,
            reservation_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
            settlement_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            max_user_fee_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            sponsor_reserve_units:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEFAULT_SPONSOR_RESERVE_UNITS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "devnet_height": self.devnet_height,
            "hash_suite": self.hash_suite,
            "pq_auth_suite": self.pq_auth_suite,
            "encryption_suite": self.encryption_suite,
            "proof_suite": self.proof_suite,
            "limits": {
                "max_channels": self.max_channels,
                "max_participants": self.max_participants,
                "max_attestations": self.max_attestations,
                "max_state_updates": self.max_state_updates,
                "max_disputes": self.max_disputes,
                "max_sponsor_reservations": self.max_sponsor_reservations,
                "max_batches": self.max_batches,
                "max_receipts": self.max_receipts,
                "max_rebates": self.max_rebates,
                "min_privacy_set": self.min_privacy_set,
                "batch_privacy_set": self.batch_privacy_set,
                "min_pq_security_bits": self.min_pq_security_bits,
            },
            "windows": {
                "dispute_window_blocks": self.dispute_window_blocks,
                "update_ttl_blocks": self.update_ttl_blocks,
                "reservation_ttl_blocks": self.reservation_ttl_blocks,
                "settlement_ttl_blocks": self.settlement_ttl_blocks,
            },
            "fees": {
                "max_user_fee_bps": self.max_user_fee_bps,
                "target_rebate_bps": self.target_rebate_bps,
                "sponsor_reserve_units": self.sponsor_reserve_units,
            }
        })
    }

    pub fn root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-CONFIG",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub channels: u64,
    pub participants: u64,
    pub attestations: u64,
    pub state_updates: u64,
    pub disputes: u64,
    pub sponsor_reservations: u64,
    pub settlement_batches: u64,
    pub receipts: u64,
    pub rebates: u64,
    pub events: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "channels": self.channels,
            "participants": self.participants,
            "attestations": self.attestations,
            "state_updates": self.state_updates,
            "disputes": self.disputes,
            "sponsor_reservations": self.sponsor_reservations,
            "settlement_batches": self.settlement_batches,
            "receipts": self.receipts,
            "rebates": self.rebates,
            "events": self.events,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-COUNTERS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ParticipantDescriptor {
    pub role: ParticipantRole,
    pub account_commitment: String,
    pub view_tag_root: String,
    pub pq_identity_root: String,
    pub encrypted_transport_key_root: String,
    pub spending_limit_commitment: String,
    pub recovery_root: String,
    pub privacy_set_root: String,
}

impl ParticipantDescriptor {
    pub fn public_record(&self) -> Value {
        json!({
            "role": self.role.as_str(),
            "account_commitment": self.account_commitment,
            "view_tag_root": self.view_tag_root,
            "pq_identity_root": self.pq_identity_root,
            "encrypted_transport_key_root": self.encrypted_transport_key_root,
            "spending_limit_commitment": self.spending_limit_commitment,
            "recovery_root": self.recovery_root,
            "privacy_set_root": self.privacy_set_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenChannelRequest {
    pub channel_kind: ChannelKind,
    pub contract_commitment: String,
    pub initial_state_commitment: String,
    pub initial_state_ciphertext_root: String,
    pub participant_set_root: String,
    pub nullifier_fence_root: String,
    pub replay_fence_root: String,
    pub fee_policy_root: String,
    pub sponsor_policy_root: String,
    pub privacy_policy_root: String,
    pub participant_descriptors: Vec<ParticipantDescriptor>,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub dispute_window_blocks: u64,
    pub min_signers: u16,
    pub max_user_fee_bps: u64,
    pub nonce: String,
}

impl OpenChannelRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "channel_kind": self.channel_kind.as_str(),
            "contract_commitment": self.contract_commitment,
            "initial_state_commitment": self.initial_state_commitment,
            "initial_state_ciphertext_root": self.initial_state_ciphertext_root,
            "participant_set_root": self.participant_set_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "replay_fence_root": self.replay_fence_root,
            "fee_policy_root": self.fee_policy_root,
            "sponsor_policy_root": self.sponsor_policy_root,
            "privacy_policy_root": self.privacy_policy_root,
            "participant_descriptors": self.participant_descriptors.iter().map(ParticipantDescriptor::public_record).collect::<Vec<_>>(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "dispute_window_blocks": self.dispute_window_blocks,
            "min_signers": self.min_signers,
            "max_user_fee_bps": self.max_user_fee_bps,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Channel {
    pub channel_id: String,
    pub channel_kind: ChannelKind,
    pub status: ChannelStatus,
    pub contract_commitment: String,
    pub latest_state_commitment: String,
    pub latest_state_ciphertext_root: String,
    pub participant_set_root: String,
    pub participant_ids: Vec<String>,
    pub update_ids: Vec<String>,
    pub dispute_ids: Vec<String>,
    pub sponsor_reservation_ids: Vec<String>,
    pub receipt_ids: Vec<String>,
    pub nullifier_fence_root: String,
    pub replay_fence_root: String,
    pub fee_policy_root: String,
    pub sponsor_policy_root: String,
    pub privacy_policy_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub dispute_window_blocks: u64,
    pub last_update_height: u64,
    pub update_sequence: u64,
    pub min_signers: u16,
    pub max_user_fee_bps: u64,
    pub accumulated_fee_commitment: String,
    pub accumulated_rebate_commitment: String,
}

impl Channel {
    pub fn public_record(&self) -> Value {
        json!({
            "channel_id": self.channel_id,
            "channel_kind": self.channel_kind.as_str(),
            "status": self.status,
            "contract_commitment": self.contract_commitment,
            "latest_state_commitment": self.latest_state_commitment,
            "latest_state_ciphertext_root": self.latest_state_ciphertext_root,
            "participant_set_root": self.participant_set_root,
            "participant_root": id_list_root("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-PARTICIPANT-LIST", self.participant_ids.iter()),
            "update_root": id_list_root("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-UPDATE-LIST", self.update_ids.iter()),
            "dispute_root": id_list_root("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-DISPUTE-LIST", self.dispute_ids.iter()),
            "sponsor_reservation_root": id_list_root("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-SPONSOR-LIST", self.sponsor_reservation_ids.iter()),
            "receipt_root": id_list_root("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-RECEIPT-LIST", self.receipt_ids.iter()),
            "nullifier_fence_root": self.nullifier_fence_root,
            "replay_fence_root": self.replay_fence_root,
            "fee_policy_root": self.fee_policy_root,
            "sponsor_policy_root": self.sponsor_policy_root,
            "privacy_policy_root": self.privacy_policy_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "dispute_window_blocks": self.dispute_window_blocks,
            "last_update_height": self.last_update_height,
            "update_sequence": self.update_sequence,
            "min_signers": self.min_signers,
            "max_user_fee_bps": self.max_user_fee_bps,
            "accumulated_fee_commitment": self.accumulated_fee_commitment,
            "accumulated_rebate_commitment": self.accumulated_rebate_commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Participant {
    pub participant_id: String,
    pub channel_id: String,
    pub role: ParticipantRole,
    pub status: ParticipantStatus,
    pub account_commitment: String,
    pub view_tag_root: String,
    pub pq_identity_root: String,
    pub encrypted_transport_key_root: String,
    pub spending_limit_commitment: String,
    pub recovery_root: String,
    pub privacy_set_root: String,
    pub attestation_ids: Vec<String>,
    pub joined_at_height: u64,
    pub rotated_at_height: Option<u64>,
    pub exited_at_height: Option<u64>,
}

impl Participant {
    pub fn public_record(&self) -> Value {
        json!({
            "participant_id": self.participant_id,
            "channel_id": self.channel_id,
            "role": self.role.as_str(),
            "status": self.status,
            "account_commitment": self.account_commitment,
            "view_tag_root": self.view_tag_root,
            "pq_identity_root": self.pq_identity_root,
            "encrypted_transport_key_root": self.encrypted_transport_key_root,
            "spending_limit_commitment": self.spending_limit_commitment,
            "recovery_root": self.recovery_root,
            "privacy_set_root": self.privacy_set_root,
            "attestation_root": id_list_root("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-PARTICIPANT-ATTESTATION-LIST", self.attestation_ids.iter()),
            "joined_at_height": self.joined_at_height,
            "rotated_at_height": self.rotated_at_height,
            "exited_at_height": self.exited_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitParticipantAttestationRequest {
    pub channel_id: String,
    pub participant_id: String,
    pub kind: AttestationKind,
    pub pq_verification_key_root: String,
    pub capability_root: String,
    pub transcript_root: String,
    pub signature_root: String,
    pub nullifier_fence_root: String,
    pub replay_fence_root: String,
    pub security_bits: u16,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: String,
}

impl SubmitParticipantAttestationRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "channel_id": self.channel_id,
            "participant_id": self.participant_id,
            "kind": self.kind.as_str(),
            "pq_verification_key_root": self.pq_verification_key_root,
            "capability_root": self.capability_root,
            "transcript_root": self.transcript_root,
            "signature_root": self.signature_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "replay_fence_root": self.replay_fence_root,
            "security_bits": self.security_bits,
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ParticipantAttestation {
    pub attestation_id: String,
    pub channel_id: String,
    pub participant_id: String,
    pub kind: AttestationKind,
    pub pq_verification_key_root: String,
    pub capability_root: String,
    pub transcript_root: String,
    pub signature_root: String,
    pub nullifier_fence_root: String,
    pub replay_fence_root: String,
    pub security_bits: u16,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
}

impl ParticipantAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "channel_id": self.channel_id,
            "participant_id": self.participant_id,
            "kind": self.kind.as_str(),
            "pq_verification_key_root": self.pq_verification_key_root,
            "capability_root": self.capability_root,
            "transcript_root": self.transcript_root,
            "signature_root": self.signature_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "replay_fence_root": self.replay_fence_root,
            "security_bits": self.security_bits,
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitEncryptedStateUpdateRequest {
    pub channel_id: String,
    pub update_kind: UpdateKind,
    pub previous_state_commitment: String,
    pub next_state_commitment: String,
    pub encrypted_delta_root: String,
    pub call_data_commitment: String,
    pub contract_output_commitment: String,
    pub signer_attestation_root: String,
    pub pq_signature_root: String,
    pub nullifier_fence_root: String,
    pub replay_fence_root: String,
    pub privacy_proof_root: String,
    pub fee_commitment: String,
    pub rebate_commitment: String,
    pub submitted_at_height: u64,
    pub valid_until_height: u64,
    pub sequence: u64,
    pub nonce: String,
}

impl SubmitEncryptedStateUpdateRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "channel_id": self.channel_id,
            "update_kind": self.update_kind.as_str(),
            "previous_state_commitment": self.previous_state_commitment,
            "next_state_commitment": self.next_state_commitment,
            "encrypted_delta_root": self.encrypted_delta_root,
            "call_data_commitment": self.call_data_commitment,
            "contract_output_commitment": self.contract_output_commitment,
            "signer_attestation_root": self.signer_attestation_root,
            "pq_signature_root": self.pq_signature_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "replay_fence_root": self.replay_fence_root,
            "privacy_proof_root": self.privacy_proof_root,
            "fee_commitment": self.fee_commitment,
            "rebate_commitment": self.rebate_commitment,
            "submitted_at_height": self.submitted_at_height,
            "valid_until_height": self.valid_until_height,
            "sequence": self.sequence,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedStateUpdate {
    pub update_id: String,
    pub channel_id: String,
    pub update_kind: UpdateKind,
    pub status: UpdateStatus,
    pub previous_state_commitment: String,
    pub next_state_commitment: String,
    pub encrypted_delta_root: String,
    pub call_data_commitment: String,
    pub contract_output_commitment: String,
    pub signer_attestation_root: String,
    pub pq_signature_root: String,
    pub nullifier_fence_root: String,
    pub replay_fence_root: String,
    pub privacy_proof_root: String,
    pub fee_commitment: String,
    pub rebate_commitment: String,
    pub submitted_at_height: u64,
    pub valid_until_height: u64,
    pub applied_at_height: Option<u64>,
    pub sequence: u64,
}

impl EncryptedStateUpdate {
    pub fn public_record(&self) -> Value {
        json!({
            "update_id": self.update_id,
            "channel_id": self.channel_id,
            "update_kind": self.update_kind.as_str(),
            "status": self.status,
            "previous_state_commitment": self.previous_state_commitment,
            "next_state_commitment": self.next_state_commitment,
            "encrypted_delta_root": self.encrypted_delta_root,
            "call_data_commitment": self.call_data_commitment,
            "contract_output_commitment": self.contract_output_commitment,
            "signer_attestation_root": self.signer_attestation_root,
            "pq_signature_root": self.pq_signature_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "replay_fence_root": self.replay_fence_root,
            "privacy_proof_root": self.privacy_proof_root,
            "fee_commitment": self.fee_commitment,
            "rebate_commitment": self.rebate_commitment,
            "submitted_at_height": self.submitted_at_height,
            "valid_until_height": self.valid_until_height,
            "applied_at_height": self.applied_at_height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenDisputeRequest {
    pub channel_id: String,
    pub disputed_update_id: String,
    pub kind: DisputeKind,
    pub claimant_commitment: String,
    pub evidence_root: String,
    pub counter_state_commitment: String,
    pub counter_state_ciphertext_root: String,
    pub nullifier_fence_root: String,
    pub replay_fence_root: String,
    pub bond_commitment: String,
    pub opened_at_height: u64,
    pub window_close_height: u64,
    pub nonce: String,
}

impl OpenDisputeRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "channel_id": self.channel_id,
            "disputed_update_id": self.disputed_update_id,
            "kind": self.kind.as_str(),
            "claimant_commitment": self.claimant_commitment,
            "evidence_root": self.evidence_root,
            "counter_state_commitment": self.counter_state_commitment,
            "counter_state_ciphertext_root": self.counter_state_ciphertext_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "replay_fence_root": self.replay_fence_root,
            "bond_commitment": self.bond_commitment,
            "opened_at_height": self.opened_at_height,
            "window_close_height": self.window_close_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DisputeWindow {
    pub dispute_id: String,
    pub channel_id: String,
    pub disputed_update_id: String,
    pub kind: DisputeKind,
    pub status: DisputeStatus,
    pub claimant_commitment: String,
    pub evidence_root: String,
    pub counter_state_commitment: String,
    pub counter_state_ciphertext_root: String,
    pub nullifier_fence_root: String,
    pub replay_fence_root: String,
    pub bond_commitment: String,
    pub resolution_root: String,
    pub opened_at_height: u64,
    pub window_close_height: u64,
    pub resolved_at_height: Option<u64>,
}

impl DisputeWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "dispute_id": self.dispute_id,
            "channel_id": self.channel_id,
            "disputed_update_id": self.disputed_update_id,
            "kind": self.kind.as_str(),
            "status": self.status,
            "claimant_commitment": self.claimant_commitment,
            "evidence_root": self.evidence_root,
            "counter_state_commitment": self.counter_state_commitment,
            "counter_state_ciphertext_root": self.counter_state_ciphertext_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "replay_fence_root": self.replay_fence_root,
            "bond_commitment": self.bond_commitment,
            "resolution_root": self.resolution_root,
            "opened_at_height": self.opened_at_height,
            "window_close_height": self.window_close_height,
            "resolved_at_height": self.resolved_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveSponsorRequest {
    pub channel_id: String,
    pub sponsor_commitment: String,
    pub beneficiary_commitment: String,
    pub fee_asset_commitment: String,
    pub reserved_fee_units: u64,
    pub max_fee_bps: u64,
    pub privacy_budget_root: String,
    pub sponsor_attestation_root: String,
    pub nullifier_fence_root: String,
    pub replay_fence_root: String,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: String,
}

impl ReserveSponsorRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "channel_id": self.channel_id,
            "sponsor_commitment": self.sponsor_commitment,
            "beneficiary_commitment": self.beneficiary_commitment,
            "fee_asset_commitment": self.fee_asset_commitment,
            "reserved_fee_units": self.reserved_fee_units,
            "max_fee_bps": self.max_fee_bps,
            "privacy_budget_root": self.privacy_budget_root,
            "sponsor_attestation_root": self.sponsor_attestation_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "replay_fence_root": self.replay_fence_root,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorReservation {
    pub reservation_id: String,
    pub channel_id: String,
    pub sponsor_commitment: String,
    pub beneficiary_commitment: String,
    pub fee_asset_commitment: String,
    pub status: SponsorReservationStatus,
    pub reserved_fee_units: u64,
    pub consumed_fee_units: u64,
    pub rebate_fee_units: u64,
    pub max_fee_bps: u64,
    pub privacy_budget_root: String,
    pub sponsor_attestation_root: String,
    pub nullifier_fence_root: String,
    pub replay_fence_root: String,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
    pub consumed_at_height: Option<u64>,
}

impl SponsorReservation {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "channel_id": self.channel_id,
            "sponsor_commitment": self.sponsor_commitment,
            "beneficiary_commitment": self.beneficiary_commitment,
            "fee_asset_commitment": self.fee_asset_commitment,
            "status": self.status,
            "reserved_fee_units": self.reserved_fee_units,
            "consumed_fee_units": self.consumed_fee_units,
            "rebate_fee_units": self.rebate_fee_units,
            "max_fee_bps": self.max_fee_bps,
            "privacy_budget_root": self.privacy_budget_root,
            "sponsor_attestation_root": self.sponsor_attestation_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "replay_fence_root": self.replay_fence_root,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
            "consumed_at_height": self.consumed_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuildSettlementBatchRequest {
    pub channel_ids: Vec<String>,
    pub update_ids: Vec<String>,
    pub dispute_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub settlement_state_root: String,
    pub settlement_receipt_root: String,
    pub batch_proof_root: String,
    pub nullifier_fence_root: String,
    pub replay_fence_root: String,
    pub batch_fee_commitment: String,
    pub batch_rebate_commitment: String,
    pub built_at_height: u64,
    pub valid_until_height: u64,
    pub nonce: String,
}

impl BuildSettlementBatchRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "channel_root": id_list_root("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-BATCH-CHANNELS", self.channel_ids.iter()),
            "update_root": id_list_root("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-BATCH-UPDATES", self.update_ids.iter()),
            "dispute_root": id_list_root("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-BATCH-DISPUTES", self.dispute_ids.iter()),
            "reservation_root": id_list_root("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-BATCH-RESERVATIONS", self.reservation_ids.iter()),
            "settlement_state_root": self.settlement_state_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "batch_proof_root": self.batch_proof_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "replay_fence_root": self.replay_fence_root,
            "batch_fee_commitment": self.batch_fee_commitment,
            "batch_rebate_commitment": self.batch_rebate_commitment,
            "built_at_height": self.built_at_height,
            "valid_until_height": self.valid_until_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementBatch {
    pub batch_id: String,
    pub status: SettlementBatchStatus,
    pub channel_ids: Vec<String>,
    pub update_ids: Vec<String>,
    pub dispute_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub receipt_ids: Vec<String>,
    pub settlement_state_root: String,
    pub settlement_receipt_root: String,
    pub batch_proof_root: String,
    pub nullifier_fence_root: String,
    pub replay_fence_root: String,
    pub batch_fee_commitment: String,
    pub batch_rebate_commitment: String,
    pub built_at_height: u64,
    pub valid_until_height: u64,
    pub finalized_at_height: Option<u64>,
}

impl SettlementBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "status": self.status,
            "channel_root": id_list_root("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-SETTLEMENT-CHANNELS", self.channel_ids.iter()),
            "update_root": id_list_root("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-SETTLEMENT-UPDATES", self.update_ids.iter()),
            "dispute_root": id_list_root("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-SETTLEMENT-DISPUTES", self.dispute_ids.iter()),
            "reservation_root": id_list_root("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-SETTLEMENT-RESERVATIONS", self.reservation_ids.iter()),
            "receipt_root": id_list_root("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-SETTLEMENT-RECEIPTS", self.receipt_ids.iter()),
            "settlement_state_root": self.settlement_state_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "batch_proof_root": self.batch_proof_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "replay_fence_root": self.replay_fence_root,
            "batch_fee_commitment": self.batch_fee_commitment,
            "batch_rebate_commitment": self.batch_rebate_commitment,
            "built_at_height": self.built_at_height,
            "valid_until_height": self.valid_until_height,
            "finalized_at_height": self.finalized_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishSettlementReceiptRequest {
    pub batch_id: String,
    pub channel_id: String,
    pub receipt_kind: ReceiptKind,
    pub subject_id: String,
    pub public_payload_root: String,
    pub encrypted_payload_root: String,
    pub proof_root: String,
    pub nullifier_fence_root: String,
    pub replay_fence_root: String,
    pub fee_commitment: String,
    pub rebate_commitment: String,
    pub published_at_height: u64,
    pub nonce: String,
}

impl PublishSettlementReceiptRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "channel_id": self.channel_id,
            "receipt_kind": self.receipt_kind.as_str(),
            "subject_id": self.subject_id,
            "public_payload_root": self.public_payload_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "proof_root": self.proof_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "replay_fence_root": self.replay_fence_root,
            "fee_commitment": self.fee_commitment,
            "rebate_commitment": self.rebate_commitment,
            "published_at_height": self.published_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub channel_id: String,
    pub receipt_kind: ReceiptKind,
    pub subject_id: String,
    pub public_payload_root: String,
    pub encrypted_payload_root: String,
    pub proof_root: String,
    pub nullifier_fence_root: String,
    pub replay_fence_root: String,
    pub fee_commitment: String,
    pub rebate_commitment: String,
    pub published_at_height: u64,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "channel_id": self.channel_id,
            "receipt_kind": self.receipt_kind.as_str(),
            "subject_id": self.subject_id,
            "public_payload_root": self.public_payload_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "proof_root": self.proof_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "replay_fence_root": self.replay_fence_root,
            "fee_commitment": self.fee_commitment,
            "rebate_commitment": self.rebate_commitment,
            "published_at_height": self.published_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishRebateRequest {
    pub channel_id: String,
    pub batch_id: String,
    pub beneficiary_commitment: String,
    pub sponsor_commitment: String,
    pub rebate_asset_commitment: String,
    pub rebate_amount_commitment: String,
    pub rebate_proof_root: String,
    pub nullifier_fence_root: String,
    pub replay_fence_root: String,
    pub published_at_height: u64,
    pub nonce: String,
}

impl PublishRebateRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "channel_id": self.channel_id,
            "batch_id": self.batch_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "sponsor_commitment": self.sponsor_commitment,
            "rebate_asset_commitment": self.rebate_asset_commitment,
            "rebate_amount_commitment": self.rebate_amount_commitment,
            "rebate_proof_root": self.rebate_proof_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "replay_fence_root": self.replay_fence_root,
            "published_at_height": self.published_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Rebate {
    pub rebate_id: String,
    pub channel_id: String,
    pub batch_id: String,
    pub beneficiary_commitment: String,
    pub sponsor_commitment: String,
    pub rebate_asset_commitment: String,
    pub rebate_amount_commitment: String,
    pub rebate_proof_root: String,
    pub nullifier_fence_root: String,
    pub replay_fence_root: String,
    pub published_at_height: u64,
}

impl Rebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "channel_id": self.channel_id,
            "batch_id": self.batch_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "sponsor_commitment": self.sponsor_commitment,
            "rebate_asset_commitment": self.rebate_asset_commitment,
            "rebate_amount_commitment": self.rebate_amount_commitment,
            "rebate_proof_root": self.rebate_proof_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "replay_fence_root": self.replay_fence_root,
            "published_at_height": self.published_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub channel_id: String,
    pub nullifier_root: String,
    pub replay_root: String,
    pub spent_note_root: String,
    pub output_note_root: String,
    pub view_tag_root: String,
    pub membership_root: String,
    pub min_privacy_set: usize,
    pub audited_at_height: u64,
}

impl PrivacyFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "channel_id": self.channel_id,
            "nullifier_root": self.nullifier_root,
            "replay_root": self.replay_root,
            "spent_note_root": self.spent_note_root,
            "output_note_root": self.output_note_root,
            "view_tag_root": self.view_tag_root,
            "membership_root": self.membership_root,
            "min_privacy_set": self.min_privacy_set,
            "audited_at_height": self.audited_at_height,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counter_root: String,
    pub channel_root: String,
    pub participant_root: String,
    pub attestation_root: String,
    pub encrypted_state_update_root: String,
    pub dispute_window_root: String,
    pub sponsor_reservation_root: String,
    pub settlement_batch_root: String,
    pub settlement_receipt_root: String,
    pub rebate_root: String,
    pub privacy_fence_root: String,
    pub nullifier_fence_root: String,
    pub replay_fence_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counter_root": self.counter_root,
            "channel_root": self.channel_root,
            "participant_root": self.participant_root,
            "attestation_root": self.attestation_root,
            "encrypted_state_update_root": self.encrypted_state_update_root,
            "dispute_window_root": self.dispute_window_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "settlement_batch_root": self.settlement_batch_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "rebate_root": self.rebate_root,
            "privacy_fence_root": self.privacy_fence_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "replay_fence_root": self.replay_fence_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub channels: BTreeMap<String, Channel>,
    pub participants: BTreeMap<String, Participant>,
    pub attestations: BTreeMap<String, ParticipantAttestation>,
    pub state_updates: BTreeMap<String, EncryptedStateUpdate>,
    pub disputes: BTreeMap<String, DisputeWindow>,
    pub sponsor_reservations: BTreeMap<String, SponsorReservation>,
    pub settlement_batches: BTreeMap<String, SettlementBatch>,
    pub receipts: BTreeMap<String, SettlementReceipt>,
    pub rebates: BTreeMap<String, Rebate>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub nullifier_fences: BTreeSet<String>,
    pub replay_fences: BTreeSet<String>,
    pub events: Vec<Value>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::devnet())
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            counters: Counters::default(),
            channels: BTreeMap::new(),
            participants: BTreeMap::new(),
            attestations: BTreeMap::new(),
            state_updates: BTreeMap::new(),
            disputes: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            nullifier_fences: BTreeSet::new(),
            replay_fences: BTreeSet::new(),
            events: Vec::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::default();
        let base_height = PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_DEVNET_HEIGHT;
        let initiator = ParticipantDescriptor {
            role: ParticipantRole::Initiator,
            account_commitment: sample_root("DEVNET-ACCOUNT", "alice"),
            view_tag_root: sample_root("DEVNET-VIEW-TAG", "alice"),
            pq_identity_root: sample_root("DEVNET-PQ-IDENTITY", "alice"),
            encrypted_transport_key_root: sample_root("DEVNET-TRANSPORT-KEY", "alice"),
            spending_limit_commitment: sample_root("DEVNET-SPENDING-LIMIT", "alice"),
            recovery_root: sample_root("DEVNET-RECOVERY", "alice"),
            privacy_set_root: sample_root("DEVNET-PRIVACY-SET", "alice"),
        };
        let counterparty = ParticipantDescriptor {
            role: ParticipantRole::Counterparty,
            account_commitment: sample_root("DEVNET-ACCOUNT", "bob"),
            view_tag_root: sample_root("DEVNET-VIEW-TAG", "bob"),
            pq_identity_root: sample_root("DEVNET-PQ-IDENTITY", "bob"),
            encrypted_transport_key_root: sample_root("DEVNET-TRANSPORT-KEY", "bob"),
            spending_limit_commitment: sample_root("DEVNET-SPENDING-LIMIT", "bob"),
            recovery_root: sample_root("DEVNET-RECOVERY", "bob"),
            privacy_set_root: sample_root("DEVNET-PRIVACY-SET", "bob"),
        };
        let watcher = ParticipantDescriptor {
            role: ParticipantRole::Watcher,
            account_commitment: sample_root("DEVNET-ACCOUNT", "watcher"),
            view_tag_root: sample_root("DEVNET-VIEW-TAG", "watcher"),
            pq_identity_root: sample_root("DEVNET-PQ-IDENTITY", "watcher"),
            encrypted_transport_key_root: sample_root("DEVNET-TRANSPORT-KEY", "watcher"),
            spending_limit_commitment: sample_root("DEVNET-SPENDING-LIMIT", "watcher"),
            recovery_root: sample_root("DEVNET-RECOVERY", "watcher"),
            privacy_set_root: sample_root("DEVNET-PRIVACY-SET", "watcher"),
        };
        let open = OpenChannelRequest {
            channel_kind: ChannelKind::DefiIntent,
            contract_commitment: sample_root("DEVNET-CONTRACT", "amm-intent-router"),
            initial_state_commitment: sample_root("DEVNET-STATE", "open"),
            initial_state_ciphertext_root: sample_root("DEVNET-STATE-CIPHERTEXT", "open"),
            participant_set_root: sample_root("DEVNET-PARTICIPANT-SET", "channel-0"),
            nullifier_fence_root: sample_root("DEVNET-NULLIFIER-FENCE", "channel-0"),
            replay_fence_root: sample_root("DEVNET-REPLAY-FENCE", "channel-0"),
            fee_policy_root: sample_root("DEVNET-FEE-POLICY", "low-fee"),
            sponsor_policy_root: sample_root("DEVNET-SPONSOR-POLICY", "sponsored"),
            privacy_policy_root: sample_root("DEVNET-PRIVACY-POLICY", "min-256"),
            participant_descriptors: vec![initiator, counterparty, watcher],
            opened_at_height: base_height,
            expires_at_height: base_height + 1_440,
            dispute_window_blocks: state.config.dispute_window_blocks,
            min_signers: 2,
            max_user_fee_bps: state.config.max_user_fee_bps,
            nonce: "devnet-channel-0".to_string(),
        };
        let channel_id = state.open_channel(open).expect("devnet channel opens");
        let participant_ids = state
            .channels
            .get(&channel_id)
            .map(|channel| channel.participant_ids.clone())
            .unwrap_or_default();
        for (index, participant_id) in participant_ids.iter().enumerate() {
            let label = format!("attestation-{index}");
            let request = SubmitParticipantAttestationRequest {
                channel_id: channel_id.clone(),
                participant_id: participant_id.clone(),
                kind: AttestationKind::PqSessionKey,
                pq_verification_key_root: sample_root("DEVNET-PQ-VK", &label),
                capability_root: sample_root("DEVNET-CAPABILITY", &label),
                transcript_root: sample_root("DEVNET-TRANSCRIPT", &label),
                signature_root: sample_root("DEVNET-PQ-SIGNATURE", &label),
                nullifier_fence_root: sample_root("DEVNET-ATTESTATION-NULLIFIER", &label),
                replay_fence_root: sample_root("DEVNET-ATTESTATION-REPLAY", &label),
                security_bits: state.config.min_pq_security_bits,
                attested_at_height: base_height + 1,
                expires_at_height: base_height + 1_441,
                nonce: label,
            };
            state
                .submit_participant_attestation(request)
                .expect("devnet attestation records");
        }
        let update = SubmitEncryptedStateUpdateRequest {
            channel_id: channel_id.clone(),
            update_kind: UpdateKind::SwapFill,
            previous_state_commitment: sample_root("DEVNET-STATE", "open"),
            next_state_commitment: sample_root("DEVNET-STATE", "swap-fill-1"),
            encrypted_delta_root: sample_root("DEVNET-DELTA", "swap-fill-1"),
            call_data_commitment: sample_root("DEVNET-CALLDATA", "swap-fill-1"),
            contract_output_commitment: sample_root("DEVNET-OUTPUT", "swap-fill-1"),
            signer_attestation_root: sample_root("DEVNET-SIGNER-ATTESTATIONS", "swap-fill-1"),
            pq_signature_root: sample_root("DEVNET-UPDATE-SIGNATURE", "swap-fill-1"),
            nullifier_fence_root: sample_root("DEVNET-UPDATE-NULLIFIER", "swap-fill-1"),
            replay_fence_root: sample_root("DEVNET-UPDATE-REPLAY", "swap-fill-1"),
            privacy_proof_root: sample_root("DEVNET-PRIVACY-PROOF", "swap-fill-1"),
            fee_commitment: sample_root("DEVNET-FEE", "swap-fill-1"),
            rebate_commitment: sample_root("DEVNET-REBATE", "swap-fill-1"),
            submitted_at_height: base_height + 2,
            valid_until_height: base_height + 98,
            sequence: 1,
            nonce: "devnet-update-1".to_string(),
        };
        let update_id = state
            .submit_encrypted_state_update(update)
            .expect("devnet update records");
        let reservation = ReserveSponsorRequest {
            channel_id: channel_id.clone(),
            sponsor_commitment: sample_root("DEVNET-SPONSOR", "relay-0"),
            beneficiary_commitment: sample_root("DEVNET-BENEFICIARY", "alice"),
            fee_asset_commitment: sample_root("DEVNET-FEE-ASSET", "xmr"),
            reserved_fee_units: state.config.sponsor_reserve_units,
            max_fee_bps: state.config.max_user_fee_bps,
            privacy_budget_root: sample_root("DEVNET-PRIVACY-BUDGET", "relay-0"),
            sponsor_attestation_root: sample_root("DEVNET-SPONSOR-ATTESTATION", "relay-0"),
            nullifier_fence_root: sample_root("DEVNET-SPONSOR-NULLIFIER", "relay-0"),
            replay_fence_root: sample_root("DEVNET-SPONSOR-REPLAY", "relay-0"),
            reserved_at_height: base_height + 3,
            expires_at_height: base_height + 75,
            nonce: "devnet-reservation-0".to_string(),
        };
        let reservation_id = state
            .reserve_sponsor(reservation)
            .expect("devnet sponsor reservation records");
        let batch = BuildSettlementBatchRequest {
            channel_ids: vec![channel_id.clone()],
            update_ids: vec![update_id.clone()],
            dispute_ids: Vec::new(),
            reservation_ids: vec![reservation_id],
            settlement_state_root: sample_root("DEVNET-SETTLEMENT-STATE", "batch-0"),
            settlement_receipt_root: sample_root("DEVNET-SETTLEMENT-RECEIPT", "batch-0"),
            batch_proof_root: sample_root("DEVNET-BATCH-PROOF", "batch-0"),
            nullifier_fence_root: sample_root("DEVNET-BATCH-NULLIFIER", "batch-0"),
            replay_fence_root: sample_root("DEVNET-BATCH-REPLAY", "batch-0"),
            batch_fee_commitment: sample_root("DEVNET-BATCH-FEE", "batch-0"),
            batch_rebate_commitment: sample_root("DEVNET-BATCH-REBATE", "batch-0"),
            built_at_height: base_height + 4,
            valid_until_height: base_height + 52,
            nonce: "devnet-batch-0".to_string(),
        };
        let batch_id = state
            .build_settlement_batch(batch)
            .expect("devnet settlement batch records");
        let receipt = PublishSettlementReceiptRequest {
            batch_id: batch_id.clone(),
            channel_id: channel_id.clone(),
            receipt_kind: ReceiptKind::SettlementPublished,
            subject_id: update_id,
            public_payload_root: sample_root("DEVNET-RECEIPT-PUBLIC", "batch-0"),
            encrypted_payload_root: sample_root("DEVNET-RECEIPT-ENCRYPTED", "batch-0"),
            proof_root: sample_root("DEVNET-RECEIPT-PROOF", "batch-0"),
            nullifier_fence_root: sample_root("DEVNET-RECEIPT-NULLIFIER", "batch-0"),
            replay_fence_root: sample_root("DEVNET-RECEIPT-REPLAY", "batch-0"),
            fee_commitment: sample_root("DEVNET-RECEIPT-FEE", "batch-0"),
            rebate_commitment: sample_root("DEVNET-RECEIPT-REBATE", "batch-0"),
            published_at_height: base_height + 5,
            nonce: "devnet-receipt-0".to_string(),
        };
        state
            .publish_settlement_receipt(receipt)
            .expect("devnet receipt records");
        let rebate = PublishRebateRequest {
            channel_id,
            batch_id,
            beneficiary_commitment: sample_root("DEVNET-BENEFICIARY", "alice"),
            sponsor_commitment: sample_root("DEVNET-SPONSOR", "relay-0"),
            rebate_asset_commitment: sample_root("DEVNET-REBATE-ASSET", "xmr"),
            rebate_amount_commitment: sample_root("DEVNET-REBATE-AMOUNT", "8bps"),
            rebate_proof_root: sample_root("DEVNET-REBATE-PROOF", "batch-0"),
            nullifier_fence_root: sample_root("DEVNET-REBATE-NULLIFIER", "batch-0"),
            replay_fence_root: sample_root("DEVNET-REBATE-REPLAY", "batch-0"),
            published_at_height: base_height + 6,
            nonce: "devnet-rebate-0".to_string(),
        };
        state.publish_rebate(rebate).expect("devnet rebate records");
        state
    }

    pub fn open_channel(
        &mut self,
        request: OpenChannelRequest,
    ) -> PrivateL2PqConfidentialContractStateChannelRuntimeResult<String> {
        self.ensure_channel_capacity()?;
        require_nonempty("contract_commitment", &request.contract_commitment)?;
        require_nonempty(
            "initial_state_commitment",
            &request.initial_state_commitment,
        )?;
        require_nonempty(
            "initial_state_ciphertext_root",
            &request.initial_state_ciphertext_root,
        )?;
        require_nonempty("nullifier_fence_root", &request.nullifier_fence_root)?;
        require_nonempty("replay_fence_root", &request.replay_fence_root)?;
        if request.participant_descriptors.len() < 2 {
            return Err("channel requires at least two participants".to_string());
        }
        if request.participant_descriptors.len() > u16::MAX as usize {
            return Err("channel participant count exceeds u16 max".to_string());
        }
        if request.min_signers == 0
            || request.min_signers as usize > request.participant_descriptors.len()
        {
            return Err("min_signers must be within participant count".to_string());
        }
        if request.max_user_fee_bps > self.config.max_user_fee_bps {
            return Err("channel fee bps exceeds configured maximum".to_string());
        }
        if request.dispute_window_blocks < self.config.dispute_window_blocks {
            return Err("dispute window below configured minimum".to_string());
        }
        if request.expires_at_height <= request.opened_at_height {
            return Err("channel expiry must be after open height".to_string());
        }
        self.insert_nullifier_fence(&request.nullifier_fence_root)?;
        self.insert_replay_fence(&request.replay_fence_root)?;
        self.counters.channels = self.counters.channels.saturating_add(1);
        let channel_id = confidential_channel_id(&request, self.counters.channels);
        if self.channels.contains_key(&channel_id) {
            return Err("channel id collision".to_string());
        }
        let mut participant_ids = Vec::with_capacity(request.participant_descriptors.len());
        for descriptor in &request.participant_descriptors {
            self.ensure_participant_capacity()?;
            self.counters.participants = self.counters.participants.saturating_add(1);
            let participant_id =
                channel_participant_id(&channel_id, descriptor, self.counters.participants);
            let participant = Participant {
                participant_id: participant_id.clone(),
                channel_id: channel_id.clone(),
                role: descriptor.role,
                status: ParticipantStatus::Invited,
                account_commitment: descriptor.account_commitment.clone(),
                view_tag_root: descriptor.view_tag_root.clone(),
                pq_identity_root: descriptor.pq_identity_root.clone(),
                encrypted_transport_key_root: descriptor.encrypted_transport_key_root.clone(),
                spending_limit_commitment: descriptor.spending_limit_commitment.clone(),
                recovery_root: descriptor.recovery_root.clone(),
                privacy_set_root: descriptor.privacy_set_root.clone(),
                attestation_ids: Vec::new(),
                joined_at_height: request.opened_at_height,
                rotated_at_height: None,
                exited_at_height: None,
            };
            self.participants
                .insert(participant_id.clone(), participant);
            participant_ids.push(participant_id);
        }
        let channel = Channel {
            channel_id: channel_id.clone(),
            channel_kind: request.channel_kind,
            status: ChannelStatus::Open,
            contract_commitment: request.contract_commitment,
            latest_state_commitment: request.initial_state_commitment,
            latest_state_ciphertext_root: request.initial_state_ciphertext_root,
            participant_set_root: request.participant_set_root,
            participant_ids,
            update_ids: Vec::new(),
            dispute_ids: Vec::new(),
            sponsor_reservation_ids: Vec::new(),
            receipt_ids: Vec::new(),
            nullifier_fence_root: request.nullifier_fence_root,
            replay_fence_root: request.replay_fence_root,
            fee_policy_root: request.fee_policy_root,
            sponsor_policy_root: request.sponsor_policy_root,
            privacy_policy_root: request.privacy_policy_root,
            opened_at_height: request.opened_at_height,
            expires_at_height: request.expires_at_height,
            dispute_window_blocks: request.dispute_window_blocks,
            last_update_height: request.opened_at_height,
            update_sequence: 0,
            min_signers: request.min_signers,
            max_user_fee_bps: request.max_user_fee_bps,
            accumulated_fee_commitment: zero_commitment("CHANNEL-FEE"),
            accumulated_rebate_commitment: zero_commitment("CHANNEL-REBATE"),
        };
        self.channels.insert(channel_id.clone(), channel);
        let participant_count = self
            .channels
            .get(&channel_id)
            .map(|channel| channel.participant_ids.len())
            .unwrap_or_default();
        self.push_event(
            "channel_opened",
            json!({ "channel_id": channel_id, "participant_count": participant_count }),
        );
        Ok(channel_id)
    }

    pub fn submit_participant_attestation(
        &mut self,
        request: SubmitParticipantAttestationRequest,
    ) -> PrivateL2PqConfidentialContractStateChannelRuntimeResult<String> {
        self.ensure_attestation_capacity()?;
        require_nonempty("channel_id", &request.channel_id)?;
        require_nonempty("participant_id", &request.participant_id)?;
        require_nonempty(
            "pq_verification_key_root",
            &request.pq_verification_key_root,
        )?;
        require_nonempty("signature_root", &request.signature_root)?;
        if request.security_bits < self.config.min_pq_security_bits {
            return Err("participant attestation does not meet PQ security floor".to_string());
        }
        if request.expires_at_height <= request.attested_at_height {
            return Err("attestation expiry must be after attestation height".to_string());
        }
        self.insert_nullifier_fence(&request.nullifier_fence_root)?;
        self.insert_replay_fence(&request.replay_fence_root)?;
        if !self.channels.contains_key(&request.channel_id) {
            return Err("channel not found".to_string());
        }
        let participant = self
            .participants
            .get_mut(&request.participant_id)
            .ok_or_else(|| "participant not found".to_string())?;
        if participant.channel_id != request.channel_id {
            return Err("participant is not attached to channel".to_string());
        }
        self.counters.attestations = self.counters.attestations.saturating_add(1);
        let attestation_id = participant_attestation_id(&request, self.counters.attestations);
        let attestation = ParticipantAttestation {
            attestation_id: attestation_id.clone(),
            channel_id: request.channel_id.clone(),
            participant_id: request.participant_id.clone(),
            kind: request.kind,
            pq_verification_key_root: request.pq_verification_key_root,
            capability_root: request.capability_root,
            transcript_root: request.transcript_root,
            signature_root: request.signature_root,
            nullifier_fence_root: request.nullifier_fence_root,
            replay_fence_root: request.replay_fence_root,
            security_bits: request.security_bits,
            attested_at_height: request.attested_at_height,
            expires_at_height: request.expires_at_height,
        };
        participant.status = ParticipantStatus::Attested;
        participant.attestation_ids.push(attestation_id.clone());
        self.attestations
            .insert(attestation_id.clone(), attestation);
        self.push_event(
            "participant_attested",
            json!({ "channel_id": request.channel_id, "participant_id": request.participant_id, "attestation_id": attestation_id }),
        );
        Ok(attestation_id)
    }

    pub fn submit_encrypted_state_update(
        &mut self,
        request: SubmitEncryptedStateUpdateRequest,
    ) -> PrivateL2PqConfidentialContractStateChannelRuntimeResult<String> {
        self.ensure_state_update_capacity()?;
        require_nonempty("channel_id", &request.channel_id)?;
        require_nonempty("next_state_commitment", &request.next_state_commitment)?;
        require_nonempty("encrypted_delta_root", &request.encrypted_delta_root)?;
        require_nonempty("pq_signature_root", &request.pq_signature_root)?;
        if request.valid_until_height <= request.submitted_at_height {
            return Err("state update validity must extend beyond submission height".to_string());
        }
        self.insert_nullifier_fence(&request.nullifier_fence_root)?;
        self.insert_replay_fence(&request.replay_fence_root)?;
        let channel = self
            .channels
            .get_mut(&request.channel_id)
            .ok_or_else(|| "channel not found".to_string())?;
        if !channel.status.accepts_updates() {
            return Err("channel does not accept state updates".to_string());
        }
        if channel.latest_state_commitment != request.previous_state_commitment {
            return Err("state update previous commitment is stale".to_string());
        }
        if request.sequence != channel.update_sequence.saturating_add(1) {
            return Err("state update sequence is not next channel sequence".to_string());
        }
        self.counters.state_updates = self.counters.state_updates.saturating_add(1);
        let update_id = encrypted_state_update_id(&request, self.counters.state_updates);
        let update = EncryptedStateUpdate {
            update_id: update_id.clone(),
            channel_id: request.channel_id.clone(),
            update_kind: request.update_kind,
            status: UpdateStatus::Applied,
            previous_state_commitment: request.previous_state_commitment,
            next_state_commitment: request.next_state_commitment.clone(),
            encrypted_delta_root: request.encrypted_delta_root.clone(),
            call_data_commitment: request.call_data_commitment,
            contract_output_commitment: request.contract_output_commitment,
            signer_attestation_root: request.signer_attestation_root,
            pq_signature_root: request.pq_signature_root,
            nullifier_fence_root: request.nullifier_fence_root,
            replay_fence_root: request.replay_fence_root,
            privacy_proof_root: request.privacy_proof_root,
            fee_commitment: request.fee_commitment.clone(),
            rebate_commitment: request.rebate_commitment.clone(),
            submitted_at_height: request.submitted_at_height,
            valid_until_height: request.valid_until_height,
            applied_at_height: Some(request.submitted_at_height),
            sequence: request.sequence,
        };
        channel.latest_state_commitment = request.next_state_commitment;
        channel.latest_state_ciphertext_root = request.encrypted_delta_root;
        channel.last_update_height = request.submitted_at_height;
        channel.update_sequence = request.sequence;
        channel.status = ChannelStatus::Updating;
        channel.accumulated_fee_commitment = request.fee_commitment;
        channel.accumulated_rebate_commitment = request.rebate_commitment;
        channel.update_ids.push(update_id.clone());
        self.state_updates.insert(update_id.clone(), update);
        self.push_event(
            "encrypted_state_update_applied",
            json!({ "channel_id": request.channel_id, "update_id": update_id }),
        );
        Ok(update_id)
    }

    pub fn open_dispute(
        &mut self,
        request: OpenDisputeRequest,
    ) -> PrivateL2PqConfidentialContractStateChannelRuntimeResult<String> {
        self.ensure_dispute_capacity()?;
        require_nonempty("channel_id", &request.channel_id)?;
        require_nonempty("disputed_update_id", &request.disputed_update_id)?;
        require_nonempty("evidence_root", &request.evidence_root)?;
        if request.window_close_height <= request.opened_at_height {
            return Err("dispute window must close after open height".to_string());
        }
        self.insert_nullifier_fence(&request.nullifier_fence_root)?;
        self.insert_replay_fence(&request.replay_fence_root)?;
        let channel = self
            .channels
            .get_mut(&request.channel_id)
            .ok_or_else(|| "channel not found".to_string())?;
        if !channel.status.accepts_disputes() {
            return Err("channel does not accept disputes".to_string());
        }
        if !self.state_updates.contains_key(&request.disputed_update_id) {
            return Err("disputed update not found".to_string());
        }
        self.counters.disputes = self.counters.disputes.saturating_add(1);
        let dispute_id = dispute_window_id(&request, self.counters.disputes);
        let dispute = DisputeWindow {
            dispute_id: dispute_id.clone(),
            channel_id: request.channel_id.clone(),
            disputed_update_id: request.disputed_update_id,
            kind: request.kind,
            status: DisputeStatus::Open,
            claimant_commitment: request.claimant_commitment,
            evidence_root: request.evidence_root,
            counter_state_commitment: request.counter_state_commitment,
            counter_state_ciphertext_root: request.counter_state_ciphertext_root,
            nullifier_fence_root: request.nullifier_fence_root,
            replay_fence_root: request.replay_fence_root,
            bond_commitment: request.bond_commitment,
            resolution_root: merkle_root(
                "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-EMPTY-DISPUTE-RESOLUTION",
                &[],
            ),
            opened_at_height: request.opened_at_height,
            window_close_height: request.window_close_height,
            resolved_at_height: None,
        };
        channel.status = ChannelStatus::Disputed;
        channel.dispute_ids.push(dispute_id.clone());
        self.disputes.insert(dispute_id.clone(), dispute);
        self.push_event(
            "dispute_opened",
            json!({ "channel_id": request.channel_id, "dispute_id": dispute_id }),
        );
        Ok(dispute_id)
    }

    pub fn reserve_sponsor(
        &mut self,
        request: ReserveSponsorRequest,
    ) -> PrivateL2PqConfidentialContractStateChannelRuntimeResult<String> {
        self.ensure_sponsor_reservation_capacity()?;
        require_nonempty("channel_id", &request.channel_id)?;
        require_nonempty("sponsor_commitment", &request.sponsor_commitment)?;
        require_nonempty("beneficiary_commitment", &request.beneficiary_commitment)?;
        if request.max_fee_bps > self.config.max_user_fee_bps {
            return Err("sponsor reservation fee bps exceeds configured maximum".to_string());
        }
        if request.expires_at_height <= request.reserved_at_height {
            return Err("reservation expiry must be after reservation height".to_string());
        }
        self.insert_nullifier_fence(&request.nullifier_fence_root)?;
        self.insert_replay_fence(&request.replay_fence_root)?;
        let channel = self
            .channels
            .get_mut(&request.channel_id)
            .ok_or_else(|| "channel not found".to_string())?;
        self.counters.sponsor_reservations = self.counters.sponsor_reservations.saturating_add(1);
        let reservation_id = sponsor_reservation_id(&request, self.counters.sponsor_reservations);
        let reservation = SponsorReservation {
            reservation_id: reservation_id.clone(),
            channel_id: request.channel_id.clone(),
            sponsor_commitment: request.sponsor_commitment,
            beneficiary_commitment: request.beneficiary_commitment,
            fee_asset_commitment: request.fee_asset_commitment,
            status: SponsorReservationStatus::Reserved,
            reserved_fee_units: request.reserved_fee_units,
            consumed_fee_units: 0,
            rebate_fee_units: 0,
            max_fee_bps: request.max_fee_bps,
            privacy_budget_root: request.privacy_budget_root,
            sponsor_attestation_root: request.sponsor_attestation_root,
            nullifier_fence_root: request.nullifier_fence_root,
            replay_fence_root: request.replay_fence_root,
            reserved_at_height: request.reserved_at_height,
            expires_at_height: request.expires_at_height,
            consumed_at_height: None,
        };
        channel.sponsor_reservation_ids.push(reservation_id.clone());
        self.sponsor_reservations
            .insert(reservation_id.clone(), reservation);
        self.push_event(
            "sponsor_reserved",
            json!({ "channel_id": request.channel_id, "reservation_id": reservation_id }),
        );
        Ok(reservation_id)
    }

    pub fn build_settlement_batch(
        &mut self,
        request: BuildSettlementBatchRequest,
    ) -> PrivateL2PqConfidentialContractStateChannelRuntimeResult<String> {
        self.ensure_batch_capacity()?;
        require_unique("channel_ids", &request.channel_ids)?;
        require_unique("update_ids", &request.update_ids)?;
        require_unique("dispute_ids", &request.dispute_ids)?;
        require_unique("reservation_ids", &request.reservation_ids)?;
        require_nonempty("settlement_state_root", &request.settlement_state_root)?;
        require_nonempty("settlement_receipt_root", &request.settlement_receipt_root)?;
        require_nonempty("batch_proof_root", &request.batch_proof_root)?;
        if request.valid_until_height <= request.built_at_height {
            return Err("settlement batch validity must extend beyond build height".to_string());
        }
        self.insert_nullifier_fence(&request.nullifier_fence_root)?;
        self.insert_replay_fence(&request.replay_fence_root)?;
        for channel_id in &request.channel_ids {
            if !self.channels.contains_key(channel_id) {
                return Err(format!("channel {channel_id} not found"));
            }
        }
        for update_id in &request.update_ids {
            if !self.state_updates.contains_key(update_id) {
                return Err(format!("state update {update_id} not found"));
            }
        }
        for dispute_id in &request.dispute_ids {
            if !self.disputes.contains_key(dispute_id) {
                return Err(format!("dispute {dispute_id} not found"));
            }
        }
        for reservation_id in &request.reservation_ids {
            if !self.sponsor_reservations.contains_key(reservation_id) {
                return Err(format!("sponsor reservation {reservation_id} not found"));
            }
        }
        self.counters.settlement_batches = self.counters.settlement_batches.saturating_add(1);
        let batch_id = settlement_batch_id(&request, self.counters.settlement_batches);
        let batch = SettlementBatch {
            batch_id: batch_id.clone(),
            status: SettlementBatchStatus::Published,
            channel_ids: request.channel_ids.clone(),
            update_ids: request.update_ids,
            dispute_ids: request.dispute_ids,
            reservation_ids: request.reservation_ids,
            receipt_ids: Vec::new(),
            settlement_state_root: request.settlement_state_root,
            settlement_receipt_root: request.settlement_receipt_root,
            batch_proof_root: request.batch_proof_root,
            nullifier_fence_root: request.nullifier_fence_root,
            replay_fence_root: request.replay_fence_root,
            batch_fee_commitment: request.batch_fee_commitment,
            batch_rebate_commitment: request.batch_rebate_commitment,
            built_at_height: request.built_at_height,
            valid_until_height: request.valid_until_height,
            finalized_at_height: None,
        };
        for channel_id in &request.channel_ids {
            if let Some(channel) = self.channels.get_mut(channel_id) {
                channel.status = ChannelStatus::Settling;
            }
        }
        self.settlement_batches.insert(batch_id.clone(), batch);
        self.push_event(
            "settlement_batch_published",
            json!({ "batch_id": batch_id }),
        );
        Ok(batch_id)
    }

    pub fn publish_settlement_receipt(
        &mut self,
        request: PublishSettlementReceiptRequest,
    ) -> PrivateL2PqConfidentialContractStateChannelRuntimeResult<String> {
        self.ensure_receipt_capacity()?;
        require_nonempty("batch_id", &request.batch_id)?;
        require_nonempty("channel_id", &request.channel_id)?;
        require_nonempty("subject_id", &request.subject_id)?;
        require_nonempty("public_payload_root", &request.public_payload_root)?;
        require_nonempty("encrypted_payload_root", &request.encrypted_payload_root)?;
        self.insert_nullifier_fence(&request.nullifier_fence_root)?;
        self.insert_replay_fence(&request.replay_fence_root)?;
        if !self.channels.contains_key(&request.channel_id) {
            return Err("channel not found".to_string());
        }
        if !self.settlement_batches.contains_key(&request.batch_id) {
            return Err("settlement batch not found".to_string());
        }
        self.counters.receipts = self.counters.receipts.saturating_add(1);
        let receipt_id = settlement_receipt_id(&request, self.counters.receipts);
        let receipt = SettlementReceipt {
            receipt_id: receipt_id.clone(),
            batch_id: request.batch_id.clone(),
            channel_id: request.channel_id.clone(),
            receipt_kind: request.receipt_kind,
            subject_id: request.subject_id,
            public_payload_root: request.public_payload_root,
            encrypted_payload_root: request.encrypted_payload_root,
            proof_root: request.proof_root,
            nullifier_fence_root: request.nullifier_fence_root,
            replay_fence_root: request.replay_fence_root,
            fee_commitment: request.fee_commitment,
            rebate_commitment: request.rebate_commitment,
            published_at_height: request.published_at_height,
        };
        if let Some(batch) = self.settlement_batches.get_mut(&request.batch_id) {
            batch.receipt_ids.push(receipt_id.clone());
        }
        if let Some(channel) = self.channels.get_mut(&request.channel_id) {
            channel.receipt_ids.push(receipt_id.clone());
        }
        self.receipts.insert(receipt_id.clone(), receipt);
        self.push_event(
            "settlement_receipt_published",
            json!({ "batch_id": request.batch_id, "channel_id": request.channel_id, "receipt_id": receipt_id }),
        );
        Ok(receipt_id)
    }

    pub fn publish_rebate(
        &mut self,
        request: PublishRebateRequest,
    ) -> PrivateL2PqConfidentialContractStateChannelRuntimeResult<String> {
        self.ensure_rebate_capacity()?;
        require_nonempty("channel_id", &request.channel_id)?;
        require_nonempty("batch_id", &request.batch_id)?;
        require_nonempty("beneficiary_commitment", &request.beneficiary_commitment)?;
        require_nonempty("rebate_proof_root", &request.rebate_proof_root)?;
        self.insert_nullifier_fence(&request.nullifier_fence_root)?;
        self.insert_replay_fence(&request.replay_fence_root)?;
        if !self.channels.contains_key(&request.channel_id) {
            return Err("channel not found".to_string());
        }
        if !self.settlement_batches.contains_key(&request.batch_id) {
            return Err("settlement batch not found".to_string());
        }
        self.counters.rebates = self.counters.rebates.saturating_add(1);
        let rebate_id = channel_rebate_id(&request, self.counters.rebates);
        let rebate = Rebate {
            rebate_id: rebate_id.clone(),
            channel_id: request.channel_id.clone(),
            batch_id: request.batch_id.clone(),
            beneficiary_commitment: request.beneficiary_commitment,
            sponsor_commitment: request.sponsor_commitment,
            rebate_asset_commitment: request.rebate_asset_commitment,
            rebate_amount_commitment: request.rebate_amount_commitment,
            rebate_proof_root: request.rebate_proof_root,
            nullifier_fence_root: request.nullifier_fence_root,
            replay_fence_root: request.replay_fence_root,
            published_at_height: request.published_at_height,
        };
        self.rebates.insert(rebate_id.clone(), rebate);
        self.push_event(
            "rebate_published",
            json!({ "batch_id": request.batch_id, "channel_id": request.channel_id, "rebate_id": rebate_id }),
        );
        Ok(rebate_id)
    }

    pub fn audit_privacy_fence(
        &mut self,
        fence: PrivacyFence,
    ) -> PrivateL2PqConfidentialContractStateChannelRuntimeResult<String> {
        if fence.min_privacy_set < self.config.min_privacy_set {
            return Err("privacy fence set below configured minimum".to_string());
        }
        require_nonempty("fence_id", &fence.fence_id)?;
        require_nonempty("channel_id", &fence.channel_id)?;
        require_nonempty("nullifier_root", &fence.nullifier_root)?;
        require_nonempty("replay_root", &fence.replay_root)?;
        if !self.channels.contains_key(&fence.channel_id) {
            return Err("channel not found".to_string());
        }
        self.insert_nullifier_fence(&fence.nullifier_root)?;
        self.insert_replay_fence(&fence.replay_root)?;
        let fence_id = fence.fence_id.clone();
        self.privacy_fences.insert(fence_id.clone(), fence);
        self.push_event("privacy_fence_audited", json!({ "fence_id": fence_id }));
        Ok(fence_id)
    }

    pub fn roots(&self) -> Roots {
        let channel_records = self
            .channels
            .values()
            .map(Channel::public_record)
            .collect::<Vec<_>>();
        let participant_records = self
            .participants
            .values()
            .map(Participant::public_record)
            .collect::<Vec<_>>();
        let attestation_records = self
            .attestations
            .values()
            .map(ParticipantAttestation::public_record)
            .collect::<Vec<_>>();
        let update_records = self
            .state_updates
            .values()
            .map(EncryptedStateUpdate::public_record)
            .collect::<Vec<_>>();
        let dispute_records = self
            .disputes
            .values()
            .map(DisputeWindow::public_record)
            .collect::<Vec<_>>();
        let reservation_records = self
            .sponsor_reservations
            .values()
            .map(SponsorReservation::public_record)
            .collect::<Vec<_>>();
        let batch_records = self
            .settlement_batches
            .values()
            .map(SettlementBatch::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .receipts
            .values()
            .map(SettlementReceipt::public_record)
            .collect::<Vec<_>>();
        let rebate_records = self
            .rebates
            .values()
            .map(Rebate::public_record)
            .collect::<Vec<_>>();
        let privacy_fence_records = self
            .privacy_fences
            .values()
            .map(PrivacyFence::public_record)
            .collect::<Vec<_>>();
        let nullifier_records = self
            .nullifier_fences
            .iter()
            .map(|fence| json!({ "nullifier_fence": fence }))
            .collect::<Vec<_>>();
        let replay_records = self
            .replay_fences
            .iter()
            .map(|fence| json!({ "replay_fence": fence }))
            .collect::<Vec<_>>();
        let config_root = self.config.root();
        let counter_root = self.counters.root();
        let channel_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-CHANNELS",
            &channel_records,
        );
        let participant_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-PARTICIPANTS",
            &participant_records,
        );
        let attestation_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-ATTESTATIONS",
            &attestation_records,
        );
        let encrypted_state_update_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-UPDATES",
            &update_records,
        );
        let dispute_window_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-DISPUTES",
            &dispute_records,
        );
        let sponsor_reservation_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-RESERVATIONS",
            &reservation_records,
        );
        let settlement_batch_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-BATCHES",
            &batch_records,
        );
        let settlement_receipt_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-RECEIPTS",
            &receipt_records,
        );
        let rebate_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-REBATES",
            &rebate_records,
        );
        let privacy_fence_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-PRIVACY-FENCES",
            &privacy_fence_records,
        );
        let nullifier_fence_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-NULLIFIER-FENCES",
            &nullifier_records,
        );
        let replay_fence_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-REPLAY-FENCES",
            &replay_records,
        );
        let public_roots = json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_PROTOCOL_VERSION,
            "config_root": config_root,
            "counter_root": counter_root,
            "channel_root": channel_root,
            "participant_root": participant_root,
            "attestation_root": attestation_root,
            "encrypted_state_update_root": encrypted_state_update_root,
            "dispute_window_root": dispute_window_root,
            "sponsor_reservation_root": sponsor_reservation_root,
            "settlement_batch_root": settlement_batch_root,
            "settlement_receipt_root": settlement_receipt_root,
            "rebate_root": rebate_root,
            "privacy_fence_root": privacy_fence_root,
            "nullifier_fence_root": nullifier_fence_root,
            "replay_fence_root": replay_fence_root,
        });
        let public_record_root_value = root_from_record(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-PUBLIC-ROOTS",
            &public_roots,
        );
        let state_root = state_root_from_record(&json!({
            "public_roots": public_roots,
            "public_record_root": public_record_root_value,
        }));
        Roots {
            config_root,
            counter_root,
            channel_root,
            participant_root,
            attestation_root,
            encrypted_state_update_root,
            dispute_window_root,
            sponsor_reservation_root,
            settlement_batch_root,
            settlement_receipt_root,
            rebate_root,
            privacy_fence_root,
            nullifier_fence_root,
            replay_fence_root,
            public_record_root: public_record_root_value,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_SCHEMA_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }

    fn push_event(&mut self, event_type: &str, payload: Value) {
        self.counters.events = self.counters.events.saturating_add(1);
        let event_id = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-EVENT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(
                    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_PROTOCOL_VERSION,
                ),
                HashPart::Str(event_type),
                HashPart::U64(self.counters.events),
                HashPart::Json(&payload),
            ],
            32,
        );
        self.events.push(json!({
            "event_id": event_id,
            "event_type": event_type,
            "sequence": self.counters.events,
            "payload": payload,
        }));
    }

    fn insert_nullifier_fence(
        &mut self,
        fence: &str,
    ) -> PrivateL2PqConfidentialContractStateChannelRuntimeResult<()> {
        require_nonempty("nullifier_fence", fence)?;
        if !self.nullifier_fences.insert(fence.to_string()) {
            return Err("nullifier fence already consumed".to_string());
        }
        Ok(())
    }

    fn insert_replay_fence(
        &mut self,
        fence: &str,
    ) -> PrivateL2PqConfidentialContractStateChannelRuntimeResult<()> {
        require_nonempty("replay_fence", fence)?;
        if !self.replay_fences.insert(fence.to_string()) {
            return Err("replay fence already consumed".to_string());
        }
        Ok(())
    }

    fn ensure_channel_capacity(
        &self,
    ) -> PrivateL2PqConfidentialContractStateChannelRuntimeResult<()> {
        if self.channels.len() >= self.config.max_channels {
            return Err("confidential state channel capacity exhausted".to_string());
        }
        Ok(())
    }

    fn ensure_participant_capacity(
        &self,
    ) -> PrivateL2PqConfidentialContractStateChannelRuntimeResult<()> {
        if self.participants.len() >= self.config.max_participants {
            return Err("state channel participant capacity exhausted".to_string());
        }
        Ok(())
    }

    fn ensure_attestation_capacity(
        &self,
    ) -> PrivateL2PqConfidentialContractStateChannelRuntimeResult<()> {
        if self.attestations.len() >= self.config.max_attestations {
            return Err("PQ participant attestation capacity exhausted".to_string());
        }
        Ok(())
    }

    fn ensure_state_update_capacity(
        &self,
    ) -> PrivateL2PqConfidentialContractStateChannelRuntimeResult<()> {
        if self.state_updates.len() >= self.config.max_state_updates {
            return Err("encrypted state update capacity exhausted".to_string());
        }
        Ok(())
    }

    fn ensure_dispute_capacity(
        &self,
    ) -> PrivateL2PqConfidentialContractStateChannelRuntimeResult<()> {
        if self.disputes.len() >= self.config.max_disputes {
            return Err("state channel dispute capacity exhausted".to_string());
        }
        Ok(())
    }

    fn ensure_sponsor_reservation_capacity(
        &self,
    ) -> PrivateL2PqConfidentialContractStateChannelRuntimeResult<()> {
        if self.sponsor_reservations.len() >= self.config.max_sponsor_reservations {
            return Err("sponsor reservation capacity exhausted".to_string());
        }
        Ok(())
    }

    fn ensure_batch_capacity(
        &self,
    ) -> PrivateL2PqConfidentialContractStateChannelRuntimeResult<()> {
        if self.settlement_batches.len() >= self.config.max_batches {
            return Err("settlement batch capacity exhausted".to_string());
        }
        Ok(())
    }

    fn ensure_receipt_capacity(
        &self,
    ) -> PrivateL2PqConfidentialContractStateChannelRuntimeResult<()> {
        if self.receipts.len() >= self.config.max_receipts {
            return Err("settlement receipt capacity exhausted".to_string());
        }
        Ok(())
    }

    fn ensure_rebate_capacity(
        &self,
    ) -> PrivateL2PqConfidentialContractStateChannelRuntimeResult<()> {
        if self.rebates.len() >= self.config.max_rebates {
            return Err("rebate capacity exhausted".to_string());
        }
        Ok(())
    }
}

pub type Runtime = State;

pub fn confidential_channel_id(request: &OpenChannelRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn channel_participant_id(
    channel_id: &str,
    descriptor: &ParticipantDescriptor,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-PARTICIPANT-ID",
        &json!({
            "sequence": sequence,
            "channel_id": channel_id,
            "descriptor": descriptor.public_record(),
        }),
    )
}

pub fn participant_attestation_id(
    request: &SubmitParticipantAttestationRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-ATTESTATION-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn encrypted_state_update_id(
    request: &SubmitEncryptedStateUpdateRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-UPDATE-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn dispute_window_id(request: &OpenDisputeRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-DISPUTE-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn sponsor_reservation_id(request: &ReserveSponsorRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-SPONSOR-RESERVATION-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn settlement_batch_id(request: &BuildSettlementBatchRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-SETTLEMENT-BATCH-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn settlement_receipt_id(request: &PublishSettlementReceiptRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-SETTLEMENT-RECEIPT-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn channel_rebate_id(request: &PublishRebateRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-REBATE-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn privacy_fence_id(channel_id: &str, nullifier_root: &str, replay_root: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-PRIVACY-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Str(channel_id),
            HashPart::Str(nullifier_root),
            HashPart::Str(replay_root),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    root_from_record(domain, payload)
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    let leaves = records
        .iter()
        .enumerate()
        .map(|(index, record)| {
            Value::String(root_from_record(
                domain,
                &json!({
                    "index": index,
                    "record": record,
                }),
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-STATE-ROOT",
        record,
    )
}

pub fn nullifier_fence_commitment(kind: &str, nullifier: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-NULLIFIER-FENCE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Str(kind),
            HashPart::Str(nullifier),
        ],
        32,
    )
}

pub fn replay_fence_commitment(channel_id: &str, nonce: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-REPLAY-FENCE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Str(channel_id),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn encrypted_payload_commitment(channel_id: &str, payload: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-ENCRYPTED-PAYLOAD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Str(channel_id),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn payload_id(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Json(payload),
        ],
        32,
    )
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
                &[HashPart::U64(index as u64), HashPart::Str(id)],
                32,
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn sample_root(domain: &str, label: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Str(label),
        ],
        32,
    )
}

fn zero_commitment(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-STATE-CHANNEL-ZERO-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_CHANNEL_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Str(label),
        ],
        32,
    )
}

fn require_nonempty(
    field: &str,
    value: &str,
) -> PrivateL2PqConfidentialContractStateChannelRuntimeResult<()> {
    if value.is_empty() {
        return Err(format!("{field} cannot be empty"));
    }
    Ok(())
}

fn require_unique(
    field: &str,
    values: &[String],
) -> PrivateL2PqConfidentialContractStateChannelRuntimeResult<()> {
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
