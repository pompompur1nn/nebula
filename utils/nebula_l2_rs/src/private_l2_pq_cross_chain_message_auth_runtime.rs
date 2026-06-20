use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqCrossChainMessageAuthRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-cross-chain-message-auth-runtime-v1";
pub const PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_PQ_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_MESSAGE_SCHEME: &str =
    "encrypted-private-cross-chain-contract-message-v1";
pub const PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_PAYLOAD_COMMITMENT_SCHEME: &str =
    "roots-only-encrypted-payload-commitment-v1";
pub const PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_COMMITTEE_SCHEME: &str =
    "pq-signer-committee-threshold-authorization-v1";
pub const PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_REPLAY_FENCE_SCHEME: &str =
    "cross-chain-message-replay-nullifier-fence-v1";
pub const PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_LOW_FEE_RELAY_SCHEME: &str =
    "low-fee-private-cross-chain-message-relay-reservation-v1";
pub const PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_EXECUTION_ACK_SCHEME: &str =
    "private-contract-execution-acknowledgement-root-v1";
pub const PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_SETTLEMENT_RECEIPT_SCHEME: &str =
    "cross-chain-message-settlement-receipt-root-v1";
pub const PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEVNET_HEIGHT: u64 = 540_000;
pub const PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_L2_NETWORK: &str = "nebula-devnet";
pub const PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_MONERO_NETWORK: &str =
    "monero-devnet";
pub const PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_FEE_ASSET_ID: &str = "asset:wxmr";
pub const PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_LOW_FEE_LANE: &str =
    "private-l2-pq-cross-chain-message-auth";
pub const PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 4_096;
pub const PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_QUORUM_WEIGHT_BPS: u64 = 6_700;
pub const PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_FAST_QUORUM_BPS: u64 = 7_500;
pub const PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_MAX_FEE_BPS: u64 = 10;
pub const PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_CHANNEL_TTL_BLOCKS: u64 = 2_880;
pub const PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_MESSAGE_TTL_BLOCKS: u64 = 48;
pub const PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 8;
pub const PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_FINALITY_BLOCKS: u64 = 12;
pub const PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_MAX_COMMITTEES: usize = 65_536;
pub const PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_MAX_CHANNELS: usize = 65_536;
pub const PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_MAX_MESSAGES: usize = 524_288;
pub const PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_MAX_AUTHORIZATIONS: usize =
    1_048_576;
pub const PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize = 524_288;
pub const PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_MAX_ACKS: usize = 524_288;
pub const PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_MAX_RECEIPTS: usize = 524_288;
pub const PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageChannelKind {
    PrivateContractCall,
    PrivateTokenBridge,
    ConfidentialSwap,
    MoneroBridgeInstruction,
    OracleCallback,
    SettlementHook,
    EmergencyRecovery,
}

impl MessageChannelKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateContractCall => "private_contract_call",
            Self::PrivateTokenBridge => "private_token_bridge",
            Self::ConfidentialSwap => "confidential_swap",
            Self::MoneroBridgeInstruction => "monero_bridge_instruction",
            Self::OracleCallback => "oracle_callback",
            Self::SettlementHook => "settlement_hook",
            Self::EmergencyRecovery => "emergency_recovery",
        }
    }

    pub fn priority_score(self) -> u64 {
        match self {
            Self::EmergencyRecovery => 10_000,
            Self::SettlementHook => 9_600,
            Self::MoneroBridgeInstruction => 9_300,
            Self::ConfidentialSwap => 8_700,
            Self::PrivateTokenBridge => 8_200,
            Self::PrivateContractCall => 7_800,
            Self::OracleCallback => 7_200,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelStatus {
    Opening,
    Active,
    Paused,
    Draining,
    Closed,
    Slashed,
}

impl ChannelStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Opening => "opening",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Closed => "closed",
            Self::Slashed => "slashed",
        }
    }

    pub fn can_accept_messages(self) -> bool {
        matches!(self, Self::Active | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadEncryptionKind {
    ThresholdMlKem,
    SenderSealedMlKem,
    ViewKeyWrapped,
    HybridPqClassic,
}

impl PayloadEncryptionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ThresholdMlKem => "threshold_ml_kem",
            Self::SenderSealedMlKem => "sender_sealed_ml_kem",
            Self::ViewKeyWrapped => "view_key_wrapped",
            Self::HybridPqClassic => "hybrid_pq_classic",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageStatus {
    Submitted,
    RelayReserved,
    PqAuthorized,
    Rejected,
    Executed,
    Acked,
    Settled,
    Expired,
    Cancelled,
}

impl MessageStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::RelayReserved => "relay_reserved",
            Self::PqAuthorized => "pq_authorized",
            Self::Rejected => "rejected",
            Self::Executed => "executed",
            Self::Acked => "acked",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::RelayReserved | Self::PqAuthorized | Self::Executed
        )
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Expired | Self::Cancelled | Self::Rejected
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeStatus {
    Forming,
    Active,
    Rotating,
    Paused,
    Retired,
    Slashed,
}

impl CommitteeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Forming => "forming",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Paused => "paused",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }

    pub fn can_authorize(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeVerdict {
    Approve,
    Reject,
    Abstain,
}

impl CommitteeVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reject => "reject",
            Self::Abstain => "abstain",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayReservationStatus {
    Reserved,
    Published,
    Settled,
    Cancelled,
    Expired,
}

impl RelayReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Published => "published",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionAckStatus {
    Accepted,
    Executed,
    Reverted,
    Deferred,
}

impl ExecutionAckStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Executed => "executed",
            Self::Reverted => "reverted",
            Self::Deferred => "deferred",
        }
    }

    pub fn successful(self) -> bool {
        matches!(self, Self::Accepted | Self::Executed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementReceiptStatus {
    PendingFinality,
    Finalized,
    Challenged,
    Failed,
}

impl SettlementReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PendingFinality => "pending_finality",
            Self::Finalized => "finalized",
            Self::Challenged => "challenged",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub low_fee_lane: String,
    pub hash_suite: String,
    pub pq_suite: String,
    pub message_scheme: String,
    pub payload_commitment_scheme: String,
    pub committee_scheme: String,
    pub replay_fence_scheme: String,
    pub low_fee_relay_scheme: String,
    pub execution_ack_scheme: String,
    pub settlement_receipt_scheme: String,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub quorum_weight_bps: u64,
    pub fast_quorum_bps: u64,
    pub max_fee_bps: u64,
    pub channel_ttl_blocks: u64,
    pub message_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub finality_blocks: u64,
    pub max_committees: usize,
    pub max_channels: usize,
    pub max_messages: usize,
    pub max_authorizations: usize,
    pub max_reservations: usize,
    pub max_acks: usize,
    pub max_receipts: usize,
    pub require_roots_only: bool,
    pub require_pq_auth: bool,
    pub require_low_fee_relay: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_L2_NETWORK
                .to_string(),
            monero_network: PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_MONERO_NETWORK
                .to_string(),
            fee_asset_id: PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_FEE_ASSET_ID
                .to_string(),
            low_fee_lane: PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_LOW_FEE_LANE
                .to_string(),
            hash_suite: PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_HASH_SUITE.to_string(),
            pq_suite: PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_PQ_SUITE.to_string(),
            message_scheme: PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_MESSAGE_SCHEME
                .to_string(),
            payload_commitment_scheme:
                PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_PAYLOAD_COMMITMENT_SCHEME.to_string(),
            committee_scheme: PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_COMMITTEE_SCHEME
                .to_string(),
            replay_fence_scheme: PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_REPLAY_FENCE_SCHEME
                .to_string(),
            low_fee_relay_scheme:
                PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_LOW_FEE_RELAY_SCHEME.to_string(),
            execution_ack_scheme:
                PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_EXECUTION_ACK_SCHEME.to_string(),
            settlement_receipt_scheme:
                PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_SETTLEMENT_RECEIPT_SCHEME.to_string(),
            min_privacy_set_size:
                PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            quorum_weight_bps:
                PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_QUORUM_WEIGHT_BPS,
            fast_quorum_bps: PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_FAST_QUORUM_BPS,
            max_fee_bps: PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_MAX_FEE_BPS,
            channel_ttl_blocks:
                PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_CHANNEL_TTL_BLOCKS,
            message_ttl_blocks:
                PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_MESSAGE_TTL_BLOCKS,
            reservation_ttl_blocks:
                PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
            finality_blocks: PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_FINALITY_BLOCKS,
            max_committees: PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_MAX_COMMITTEES,
            max_channels: PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_MAX_CHANNELS,
            max_messages: PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_MAX_MESSAGES,
            max_authorizations:
                PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_MAX_AUTHORIZATIONS,
            max_reservations:
                PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_acks: PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_MAX_ACKS,
            max_receipts: PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEFAULT_MAX_RECEIPTS,
            require_roots_only: true,
            require_pq_auth: true,
            require_low_fee_relay: true,
        }
    }

    pub fn validate(&self) -> PrivateL2PqCrossChainMessageAuthRuntimeResult<()> {
        required("protocol_version", &self.protocol_version)?;
        required("chain_id", &self.chain_id)?;
        required("l2_network", &self.l2_network)?;
        required("monero_network", &self.monero_network)?;
        required("fee_asset_id", &self.fee_asset_id)?;
        required("low_fee_lane", &self.low_fee_lane)?;
        required("hash_suite", &self.hash_suite)?;
        required("pq_suite", &self.pq_suite)?;
        required("message_scheme", &self.message_scheme)?;
        required("payload_commitment_scheme", &self.payload_commitment_scheme)?;
        required("committee_scheme", &self.committee_scheme)?;
        required("replay_fence_scheme", &self.replay_fence_scheme)?;
        required("low_fee_relay_scheme", &self.low_fee_relay_scheme)?;
        required("execution_ack_scheme", &self.execution_ack_scheme)?;
        required("settlement_receipt_scheme", &self.settlement_receipt_scheme)?;
        if self.chain_id != CHAIN_ID {
            return Err("PQ cross-chain message auth chain id mismatch".to_string());
        }
        if self.schema_version == 0 {
            return Err("PQ cross-chain message auth schema version is invalid".to_string());
        }
        if !self.require_roots_only {
            return Err(
                "PQ cross-chain message auth requires roots-only private records".to_string(),
            );
        }
        if self.min_privacy_set_size == 0 || self.min_pq_security_bits < 192 {
            return Err("PQ cross-chain message auth privacy/PQ floor is invalid".to_string());
        }
        if self.quorum_weight_bps == 0
            || self.quorum_weight_bps > PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_MAX_BPS
            || self.fast_quorum_bps < self.quorum_weight_bps
            || self.fast_quorum_bps > PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_MAX_BPS
            || self.max_fee_bps > PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_MAX_BPS
        {
            return Err("PQ cross-chain message auth BPS policy is invalid".to_string());
        }
        if self.channel_ttl_blocks == 0
            || self.message_ttl_blocks == 0
            || self.reservation_ttl_blocks == 0
            || self.finality_blocks == 0
        {
            return Err("PQ cross-chain message auth block windows must be positive".to_string());
        }
        if self.max_committees == 0
            || self.max_channels == 0
            || self.max_messages == 0
            || self.max_authorizations == 0
            || self.max_reservations == 0
            || self.max_acks == 0
            || self.max_receipts == 0
        {
            return Err("PQ cross-chain message auth capacities must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_cross_chain_message_auth_config",
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "low_fee_lane": self.low_fee_lane,
            "hash_suite": self.hash_suite,
            "pq_suite": self.pq_suite,
            "message_scheme": self.message_scheme,
            "payload_commitment_scheme": self.payload_commitment_scheme,
            "committee_scheme": self.committee_scheme,
            "replay_fence_scheme": self.replay_fence_scheme,
            "low_fee_relay_scheme": self.low_fee_relay_scheme,
            "execution_ack_scheme": self.execution_ack_scheme,
            "settlement_receipt_scheme": self.settlement_receipt_scheme,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "quorum_weight_bps": self.quorum_weight_bps,
            "fast_quorum_bps": self.fast_quorum_bps,
            "max_fee_bps": self.max_fee_bps,
            "channel_ttl_blocks": self.channel_ttl_blocks,
            "message_ttl_blocks": self.message_ttl_blocks,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
            "finality_blocks": self.finality_blocks,
            "max_committees": self.max_committees,
            "max_channels": self.max_channels,
            "max_messages": self.max_messages,
            "max_authorizations": self.max_authorizations,
            "max_reservations": self.max_reservations,
            "max_acks": self.max_acks,
            "max_receipts": self.max_receipts,
            "require_roots_only": self.require_roots_only,
            "require_pq_auth": self.require_pq_auth,
            "require_low_fee_relay": self.require_low_fee_relay,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub committee_count: u64,
    pub channel_count: u64,
    pub message_count: u64,
    pub authorization_count: u64,
    pub reservation_count: u64,
    pub ack_count: u64,
    pub receipt_count: u64,
    pub replay_rejection_count: u64,
    pub privacy_floor_rejection_count: u64,
    pub pq_security_rejection_count: u64,
    pub consumed_nullifier_count: u64,
    pub total_reserved_fee_bps: u64,
    pub total_settled_fee_bps: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_cross_chain_message_auth_counters",
            "committee_count": self.committee_count,
            "channel_count": self.channel_count,
            "message_count": self.message_count,
            "authorization_count": self.authorization_count,
            "reservation_count": self.reservation_count,
            "ack_count": self.ack_count,
            "receipt_count": self.receipt_count,
            "replay_rejection_count": self.replay_rejection_count,
            "privacy_floor_rejection_count": self.privacy_floor_rejection_count,
            "pq_security_rejection_count": self.pq_security_rejection_count,
            "consumed_nullifier_count": self.consumed_nullifier_count,
            "total_reserved_fee_bps": self.total_reserved_fee_bps,
            "total_settled_fee_bps": self.total_settled_fee_bps,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterPqSignerCommitteeRequest {
    pub committee_label: String,
    pub signer_committee_root: String,
    pub operator_set_root: String,
    pub pq_public_key_root: String,
    pub stake_weight_root: String,
    pub low_fee_policy_root: String,
    pub privacy_proof_root: String,
    pub epoch: u64,
    pub member_set_size: u64,
    pub committee_weight_bps: u64,
    pub pq_security_bits: u16,
    pub registered_at_height: u64,
}

impl RegisterPqSignerCommitteeRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqCrossChainMessageAuthRuntimeResult<()> {
        required("committee_label", &self.committee_label)?;
        required("signer_committee_root", &self.signer_committee_root)?;
        required("operator_set_root", &self.operator_set_root)?;
        required("pq_public_key_root", &self.pq_public_key_root)?;
        required("stake_weight_root", &self.stake_weight_root)?;
        required("low_fee_policy_root", &self.low_fee_policy_root)?;
        required("privacy_proof_root", &self.privacy_proof_root)?;
        validate_privacy_and_pq(self.member_set_size, self.pq_security_bits, config)?;
        if self.committee_weight_bps < config.quorum_weight_bps
            || self.committee_weight_bps > PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_MAX_BPS
        {
            return Err(
                "PQ cross-chain message auth signer committee weight outside quorum policy"
                    .to_string(),
            );
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "committee_label": self.committee_label,
            "signer_committee_root": self.signer_committee_root,
            "operator_set_root": self.operator_set_root,
            "pq_public_key_root": self.pq_public_key_root,
            "stake_weight_root": self.stake_weight_root,
            "low_fee_policy_root": self.low_fee_policy_root,
            "privacy_proof_root": self.privacy_proof_root,
            "epoch": self.epoch,
            "member_set_size": self.member_set_size,
            "committee_weight_bps": self.committee_weight_bps,
            "pq_security_bits": self.pq_security_bits,
            "registered_at_height": self.registered_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenMessageChannelRequest {
    pub channel_kind: MessageChannelKind,
    pub source_chain_id: String,
    pub destination_chain_id: String,
    pub source_contract_root: String,
    pub destination_contract_root: String,
    pub channel_policy_root: String,
    pub signer_committee_root: String,
    pub pq_public_key_root: String,
    pub low_fee_policy_root: String,
    pub privacy_proof_root: String,
    pub epoch: u64,
    pub committee_weight_bps: u64,
    pub member_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
}

impl OpenMessageChannelRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqCrossChainMessageAuthRuntimeResult<()> {
        required("source_chain_id", &self.source_chain_id)?;
        required("destination_chain_id", &self.destination_chain_id)?;
        required("source_contract_root", &self.source_contract_root)?;
        required("destination_contract_root", &self.destination_contract_root)?;
        required("channel_policy_root", &self.channel_policy_root)?;
        required("signer_committee_root", &self.signer_committee_root)?;
        required("pq_public_key_root", &self.pq_public_key_root)?;
        required("low_fee_policy_root", &self.low_fee_policy_root)?;
        required("privacy_proof_root", &self.privacy_proof_root)?;
        validate_privacy_and_pq(self.member_set_size, self.pq_security_bits, config)?;
        if self.committee_weight_bps < config.quorum_weight_bps
            || self.committee_weight_bps > PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_MAX_BPS
        {
            return Err(
                "PQ cross-chain message auth committee weight outside quorum policy".to_string(),
            );
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "channel_kind": self.channel_kind.as_str(),
            "source_chain_id": self.source_chain_id,
            "destination_chain_id": self.destination_chain_id,
            "source_contract_root": self.source_contract_root,
            "destination_contract_root": self.destination_contract_root,
            "channel_policy_root": self.channel_policy_root,
            "signer_committee_root": self.signer_committee_root,
            "pq_public_key_root": self.pq_public_key_root,
            "low_fee_policy_root": self.low_fee_policy_root,
            "privacy_proof_root": self.privacy_proof_root,
            "epoch": self.epoch,
            "committee_weight_bps": self.committee_weight_bps,
            "member_set_size": self.member_set_size,
            "pq_security_bits": self.pq_security_bits,
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitEncryptedPayloadMessageRequest {
    pub channel_id: String,
    pub channel_kind: MessageChannelKind,
    pub sender_commitment: String,
    pub recipient_commitment_root: String,
    pub encrypted_payload_root: String,
    pub payload_commitment_root: String,
    pub payload_ciphertext_root: String,
    pub payload_opening_root: String,
    pub access_policy_root: String,
    pub pq_encryption_root: String,
    pub pq_authorization_request_root: String,
    pub replay_nullifier: String,
    pub message_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub priority_weight: Option<u64>,
    pub submitted_at_height: u64,
}

impl SubmitEncryptedPayloadMessageRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqCrossChainMessageAuthRuntimeResult<()> {
        required("channel_id", &self.channel_id)?;
        required("sender_commitment", &self.sender_commitment)?;
        required("recipient_commitment_root", &self.recipient_commitment_root)?;
        required("encrypted_payload_root", &self.encrypted_payload_root)?;
        required("payload_commitment_root", &self.payload_commitment_root)?;
        required("payload_ciphertext_root", &self.payload_ciphertext_root)?;
        required("payload_opening_root", &self.payload_opening_root)?;
        required("access_policy_root", &self.access_policy_root)?;
        required("pq_encryption_root", &self.pq_encryption_root)?;
        required(
            "pq_authorization_request_root",
            &self.pq_authorization_request_root,
        )?;
        required("replay_nullifier", &self.replay_nullifier)?;
        required("message_nullifier", &self.message_nullifier)?;
        validate_privacy_and_pq(self.privacy_set_size, self.pq_security_bits, config)?;
        if self.max_fee_bps > config.max_fee_bps {
            return Err("PQ cross-chain message auth message fee exceeds low-fee cap".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "channel_id": self.channel_id,
            "channel_kind": self.channel_kind.as_str(),
            "sender_commitment": self.sender_commitment,
            "recipient_commitment_root": self.recipient_commitment_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "payload_commitment_root": self.payload_commitment_root,
            "payload_ciphertext_root": self.payload_ciphertext_root,
            "payload_opening_root": self.payload_opening_root,
            "access_policy_root": self.access_policy_root,
            "pq_encryption_root": self.pq_encryption_root,
            "pq_authorization_request_root": self.pq_authorization_request_root,
            "replay_nullifier": self.replay_nullifier,
            "message_nullifier": self.message_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "priority_weight": self.priority_weight,
            "submitted_at_height": self.submitted_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitPqCommitteeAuthorizationRequest {
    pub message_id: String,
    pub channel_id: String,
    pub signer_committee_root: String,
    pub signer_commitment: String,
    pub verdict: CommitteeVerdict,
    pub authorization_weight_bps: u64,
    pub payload_check_root: String,
    pub destination_check_root: String,
    pub replay_fence_root: String,
    pub pq_signature_root: String,
    pub privacy_proof_root: String,
    pub authorization_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub authorized_at_height: u64,
}

impl SubmitPqCommitteeAuthorizationRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqCrossChainMessageAuthRuntimeResult<()> {
        required("message_id", &self.message_id)?;
        required("channel_id", &self.channel_id)?;
        required("signer_committee_root", &self.signer_committee_root)?;
        required("signer_commitment", &self.signer_commitment)?;
        required("payload_check_root", &self.payload_check_root)?;
        required("destination_check_root", &self.destination_check_root)?;
        required("replay_fence_root", &self.replay_fence_root)?;
        required("pq_signature_root", &self.pq_signature_root)?;
        required("privacy_proof_root", &self.privacy_proof_root)?;
        required("authorization_nullifier", &self.authorization_nullifier)?;
        validate_privacy_and_pq(self.privacy_set_size, self.pq_security_bits, config)?;
        if self.authorization_weight_bps > PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_MAX_BPS {
            return Err(
                "PQ cross-chain message auth authorization weight exceeds BPS range".to_string(),
            );
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "message_id": self.message_id,
            "channel_id": self.channel_id,
            "signer_committee_root": self.signer_committee_root,
            "signer_commitment": self.signer_commitment,
            "verdict": self.verdict.as_str(),
            "authorization_weight_bps": self.authorization_weight_bps,
            "payload_check_root": self.payload_check_root,
            "destination_check_root": self.destination_check_root,
            "replay_fence_root": self.replay_fence_root,
            "pq_signature_root": self.pq_signature_root,
            "privacy_proof_root": self.privacy_proof_root,
            "authorization_nullifier": self.authorization_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "authorized_at_height": self.authorized_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveLowFeeRelayRequest {
    pub message_id: String,
    pub channel_id: String,
    pub relayer_commitment: String,
    pub relay_window_root: String,
    pub relay_route_root: String,
    pub bandwidth_commitment_root: String,
    pub low_fee_sponsor_root: String,
    pub fee_receipt_root: String,
    pub pq_relayer_signature_root: String,
    pub relay_nullifier: String,
    pub max_fee_bps: u64,
    pub reserved_at_height: u64,
}

impl ReserveLowFeeRelayRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqCrossChainMessageAuthRuntimeResult<()> {
        required("message_id", &self.message_id)?;
        required("channel_id", &self.channel_id)?;
        required("relayer_commitment", &self.relayer_commitment)?;
        required("relay_window_root", &self.relay_window_root)?;
        required("relay_route_root", &self.relay_route_root)?;
        required("bandwidth_commitment_root", &self.bandwidth_commitment_root)?;
        if config.require_low_fee_relay {
            required("low_fee_sponsor_root", &self.low_fee_sponsor_root)?;
        }
        required("fee_receipt_root", &self.fee_receipt_root)?;
        required("pq_relayer_signature_root", &self.pq_relayer_signature_root)?;
        required("relay_nullifier", &self.relay_nullifier)?;
        if self.max_fee_bps > config.max_fee_bps {
            return Err(
                "PQ cross-chain message auth relay reservation fee exceeds cap".to_string(),
            );
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "message_id": self.message_id,
            "channel_id": self.channel_id,
            "relayer_commitment": self.relayer_commitment,
            "relay_window_root": self.relay_window_root,
            "relay_route_root": self.relay_route_root,
            "bandwidth_commitment_root": self.bandwidth_commitment_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "fee_receipt_root": self.fee_receipt_root,
            "pq_relayer_signature_root": self.pq_relayer_signature_root,
            "relay_nullifier": self.relay_nullifier,
            "max_fee_bps": self.max_fee_bps,
            "reserved_at_height": self.reserved_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishExecutionAcknowledgementRequest {
    pub message_id: String,
    pub channel_id: String,
    pub reservation_id: String,
    pub execution_status: ExecutionAckStatus,
    pub executor_commitment: String,
    pub execution_trace_root: String,
    pub output_commitment_root: String,
    pub consumed_nullifier_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub gas_receipt_root: String,
    pub pq_executor_signature_root: String,
    pub ack_nullifier: String,
    pub executed_at_height: u64,
}

impl PublishExecutionAcknowledgementRequest {
    pub fn validate(&self) -> PrivateL2PqCrossChainMessageAuthRuntimeResult<()> {
        required("message_id", &self.message_id)?;
        required("channel_id", &self.channel_id)?;
        required("reservation_id", &self.reservation_id)?;
        required("executor_commitment", &self.executor_commitment)?;
        required("execution_trace_root", &self.execution_trace_root)?;
        required("output_commitment_root", &self.output_commitment_root)?;
        required("consumed_nullifier_root", &self.consumed_nullifier_root)?;
        required("state_root_before", &self.state_root_before)?;
        required("state_root_after", &self.state_root_after)?;
        required("gas_receipt_root", &self.gas_receipt_root)?;
        required(
            "pq_executor_signature_root",
            &self.pq_executor_signature_root,
        )?;
        required("ack_nullifier", &self.ack_nullifier)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "message_id": self.message_id,
            "channel_id": self.channel_id,
            "reservation_id": self.reservation_id,
            "execution_status": self.execution_status.as_str(),
            "executor_commitment": self.executor_commitment,
            "execution_trace_root": self.execution_trace_root,
            "output_commitment_root": self.output_commitment_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "gas_receipt_root": self.gas_receipt_root,
            "pq_executor_signature_root": self.pq_executor_signature_root,
            "ack_nullifier": self.ack_nullifier,
            "executed_at_height": self.executed_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishSettlementReceiptRequest {
    pub message_id: String,
    pub channel_id: String,
    pub ack_id: String,
    pub receipt_status: SettlementReceiptStatus,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub public_input_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub output_commitment_root: String,
    pub consumed_nullifier_root: String,
    pub low_fee_settlement_root: String,
    pub pq_settlement_signature_root: String,
    pub receipt_nullifier: String,
    pub settled_fee_bps: u64,
    pub settled_at_height: u64,
}

impl PublishSettlementReceiptRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqCrossChainMessageAuthRuntimeResult<()> {
        required("message_id", &self.message_id)?;
        required("channel_id", &self.channel_id)?;
        required("ack_id", &self.ack_id)?;
        required("settlement_tx_root", &self.settlement_tx_root)?;
        required("settlement_proof_root", &self.settlement_proof_root)?;
        required("public_input_root", &self.public_input_root)?;
        required("state_root_before", &self.state_root_before)?;
        required("state_root_after", &self.state_root_after)?;
        required("output_commitment_root", &self.output_commitment_root)?;
        required("consumed_nullifier_root", &self.consumed_nullifier_root)?;
        required("low_fee_settlement_root", &self.low_fee_settlement_root)?;
        required(
            "pq_settlement_signature_root",
            &self.pq_settlement_signature_root,
        )?;
        required("receipt_nullifier", &self.receipt_nullifier)?;
        if self.settled_fee_bps > config.max_fee_bps {
            return Err("PQ cross-chain message auth settlement fee exceeds cap".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "message_id": self.message_id,
            "channel_id": self.channel_id,
            "ack_id": self.ack_id,
            "receipt_status": self.receipt_status.as_str(),
            "settlement_tx_root": self.settlement_tx_root,
            "settlement_proof_root": self.settlement_proof_root,
            "public_input_root": self.public_input_root,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "output_commitment_root": self.output_commitment_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
            "low_fee_settlement_root": self.low_fee_settlement_root,
            "pq_settlement_signature_root": self.pq_settlement_signature_root,
            "receipt_nullifier": self.receipt_nullifier,
            "settled_fee_bps": self.settled_fee_bps,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSignerCommitteeRecord {
    pub committee_id: String,
    pub request: RegisterPqSignerCommitteeRequest,
    pub status: CommitteeStatus,
}

impl PqSignerCommitteeRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "committee_id": self.committee_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageChannelRecord {
    pub channel_id: String,
    pub request: OpenMessageChannelRequest,
    pub status: ChannelStatus,
    pub committee_status: CommitteeStatus,
    pub next_sequence: u64,
    pub expires_at_height: u64,
    pub message_ids: Vec<String>,
}

impl MessageChannelRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "channel_id": self.channel_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "committee_status": self.committee_status.as_str(),
            "next_sequence": self.next_sequence,
            "expires_at_height": self.expires_at_height,
            "message_ids": self.message_ids,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedPayloadMessageRecord {
    pub message_id: String,
    pub sequence: u64,
    pub request: SubmitEncryptedPayloadMessageRequest,
    pub approved_weight_bps: u64,
    pub rejected_weight_bps: u64,
    pub status: MessageStatus,
    pub expires_at_height: u64,
    pub authorization_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub ack_ids: Vec<String>,
    pub receipt_ids: Vec<String>,
}

impl EncryptedPayloadMessageRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "message_id": self.message_id,
            "sequence": self.sequence,
            "request": self.request.public_record(),
            "approved_weight_bps": self.approved_weight_bps,
            "rejected_weight_bps": self.rejected_weight_bps,
            "status": self.status.as_str(),
            "expires_at_height": self.expires_at_height,
            "authorization_ids": self.authorization_ids,
            "reservation_ids": self.reservation_ids,
            "ack_ids": self.ack_ids,
            "receipt_ids": self.receipt_ids,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCommitteeAuthorizationRecord {
    pub authorization_id: String,
    pub request: SubmitPqCommitteeAuthorizationRequest,
}

impl PqCommitteeAuthorizationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "authorization_id": self.authorization_id,
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeRelayReservationRecord {
    pub reservation_id: String,
    pub request: ReserveLowFeeRelayRequest,
    pub status: RelayReservationStatus,
    pub expires_at_height: u64,
}

impl LowFeeRelayReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionAcknowledgementRecord {
    pub ack_id: String,
    pub request: PublishExecutionAcknowledgementRequest,
    pub finality_height: u64,
}

impl ExecutionAcknowledgementRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "ack_id": self.ack_id,
            "request": self.request.public_record(),
            "finality_height": self.finality_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceiptRecord {
    pub receipt_id: String,
    pub request: PublishSettlementReceiptRequest,
    pub finality_height: u64,
}

impl SettlementReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "request": self.request.public_record(),
            "finality_height": self.finality_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub counter_root: String,
    pub committee_root: String,
    pub channel_root: String,
    pub message_root: String,
    pub authorization_root: String,
    pub reservation_root: String,
    pub ack_root: String,
    pub receipt_root: String,
    pub replay_nullifier_root: String,
    pub consumed_nullifier_root: String,
    pub payload_commitment_root: String,
    pub pq_authorization_root: String,
    pub low_fee_relay_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counter_root": self.counter_root,
            "committee_root": self.committee_root,
            "channel_root": self.channel_root,
            "message_root": self.message_root,
            "authorization_root": self.authorization_root,
            "reservation_root": self.reservation_root,
            "ack_root": self.ack_root,
            "receipt_root": self.receipt_root,
            "replay_nullifier_root": self.replay_nullifier_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
            "payload_commitment_root": self.payload_commitment_root,
            "pq_authorization_root": self.pq_authorization_root,
            "low_fee_relay_root": self.low_fee_relay_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }

    pub fn root(&self) -> String {
        payload_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub chain_id: String,
    pub protocol_version: String,
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub committees: BTreeMap<String, PqSignerCommitteeRecord>,
    pub channels: BTreeMap<String, MessageChannelRecord>,
    pub messages: BTreeMap<String, EncryptedPayloadMessageRecord>,
    pub authorizations: BTreeMap<String, PqCommitteeAuthorizationRecord>,
    pub reservations: BTreeMap<String, LowFeeRelayReservationRecord>,
    pub acknowledgements: BTreeMap<String, ExecutionAcknowledgementRecord>,
    pub receipts: BTreeMap<String, SettlementReceiptRecord>,
    pub replay_nullifiers: BTreeSet<String>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> PrivateL2PqCrossChainMessageAuthRuntimeResult<Self> {
        Self::new(
            Config::devnet(),
            PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_DEVNET_HEIGHT,
        )
    }

    pub fn new(
        config: Config,
        current_height: u64,
    ) -> PrivateL2PqCrossChainMessageAuthRuntimeResult<Self> {
        config.validate()?;
        Ok(Self {
            chain_id: config.chain_id.clone(),
            protocol_version: PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            config,
            counters: Counters::default(),
            current_height,
            committees: BTreeMap::new(),
            channels: BTreeMap::new(),
            messages: BTreeMap::new(),
            authorizations: BTreeMap::new(),
            reservations: BTreeMap::new(),
            acknowledgements: BTreeMap::new(),
            receipts: BTreeMap::new(),
            replay_nullifiers: BTreeSet::new(),
            consumed_nullifiers: BTreeSet::new(),
        })
    }

    pub fn register_pq_signer_committee(
        &mut self,
        request: RegisterPqSignerCommitteeRequest,
    ) -> PrivateL2PqCrossChainMessageAuthRuntimeResult<PqSignerCommitteeRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.committees.len() >= self.config.max_committees {
            return Err(
                "PQ cross-chain message auth signer committee capacity exhausted".to_string(),
            );
        }
        self.counters.committee_count = self.counters.committee_count.saturating_add(1);
        self.current_height = self.current_height.max(request.registered_at_height);
        let committee_id = pq_signer_committee_id(&request, self.counters.committee_count);
        let record = PqSignerCommitteeRecord {
            committee_id: committee_id.clone(),
            request,
            status: CommitteeStatus::Active,
        };
        self.committees.insert(committee_id, record.clone());
        Ok(record)
    }

    pub fn open_message_channel(
        &mut self,
        request: OpenMessageChannelRequest,
    ) -> PrivateL2PqCrossChainMessageAuthRuntimeResult<MessageChannelRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.channels.len() >= self.config.max_channels {
            return Err("PQ cross-chain message auth channel capacity exhausted".to_string());
        }
        self.counters.channel_count = self.counters.channel_count.saturating_add(1);
        self.current_height = self.current_height.max(request.opened_at_height);
        let channel_id = message_channel_id(&request, self.counters.channel_count);
        let record = MessageChannelRecord {
            channel_id: channel_id.clone(),
            expires_at_height: request
                .opened_at_height
                .saturating_add(self.config.channel_ttl_blocks),
            request,
            status: ChannelStatus::Active,
            committee_status: CommitteeStatus::Active,
            next_sequence: 0,
            message_ids: Vec::new(),
        };
        self.channels.insert(channel_id, record.clone());
        Ok(record)
    }

    pub fn submit_encrypted_payload_message(
        &mut self,
        request: SubmitEncryptedPayloadMessageRequest,
    ) -> PrivateL2PqCrossChainMessageAuthRuntimeResult<EncryptedPayloadMessageRecord> {
        self.config.validate()?;
        request.validate(&self.config).map_err(|err| {
            if err.contains("privacy") {
                self.counters.privacy_floor_rejection_count = self
                    .counters
                    .privacy_floor_rejection_count
                    .saturating_add(1);
            }
            if err.contains("PQ") || err.contains("pq") {
                self.counters.pq_security_rejection_count =
                    self.counters.pq_security_rejection_count.saturating_add(1);
            }
            err
        })?;
        if self.messages.len() >= self.config.max_messages {
            return Err("PQ cross-chain message auth message capacity exhausted".to_string());
        }
        {
            let channel = self
                .channels
                .get(&request.channel_id)
                .ok_or_else(|| "PQ cross-chain message auth channel not found".to_string())?;
            if !channel.status.can_accept_messages()
                || !channel.committee_status.can_authorize()
                || channel.request.channel_kind != request.channel_kind
                || request.submitted_at_height >= channel.expires_at_height
            {
                return Err("PQ cross-chain message auth channel cannot accept message".to_string());
            }
        }
        self.insert_replay_nullifier(&request.replay_nullifier)?;
        self.insert_consumed_nullifier(&request.message_nullifier)?;
        let sequence = self
            .channels
            .get(&request.channel_id)
            .map(|channel| channel.next_sequence)
            .unwrap_or_default();
        self.counters.message_count = self.counters.message_count.saturating_add(1);
        self.current_height = self.current_height.max(request.submitted_at_height);
        let message_id =
            encrypted_payload_message_id(&request, sequence, self.counters.message_count);
        let record = EncryptedPayloadMessageRecord {
            message_id: message_id.clone(),
            sequence,
            expires_at_height: request
                .submitted_at_height
                .saturating_add(self.config.message_ttl_blocks),
            request: request.clone(),
            approved_weight_bps: 0,
            rejected_weight_bps: 0,
            status: MessageStatus::Submitted,
            authorization_ids: Vec::new(),
            reservation_ids: Vec::new(),
            ack_ids: Vec::new(),
            receipt_ids: Vec::new(),
        };
        if let Some(channel) = self.channels.get_mut(&request.channel_id) {
            channel.next_sequence = channel.next_sequence.saturating_add(1);
            channel.message_ids.push(message_id.clone());
        }
        self.messages.insert(message_id, record.clone());
        Ok(record)
    }

    pub fn submit_pq_committee_authorization(
        &mut self,
        request: SubmitPqCommitteeAuthorizationRequest,
    ) -> PrivateL2PqCrossChainMessageAuthRuntimeResult<PqCommitteeAuthorizationRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.authorizations.len() >= self.config.max_authorizations {
            return Err("PQ cross-chain message auth authorization capacity exhausted".to_string());
        }
        {
            let channel = self
                .channels
                .get(&request.channel_id)
                .ok_or_else(|| "PQ cross-chain message auth channel not found".to_string())?;
            if !channel.committee_status.can_authorize()
                || channel.request.signer_committee_root != request.signer_committee_root
            {
                return Err("PQ cross-chain message auth signer committee mismatch".to_string());
            }
            let message = self
                .messages
                .get(&request.message_id)
                .ok_or_else(|| "PQ cross-chain message auth message not found".to_string())?;
            if message.request.channel_id != request.channel_id
                || !message.status.live()
                || request.authorized_at_height >= message.expires_at_height
            {
                return Err("PQ cross-chain message auth message cannot be authorized".to_string());
            }
        }
        self.insert_consumed_nullifier(&request.authorization_nullifier)?;
        self.counters.authorization_count = self.counters.authorization_count.saturating_add(1);
        self.current_height = self.current_height.max(request.authorized_at_height);
        let authorization_id =
            pq_committee_authorization_id(&request, self.counters.authorization_count);
        let record = PqCommitteeAuthorizationRecord {
            authorization_id: authorization_id.clone(),
            request: request.clone(),
        };
        if let Some(message) = self.messages.get_mut(&request.message_id) {
            match request.verdict {
                CommitteeVerdict::Approve => {
                    message.approved_weight_bps = message
                        .approved_weight_bps
                        .saturating_add(request.authorization_weight_bps)
                        .min(PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_MAX_BPS);
                }
                CommitteeVerdict::Reject => {
                    message.rejected_weight_bps = message
                        .rejected_weight_bps
                        .saturating_add(request.authorization_weight_bps)
                        .min(PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_MAX_BPS);
                }
                CommitteeVerdict::Abstain => {}
            }
            message.authorization_ids.push(authorization_id.clone());
            if message.approved_weight_bps >= self.config.fast_quorum_bps {
                message.status = MessageStatus::PqAuthorized;
            } else if message.rejected_weight_bps >= self.config.quorum_weight_bps {
                message.status = MessageStatus::Rejected;
            }
        }
        self.authorizations.insert(authorization_id, record.clone());
        Ok(record)
    }

    pub fn reserve_low_fee_relay(
        &mut self,
        request: ReserveLowFeeRelayRequest,
    ) -> PrivateL2PqCrossChainMessageAuthRuntimeResult<LowFeeRelayReservationRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.reservations.len() >= self.config.max_reservations {
            return Err("PQ cross-chain message auth reservation capacity exhausted".to_string());
        }
        {
            let message = self
                .messages
                .get(&request.message_id)
                .ok_or_else(|| "PQ cross-chain message auth message not found".to_string())?;
            if message.request.channel_id != request.channel_id
                || !message.status.live()
                || request.reserved_at_height >= message.expires_at_height
            {
                return Err("PQ cross-chain message auth message cannot reserve relay".to_string());
            }
        }
        self.insert_consumed_nullifier(&request.relay_nullifier)?;
        self.counters.reservation_count = self.counters.reservation_count.saturating_add(1);
        self.counters.total_reserved_fee_bps = self
            .counters
            .total_reserved_fee_bps
            .saturating_add(request.max_fee_bps);
        self.current_height = self.current_height.max(request.reserved_at_height);
        let reservation_id =
            low_fee_relay_reservation_id(&request, self.counters.reservation_count);
        let record = LowFeeRelayReservationRecord {
            reservation_id: reservation_id.clone(),
            expires_at_height: request
                .reserved_at_height
                .saturating_add(self.config.reservation_ttl_blocks),
            request: request.clone(),
            status: RelayReservationStatus::Reserved,
        };
        if let Some(message) = self.messages.get_mut(&request.message_id) {
            message.status = MessageStatus::RelayReserved;
            message.reservation_ids.push(reservation_id.clone());
        }
        self.reservations.insert(reservation_id, record.clone());
        Ok(record)
    }

    pub fn publish_execution_acknowledgement(
        &mut self,
        request: PublishExecutionAcknowledgementRequest,
    ) -> PrivateL2PqCrossChainMessageAuthRuntimeResult<ExecutionAcknowledgementRecord> {
        self.config.validate()?;
        request.validate()?;
        if self.acknowledgements.len() >= self.config.max_acks {
            return Err(
                "PQ cross-chain message auth acknowledgement capacity exhausted".to_string(),
            );
        }
        {
            let message = self
                .messages
                .get(&request.message_id)
                .ok_or_else(|| "PQ cross-chain message auth message not found".to_string())?;
            if message.request.channel_id != request.channel_id
                || request.executed_at_height >= message.expires_at_height
                || message.approved_weight_bps < self.config.fast_quorum_bps
                || matches!(
                    message.status,
                    MessageStatus::Rejected | MessageStatus::Settled
                )
            {
                return Err(
                    "PQ cross-chain message auth message cannot receive execution acknowledgement"
                        .to_string(),
                );
            }
            let reservation = self
                .reservations
                .get(&request.reservation_id)
                .ok_or_else(|| {
                    "PQ cross-chain message auth reservation not found for acknowledgement"
                        .to_string()
                })?;
            if reservation.request.message_id != request.message_id
                || request.executed_at_height >= reservation.expires_at_height
            {
                return Err(
                    "PQ cross-chain message auth acknowledgement reservation mismatch".to_string(),
                );
            }
        }
        self.insert_consumed_nullifier(&request.ack_nullifier)?;
        self.counters.ack_count = self.counters.ack_count.saturating_add(1);
        self.current_height = self.current_height.max(request.executed_at_height);
        let ack_id = execution_acknowledgement_id(&request, self.counters.ack_count);
        let record = ExecutionAcknowledgementRecord {
            ack_id: ack_id.clone(),
            finality_height: request
                .executed_at_height
                .saturating_add(self.config.finality_blocks),
            request: request.clone(),
        };
        if let Some(message) = self.messages.get_mut(&request.message_id) {
            message.status = if request.execution_status.successful() {
                MessageStatus::Acked
            } else {
                MessageStatus::Executed
            };
            message.ack_ids.push(ack_id.clone());
        }
        if let Some(reservation) = self.reservations.get_mut(&request.reservation_id) {
            reservation.status = RelayReservationStatus::Published;
        }
        self.acknowledgements.insert(ack_id, record.clone());
        Ok(record)
    }

    pub fn publish_settlement_receipt(
        &mut self,
        request: PublishSettlementReceiptRequest,
    ) -> PrivateL2PqCrossChainMessageAuthRuntimeResult<SettlementReceiptRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.receipts.len() >= self.config.max_receipts {
            return Err("PQ cross-chain message auth receipt capacity exhausted".to_string());
        }
        {
            let ack = self.acknowledgements.get(&request.ack_id).ok_or_else(|| {
                "PQ cross-chain message auth acknowledgement not found for receipt".to_string()
            })?;
            if ack.request.message_id != request.message_id
                || ack.request.channel_id != request.channel_id
                || ack.request.state_root_after != request.state_root_before
            {
                return Err(
                    "PQ cross-chain message auth settlement acknowledgement mismatch".to_string(),
                );
            }
            let message = self
                .messages
                .get(&request.message_id)
                .ok_or_else(|| "PQ cross-chain message auth message not found".to_string())?;
            if message.status.terminal() {
                return Err("PQ cross-chain message auth message already terminal".to_string());
            }
        }
        self.insert_consumed_nullifier(&request.receipt_nullifier)?;
        self.counters.receipt_count = self.counters.receipt_count.saturating_add(1);
        self.counters.total_settled_fee_bps = self
            .counters
            .total_settled_fee_bps
            .saturating_add(request.settled_fee_bps);
        self.current_height = self.current_height.max(request.settled_at_height);
        let receipt_id = settlement_receipt_id(&request, self.counters.receipt_count);
        let record = SettlementReceiptRecord {
            receipt_id: receipt_id.clone(),
            finality_height: request
                .settled_at_height
                .saturating_add(self.config.finality_blocks),
            request: request.clone(),
        };
        if let Some(message) = self.messages.get_mut(&request.message_id) {
            message.status = match request.receipt_status {
                SettlementReceiptStatus::PendingFinality | SettlementReceiptStatus::Finalized => {
                    MessageStatus::Settled
                }
                SettlementReceiptStatus::Challenged | SettlementReceiptStatus::Failed => {
                    MessageStatus::Rejected
                }
            };
            message.receipt_ids.push(receipt_id.clone());
        }
        for reservation in self.reservations.values_mut() {
            if reservation.request.message_id == request.message_id {
                reservation.status = RelayReservationStatus::Settled;
            }
        }
        self.receipts.insert(receipt_id, record.clone());
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        let config_root = root_from_record(
            "PRIVATE-L2-PQ-CROSS-CHAIN-MESSAGE-AUTH-CONFIG",
            &self.config.public_record(),
        );
        let counter_root = root_from_record(
            "PRIVATE-L2-PQ-CROSS-CHAIN-MESSAGE-AUTH-COUNTERS",
            &self.counters.public_record(),
        );
        let committee_root = merkle_root(
            "PRIVATE-L2-PQ-CROSS-CHAIN-MESSAGE-AUTH-COMMITTEES",
            &self
                .committees
                .values()
                .map(PqSignerCommitteeRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let channel_root = merkle_root(
            "PRIVATE-L2-PQ-CROSS-CHAIN-MESSAGE-AUTH-CHANNELS",
            &self
                .channels
                .values()
                .map(MessageChannelRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let message_root = merkle_root(
            "PRIVATE-L2-PQ-CROSS-CHAIN-MESSAGE-AUTH-MESSAGES",
            &self
                .messages
                .values()
                .map(EncryptedPayloadMessageRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let authorization_root = merkle_root(
            "PRIVATE-L2-PQ-CROSS-CHAIN-MESSAGE-AUTH-AUTHORIZATIONS",
            &self
                .authorizations
                .values()
                .map(PqCommitteeAuthorizationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let reservation_root = merkle_root(
            "PRIVATE-L2-PQ-CROSS-CHAIN-MESSAGE-AUTH-RESERVATIONS",
            &self
                .reservations
                .values()
                .map(LowFeeRelayReservationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let ack_root = merkle_root(
            "PRIVATE-L2-PQ-CROSS-CHAIN-MESSAGE-AUTH-ACKS",
            &self
                .acknowledgements
                .values()
                .map(ExecutionAcknowledgementRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let receipt_root = merkle_root(
            "PRIVATE-L2-PQ-CROSS-CHAIN-MESSAGE-AUTH-RECEIPTS",
            &self
                .receipts
                .values()
                .map(SettlementReceiptRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let replay_nullifier_root = merkle_root(
            "PRIVATE-L2-PQ-CROSS-CHAIN-MESSAGE-AUTH-REPLAY-NULLIFIERS",
            &self
                .replay_nullifiers
                .iter()
                .map(|nullifier| json!({ "nullifier": nullifier }))
                .collect::<Vec<_>>(),
        );
        let consumed_nullifier_root = merkle_root(
            "PRIVATE-L2-PQ-CROSS-CHAIN-MESSAGE-AUTH-CONSUMED-NULLIFIERS",
            &self
                .consumed_nullifiers
                .iter()
                .map(|nullifier| json!({ "nullifier": nullifier }))
                .collect::<Vec<_>>(),
        );
        let payload_commitment_root = merkle_root(
            "PRIVATE-L2-PQ-CROSS-CHAIN-MESSAGE-AUTH-PAYLOAD-COMMITMENTS",
            &self
                .messages
                .values()
                .map(|message| {
                    json!({
                        "message_id": message.message_id,
                        "encrypted_payload_root": message.request.encrypted_payload_root,
                        "payload_commitment_root": message.request.payload_commitment_root,
                        "payload_ciphertext_root": message.request.payload_ciphertext_root,
                    })
                })
                .collect::<Vec<_>>(),
        );
        let pq_authorization_root = merkle_root(
            "PRIVATE-L2-PQ-CROSS-CHAIN-MESSAGE-AUTH-PQ-AUTHORIZATION-ROOT",
            &self
                .authorizations
                .values()
                .map(|authorization| {
                    json!({
                        "authorization_id": authorization.authorization_id,
                        "pq_signature_root": authorization.request.pq_signature_root,
                        "verdict": authorization.request.verdict.as_str(),
                    })
                })
                .collect::<Vec<_>>(),
        );
        let low_fee_relay_root = merkle_root(
            "PRIVATE-L2-PQ-CROSS-CHAIN-MESSAGE-AUTH-LOW-FEE-RELAY-ROOT",
            &self
                .reservations
                .values()
                .map(|reservation| {
                    json!({
                        "reservation_id": reservation.reservation_id,
                        "low_fee_sponsor_root": reservation.request.low_fee_sponsor_root,
                        "fee_receipt_root": reservation.request.fee_receipt_root,
                        "status": reservation.status.as_str(),
                    })
                })
                .collect::<Vec<_>>(),
        );
        let public_record_root = merkle_root(
            "PRIVATE-L2-PQ-CROSS-CHAIN-MESSAGE-AUTH-PUBLIC-RECORDS",
            &self
                .public_records_without_state_root()
                .into_iter()
                .map(|(_, record)| record)
                .collect::<Vec<_>>(),
        );
        let state_root = root_from_record(
            "PRIVATE-L2-PQ-CROSS-CHAIN-MESSAGE-AUTH-STATE",
            &json!({
                "chain_id": self.chain_id,
                "protocol_version": self.protocol_version,
                "current_height": self.current_height,
                "config_root": config_root,
                "counter_root": counter_root,
                "committee_root": committee_root,
                "channel_root": channel_root,
                "message_root": message_root,
                "authorization_root": authorization_root,
                "reservation_root": reservation_root,
                "ack_root": ack_root,
                "receipt_root": receipt_root,
                "replay_nullifier_root": replay_nullifier_root,
                "consumed_nullifier_root": consumed_nullifier_root,
                "payload_commitment_root": payload_commitment_root,
                "pq_authorization_root": pq_authorization_root,
                "low_fee_relay_root": low_fee_relay_root,
                "public_record_root": public_record_root,
            }),
        );
        Roots {
            config_root,
            counter_root,
            committee_root,
            channel_root,
            message_root,
            authorization_root,
            reservation_root,
            ack_root,
            receipt_root,
            replay_nullifier_root,
            consumed_nullifier_root,
            payload_commitment_root,
            pq_authorization_root,
            low_fee_relay_root,
            public_record_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_l2_pq_cross_chain_message_auth_runtime",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_SCHEMA_VERSION,
            "hash_suite": PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_HASH_SUITE,
            "pq_suite": PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_PQ_SUITE,
            "message_scheme": PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_MESSAGE_SCHEME,
            "payload_commitment_scheme": PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_PAYLOAD_COMMITMENT_SCHEME,
            "committee_scheme": PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_COMMITTEE_SCHEME,
            "replay_fence_scheme": PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_REPLAY_FENCE_SCHEME,
            "low_fee_relay_scheme": PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_LOW_FEE_RELAY_SCHEME,
            "execution_ack_scheme": PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_EXECUTION_ACK_SCHEME,
            "settlement_receipt_scheme": PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_SETTLEMENT_RECEIPT_SCHEME,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "committee_ids": self.committees.keys().cloned().collect::<Vec<_>>(),
            "channel_ids": self.channels.keys().cloned().collect::<Vec<_>>(),
            "message_ids": self.messages.keys().cloned().collect::<Vec<_>>(),
            "authorization_ids": self.authorizations.keys().cloned().collect::<Vec<_>>(),
            "reservation_ids": self.reservations.keys().cloned().collect::<Vec<_>>(),
            "ack_ids": self.acknowledgements.keys().cloned().collect::<Vec<_>>(),
            "receipt_ids": self.receipts.keys().cloned().collect::<Vec<_>>(),
            "privacy_boundary": "public_records_expose_roots_commitments_ids_and_status_only",
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn public_records_without_state_root(&self) -> BTreeMap<String, Value> {
        let mut records = BTreeMap::new();
        records.insert("config".to_string(), self.config.public_record());
        records.insert("counters".to_string(), self.counters.public_record());
        for committee in self.committees.values() {
            records.insert(
                format!("committee:{}", committee.committee_id),
                committee.public_record(),
            );
        }
        for channel in self.channels.values() {
            records.insert(
                format!("channel:{}", channel.channel_id),
                channel.public_record(),
            );
        }
        for message in self.messages.values() {
            records.insert(
                format!("message:{}", message.message_id),
                message.public_record(),
            );
        }
        for authorization in self.authorizations.values() {
            records.insert(
                format!("authorization:{}", authorization.authorization_id),
                authorization.public_record(),
            );
        }
        for reservation in self.reservations.values() {
            records.insert(
                format!("reservation:{}", reservation.reservation_id),
                reservation.public_record(),
            );
        }
        for acknowledgement in self.acknowledgements.values() {
            records.insert(
                format!("ack:{}", acknowledgement.ack_id),
                acknowledgement.public_record(),
            );
        }
        for receipt in self.receipts.values() {
            records.insert(
                format!("receipt:{}", receipt.receipt_id),
                receipt.public_record(),
            );
        }
        records
    }

    fn insert_replay_nullifier(
        &mut self,
        nullifier: &str,
    ) -> PrivateL2PqCrossChainMessageAuthRuntimeResult<()> {
        let nullifier_root = nullifier_root("REPLAY", nullifier);
        if !self.replay_nullifiers.insert(nullifier_root) {
            self.counters.replay_rejection_count =
                self.counters.replay_rejection_count.saturating_add(1);
            return Err(
                "PQ cross-chain message auth replay nullifier already observed".to_string(),
            );
        }
        Ok(())
    }

    fn insert_consumed_nullifier(
        &mut self,
        nullifier: &str,
    ) -> PrivateL2PqCrossChainMessageAuthRuntimeResult<()> {
        let nullifier_root = nullifier_root("CONSUMED", nullifier);
        if !self.consumed_nullifiers.insert(nullifier_root) {
            return Err("PQ cross-chain message auth nullifier already consumed".to_string());
        }
        self.counters.consumed_nullifier_count =
            self.counters.consumed_nullifier_count.saturating_add(1);
        Ok(())
    }
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_PQ_CROSS_CHAIN_MESSAGE_AUTH_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    root_from_record(
        &format!("PRIVATE-L2-PQ-CROSS-CHAIN-MESSAGE-AUTH-PAYLOAD-{domain}"),
        payload,
    )
}

pub fn private_l2_pq_cross_chain_message_auth_runtime_state_root(state: &State) -> String {
    state.state_root()
}

pub fn private_l2_pq_cross_chain_message_auth_runtime_public_record(state: &State) -> Value {
    state.public_record()
}

pub fn private_l2_pq_cross_chain_message_auth_runtime_payload_root(
    domain: &str,
    payload: &Value,
) -> String {
    payload_root(domain, payload)
}

pub fn devnet() -> PrivateL2PqCrossChainMessageAuthRuntimeResult<State> {
    State::devnet()
}

pub fn pq_signer_committee_id(request: &RegisterPqSignerCommitteeRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CROSS-CHAIN-MESSAGE-AUTH-SIGNER-COMMITTEE-ID",
        &json!({
            "counter": counter,
            "committee_label": request.committee_label,
            "signer_committee_root": request.signer_committee_root,
            "operator_set_root": request.operator_set_root,
            "pq_public_key_root": request.pq_public_key_root,
            "epoch": request.epoch,
        }),
    )
}

pub fn message_channel_id(request: &OpenMessageChannelRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CROSS-CHAIN-MESSAGE-AUTH-CHANNEL-ID",
        &json!({
            "counter": counter,
            "channel_kind": request.channel_kind.as_str(),
            "source_chain_id": request.source_chain_id,
            "destination_chain_id": request.destination_chain_id,
            "source_contract_root": request.source_contract_root,
            "destination_contract_root": request.destination_contract_root,
            "signer_committee_root": request.signer_committee_root,
            "epoch": request.epoch,
        }),
    )
}

pub fn encrypted_payload_message_id(
    request: &SubmitEncryptedPayloadMessageRequest,
    sequence: u64,
    counter: u64,
) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CROSS-CHAIN-MESSAGE-AUTH-MESSAGE-ID",
        &json!({
            "counter": counter,
            "sequence": sequence,
            "channel_id": request.channel_id,
            "channel_kind": request.channel_kind.as_str(),
            "sender_commitment": request.sender_commitment,
            "encrypted_payload_root": request.encrypted_payload_root,
            "payload_commitment_root": request.payload_commitment_root,
            "replay_nullifier": request.replay_nullifier,
            "message_nullifier": request.message_nullifier,
        }),
    )
}

pub fn pq_committee_authorization_id(
    request: &SubmitPqCommitteeAuthorizationRequest,
    counter: u64,
) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CROSS-CHAIN-MESSAGE-AUTH-AUTHORIZATION-ID",
        &json!({
            "counter": counter,
            "message_id": request.message_id,
            "channel_id": request.channel_id,
            "signer_committee_root": request.signer_committee_root,
            "signer_commitment": request.signer_commitment,
            "verdict": request.verdict.as_str(),
            "authorization_nullifier": request.authorization_nullifier,
        }),
    )
}

pub fn low_fee_relay_reservation_id(request: &ReserveLowFeeRelayRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CROSS-CHAIN-MESSAGE-AUTH-RELAY-RESERVATION-ID",
        &json!({
            "counter": counter,
            "message_id": request.message_id,
            "channel_id": request.channel_id,
            "relayer_commitment": request.relayer_commitment,
            "relay_window_root": request.relay_window_root,
            "relay_route_root": request.relay_route_root,
            "relay_nullifier": request.relay_nullifier,
        }),
    )
}

pub fn execution_acknowledgement_id(
    request: &PublishExecutionAcknowledgementRequest,
    counter: u64,
) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CROSS-CHAIN-MESSAGE-AUTH-EXECUTION-ACK-ID",
        &json!({
            "counter": counter,
            "message_id": request.message_id,
            "channel_id": request.channel_id,
            "reservation_id": request.reservation_id,
            "execution_status": request.execution_status.as_str(),
            "execution_trace_root": request.execution_trace_root,
            "state_root_after": request.state_root_after,
            "ack_nullifier": request.ack_nullifier,
        }),
    )
}

pub fn settlement_receipt_id(request: &PublishSettlementReceiptRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CROSS-CHAIN-MESSAGE-AUTH-SETTLEMENT-RECEIPT-ID",
        &json!({
            "counter": counter,
            "message_id": request.message_id,
            "channel_id": request.channel_id,
            "ack_id": request.ack_id,
            "receipt_status": request.receipt_status.as_str(),
            "settlement_tx_root": request.settlement_tx_root,
            "settlement_proof_root": request.settlement_proof_root,
            "receipt_nullifier": request.receipt_nullifier,
            "settled_at_height": request.settled_at_height,
        }),
    )
}

pub fn encrypted_payload_commitment_root(
    encrypted_payload_root: &str,
    payload_commitment_root: &str,
    payload_ciphertext_root: &str,
    access_policy_root: &str,
) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CROSS-CHAIN-MESSAGE-AUTH-ENCRYPTED-PAYLOAD-COMMITMENT",
        &json!({
            "encrypted_payload_root": encrypted_payload_root,
            "payload_commitment_root": payload_commitment_root,
            "payload_ciphertext_root": payload_ciphertext_root,
            "access_policy_root": access_policy_root,
        }),
    )
}

pub fn replay_fence_root(
    channel_id: &str,
    replay_nullifier: &str,
    message_nullifier: &str,
) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CROSS-CHAIN-MESSAGE-AUTH-REPLAY-FENCE",
        &json!({
            "channel_id": channel_id,
            "replay_nullifier": replay_nullifier,
            "message_nullifier": message_nullifier,
        }),
    )
}

pub fn nullifier_root(kind: &str, nullifier: &str) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CROSS-CHAIN-MESSAGE-AUTH-NULLIFIER",
        &json!({
            "kind": kind,
            "nullifier": nullifier,
        }),
    )
}

fn validate_privacy_and_pq(
    privacy_set_size: u64,
    pq_security_bits: u16,
    config: &Config,
) -> PrivateL2PqCrossChainMessageAuthRuntimeResult<()> {
    if privacy_set_size < config.min_privacy_set_size {
        return Err("PQ cross-chain message auth privacy set below minimum".to_string());
    }
    if pq_security_bits < config.min_pq_security_bits {
        return Err("PQ cross-chain message auth PQ security bits below minimum".to_string());
    }
    Ok(())
}

fn required(field: &str, value: &str) -> PrivateL2PqCrossChainMessageAuthRuntimeResult<()> {
    if value.trim().is_empty() {
        return Err(format!(
            "PQ cross-chain message auth field {field} is required"
        ));
    }
    Ok(())
}
