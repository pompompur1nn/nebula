use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash as stable_hash_hex, merkle_root, HashPart},
    CHAIN_ID,
};

pub type CrossLayerMessageBusResult<T> = Result<T, String>;

pub const CROSS_LAYER_MESSAGE_BUS_PROTOCOL_VERSION: &str = "nebula-cross-layer-message-bus-v1";
pub const CROSS_LAYER_MESSAGE_BUS_PQ_ENVELOPE_SCHEME: &str = "ml-dsa-87-cross-layer-envelope-v1";
pub const CROSS_LAYER_MESSAGE_BUS_PRIVACY_PROOF_SCHEME: &str =
    "zk-private-message-route-proof-shake256-v1";
pub const CROSS_LAYER_MESSAGE_BUS_REPLAY_NULLIFIER_SCHEME: &str =
    "shake256-cross-layer-replay-nullifier-v1";
pub const CROSS_LAYER_MESSAGE_BUS_DEFAULT_HEIGHT: u64 = 96;
pub const CROSS_LAYER_MESSAGE_BUS_DEFAULT_MESSAGE_TTL_BLOCKS: u64 = 96;
pub const CROSS_LAYER_MESSAGE_BUS_DEFAULT_TICKET_TTL_BLOCKS: u64 = 48;
pub const CROSS_LAYER_MESSAGE_BUS_DEFAULT_ACK_TTL_BLOCKS: u64 = 72;
pub const CROSS_LAYER_MESSAGE_BUS_DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 12;
pub const CROSS_LAYER_MESSAGE_BUS_DEFAULT_MAX_BATCH_MESSAGES: usize = 128;
pub const CROSS_LAYER_MESSAGE_BUS_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 96;
pub const CROSS_LAYER_MESSAGE_BUS_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const CROSS_LAYER_MESSAGE_BUS_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossLayerDomain {
    Wallet,
    PrivateContract,
    MoneroBridge,
    Sequencer,
    Prover,
    DataAvailability,
    Operator,
    Governance,
    Emergency,
}

impl CrossLayerDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wallet => "wallet",
            Self::PrivateContract => "private_contract",
            Self::MoneroBridge => "monero_bridge",
            Self::Sequencer => "sequencer",
            Self::Prover => "prover",
            Self::DataAvailability => "data_availability",
            Self::Operator => "operator",
            Self::Governance => "governance",
            Self::Emergency => "emergency",
        }
    }

    pub fn privacy_floor(self) -> u64 {
        match self {
            Self::Wallet => 160,
            Self::PrivateContract => 128,
            Self::MoneroBridge => 160,
            Self::Sequencer => 96,
            Self::Prover => 64,
            Self::DataAvailability => 64,
            Self::Operator => 48,
            Self::Governance => 96,
            Self::Emergency => 128,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossLayerMessageKind {
    PrivateContractCall,
    TokenTransfer,
    MoneroDepositNotice,
    MoneroWithdrawalRequest,
    SettlementReceipt,
    ProofRequest,
    ProofReceipt,
    FeeSponsorship,
    StateSync,
    WalletRecovery,
    OperatorAlert,
    GovernanceAction,
    EmergencyExit,
}

impl CrossLayerMessageKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateContractCall => "private_contract_call",
            Self::TokenTransfer => "token_transfer",
            Self::MoneroDepositNotice => "monero_deposit_notice",
            Self::MoneroWithdrawalRequest => "monero_withdrawal_request",
            Self::SettlementReceipt => "settlement_receipt",
            Self::ProofRequest => "proof_request",
            Self::ProofReceipt => "proof_receipt",
            Self::FeeSponsorship => "fee_sponsorship",
            Self::StateSync => "state_sync",
            Self::WalletRecovery => "wallet_recovery",
            Self::OperatorAlert => "operator_alert",
            Self::GovernanceAction => "governance_action",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn requires_ack(self) -> bool {
        matches!(
            self,
            Self::PrivateContractCall
                | Self::TokenTransfer
                | Self::MoneroWithdrawalRequest
                | Self::SettlementReceipt
                | Self::ProofRequest
                | Self::WalletRecovery
                | Self::EmergencyExit
        )
    }

    pub fn default_priority(self) -> u64 {
        match self {
            Self::EmergencyExit => 120,
            Self::WalletRecovery => 105,
            Self::MoneroWithdrawalRequest => 100,
            Self::SettlementReceipt => 95,
            Self::PrivateContractCall => 80,
            Self::TokenTransfer => 75,
            Self::ProofRequest => 70,
            Self::ProofReceipt => 70,
            Self::MoneroDepositNotice => 65,
            Self::FeeSponsorship => 60,
            Self::StateSync => 50,
            Self::OperatorAlert => 90,
            Self::GovernanceAction => 45,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadPrivacyMode {
    FullyShielded,
    CommitmentOnly,
    MetadataPublic,
    EmergencyPublic,
}

impl PayloadPrivacyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FullyShielded => "fully_shielded",
            Self::CommitmentOnly => "commitment_only",
            Self::MetadataPublic => "metadata_public",
            Self::EmergencyPublic => "emergency_public",
        }
    }

    pub fn public_leakage_bps(self) -> u64 {
        match self {
            Self::FullyShielded => 0,
            Self::CommitmentOnly => 500,
            Self::MetadataPublic => 2_500,
            Self::EmergencyPublic => CROSS_LAYER_MESSAGE_BUS_MAX_BPS,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageEnvelopeStatus {
    Draft,
    Queued,
    Routed,
    Delivered,
    Acknowledged,
    Expired,
    Rejected,
    Cancelled,
}

impl MessageEnvelopeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Queued => "queued",
            Self::Routed => "routed",
            Self::Delivered => "delivered",
            Self::Acknowledged => "acknowledged",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Draft | Self::Queued | Self::Routed | Self::Delivered
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutePolicyStatus {
    Active,
    Congested,
    Degraded,
    Paused,
    Retired,
}

impl RoutePolicyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Congested => "congested",
            Self::Degraded => "degraded",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Congested | Self::Degraded)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayGuardStatus {
    Active,
    Consumed,
    Expired,
    Quarantined,
}

impl ReplayGuardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryTicketStatus {
    Open,
    Assigned,
    Submitted,
    Delivered,
    Expired,
    Slashed,
}

impl DeliveryTicketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Assigned => "assigned",
            Self::Submitted => "submitted",
            Self::Delivered => "delivered",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Open | Self::Assigned | Self::Submitted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Reserved,
    Applied,
    Settled,
    Expired,
    Revoked,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Reserved | Self::Applied)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AckReceiptStatus {
    Pending,
    Accepted,
    Rejected,
    TimedOut,
    Challenged,
}

impl AckReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::TimedOut => "timed_out",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageBatchStatus {
    Open,
    Sealed,
    Posted,
    Finalized,
    Disputed,
    Expired,
}

impl MessageBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Posted => "posted",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_messages(self) -> bool {
        matches!(self, Self::Open)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossLayerMessageBusConfig {
    pub protocol_version: String,
    pub chain_id: String,
    pub default_message_ttl_blocks: u64,
    pub default_ticket_ttl_blocks: u64,
    pub default_ack_ttl_blocks: u64,
    pub batch_window_blocks: u64,
    pub max_batch_messages: usize,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub allow_emergency_public_payloads: bool,
}

impl Default for CrossLayerMessageBusConfig {
    fn default() -> Self {
        Self {
            protocol_version: CROSS_LAYER_MESSAGE_BUS_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            default_message_ttl_blocks: CROSS_LAYER_MESSAGE_BUS_DEFAULT_MESSAGE_TTL_BLOCKS,
            default_ticket_ttl_blocks: CROSS_LAYER_MESSAGE_BUS_DEFAULT_TICKET_TTL_BLOCKS,
            default_ack_ttl_blocks: CROSS_LAYER_MESSAGE_BUS_DEFAULT_ACK_TTL_BLOCKS,
            batch_window_blocks: CROSS_LAYER_MESSAGE_BUS_DEFAULT_BATCH_WINDOW_BLOCKS,
            max_batch_messages: CROSS_LAYER_MESSAGE_BUS_DEFAULT_MAX_BATCH_MESSAGES,
            min_privacy_set_size: CROSS_LAYER_MESSAGE_BUS_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: CROSS_LAYER_MESSAGE_BUS_DEFAULT_MIN_PQ_SECURITY_BITS,
            allow_emergency_public_payloads: false,
        }
    }
}

impl CrossLayerMessageBusConfig {
    pub fn devnet() -> Self {
        Self {
            default_message_ttl_blocks: 48,
            default_ticket_ttl_blocks: 24,
            default_ack_ttl_blocks: 36,
            batch_window_blocks: 6,
            max_batch_messages: 64,
            min_privacy_set_size: 128,
            ..Self::default()
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "cross_layer_message_bus_config",
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "default_message_ttl_blocks": self.default_message_ttl_blocks,
            "default_ticket_ttl_blocks": self.default_ticket_ttl_blocks,
            "default_ack_ttl_blocks": self.default_ack_ttl_blocks,
            "batch_window_blocks": self.batch_window_blocks,
            "max_batch_messages": self.max_batch_messages,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "allow_emergency_public_payloads": self.allow_emergency_public_payloads,
        })
    }

    pub fn config_root(&self) -> String {
        cross_layer_message_bus_payload_root(
            "CROSS-LAYER-MESSAGE-BUS-CONFIG",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> CrossLayerMessageBusResult<()> {
        ensure_non_empty(&self.protocol_version, "protocol version")?;
        ensure_non_empty(&self.chain_id, "chain id")?;
        ensure_positive(self.default_message_ttl_blocks, "message ttl")?;
        ensure_positive(self.default_ticket_ttl_blocks, "ticket ttl")?;
        ensure_positive(self.default_ack_ttl_blocks, "ack ttl")?;
        ensure_positive(self.batch_window_blocks, "batch window")?;
        if self.max_batch_messages == 0 {
            return Err("max batch messages must be positive".to_string());
        }
        if self.min_privacy_set_size < 32 {
            return Err("minimum privacy set size must be at least 32".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("minimum pq security bits must be at least 192".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRouteEnvelope {
    pub pq_envelope_id: String,
    pub signer_commitment: String,
    pub signature_scheme: String,
    pub security_bits: u16,
    pub replay_domain: String,
    pub signed_payload_root: String,
    pub signature_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl PqRouteEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        signer_commitment: &str,
        signature_scheme: &str,
        security_bits: u16,
        replay_domain: &str,
        signed_payload: &Value,
        signature: &Value,
        created_at_height: u64,
        expires_at_height: u64,
    ) -> CrossLayerMessageBusResult<Self> {
        let signed_payload_root =
            cross_layer_message_bus_payload_root("CROSS-LAYER-PQ-SIGNED-PAYLOAD", signed_payload);
        let signature_root =
            cross_layer_message_bus_payload_root("CROSS-LAYER-PQ-SIGNATURE", signature);
        let pq_envelope_id = pq_route_envelope_id(
            signer_commitment,
            signature_scheme,
            replay_domain,
            created_at_height,
            &signed_payload_root,
        );
        let envelope = Self {
            pq_envelope_id,
            signer_commitment: signer_commitment.to_string(),
            signature_scheme: signature_scheme.to_string(),
            security_bits,
            replay_domain: replay_domain.to_string(),
            signed_payload_root,
            signature_root,
            created_at_height,
            expires_at_height,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_route_envelope",
            "pq_envelope_id": self.pq_envelope_id,
            "signer_commitment": self.signer_commitment,
            "signature_scheme": self.signature_scheme,
            "security_bits": self.security_bits,
            "replay_domain": self.replay_domain,
            "signed_payload_root": self.signed_payload_root,
            "signature_root": self.signature_root,
            "scheme": CROSS_LAYER_MESSAGE_BUS_PQ_ENVELOPE_SCHEME,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        cross_layer_message_bus_payload_root("CROSS-LAYER-PQ-ROUTE-ENVELOPE", &self.public_record())
    }

    pub fn validate(&self) -> CrossLayerMessageBusResult<()> {
        ensure_non_empty(&self.pq_envelope_id, "pq envelope id")?;
        ensure_non_empty(&self.signer_commitment, "signer commitment")?;
        ensure_non_empty(&self.signature_scheme, "signature scheme")?;
        if self.security_bits < 192 {
            return Err("pq envelope security bits below minimum".to_string());
        }
        ensure_non_empty(&self.replay_domain, "replay domain")?;
        ensure_non_empty(&self.signed_payload_root, "signed payload root")?;
        ensure_non_empty(&self.signature_root, "signature root")?;
        ensure_height_window(
            self.created_at_height,
            self.expires_at_height,
            "pq envelope",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateMessageEnvelope {
    pub message_id: String,
    pub source_domain: CrossLayerDomain,
    pub target_domain: CrossLayerDomain,
    pub kind: CrossLayerMessageKind,
    pub status: MessageEnvelopeStatus,
    pub sender_commitment: String,
    pub recipient_commitment: String,
    pub payload_commitment_root: String,
    pub payload_metadata_root: String,
    pub privacy_mode: PayloadPrivacyMode,
    pub privacy_set_size: u64,
    pub priority: u64,
    pub fee_cap_micro_units: u64,
    pub low_fee_lane: String,
    pub replay_nullifier: String,
    pub pq_envelope_id: String,
    pub route_policy_id: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivateMessageEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source_domain: CrossLayerDomain,
        target_domain: CrossLayerDomain,
        kind: CrossLayerMessageKind,
        sender_commitment: &str,
        recipient_commitment: &str,
        payload: &Value,
        metadata: &Value,
        privacy_mode: PayloadPrivacyMode,
        privacy_set_size: u64,
        fee_cap_micro_units: u64,
        low_fee_lane: &str,
        replay_nullifier: &str,
        pq_envelope_id: &str,
        route_policy_id: &str,
        created_at_height: u64,
        expires_at_height: u64,
    ) -> CrossLayerMessageBusResult<Self> {
        let payload_commitment_root =
            cross_layer_message_bus_payload_root("CROSS-LAYER-MESSAGE-PAYLOAD", payload);
        let payload_metadata_root =
            cross_layer_message_bus_payload_root("CROSS-LAYER-MESSAGE-METADATA", metadata);
        let message_id = cross_layer_message_id(
            source_domain,
            target_domain,
            kind,
            sender_commitment,
            replay_nullifier,
            created_at_height,
            &payload_commitment_root,
        );
        let envelope = Self {
            message_id,
            source_domain,
            target_domain,
            kind,
            status: MessageEnvelopeStatus::Queued,
            sender_commitment: sender_commitment.to_string(),
            recipient_commitment: recipient_commitment.to_string(),
            payload_commitment_root,
            payload_metadata_root,
            privacy_mode,
            privacy_set_size,
            priority: kind.default_priority(),
            fee_cap_micro_units,
            low_fee_lane: low_fee_lane.to_string(),
            replay_nullifier: replay_nullifier.to_string(),
            pq_envelope_id: pq_envelope_id.to_string(),
            route_policy_id: route_policy_id.to_string(),
            created_at_height,
            expires_at_height,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn requires_ack(&self) -> bool {
        self.kind.requires_ack()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_message_envelope",
            "message_id": self.message_id,
            "source_domain": self.source_domain.as_str(),
            "target_domain": self.target_domain.as_str(),
            "message_kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "sender_commitment": self.sender_commitment,
            "recipient_commitment": self.recipient_commitment,
            "payload_commitment_root": self.payload_commitment_root,
            "payload_metadata_root": self.payload_metadata_root,
            "privacy_mode": self.privacy_mode.as_str(),
            "privacy_set_size": self.privacy_set_size,
            "privacy_leakage_bps": self.privacy_mode.public_leakage_bps(),
            "priority": self.priority,
            "fee_cap_micro_units": self.fee_cap_micro_units,
            "low_fee_lane": self.low_fee_lane,
            "replay_nullifier": self.replay_nullifier,
            "replay_nullifier_scheme": CROSS_LAYER_MESSAGE_BUS_REPLAY_NULLIFIER_SCHEME,
            "pq_envelope_id": self.pq_envelope_id,
            "route_policy_id": self.route_policy_id,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        cross_layer_message_bus_payload_root("CROSS-LAYER-PRIVATE-MESSAGE", &self.public_record())
    }

    pub fn validate(&self) -> CrossLayerMessageBusResult<()> {
        ensure_non_empty(&self.message_id, "message id")?;
        ensure_non_empty(&self.sender_commitment, "sender commitment")?;
        ensure_non_empty(&self.recipient_commitment, "recipient commitment")?;
        ensure_non_empty(&self.payload_commitment_root, "payload commitment root")?;
        ensure_non_empty(&self.payload_metadata_root, "payload metadata root")?;
        ensure_positive(self.privacy_set_size, "privacy set size")?;
        ensure_positive(self.priority, "priority")?;
        ensure_positive(self.fee_cap_micro_units, "fee cap micro units")?;
        ensure_non_empty(&self.low_fee_lane, "low fee lane")?;
        ensure_non_empty(&self.replay_nullifier, "replay nullifier")?;
        ensure_non_empty(&self.pq_envelope_id, "pq envelope id")?;
        ensure_non_empty(&self.route_policy_id, "route policy id")?;
        ensure_height_window(self.created_at_height, self.expires_at_height, "message")?;
        if self.privacy_mode == PayloadPrivacyMode::EmergencyPublic
            && self.kind != CrossLayerMessageKind::EmergencyExit
            && self.kind != CrossLayerMessageKind::OperatorAlert
        {
            return Err("emergency public payloads are limited to emergency flows".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossLayerRoutePolicy {
    pub route_policy_id: String,
    pub source_domain: CrossLayerDomain,
    pub target_domain: CrossLayerDomain,
    pub allowed_kinds: BTreeSet<CrossLayerMessageKind>,
    pub status: RoutePolicyStatus,
    pub max_fee_cap_micro_units: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_latency_blocks: u64,
    pub low_fee_lane: String,
    pub policy_root: String,
    pub updated_at_height: u64,
}

impl CrossLayerRoutePolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source_domain: CrossLayerDomain,
        target_domain: CrossLayerDomain,
        allowed_kinds: BTreeSet<CrossLayerMessageKind>,
        max_fee_cap_micro_units: u64,
        min_privacy_set_size: u64,
        min_pq_security_bits: u16,
        max_latency_blocks: u64,
        low_fee_lane: &str,
        policy: &Value,
        updated_at_height: u64,
    ) -> CrossLayerMessageBusResult<Self> {
        let policy_root = cross_layer_message_bus_payload_root("CROSS-LAYER-ROUTE-POLICY", policy);
        let route_policy_id = route_policy_id(
            source_domain,
            target_domain,
            low_fee_lane,
            updated_at_height,
            &policy_root,
        );
        let route = Self {
            route_policy_id,
            source_domain,
            target_domain,
            allowed_kinds,
            status: RoutePolicyStatus::Active,
            max_fee_cap_micro_units,
            min_privacy_set_size,
            min_pq_security_bits,
            max_latency_blocks,
            low_fee_lane: low_fee_lane.to_string(),
            policy_root,
            updated_at_height,
        };
        route.validate()?;
        Ok(route)
    }

    pub fn admits(&self, envelope: &PrivateMessageEnvelope, pq_security_bits: u16) -> bool {
        self.status.usable()
            && self.source_domain == envelope.source_domain
            && self.target_domain == envelope.target_domain
            && self.allowed_kinds.contains(&envelope.kind)
            && envelope.fee_cap_micro_units <= self.max_fee_cap_micro_units
            && envelope.privacy_set_size >= self.min_privacy_set_size
            && pq_security_bits >= self.min_pq_security_bits
    }

    pub fn public_record(&self) -> Value {
        let kinds = self
            .allowed_kinds
            .iter()
            .map(|kind| kind.as_str())
            .collect::<Vec<_>>();
        json!({
            "kind": "cross_layer_route_policy",
            "route_policy_id": self.route_policy_id,
            "source_domain": self.source_domain.as_str(),
            "target_domain": self.target_domain.as_str(),
            "allowed_kinds": kinds,
            "status": self.status.as_str(),
            "max_fee_cap_micro_units": self.max_fee_cap_micro_units,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_latency_blocks": self.max_latency_blocks,
            "low_fee_lane": self.low_fee_lane,
            "policy_root": self.policy_root,
            "updated_at_height": self.updated_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        cross_layer_message_bus_payload_root(
            "CROSS-LAYER-ROUTE-POLICY-STATE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> CrossLayerMessageBusResult<()> {
        ensure_non_empty(&self.route_policy_id, "route policy id")?;
        if self.allowed_kinds.is_empty() {
            return Err("route policy must allow at least one kind".to_string());
        }
        ensure_positive(self.max_fee_cap_micro_units, "max fee cap")?;
        ensure_positive(self.min_privacy_set_size, "min privacy set size")?;
        if self.min_pq_security_bits < 192 {
            return Err("route policy pq security below minimum".to_string());
        }
        ensure_positive(self.max_latency_blocks, "max latency blocks")?;
        ensure_non_empty(&self.low_fee_lane, "low fee lane")?;
        ensure_non_empty(&self.policy_root, "policy root")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayGuard {
    pub replay_guard_id: String,
    pub message_id: String,
    pub replay_nullifier: String,
    pub source_domain: CrossLayerDomain,
    pub status: ReplayGuardStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub guard_root: String,
}

impl ReplayGuard {
    pub fn new(
        message_id: &str,
        replay_nullifier: &str,
        source_domain: CrossLayerDomain,
        opened_at_height: u64,
        expires_at_height: u64,
        guard: &Value,
    ) -> CrossLayerMessageBusResult<Self> {
        let guard_root = cross_layer_message_bus_payload_root("CROSS-LAYER-REPLAY-GUARD", guard);
        let replay_guard_id = replay_guard_id(
            message_id,
            replay_nullifier,
            source_domain,
            opened_at_height,
            &guard_root,
        );
        let replay = Self {
            replay_guard_id,
            message_id: message_id.to_string(),
            replay_nullifier: replay_nullifier.to_string(),
            source_domain,
            status: ReplayGuardStatus::Active,
            opened_at_height,
            expires_at_height,
            guard_root,
        };
        replay.validate()?;
        Ok(replay)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "replay_guard",
            "replay_guard_id": self.replay_guard_id,
            "message_id": self.message_id,
            "replay_nullifier": self.replay_nullifier,
            "source_domain": self.source_domain.as_str(),
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "guard_root": self.guard_root,
        })
    }

    pub fn state_root(&self) -> String {
        cross_layer_message_bus_payload_root(
            "CROSS-LAYER-REPLAY-GUARD-STATE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> CrossLayerMessageBusResult<()> {
        ensure_non_empty(&self.replay_guard_id, "replay guard id")?;
        ensure_non_empty(&self.message_id, "message id")?;
        ensure_non_empty(&self.replay_nullifier, "replay nullifier")?;
        ensure_height_window(
            self.opened_at_height,
            self.expires_at_height,
            "replay guard",
        )?;
        ensure_non_empty(&self.guard_root, "guard root")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryTicket {
    pub ticket_id: String,
    pub message_id: String,
    pub route_policy_id: String,
    pub assigned_relayer: String,
    pub status: DeliveryTicketStatus,
    pub priority: u64,
    pub fee_cap_micro_units: u64,
    pub delivery_proof_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl DeliveryTicket {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        message_id: &str,
        route_policy_id: &str,
        assigned_relayer: &str,
        priority: u64,
        fee_cap_micro_units: u64,
        delivery_proof: &Value,
        opened_at_height: u64,
        expires_at_height: u64,
    ) -> CrossLayerMessageBusResult<Self> {
        let delivery_proof_root =
            cross_layer_message_bus_payload_root("CROSS-LAYER-DELIVERY-PROOF", delivery_proof);
        let ticket_id = delivery_ticket_id(
            message_id,
            route_policy_id,
            assigned_relayer,
            opened_at_height,
            &delivery_proof_root,
        );
        let ticket = Self {
            ticket_id,
            message_id: message_id.to_string(),
            route_policy_id: route_policy_id.to_string(),
            assigned_relayer: assigned_relayer.to_string(),
            status: DeliveryTicketStatus::Open,
            priority,
            fee_cap_micro_units,
            delivery_proof_root,
            opened_at_height,
            expires_at_height,
        };
        ticket.validate()?;
        Ok(ticket)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "delivery_ticket",
            "ticket_id": self.ticket_id,
            "message_id": self.message_id,
            "route_policy_id": self.route_policy_id,
            "assigned_relayer": self.assigned_relayer,
            "status": self.status.as_str(),
            "priority": self.priority,
            "fee_cap_micro_units": self.fee_cap_micro_units,
            "delivery_proof_root": self.delivery_proof_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        cross_layer_message_bus_payload_root("CROSS-LAYER-DELIVERY-TICKET", &self.public_record())
    }

    pub fn validate(&self) -> CrossLayerMessageBusResult<()> {
        ensure_non_empty(&self.ticket_id, "ticket id")?;
        ensure_non_empty(&self.message_id, "message id")?;
        ensure_non_empty(&self.route_policy_id, "route policy id")?;
        ensure_non_empty(&self.assigned_relayer, "assigned relayer")?;
        ensure_positive(self.priority, "ticket priority")?;
        ensure_positive(self.fee_cap_micro_units, "ticket fee cap")?;
        ensure_non_empty(&self.delivery_proof_root, "delivery proof root")?;
        ensure_height_window(
            self.opened_at_height,
            self.expires_at_height,
            "delivery ticket",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeMessageSponsorship {
    pub sponsorship_id: String,
    pub message_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub sponsored_micro_units: u64,
    pub lane: String,
    pub status: SponsorshipStatus,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
    pub proof_root: String,
}

impl LowFeeMessageSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        message_id: &str,
        sponsor_commitment: &str,
        fee_asset_id: &str,
        sponsored_micro_units: u64,
        lane: &str,
        reserved_at_height: u64,
        expires_at_height: u64,
        proof: &Value,
    ) -> CrossLayerMessageBusResult<Self> {
        let proof_root =
            cross_layer_message_bus_payload_root("CROSS-LAYER-LOW-FEE-SPONSORSHIP-PROOF", proof);
        let sponsorship_id = message_sponsorship_id(
            message_id,
            sponsor_commitment,
            fee_asset_id,
            reserved_at_height,
            &proof_root,
        );
        let sponsorship = Self {
            sponsorship_id,
            message_id: message_id.to_string(),
            sponsor_commitment: sponsor_commitment.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            sponsored_micro_units,
            lane: lane.to_string(),
            status: SponsorshipStatus::Reserved,
            reserved_at_height,
            expires_at_height,
            proof_root,
        };
        sponsorship.validate()?;
        Ok(sponsorship)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_message_sponsorship",
            "sponsorship_id": self.sponsorship_id,
            "message_id": self.message_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "sponsored_micro_units": self.sponsored_micro_units,
            "lane": self.lane,
            "status": self.status.as_str(),
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
            "proof_root": self.proof_root,
        })
    }

    pub fn state_root(&self) -> String {
        cross_layer_message_bus_payload_root(
            "CROSS-LAYER-LOW-FEE-MESSAGE-SPONSORSHIP",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> CrossLayerMessageBusResult<()> {
        ensure_non_empty(&self.sponsorship_id, "sponsorship id")?;
        ensure_non_empty(&self.message_id, "message id")?;
        ensure_non_empty(&self.sponsor_commitment, "sponsor commitment")?;
        ensure_non_empty(&self.fee_asset_id, "fee asset id")?;
        ensure_positive(self.sponsored_micro_units, "sponsored micro units")?;
        ensure_non_empty(&self.lane, "sponsorship lane")?;
        ensure_height_window(
            self.reserved_at_height,
            self.expires_at_height,
            "sponsorship",
        )?;
        ensure_non_empty(&self.proof_root, "sponsorship proof root")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageAckReceipt {
    pub ack_id: String,
    pub message_id: String,
    pub ticket_id: String,
    pub source_domain: CrossLayerDomain,
    pub target_domain: CrossLayerDomain,
    pub status: AckReceiptStatus,
    pub ack_payload_root: String,
    pub pq_witness_root: String,
    pub observed_at_height: u64,
    pub expires_at_height: u64,
}

impl MessageAckReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        message_id: &str,
        ticket_id: &str,
        source_domain: CrossLayerDomain,
        target_domain: CrossLayerDomain,
        status: AckReceiptStatus,
        ack_payload: &Value,
        pq_witness: &Value,
        observed_at_height: u64,
        expires_at_height: u64,
    ) -> CrossLayerMessageBusResult<Self> {
        let ack_payload_root =
            cross_layer_message_bus_payload_root("CROSS-LAYER-ACK-PAYLOAD", ack_payload);
        let pq_witness_root =
            cross_layer_message_bus_payload_root("CROSS-LAYER-ACK-PQ-WITNESS", pq_witness);
        let ack_id = message_ack_id(
            message_id,
            ticket_id,
            source_domain,
            target_domain,
            observed_at_height,
            &ack_payload_root,
        );
        let ack = Self {
            ack_id,
            message_id: message_id.to_string(),
            ticket_id: ticket_id.to_string(),
            source_domain,
            target_domain,
            status,
            ack_payload_root,
            pq_witness_root,
            observed_at_height,
            expires_at_height,
        };
        ack.validate()?;
        Ok(ack)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "message_ack_receipt",
            "ack_id": self.ack_id,
            "message_id": self.message_id,
            "ticket_id": self.ticket_id,
            "source_domain": self.source_domain.as_str(),
            "target_domain": self.target_domain.as_str(),
            "status": self.status.as_str(),
            "ack_payload_root": self.ack_payload_root,
            "pq_witness_root": self.pq_witness_root,
            "observed_at_height": self.observed_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        cross_layer_message_bus_payload_root("CROSS-LAYER-MESSAGE-ACK", &self.public_record())
    }

    pub fn validate(&self) -> CrossLayerMessageBusResult<()> {
        ensure_non_empty(&self.ack_id, "ack id")?;
        ensure_non_empty(&self.message_id, "message id")?;
        ensure_non_empty(&self.ticket_id, "ticket id")?;
        ensure_non_empty(&self.ack_payload_root, "ack payload root")?;
        ensure_non_empty(&self.pq_witness_root, "pq witness root")?;
        ensure_height_window(
            self.observed_at_height,
            self.expires_at_height,
            "ack receipt",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageBatch {
    pub batch_id: String,
    pub status: MessageBatchStatus,
    pub source_domain: CrossLayerDomain,
    pub target_domain: CrossLayerDomain,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
    pub posted_at_height: u64,
    pub message_root: String,
    pub route_policy_root: String,
    pub sponsorship_root: String,
    pub ack_root: String,
    pub batch_proof_root: String,
    pub message_count: u64,
    pub total_fee_cap_micro_units: u64,
}

impl MessageBatch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source_domain: CrossLayerDomain,
        target_domain: CrossLayerDomain,
        opened_at_height: u64,
        closes_at_height: u64,
        message_root: &str,
        route_policy_root: &str,
        sponsorship_root: &str,
        ack_root: &str,
        batch_proof: &Value,
        message_count: u64,
        total_fee_cap_micro_units: u64,
    ) -> CrossLayerMessageBusResult<Self> {
        let batch_proof_root =
            cross_layer_message_bus_payload_root("CROSS-LAYER-BATCH-PROOF", batch_proof);
        let batch_id = message_batch_id(
            source_domain,
            target_domain,
            opened_at_height,
            message_root,
            &batch_proof_root,
        );
        let batch = Self {
            batch_id,
            status: MessageBatchStatus::Open,
            source_domain,
            target_domain,
            opened_at_height,
            closes_at_height,
            posted_at_height: 0,
            message_root: message_root.to_string(),
            route_policy_root: route_policy_root.to_string(),
            sponsorship_root: sponsorship_root.to_string(),
            ack_root: ack_root.to_string(),
            batch_proof_root,
            message_count,
            total_fee_cap_micro_units,
        };
        batch.validate()?;
        Ok(batch)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "message_batch",
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "source_domain": self.source_domain.as_str(),
            "target_domain": self.target_domain.as_str(),
            "opened_at_height": self.opened_at_height,
            "closes_at_height": self.closes_at_height,
            "posted_at_height": self.posted_at_height,
            "message_root": self.message_root,
            "route_policy_root": self.route_policy_root,
            "sponsorship_root": self.sponsorship_root,
            "ack_root": self.ack_root,
            "batch_proof_root": self.batch_proof_root,
            "message_count": self.message_count,
            "total_fee_cap_micro_units": self.total_fee_cap_micro_units,
        })
    }

    pub fn state_root(&self) -> String {
        cross_layer_message_bus_payload_root("CROSS-LAYER-MESSAGE-BATCH", &self.public_record())
    }

    pub fn validate(&self) -> CrossLayerMessageBusResult<()> {
        ensure_non_empty(&self.batch_id, "batch id")?;
        ensure_height_window(
            self.opened_at_height,
            self.closes_at_height,
            "message batch",
        )?;
        ensure_non_empty(&self.message_root, "message root")?;
        ensure_non_empty(&self.route_policy_root, "route policy root")?;
        ensure_non_empty(&self.sponsorship_root, "sponsorship root")?;
        ensure_non_empty(&self.ack_root, "ack root")?;
        ensure_non_empty(&self.batch_proof_root, "batch proof root")?;
        ensure_positive(self.message_count, "message count")?;
        ensure_positive(self.total_fee_cap_micro_units, "total fee cap")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossLayerPublicRecord {
    pub public_record_id: String,
    pub subject_id: String,
    pub subject_kind: String,
    pub record_root: String,
    pub disclosure_bps: u64,
    pub published_at_height: u64,
}

impl CrossLayerPublicRecord {
    pub fn new(
        subject_id: &str,
        subject_kind: &str,
        record: &Value,
        disclosure_bps: u64,
        published_at_height: u64,
    ) -> CrossLayerMessageBusResult<Self> {
        ensure_bps(disclosure_bps, "public record disclosure")?;
        let record_root = cross_layer_message_bus_payload_root("CROSS-LAYER-PUBLIC-RECORD", record);
        let public_record_id =
            public_record_id(subject_id, subject_kind, published_at_height, &record_root);
        let public = Self {
            public_record_id,
            subject_id: subject_id.to_string(),
            subject_kind: subject_kind.to_string(),
            record_root,
            disclosure_bps,
            published_at_height,
        };
        public.validate()?;
        Ok(public)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "cross_layer_public_record",
            "public_record_id": self.public_record_id,
            "subject_id": self.subject_id,
            "subject_kind": self.subject_kind,
            "record_root": self.record_root,
            "disclosure_bps": self.disclosure_bps,
            "published_at_height": self.published_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        cross_layer_message_bus_payload_root(
            "CROSS-LAYER-PUBLIC-RECORD-STATE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> CrossLayerMessageBusResult<()> {
        ensure_non_empty(&self.public_record_id, "public record id")?;
        ensure_non_empty(&self.subject_id, "subject id")?;
        ensure_non_empty(&self.subject_kind, "subject kind")?;
        ensure_non_empty(&self.record_root, "record root")?;
        ensure_bps(self.disclosure_bps, "disclosure")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossLayerMessageBusRoots {
    pub config_root: String,
    pub pq_envelope_root: String,
    pub message_root: String,
    pub route_policy_root: String,
    pub replay_guard_root: String,
    pub delivery_ticket_root: String,
    pub sponsorship_root: String,
    pub ack_receipt_root: String,
    pub batch_root: String,
    pub public_record_root: String,
    pub active_route_root: String,
}

impl CrossLayerMessageBusRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "cross_layer_message_bus_roots",
            "config_root": self.config_root,
            "pq_envelope_root": self.pq_envelope_root,
            "message_root": self.message_root,
            "route_policy_root": self.route_policy_root,
            "replay_guard_root": self.replay_guard_root,
            "delivery_ticket_root": self.delivery_ticket_root,
            "sponsorship_root": self.sponsorship_root,
            "ack_receipt_root": self.ack_receipt_root,
            "batch_root": self.batch_root,
            "public_record_root": self.public_record_root,
            "active_route_root": self.active_route_root,
        })
    }

    pub fn state_root(&self) -> String {
        cross_layer_message_bus_payload_root("CROSS-LAYER-MESSAGE-BUS-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossLayerMessageBusCounters {
    pub pq_envelope_count: u64,
    pub message_count: u64,
    pub live_message_count: u64,
    pub route_policy_count: u64,
    pub usable_route_policy_count: u64,
    pub replay_guard_count: u64,
    pub active_replay_guard_count: u64,
    pub delivery_ticket_count: u64,
    pub live_ticket_count: u64,
    pub sponsorship_count: u64,
    pub usable_sponsorship_count: u64,
    pub ack_receipt_count: u64,
    pub accepted_ack_count: u64,
    pub batch_count: u64,
    pub open_batch_count: u64,
    pub public_record_count: u64,
    pub total_fee_cap_micro_units: u64,
    pub sponsored_micro_units: u64,
}

impl CrossLayerMessageBusCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "cross_layer_message_bus_counters",
            "pq_envelope_count": self.pq_envelope_count,
            "message_count": self.message_count,
            "live_message_count": self.live_message_count,
            "route_policy_count": self.route_policy_count,
            "usable_route_policy_count": self.usable_route_policy_count,
            "replay_guard_count": self.replay_guard_count,
            "active_replay_guard_count": self.active_replay_guard_count,
            "delivery_ticket_count": self.delivery_ticket_count,
            "live_ticket_count": self.live_ticket_count,
            "sponsorship_count": self.sponsorship_count,
            "usable_sponsorship_count": self.usable_sponsorship_count,
            "ack_receipt_count": self.ack_receipt_count,
            "accepted_ack_count": self.accepted_ack_count,
            "batch_count": self.batch_count,
            "open_batch_count": self.open_batch_count,
            "public_record_count": self.public_record_count,
            "total_fee_cap_micro_units": self.total_fee_cap_micro_units,
            "sponsored_micro_units": self.sponsored_micro_units,
        })
    }

    pub fn state_root(&self) -> String {
        cross_layer_message_bus_payload_root(
            "CROSS-LAYER-MESSAGE-BUS-COUNTERS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossLayerMessageBusState {
    pub config: CrossLayerMessageBusConfig,
    pub height: u64,
    pub pq_envelopes: BTreeMap<String, PqRouteEnvelope>,
    pub messages: BTreeMap<String, PrivateMessageEnvelope>,
    pub route_policies: BTreeMap<String, CrossLayerRoutePolicy>,
    pub replay_guards: BTreeMap<String, ReplayGuard>,
    pub delivery_tickets: BTreeMap<String, DeliveryTicket>,
    pub sponsorships: BTreeMap<String, LowFeeMessageSponsorship>,
    pub ack_receipts: BTreeMap<String, MessageAckReceipt>,
    pub batches: BTreeMap<String, MessageBatch>,
    pub public_records: BTreeMap<String, CrossLayerPublicRecord>,
}

impl CrossLayerMessageBusState {
    pub fn new(config: CrossLayerMessageBusConfig) -> CrossLayerMessageBusResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height: 0,
            pq_envelopes: BTreeMap::new(),
            messages: BTreeMap::new(),
            route_policies: BTreeMap::new(),
            replay_guards: BTreeMap::new(),
            delivery_tickets: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            ack_receipts: BTreeMap::new(),
            batches: BTreeMap::new(),
            public_records: BTreeMap::new(),
        })
    }

    pub fn devnet() -> CrossLayerMessageBusResult<Self> {
        let mut state = Self::new(CrossLayerMessageBusConfig::devnet())?;
        state.height = CROSS_LAYER_MESSAGE_BUS_DEFAULT_HEIGHT;
        let height = state.height;

        let mut bridge_kinds = BTreeSet::new();
        bridge_kinds.insert(CrossLayerMessageKind::MoneroWithdrawalRequest);
        bridge_kinds.insert(CrossLayerMessageKind::SettlementReceipt);
        bridge_kinds.insert(CrossLayerMessageKind::FeeSponsorship);
        let bridge_route = CrossLayerRoutePolicy::new(
            CrossLayerDomain::Wallet,
            CrossLayerDomain::MoneroBridge,
            bridge_kinds,
            2_500,
            state.config.min_privacy_set_size,
            state.config.min_pq_security_bits,
            4,
            "monero_bridge_exit",
            &json!({"fixture": "wallet_to_monero_bridge", "low_fee": true}),
            height,
        )?;
        let bridge_route_id = bridge_route.route_policy_id.clone();
        state.insert_route_policy(bridge_route)?;

        let mut contract_kinds = BTreeSet::new();
        contract_kinds.insert(CrossLayerMessageKind::PrivateContractCall);
        contract_kinds.insert(CrossLayerMessageKind::TokenTransfer);
        contract_kinds.insert(CrossLayerMessageKind::ProofRequest);
        let contract_route = CrossLayerRoutePolicy::new(
            CrossLayerDomain::Wallet,
            CrossLayerDomain::PrivateContract,
            contract_kinds,
            1_800,
            state.config.min_privacy_set_size,
            state.config.min_pq_security_bits,
            2,
            "private_contract_call",
            &json!({"fixture": "wallet_to_private_contract", "fast_lane": true}),
            height,
        )?;
        let contract_route_id = contract_route.route_policy_id.clone();
        state.insert_route_policy(contract_route)?;

        let pq_bridge = PqRouteEnvelope::new(
            "devnet-wallet-pq-signer",
            "ml-dsa-87",
            state.config.min_pq_security_bits,
            "devnet-cross-layer-bridge",
            &json!({"intent": "withdraw_xmr", "route_policy_id": bridge_route_id}),
            &json!({"signature": "devnet-pq-signature-bridge"}),
            height,
            height + state.config.default_message_ttl_blocks,
        )?;
        let pq_bridge_id = pq_bridge.pq_envelope_id.clone();
        state.insert_pq_envelope(pq_bridge)?;

        let bridge_message = PrivateMessageEnvelope::new(
            CrossLayerDomain::Wallet,
            CrossLayerDomain::MoneroBridge,
            CrossLayerMessageKind::MoneroWithdrawalRequest,
            "devnet-wallet-commitment",
            "devnet-bridge-commitment",
            &json!({"withdrawal": "sealed", "amount_commitment": "devnet-xmr-amount"}),
            &json!({"lane": "monero_bridge_exit", "urgency": "fast"}),
            PayloadPrivacyMode::FullyShielded,
            state.config.min_privacy_set_size,
            1_250,
            "monero_bridge_exit",
            "devnet-replay-nullifier-bridge-0",
            &pq_bridge_id,
            &bridge_route_id,
            height,
            height + state.config.default_message_ttl_blocks,
        )?;
        let bridge_message_id = bridge_message.message_id.clone();
        state.insert_message(bridge_message)?;

        let ticket = DeliveryTicket::new(
            &bridge_message_id,
            &bridge_route_id,
            "devnet-fast-relayer",
            100,
            1_250,
            &json!({"delivery": "devnet-bridge-ticket"}),
            height,
            height + state.config.default_ticket_ttl_blocks,
        )?;
        let ticket_id = ticket.ticket_id.clone();
        state.insert_delivery_ticket(ticket)?;

        let sponsorship = LowFeeMessageSponsorship::new(
            &bridge_message_id,
            "devnet-low-fee-sponsor",
            "wxmr-devnet",
            900,
            "monero_bridge_exit",
            height,
            height + state.config.default_message_ttl_blocks,
            &json!({"rebate": "bridge-exit-devnet"}),
        )?;
        state.insert_sponsorship(sponsorship)?;

        let ack = MessageAckReceipt::new(
            &bridge_message_id,
            &ticket_id,
            CrossLayerDomain::Wallet,
            CrossLayerDomain::MoneroBridge,
            AckReceiptStatus::Pending,
            &json!({"ack": "pending-watchtower-quorum"}),
            &json!({"pq_witness": "devnet-watchtower-pq"}),
            height + 1,
            height + state.config.default_ack_ttl_blocks,
        )?;
        state.insert_ack_receipt(ack)?;

        let pq_contract = PqRouteEnvelope::new(
            "devnet-wallet-contract-pq-signer",
            "ml-dsa-87",
            state.config.min_pq_security_bits,
            "devnet-cross-layer-contract",
            &json!({"intent": "private_contract_call", "route_policy_id": contract_route_id}),
            &json!({"signature": "devnet-pq-signature-contract"}),
            height,
            height + state.config.default_message_ttl_blocks,
        )?;
        let pq_contract_id = pq_contract.pq_envelope_id.clone();
        state.insert_pq_envelope(pq_contract)?;

        let contract_message = PrivateMessageEnvelope::new(
            CrossLayerDomain::Wallet,
            CrossLayerDomain::PrivateContract,
            CrossLayerMessageKind::PrivateContractCall,
            "devnet-wallet-commitment",
            "devnet-private-contract-commitment",
            &json!({"call": "sealed_swap", "selector_commitment": "devnet-selector"}),
            &json!({"lane": "private_contract_call", "contract": "shielded-amm"}),
            PayloadPrivacyMode::CommitmentOnly,
            state.config.min_privacy_set_size,
            1_500,
            "private_contract_call",
            "devnet-replay-nullifier-contract-0",
            &pq_contract_id,
            &contract_route_id,
            height,
            height + state.config.default_message_ttl_blocks,
        )?;
        state.insert_message(contract_message)?;

        let message_root = private_message_collection_root(&state.messages);
        let batch = MessageBatch::new(
            CrossLayerDomain::Wallet,
            CrossLayerDomain::MoneroBridge,
            height,
            height + state.config.batch_window_blocks,
            &message_root,
            &route_policy_collection_root(&state.route_policies),
            &sponsorship_collection_root(&state.sponsorships),
            &ack_receipt_collection_root(&state.ack_receipts),
            &json!({"batch": "devnet-cross-layer-batch"}),
            state.messages.len() as u64,
            state.total_fee_cap_micro_units(),
        )?;
        state.insert_batch(batch)?;

        let record = state.public_record_without_state_root();
        state.publish_public_record("cross_layer_message_bus_devnet", "bootstrap", &record, 500)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> CrossLayerMessageBusResult<String> {
        if height < self.height {
            return Err("cross layer message bus height cannot move backwards".to_string());
        }
        self.height = height;
        for message in self.messages.values_mut() {
            if message.status.live() && message.expires_at_height < height {
                message.status = MessageEnvelopeStatus::Expired;
            }
        }
        for replay in self.replay_guards.values_mut() {
            if replay.status.usable() && replay.expires_at_height < height {
                replay.status = ReplayGuardStatus::Expired;
            }
        }
        for ticket in self.delivery_tickets.values_mut() {
            if ticket.status.live() && ticket.expires_at_height < height {
                ticket.status = DeliveryTicketStatus::Expired;
            }
        }
        for sponsorship in self.sponsorships.values_mut() {
            if sponsorship.status.usable() && sponsorship.expires_at_height < height {
                sponsorship.status = SponsorshipStatus::Expired;
            }
        }
        for ack in self.ack_receipts.values_mut() {
            if ack.status == AckReceiptStatus::Pending && ack.expires_at_height < height {
                ack.status = AckReceiptStatus::TimedOut;
            }
        }
        for batch in self.batches.values_mut() {
            if batch.status.accepts_messages() && batch.closes_at_height < height {
                batch.status = MessageBatchStatus::Expired;
            }
        }
        self.validate()
    }

    pub fn insert_pq_envelope(
        &mut self,
        envelope: PqRouteEnvelope,
    ) -> CrossLayerMessageBusResult<String> {
        envelope.validate()?;
        if envelope.security_bits < self.config.min_pq_security_bits {
            return Err("pq envelope security bits below configured floor".to_string());
        }
        let id = envelope.pq_envelope_id.clone();
        self.pq_envelopes.insert(id.clone(), envelope);
        self.validate()?;
        Ok(id)
    }

    pub fn insert_route_policy(
        &mut self,
        policy: CrossLayerRoutePolicy,
    ) -> CrossLayerMessageBusResult<String> {
        policy.validate()?;
        if policy.min_privacy_set_size < self.config.min_privacy_set_size {
            return Err("route policy privacy set below configured floor".to_string());
        }
        if policy.min_pq_security_bits < self.config.min_pq_security_bits {
            return Err("route policy pq security below configured floor".to_string());
        }
        let id = policy.route_policy_id.clone();
        self.route_policies.insert(id.clone(), policy);
        self.validate()?;
        Ok(id)
    }

    pub fn insert_message(
        &mut self,
        message: PrivateMessageEnvelope,
    ) -> CrossLayerMessageBusResult<String> {
        message.validate()?;
        let pq = self
            .pq_envelopes
            .get(&message.pq_envelope_id)
            .ok_or_else(|| "message references unknown pq envelope".to_string())?;
        let route = self
            .route_policies
            .get(&message.route_policy_id)
            .ok_or_else(|| "message references unknown route policy".to_string())?;
        if !route.admits(&message, pq.security_bits) {
            return Err("route policy does not admit message".to_string());
        }
        if message.privacy_set_size < self.config.min_privacy_set_size {
            return Err("message privacy set below configured floor".to_string());
        }
        if !self.config.allow_emergency_public_payloads
            && message.privacy_mode == PayloadPrivacyMode::EmergencyPublic
        {
            return Err("emergency public payloads are disabled".to_string());
        }
        let replay = ReplayGuard::new(
            &message.message_id,
            &message.replay_nullifier,
            message.source_domain,
            message.created_at_height,
            message.expires_at_height,
            &json!({"message_id": message.message_id, "nullifier": message.replay_nullifier}),
        )?;
        let id = message.message_id.clone();
        self.messages.insert(id.clone(), message);
        self.replay_guards
            .insert(replay.replay_guard_id.clone(), replay);
        self.validate()?;
        Ok(id)
    }

    pub fn insert_delivery_ticket(
        &mut self,
        ticket: DeliveryTicket,
    ) -> CrossLayerMessageBusResult<String> {
        ticket.validate()?;
        if !self.messages.contains_key(&ticket.message_id) {
            return Err("delivery ticket references unknown message".to_string());
        }
        if !self.route_policies.contains_key(&ticket.route_policy_id) {
            return Err("delivery ticket references unknown route policy".to_string());
        }
        let id = ticket.ticket_id.clone();
        self.delivery_tickets.insert(id.clone(), ticket);
        self.validate()?;
        Ok(id)
    }

    pub fn insert_sponsorship(
        &mut self,
        sponsorship: LowFeeMessageSponsorship,
    ) -> CrossLayerMessageBusResult<String> {
        sponsorship.validate()?;
        if !self.messages.contains_key(&sponsorship.message_id) {
            return Err("sponsorship references unknown message".to_string());
        }
        let id = sponsorship.sponsorship_id.clone();
        self.sponsorships.insert(id.clone(), sponsorship);
        self.validate()?;
        Ok(id)
    }

    pub fn insert_ack_receipt(
        &mut self,
        ack: MessageAckReceipt,
    ) -> CrossLayerMessageBusResult<String> {
        ack.validate()?;
        if !self.messages.contains_key(&ack.message_id) {
            return Err("ack references unknown message".to_string());
        }
        if !self.delivery_tickets.contains_key(&ack.ticket_id) {
            return Err("ack references unknown delivery ticket".to_string());
        }
        let id = ack.ack_id.clone();
        self.ack_receipts.insert(id.clone(), ack);
        self.validate()?;
        Ok(id)
    }

    pub fn insert_batch(&mut self, batch: MessageBatch) -> CrossLayerMessageBusResult<String> {
        batch.validate()?;
        if batch.message_count as usize > self.config.max_batch_messages {
            return Err("message batch exceeds configured max messages".to_string());
        }
        let id = batch.batch_id.clone();
        self.batches.insert(id.clone(), batch);
        self.validate()?;
        Ok(id)
    }

    pub fn publish_public_record(
        &mut self,
        subject_id: &str,
        subject_kind: &str,
        record: &Value,
        disclosure_bps: u64,
    ) -> CrossLayerMessageBusResult<String> {
        let public = CrossLayerPublicRecord::new(
            subject_id,
            subject_kind,
            record,
            disclosure_bps,
            self.height,
        )?;
        let id = public.public_record_id.clone();
        self.public_records.insert(id.clone(), public);
        self.validate()?;
        Ok(id)
    }

    pub fn active_message_ids(&self) -> Vec<String> {
        self.messages
            .values()
            .filter(|message| message.status.live())
            .map(|message| message.message_id.clone())
            .collect()
    }

    pub fn active_route_ids(&self) -> Vec<String> {
        self.route_policies
            .values()
            .filter(|route| route.status.usable())
            .map(|route| route.route_policy_id.clone())
            .collect()
    }

    pub fn total_fee_cap_micro_units(&self) -> u64 {
        self.messages
            .values()
            .map(|message| message.fee_cap_micro_units)
            .fold(0_u64, u64::saturating_add)
    }

    pub fn total_sponsored_micro_units(&self) -> u64 {
        self.sponsorships
            .values()
            .filter(|sponsorship| sponsorship.status.usable())
            .map(|sponsorship| sponsorship.sponsored_micro_units)
            .fold(0_u64, u64::saturating_add)
    }

    pub fn roots(&self) -> CrossLayerMessageBusRoots {
        CrossLayerMessageBusRoots {
            config_root: self.config.config_root(),
            pq_envelope_root: pq_envelope_collection_root(&self.pq_envelopes),
            message_root: private_message_collection_root(&self.messages),
            route_policy_root: route_policy_collection_root(&self.route_policies),
            replay_guard_root: replay_guard_collection_root(&self.replay_guards),
            delivery_ticket_root: delivery_ticket_collection_root(&self.delivery_tickets),
            sponsorship_root: sponsorship_collection_root(&self.sponsorships),
            ack_receipt_root: ack_receipt_collection_root(&self.ack_receipts),
            batch_root: message_batch_collection_root(&self.batches),
            public_record_root: public_record_collection_root(&self.public_records),
            active_route_root: cross_layer_message_bus_payload_root(
                "CROSS-LAYER-ACTIVE-ROUTES",
                &json!(self.active_route_ids()),
            ),
        }
    }

    pub fn counters(&self) -> CrossLayerMessageBusCounters {
        CrossLayerMessageBusCounters {
            pq_envelope_count: self.pq_envelopes.len() as u64,
            message_count: self.messages.len() as u64,
            live_message_count: self
                .messages
                .values()
                .filter(|message| message.status.live())
                .count() as u64,
            route_policy_count: self.route_policies.len() as u64,
            usable_route_policy_count: self
                .route_policies
                .values()
                .filter(|route| route.status.usable())
                .count() as u64,
            replay_guard_count: self.replay_guards.len() as u64,
            active_replay_guard_count: self
                .replay_guards
                .values()
                .filter(|guard| guard.status.usable())
                .count() as u64,
            delivery_ticket_count: self.delivery_tickets.len() as u64,
            live_ticket_count: self
                .delivery_tickets
                .values()
                .filter(|ticket| ticket.status.live())
                .count() as u64,
            sponsorship_count: self.sponsorships.len() as u64,
            usable_sponsorship_count: self
                .sponsorships
                .values()
                .filter(|sponsorship| sponsorship.status.usable())
                .count() as u64,
            ack_receipt_count: self.ack_receipts.len() as u64,
            accepted_ack_count: self
                .ack_receipts
                .values()
                .filter(|ack| ack.status == AckReceiptStatus::Accepted)
                .count() as u64,
            batch_count: self.batches.len() as u64,
            open_batch_count: self
                .batches
                .values()
                .filter(|batch| batch.status.accepts_messages())
                .count() as u64,
            public_record_count: self.public_records.len() as u64,
            total_fee_cap_micro_units: self.total_fee_cap_micro_units(),
            sponsored_micro_units: self.total_sponsored_micro_units(),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "cross_layer_message_bus_state",
            "protocol_version": CROSS_LAYER_MESSAGE_BUS_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.state_root(),
            "counters": counters.public_record(),
            "counters_root": counters.state_root(),
            "active_message_ids": self.active_message_ids(),
            "active_route_ids": self.active_route_ids(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut object) = record {
            object.insert("state_root".to_string(), json!(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        cross_layer_message_bus_payload_root(
            "CROSS-LAYER-MESSAGE-BUS-STATE",
            &self.public_record_without_state_root(),
        )
    }

    pub fn validate(&self) -> CrossLayerMessageBusResult<String> {
        self.config.validate()?;
        for envelope in self.pq_envelopes.values() {
            envelope.validate()?;
            if envelope.security_bits < self.config.min_pq_security_bits {
                return Err("pq envelope below configured security floor".to_string());
            }
        }
        for route in self.route_policies.values() {
            route.validate()?;
            if route.min_privacy_set_size < self.config.min_privacy_set_size {
                return Err("route privacy set below configured floor".to_string());
            }
        }
        let mut nullifiers = BTreeSet::new();
        for message in self.messages.values() {
            message.validate()?;
            let pq = self
                .pq_envelopes
                .get(&message.pq_envelope_id)
                .ok_or_else(|| "message references unknown pq envelope".to_string())?;
            let route = self
                .route_policies
                .get(&message.route_policy_id)
                .ok_or_else(|| "message references unknown route policy".to_string())?;
            if !route.admits(message, pq.security_bits) {
                return Err("message fails route admission".to_string());
            }
            if !nullifiers.insert(message.replay_nullifier.clone()) {
                return Err("duplicate replay nullifier".to_string());
            }
            if message.status.live() && message.expires_at_height < self.height {
                return Err("live message expired before bus height".to_string());
            }
        }
        for guard in self.replay_guards.values() {
            guard.validate()?;
            if !self.messages.contains_key(&guard.message_id) {
                return Err("replay guard references unknown message".to_string());
            }
        }
        for ticket in self.delivery_tickets.values() {
            ticket.validate()?;
            if !self.messages.contains_key(&ticket.message_id) {
                return Err("delivery ticket references unknown message".to_string());
            }
            if !self.route_policies.contains_key(&ticket.route_policy_id) {
                return Err("delivery ticket references unknown route policy".to_string());
            }
        }
        for sponsorship in self.sponsorships.values() {
            sponsorship.validate()?;
            if !self.messages.contains_key(&sponsorship.message_id) {
                return Err("sponsorship references unknown message".to_string());
            }
        }
        for ack in self.ack_receipts.values() {
            ack.validate()?;
            if !self.messages.contains_key(&ack.message_id) {
                return Err("ack references unknown message".to_string());
            }
            if !self.delivery_tickets.contains_key(&ack.ticket_id) {
                return Err("ack references unknown delivery ticket".to_string());
            }
        }
        for batch in self.batches.values() {
            batch.validate()?;
            if batch.message_count as usize > self.config.max_batch_messages {
                return Err("batch exceeds configured max messages".to_string());
            }
        }
        for public in self.public_records.values() {
            public.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn cross_layer_message_bus_payload_root(domain: &str, payload: &Value) -> String {
    stable_hash_hex(domain, &[HashPart::Json(payload)], 32)
}

pub fn pq_route_envelope_id(
    signer_commitment: &str,
    signature_scheme: &str,
    replay_domain: &str,
    created_at_height: u64,
    signed_payload_root: &str,
) -> String {
    stable_hash_hex(
        "CROSS-LAYER-PQ-ROUTE-ENVELOPE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(signer_commitment),
            HashPart::Str(signature_scheme),
            HashPart::Str(replay_domain),
            HashPart::Int(created_at_height as i128),
            HashPart::Str(signed_payload_root),
        ],
        32,
    )
}

pub fn cross_layer_message_id(
    source_domain: CrossLayerDomain,
    target_domain: CrossLayerDomain,
    kind: CrossLayerMessageKind,
    sender_commitment: &str,
    replay_nullifier: &str,
    created_at_height: u64,
    payload_commitment_root: &str,
) -> String {
    stable_hash_hex(
        "CROSS-LAYER-MESSAGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(source_domain.as_str()),
            HashPart::Str(target_domain.as_str()),
            HashPart::Str(kind.as_str()),
            HashPart::Str(sender_commitment),
            HashPart::Str(replay_nullifier),
            HashPart::Int(created_at_height as i128),
            HashPart::Str(payload_commitment_root),
        ],
        32,
    )
}

pub fn route_policy_id(
    source_domain: CrossLayerDomain,
    target_domain: CrossLayerDomain,
    low_fee_lane: &str,
    updated_at_height: u64,
    policy_root: &str,
) -> String {
    stable_hash_hex(
        "CROSS-LAYER-ROUTE-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(source_domain.as_str()),
            HashPart::Str(target_domain.as_str()),
            HashPart::Str(low_fee_lane),
            HashPart::Int(updated_at_height as i128),
            HashPart::Str(policy_root),
        ],
        32,
    )
}

pub fn replay_guard_id(
    message_id: &str,
    replay_nullifier: &str,
    source_domain: CrossLayerDomain,
    opened_at_height: u64,
    guard_root: &str,
) -> String {
    stable_hash_hex(
        "CROSS-LAYER-REPLAY-GUARD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(message_id),
            HashPart::Str(replay_nullifier),
            HashPart::Str(source_domain.as_str()),
            HashPart::Int(opened_at_height as i128),
            HashPart::Str(guard_root),
        ],
        32,
    )
}

pub fn delivery_ticket_id(
    message_id: &str,
    route_policy_id: &str,
    assigned_relayer: &str,
    opened_at_height: u64,
    delivery_proof_root: &str,
) -> String {
    stable_hash_hex(
        "CROSS-LAYER-DELIVERY-TICKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(message_id),
            HashPart::Str(route_policy_id),
            HashPart::Str(assigned_relayer),
            HashPart::Int(opened_at_height as i128),
            HashPart::Str(delivery_proof_root),
        ],
        32,
    )
}

pub fn message_sponsorship_id(
    message_id: &str,
    sponsor_commitment: &str,
    fee_asset_id: &str,
    reserved_at_height: u64,
    proof_root: &str,
) -> String {
    stable_hash_hex(
        "CROSS-LAYER-MESSAGE-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(message_id),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(fee_asset_id),
            HashPart::Int(reserved_at_height as i128),
            HashPart::Str(proof_root),
        ],
        32,
    )
}

pub fn message_ack_id(
    message_id: &str,
    ticket_id: &str,
    source_domain: CrossLayerDomain,
    target_domain: CrossLayerDomain,
    observed_at_height: u64,
    ack_payload_root: &str,
) -> String {
    stable_hash_hex(
        "CROSS-LAYER-MESSAGE-ACK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(message_id),
            HashPart::Str(ticket_id),
            HashPart::Str(source_domain.as_str()),
            HashPart::Str(target_domain.as_str()),
            HashPart::Int(observed_at_height as i128),
            HashPart::Str(ack_payload_root),
        ],
        32,
    )
}

pub fn message_batch_id(
    source_domain: CrossLayerDomain,
    target_domain: CrossLayerDomain,
    opened_at_height: u64,
    message_root: &str,
    batch_proof_root: &str,
) -> String {
    stable_hash_hex(
        "CROSS-LAYER-MESSAGE-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(source_domain.as_str()),
            HashPart::Str(target_domain.as_str()),
            HashPart::Int(opened_at_height as i128),
            HashPart::Str(message_root),
            HashPart::Str(batch_proof_root),
        ],
        32,
    )
}

pub fn public_record_id(
    subject_id: &str,
    subject_kind: &str,
    published_at_height: u64,
    record_root: &str,
) -> String {
    stable_hash_hex(
        "CROSS-LAYER-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_id),
            HashPart::Str(subject_kind),
            HashPart::Int(published_at_height as i128),
            HashPart::Str(record_root),
        ],
        32,
    )
}

pub fn pq_envelope_collection_root(items: &BTreeMap<String, PqRouteEnvelope>) -> String {
    collection_root(
        "CROSS-LAYER-PQ-ENVELOPE-COLLECTION",
        items.values().map(PqRouteEnvelope::public_record).collect(),
    )
}

pub fn private_message_collection_root(items: &BTreeMap<String, PrivateMessageEnvelope>) -> String {
    collection_root(
        "CROSS-LAYER-PRIVATE-MESSAGE-COLLECTION",
        items
            .values()
            .map(PrivateMessageEnvelope::public_record)
            .collect(),
    )
}

pub fn route_policy_collection_root(items: &BTreeMap<String, CrossLayerRoutePolicy>) -> String {
    collection_root(
        "CROSS-LAYER-ROUTE-POLICY-COLLECTION",
        items
            .values()
            .map(CrossLayerRoutePolicy::public_record)
            .collect(),
    )
}

pub fn replay_guard_collection_root(items: &BTreeMap<String, ReplayGuard>) -> String {
    collection_root(
        "CROSS-LAYER-REPLAY-GUARD-COLLECTION",
        items.values().map(ReplayGuard::public_record).collect(),
    )
}

pub fn delivery_ticket_collection_root(items: &BTreeMap<String, DeliveryTicket>) -> String {
    collection_root(
        "CROSS-LAYER-DELIVERY-TICKET-COLLECTION",
        items.values().map(DeliveryTicket::public_record).collect(),
    )
}

pub fn sponsorship_collection_root(items: &BTreeMap<String, LowFeeMessageSponsorship>) -> String {
    collection_root(
        "CROSS-LAYER-SPONSORSHIP-COLLECTION",
        items
            .values()
            .map(LowFeeMessageSponsorship::public_record)
            .collect(),
    )
}

pub fn ack_receipt_collection_root(items: &BTreeMap<String, MessageAckReceipt>) -> String {
    collection_root(
        "CROSS-LAYER-ACK-RECEIPT-COLLECTION",
        items
            .values()
            .map(MessageAckReceipt::public_record)
            .collect(),
    )
}

pub fn message_batch_collection_root(items: &BTreeMap<String, MessageBatch>) -> String {
    collection_root(
        "CROSS-LAYER-MESSAGE-BATCH-COLLECTION",
        items.values().map(MessageBatch::public_record).collect(),
    )
}

pub fn public_record_collection_root(items: &BTreeMap<String, CrossLayerPublicRecord>) -> String {
    collection_root(
        "CROSS-LAYER-PUBLIC-RECORD-COLLECTION",
        items
            .values()
            .map(CrossLayerPublicRecord::public_record)
            .collect(),
    )
}

fn collection_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

fn ensure_non_empty(value: &str, label: &str) -> CrossLayerMessageBusResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn ensure_positive(value: u64, label: &str) -> CrossLayerMessageBusResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_bps(value: u64, label: &str) -> CrossLayerMessageBusResult<()> {
    if value > CROSS_LAYER_MESSAGE_BUS_MAX_BPS {
        return Err(format!("{label} exceeds basis-point maximum"));
    }
    Ok(())
}

fn ensure_height_window(
    start_height: u64,
    end_height: u64,
    label: &str,
) -> CrossLayerMessageBusResult<()> {
    if end_height <= start_height {
        return Err(format!("{label} height window is inverted"));
    }
    Ok(())
}
