use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type CrossRollupPrivateMessagingResult<T> = Result<T, String>;

pub const CROSS_ROLLUP_PRIVATE_MESSAGING_PROTOCOL_VERSION: &str =
    "nebula-cross-rollup-private-messaging-v1";
pub const CROSS_ROLLUP_PRIVATE_MESSAGING_ENCRYPTION_SCHEME: &str =
    "ml-kem-1024+shake256-private-rollup-packet-v1";
pub const CROSS_ROLLUP_PRIVATE_MESSAGING_PQ_AUTH_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-128f-route-attestation-v1";
pub const CROSS_ROLLUP_PRIVATE_MESSAGING_REPLAY_NULLIFIER_SCHEME: &str =
    "shake256-cross-rollup-message-nullifier-v1";
pub const CROSS_ROLLUP_PRIVATE_MESSAGING_DISCLOSURE_SCHEME: &str =
    "zk-selective-cross-rollup-disclosure-v1";
pub const CROSS_ROLLUP_PRIVATE_MESSAGING_DEVNET_HEIGHT: u64 = 640;
pub const CROSS_ROLLUP_PRIVATE_MESSAGING_DEFAULT_PACKET_TTL_BLOCKS: u64 = 72;
pub const CROSS_ROLLUP_PRIVATE_MESSAGING_DEFAULT_ROUTE_TTL_BLOCKS: u64 = 7_200;
pub const CROSS_ROLLUP_PRIVATE_MESSAGING_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 96;
pub const CROSS_ROLLUP_PRIVATE_MESSAGING_DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 14_400;
pub const CROSS_ROLLUP_PRIVATE_MESSAGING_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 128;
pub const CROSS_ROLLUP_PRIVATE_MESSAGING_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const CROSS_ROLLUP_PRIVATE_MESSAGING_DEFAULT_MAX_PACKET_BYTES: u64 = 262_144;
pub const CROSS_ROLLUP_PRIVATE_MESSAGING_DEFAULT_MAX_FEE_UNITS: u64 = 20_000;
pub const CROSS_ROLLUP_PRIVATE_MESSAGING_DEFAULT_SPONSOR_BUDGET_UNITS: u64 = 500_000;
pub const CROSS_ROLLUP_PRIVATE_MESSAGING_MAX_BPS: u64 = 10_000;
pub const CROSS_ROLLUP_PRIVATE_MESSAGING_MAX_ROUTES: usize = 16_384;
pub const CROSS_ROLLUP_PRIVATE_MESSAGING_MAX_ATTESTATIONS: usize = 65_536;
pub const CROSS_ROLLUP_PRIVATE_MESSAGING_MAX_PACKETS: usize = 131_072;
pub const CROSS_ROLLUP_PRIVATE_MESSAGING_MAX_SPONSORS: usize = 65_536;
pub const CROSS_ROLLUP_PRIVATE_MESSAGING_MAX_RECEIPTS: usize = 131_072;
pub const CROSS_ROLLUP_PRIVATE_MESSAGING_MAX_DISCLOSURES: usize = 65_536;
pub const CROSS_ROLLUP_PRIVATE_MESSAGING_MAX_EVENTS: usize = 131_072;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollupDomainKind {
    NebulaPrivateDeFi,
    MoneroBridge,
    SettlementHub,
    ProverNetwork,
    DataAvailability,
    WalletRecovery,
    Governance,
    ExternalRollup(String),
}

impl RollupDomainKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::NebulaPrivateDeFi => "nebula_private_defi".to_string(),
            Self::MoneroBridge => "monero_bridge".to_string(),
            Self::SettlementHub => "settlement_hub".to_string(),
            Self::ProverNetwork => "prover_network".to_string(),
            Self::DataAvailability => "data_availability".to_string(),
            Self::WalletRecovery => "wallet_recovery".to_string(),
            Self::Governance => "governance".to_string(),
            Self::ExternalRollup(value) => value.clone(),
        }
    }

    pub fn default_privacy_floor(&self) -> u64 {
        match self {
            Self::NebulaPrivateDeFi => 192,
            Self::MoneroBridge => 160,
            Self::SettlementHub => 128,
            Self::ProverNetwork => 96,
            Self::DataAvailability => 64,
            Self::WalletRecovery => 192,
            Self::Governance => 96,
            Self::ExternalRollup(_) => 96,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateMessageKind {
    ShieldedContractCall,
    PrivateTokenTransfer,
    PrivateNftTransfer,
    MoneroDepositNotice,
    MoneroWithdrawalIntent,
    ProofRequest,
    ProofReceipt,
    LiquidityRoute,
    SettlementReceipt,
    WalletRecovery,
    GovernanceVote,
    EmergencyExit,
    Custom(String),
}

impl PrivateMessageKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::ShieldedContractCall => "shielded_contract_call".to_string(),
            Self::PrivateTokenTransfer => "private_token_transfer".to_string(),
            Self::PrivateNftTransfer => "private_nft_transfer".to_string(),
            Self::MoneroDepositNotice => "monero_deposit_notice".to_string(),
            Self::MoneroWithdrawalIntent => "monero_withdrawal_intent".to_string(),
            Self::ProofRequest => "proof_request".to_string(),
            Self::ProofReceipt => "proof_receipt".to_string(),
            Self::LiquidityRoute => "liquidity_route".to_string(),
            Self::SettlementReceipt => "settlement_receipt".to_string(),
            Self::WalletRecovery => "wallet_recovery".to_string(),
            Self::GovernanceVote => "governance_vote".to_string(),
            Self::EmergencyExit => "emergency_exit".to_string(),
            Self::Custom(value) => value.clone(),
        }
    }

    pub fn priority_weight(&self) -> u64 {
        match self {
            Self::EmergencyExit => 120,
            Self::WalletRecovery => 110,
            Self::MoneroWithdrawalIntent => 105,
            Self::SettlementReceipt => 96,
            Self::ShieldedContractCall => 88,
            Self::LiquidityRoute => 82,
            Self::ProofRequest => 74,
            Self::ProofReceipt => 72,
            Self::PrivateTokenTransfer => 70,
            Self::PrivateNftTransfer => 66,
            Self::MoneroDepositNotice => 64,
            Self::GovernanceVote => 48,
            Self::Custom(_) => 50,
        }
    }

    pub fn requires_delivery_receipt(&self) -> bool {
        matches!(
            self,
            Self::ShieldedContractCall
                | Self::PrivateTokenTransfer
                | Self::PrivateNftTransfer
                | Self::MoneroWithdrawalIntent
                | Self::ProofRequest
                | Self::LiquidityRoute
                | Self::SettlementReceipt
                | Self::WalletRecovery
                | Self::EmergencyExit
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

    pub fn accepts_packets(self) -> bool {
        matches!(self, Self::Active | Self::Congested | Self::Degraded)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteTrustMode {
    PqCommittee,
    LightClient,
    OptimisticChallenge,
    EmergencyGuardian,
}

impl RouteTrustMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqCommittee => "pq_committee",
            Self::LightClient => "light_client",
            Self::OptimisticChallenge => "optimistic_challenge",
            Self::EmergencyGuardian => "emergency_guardian",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketPrivacyMode {
    FullyShielded,
    CommitmentOnly,
    RouteMetadataPublic,
    EmergencyPublic,
}

impl PacketPrivacyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FullyShielded => "fully_shielded",
            Self::CommitmentOnly => "commitment_only",
            Self::RouteMetadataPublic => "route_metadata_public",
            Self::EmergencyPublic => "emergency_public",
        }
    }

    pub fn leakage_bps(self) -> u64 {
        match self {
            Self::FullyShielded => 0,
            Self::CommitmentOnly => 400,
            Self::RouteMetadataPublic => 2_000,
            Self::EmergencyPublic => CROSS_ROLLUP_PRIVATE_MESSAGING_MAX_BPS,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketStatus {
    Queued,
    Authorized,
    Relayed,
    Delivered,
    Acknowledged,
    Expired,
    Rejected,
    Cancelled,
}

impl PacketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Authorized => "authorized",
            Self::Relayed => "relayed",
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
            Self::Queued | Self::Authorized | Self::Relayed | Self::Delivered
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Pending,
    Active,
    Revoked,
    Expired,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorStatus {
    Active,
    Exhausted,
    Frozen,
    Expired,
}

impl SponsorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Exhausted => "exhausted",
            Self::Frozen => "frozen",
            Self::Expired => "expired",
        }
    }

    pub fn can_spend(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    Posted,
    Finalized,
    Disputed,
    Expired,
}

impl DeliveryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossRollupEventKind {
    RouteRegistered,
    RouteAttested,
    PacketQueued,
    PacketRelayed,
    PacketDelivered,
    PacketAcknowledged,
    SponsorDebited,
    DisclosureIssued,
    RoutePaused,
}

impl CrossRollupEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RouteRegistered => "route_registered",
            Self::RouteAttested => "route_attested",
            Self::PacketQueued => "packet_queued",
            Self::PacketRelayed => "packet_relayed",
            Self::PacketDelivered => "packet_delivered",
            Self::PacketAcknowledged => "packet_acknowledged",
            Self::SponsorDebited => "sponsor_debited",
            Self::DisclosureIssued => "disclosure_issued",
            Self::RoutePaused => "route_paused",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossRollupPrivateMessagingConfig {
    pub protocol_version: String,
    pub encryption_scheme: String,
    pub pq_auth_scheme: String,
    pub replay_nullifier_scheme: String,
    pub disclosure_scheme: String,
    pub packet_ttl_blocks: u64,
    pub route_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_packet_bytes: u64,
    pub max_fee_units: u64,
    pub default_sponsor_budget_units: u64,
    pub max_public_leakage_bps: u64,
}

impl CrossRollupPrivateMessagingConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_version: CROSS_ROLLUP_PRIVATE_MESSAGING_PROTOCOL_VERSION.to_string(),
            encryption_scheme: CROSS_ROLLUP_PRIVATE_MESSAGING_ENCRYPTION_SCHEME.to_string(),
            pq_auth_scheme: CROSS_ROLLUP_PRIVATE_MESSAGING_PQ_AUTH_SCHEME.to_string(),
            replay_nullifier_scheme: CROSS_ROLLUP_PRIVATE_MESSAGING_REPLAY_NULLIFIER_SCHEME
                .to_string(),
            disclosure_scheme: CROSS_ROLLUP_PRIVATE_MESSAGING_DISCLOSURE_SCHEME.to_string(),
            packet_ttl_blocks: CROSS_ROLLUP_PRIVATE_MESSAGING_DEFAULT_PACKET_TTL_BLOCKS,
            route_ttl_blocks: CROSS_ROLLUP_PRIVATE_MESSAGING_DEFAULT_ROUTE_TTL_BLOCKS,
            receipt_ttl_blocks: CROSS_ROLLUP_PRIVATE_MESSAGING_DEFAULT_RECEIPT_TTL_BLOCKS,
            sponsor_ttl_blocks: CROSS_ROLLUP_PRIVATE_MESSAGING_DEFAULT_SPONSOR_TTL_BLOCKS,
            min_privacy_set_size: CROSS_ROLLUP_PRIVATE_MESSAGING_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: CROSS_ROLLUP_PRIVATE_MESSAGING_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_packet_bytes: CROSS_ROLLUP_PRIVATE_MESSAGING_DEFAULT_MAX_PACKET_BYTES,
            max_fee_units: CROSS_ROLLUP_PRIVATE_MESSAGING_DEFAULT_MAX_FEE_UNITS,
            default_sponsor_budget_units:
                CROSS_ROLLUP_PRIVATE_MESSAGING_DEFAULT_SPONSOR_BUDGET_UNITS,
            max_public_leakage_bps: 2_500,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "cross_rollup_private_messaging_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "encryption_scheme": self.encryption_scheme,
            "pq_auth_scheme": self.pq_auth_scheme,
            "replay_nullifier_scheme": self.replay_nullifier_scheme,
            "disclosure_scheme": self.disclosure_scheme,
            "packet_ttl_blocks": self.packet_ttl_blocks,
            "route_ttl_blocks": self.route_ttl_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "sponsor_ttl_blocks": self.sponsor_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_packet_bytes": self.max_packet_bytes,
            "max_fee_units": self.max_fee_units,
            "default_sponsor_budget_units": self.default_sponsor_budget_units,
            "max_public_leakage_bps": self.max_public_leakage_bps,
        })
    }

    pub fn validate(&self) -> CrossRollupPrivateMessagingResult<()> {
        ensure_non_empty(&self.protocol_version, "protocol version")?;
        ensure_non_empty(&self.encryption_scheme, "encryption scheme")?;
        ensure_non_empty(&self.pq_auth_scheme, "pq auth scheme")?;
        ensure_non_empty(&self.replay_nullifier_scheme, "replay nullifier scheme")?;
        ensure_non_empty(&self.disclosure_scheme, "disclosure scheme")?;
        ensure_positive(self.packet_ttl_blocks, "packet ttl")?;
        ensure_positive(self.route_ttl_blocks, "route ttl")?;
        ensure_positive(self.receipt_ttl_blocks, "receipt ttl")?;
        ensure_positive(self.sponsor_ttl_blocks, "sponsor ttl")?;
        ensure_positive(self.min_privacy_set_size, "min privacy set size")?;
        ensure_positive(self.min_pq_security_bits as u64, "min pq security bits")?;
        ensure_positive(self.max_packet_bytes, "max packet bytes")?;
        ensure_positive(self.max_fee_units, "max fee units")?;
        ensure_positive(self.default_sponsor_budget_units, "default sponsor budget")?;
        ensure_bps(self.max_public_leakage_bps, "max public leakage bps")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossRollupRoutePolicy {
    pub route_id: String,
    pub source_domain: RollupDomainKind,
    pub target_domain: RollupDomainKind,
    pub trust_mode: RouteTrustMode,
    pub status: RoutePolicyStatus,
    pub lane_key: String,
    pub endpoint_commitment: String,
    pub relayer_committee_root: String,
    pub pq_committee_root: String,
    pub low_fee_lane: String,
    pub max_packet_bytes: u64,
    pub max_fee_units: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub challenge_window_blocks: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub metadata_root: String,
}

impl CrossRollupRoutePolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source_domain: RollupDomainKind,
        target_domain: RollupDomainKind,
        trust_mode: RouteTrustMode,
        lane_key: &str,
        endpoint_commitment: &str,
        relayer_committee: &[String],
        pq_committee: &[String],
        max_packet_bytes: u64,
        max_fee_units: u64,
        min_privacy_set_size: u64,
        min_pq_security_bits: u16,
        challenge_window_blocks: u64,
        opened_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> CrossRollupPrivateMessagingResult<Self> {
        ensure_non_empty(lane_key, "lane key")?;
        ensure_non_empty(endpoint_commitment, "endpoint commitment")?;
        ensure_string_set(relayer_committee, "relayer committee")?;
        ensure_string_set(pq_committee, "pq committee")?;
        ensure_positive(max_packet_bytes, "max packet bytes")?;
        ensure_positive(max_fee_units, "max fee units")?;
        ensure_positive(min_privacy_set_size, "min privacy set size")?;
        ensure_positive(min_pq_security_bits as u64, "min pq security bits")?;
        validate_height_window(opened_at_height, expires_at_height, "route")?;
        let relayer_committee_root =
            cross_rollup_private_messaging_string_set_root("RELAYER-COMMITTEE", relayer_committee);
        let pq_committee_root =
            cross_rollup_private_messaging_string_set_root("PQ-COMMITTEE", pq_committee);
        let metadata_root = cross_rollup_private_messaging_payload_root("ROUTE-METADATA", metadata);
        let low_fee_lane = cross_rollup_private_messaging_string_root("LOW-FEE-LANE", lane_key);
        let route_id = cross_rollup_route_policy_id(
            &source_domain,
            &target_domain,
            trust_mode,
            lane_key,
            endpoint_commitment,
            &relayer_committee_root,
            &pq_committee_root,
        );
        let route = Self {
            route_id,
            source_domain,
            target_domain,
            trust_mode,
            status: RoutePolicyStatus::Active,
            lane_key: lane_key.to_string(),
            endpoint_commitment: endpoint_commitment.to_string(),
            relayer_committee_root,
            pq_committee_root,
            low_fee_lane,
            max_packet_bytes,
            max_fee_units,
            min_privacy_set_size,
            min_pq_security_bits,
            challenge_window_blocks,
            opened_at_height,
            expires_at_height,
            metadata_root,
        };
        route.validate()?;
        Ok(route)
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.expires_at_height {
            self.status = RoutePolicyStatus::Retired;
        }
    }

    pub fn accepts_packets_at(&self, height: u64) -> bool {
        self.status.accepts_packets()
            && self.opened_at_height <= height
            && height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "cross_rollup_route_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": CROSS_ROLLUP_PRIVATE_MESSAGING_PROTOCOL_VERSION,
            "route_id": self.route_id,
            "source_domain": self.source_domain.as_str(),
            "target_domain": self.target_domain.as_str(),
            "trust_mode": self.trust_mode.as_str(),
            "status": self.status.as_str(),
            "lane_key": self.lane_key,
            "endpoint_commitment": self.endpoint_commitment,
            "relayer_committee_root": self.relayer_committee_root,
            "pq_committee_root": self.pq_committee_root,
            "low_fee_lane": self.low_fee_lane,
            "max_packet_bytes": self.max_packet_bytes,
            "max_fee_units": self.max_fee_units,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "challenge_window_blocks": self.challenge_window_blocks,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn state_root(&self) -> String {
        cross_rollup_private_messaging_payload_root("ROUTE-POLICY", &self.public_record())
    }

    pub fn validate(&self) -> CrossRollupPrivateMessagingResult<()> {
        ensure_non_empty(&self.route_id, "route id")?;
        ensure_non_empty(&self.lane_key, "lane key")?;
        ensure_non_empty(&self.endpoint_commitment, "endpoint commitment")?;
        ensure_non_empty(&self.relayer_committee_root, "relayer committee root")?;
        ensure_non_empty(&self.pq_committee_root, "pq committee root")?;
        ensure_non_empty(&self.low_fee_lane, "low fee lane")?;
        ensure_non_empty(&self.metadata_root, "metadata root")?;
        ensure_positive(self.max_packet_bytes, "max packet bytes")?;
        ensure_positive(self.max_fee_units, "max fee units")?;
        ensure_positive(self.min_privacy_set_size, "min privacy set size")?;
        ensure_positive(self.min_pq_security_bits as u64, "min pq security bits")?;
        validate_height_window(self.opened_at_height, self.expires_at_height, "route")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRouteAttestation {
    pub attestation_id: String,
    pub route_id: String,
    pub signer_commitment: String,
    pub pq_public_key_commitment: String,
    pub signature_root: String,
    pub status: AttestationStatus,
    pub quorum_weight_bps: u64,
    pub privacy_set_size: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub transcript_root: String,
}

impl PqRouteAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        route_id: &str,
        signer_commitment: &str,
        pq_public_key_commitment: &str,
        signature: &Value,
        quorum_weight_bps: u64,
        privacy_set_size: u64,
        issued_at_height: u64,
        expires_at_height: u64,
        transcript: &Value,
    ) -> CrossRollupPrivateMessagingResult<Self> {
        ensure_non_empty(route_id, "route id")?;
        ensure_non_empty(signer_commitment, "signer commitment")?;
        ensure_non_empty(pq_public_key_commitment, "pq public key commitment")?;
        ensure_bps(quorum_weight_bps, "quorum weight")?;
        ensure_positive(privacy_set_size, "privacy set size")?;
        validate_height_window(issued_at_height, expires_at_height, "attestation")?;
        let signature_root =
            cross_rollup_private_messaging_payload_root("PQ-ROUTE-SIGNATURE", signature);
        let transcript_root =
            cross_rollup_private_messaging_payload_root("PQ-ROUTE-TRANSCRIPT", transcript);
        let attestation_id = pq_route_attestation_id(
            route_id,
            signer_commitment,
            pq_public_key_commitment,
            &signature_root,
            issued_at_height,
        );
        let attestation = Self {
            attestation_id,
            route_id: route_id.to_string(),
            signer_commitment: signer_commitment.to_string(),
            pq_public_key_commitment: pq_public_key_commitment.to_string(),
            signature_root,
            status: AttestationStatus::Active,
            quorum_weight_bps,
            privacy_set_size,
            issued_at_height,
            expires_at_height,
            transcript_root,
        };
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.expires_at_height {
            self.status = AttestationStatus::Expired;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_route_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": CROSS_ROLLUP_PRIVATE_MESSAGING_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "route_id": self.route_id,
            "signer_commitment": self.signer_commitment,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "signature_root": self.signature_root,
            "status": self.status.as_str(),
            "quorum_weight_bps": self.quorum_weight_bps,
            "privacy_set_size": self.privacy_set_size,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "transcript_root": self.transcript_root,
        })
    }

    pub fn state_root(&self) -> String {
        cross_rollup_private_messaging_payload_root("PQ-ROUTE-ATTESTATION", &self.public_record())
    }

    pub fn validate(&self) -> CrossRollupPrivateMessagingResult<()> {
        ensure_non_empty(&self.attestation_id, "attestation id")?;
        ensure_non_empty(&self.route_id, "route id")?;
        ensure_non_empty(&self.signer_commitment, "signer commitment")?;
        ensure_non_empty(&self.pq_public_key_commitment, "pq public key commitment")?;
        ensure_non_empty(&self.signature_root, "signature root")?;
        ensure_non_empty(&self.transcript_root, "transcript root")?;
        ensure_bps(self.quorum_weight_bps, "quorum weight")?;
        ensure_positive(self.privacy_set_size, "privacy set size")?;
        validate_height_window(self.issued_at_height, self.expires_at_height, "attestation")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateMessagePacket {
    pub packet_id: String,
    pub route_id: String,
    pub message_kind: PrivateMessageKind,
    pub privacy_mode: PacketPrivacyMode,
    pub status: PacketStatus,
    pub sender_commitment: String,
    pub recipient_commitment: String,
    pub payload_ciphertext_root: String,
    pub payload_commitment_root: String,
    pub route_hint_root: String,
    pub replay_nullifier: String,
    pub fee_asset_id: String,
    pub max_fee_units: u64,
    pub packet_bytes: u64,
    pub privacy_set_size: u64,
    pub priority_weight: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub sponsor_id: Option<String>,
}

impl PrivateMessagePacket {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        route_id: &str,
        message_kind: PrivateMessageKind,
        privacy_mode: PacketPrivacyMode,
        sender_commitment: &str,
        recipient_commitment: &str,
        payload_ciphertext: &Value,
        payload_commitment: &Value,
        route_hint: &Value,
        fee_asset_id: &str,
        max_fee_units: u64,
        packet_bytes: u64,
        privacy_set_size: u64,
        submitted_at_height: u64,
        expires_at_height: u64,
        sponsor_id: Option<String>,
    ) -> CrossRollupPrivateMessagingResult<Self> {
        ensure_non_empty(route_id, "route id")?;
        ensure_non_empty(sender_commitment, "sender commitment")?;
        ensure_non_empty(recipient_commitment, "recipient commitment")?;
        ensure_non_empty(fee_asset_id, "fee asset id")?;
        ensure_positive(max_fee_units, "max fee units")?;
        ensure_positive(packet_bytes, "packet bytes")?;
        ensure_positive(privacy_set_size, "privacy set size")?;
        validate_height_window(submitted_at_height, expires_at_height, "packet")?;
        let payload_ciphertext_root =
            cross_rollup_private_messaging_payload_root("PACKET-CIPHERTEXT", payload_ciphertext);
        let payload_commitment_root =
            cross_rollup_private_messaging_payload_root("PACKET-COMMITMENT", payload_commitment);
        let route_hint_root =
            cross_rollup_private_messaging_payload_root("PACKET-ROUTE-HINT", route_hint);
        let replay_nullifier = cross_rollup_message_replay_nullifier(
            route_id,
            sender_commitment,
            recipient_commitment,
            &payload_commitment_root,
            submitted_at_height,
        );
        let packet_id = private_message_packet_id(
            route_id,
            &message_kind,
            sender_commitment,
            recipient_commitment,
            &payload_ciphertext_root,
            &replay_nullifier,
        );
        let packet = Self {
            packet_id,
            route_id: route_id.to_string(),
            message_kind,
            privacy_mode,
            status: PacketStatus::Queued,
            sender_commitment: sender_commitment.to_string(),
            recipient_commitment: recipient_commitment.to_string(),
            payload_ciphertext_root,
            payload_commitment_root,
            route_hint_root,
            replay_nullifier,
            fee_asset_id: fee_asset_id.to_string(),
            max_fee_units,
            packet_bytes,
            privacy_set_size,
            priority_weight: 0,
            submitted_at_height,
            expires_at_height,
            sponsor_id,
        }
        .with_priority();
        packet.validate()?;
        Ok(packet)
    }

    fn with_priority(mut self) -> Self {
        let privacy_bonus = match self.privacy_mode {
            PacketPrivacyMode::FullyShielded => 20,
            PacketPrivacyMode::CommitmentOnly => 10,
            PacketPrivacyMode::RouteMetadataPublic => 4,
            PacketPrivacyMode::EmergencyPublic => 0,
        };
        self.priority_weight = self
            .message_kind
            .priority_weight()
            .saturating_add(privacy_bonus);
        self
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.expires_at_height && self.status.live() {
            self.status = PacketStatus::Expired;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_cross_rollup_message_packet",
            "chain_id": CHAIN_ID,
            "protocol_version": CROSS_ROLLUP_PRIVATE_MESSAGING_PROTOCOL_VERSION,
            "packet_id": self.packet_id,
            "route_id": self.route_id,
            "message_kind": self.message_kind.as_str(),
            "privacy_mode": self.privacy_mode.as_str(),
            "status": self.status.as_str(),
            "sender_commitment": self.sender_commitment,
            "recipient_commitment": self.recipient_commitment,
            "payload_ciphertext_root": self.payload_ciphertext_root,
            "payload_commitment_root": self.payload_commitment_root,
            "route_hint_root": self.route_hint_root,
            "replay_nullifier": self.replay_nullifier,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_units": self.max_fee_units,
            "packet_bytes": self.packet_bytes,
            "privacy_set_size": self.privacy_set_size,
            "priority_weight": self.priority_weight,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "sponsor_id": self.sponsor_id,
            "requires_delivery_receipt": self.message_kind.requires_delivery_receipt(),
        })
    }

    pub fn state_root(&self) -> String {
        cross_rollup_private_messaging_payload_root("PRIVATE-MESSAGE-PACKET", &self.public_record())
    }

    pub fn validate(&self) -> CrossRollupPrivateMessagingResult<()> {
        ensure_non_empty(&self.packet_id, "packet id")?;
        ensure_non_empty(&self.route_id, "route id")?;
        ensure_non_empty(&self.sender_commitment, "sender commitment")?;
        ensure_non_empty(&self.recipient_commitment, "recipient commitment")?;
        ensure_non_empty(&self.payload_ciphertext_root, "payload ciphertext root")?;
        ensure_non_empty(&self.payload_commitment_root, "payload commitment root")?;
        ensure_non_empty(&self.route_hint_root, "route hint root")?;
        ensure_non_empty(&self.replay_nullifier, "replay nullifier")?;
        ensure_non_empty(&self.fee_asset_id, "fee asset id")?;
        ensure_positive(self.max_fee_units, "max fee units")?;
        ensure_positive(self.packet_bytes, "packet bytes")?;
        ensure_positive(self.privacy_set_size, "privacy set size")?;
        ensure_positive(self.priority_weight, "priority weight")?;
        validate_height_window(self.submitted_at_height, self.expires_at_height, "packet")?;
        if self.privacy_mode.leakage_bps() > CROSS_ROLLUP_PRIVATE_MESSAGING_MAX_BPS {
            return Err("packet privacy leakage exceeds maximum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelaySponsorPool {
    pub sponsor_id: String,
    pub sponsor_commitment: String,
    pub route_allowlist_root: String,
    pub fee_asset_id: String,
    pub budget_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub max_fee_units_per_packet: u64,
    pub status: SponsorStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub policy_root: String,
}

impl RelaySponsorPool {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_commitment: &str,
        route_allowlist: &[String],
        fee_asset_id: &str,
        budget_units: u64,
        max_fee_units_per_packet: u64,
        opened_at_height: u64,
        expires_at_height: u64,
        policy: &Value,
    ) -> CrossRollupPrivateMessagingResult<Self> {
        ensure_non_empty(sponsor_commitment, "sponsor commitment")?;
        ensure_string_set(route_allowlist, "route allowlist")?;
        ensure_non_empty(fee_asset_id, "fee asset id")?;
        ensure_positive(budget_units, "budget units")?;
        ensure_positive(max_fee_units_per_packet, "max fee units per packet")?;
        validate_height_window(opened_at_height, expires_at_height, "sponsor")?;
        let route_allowlist_root = cross_rollup_private_messaging_string_set_root(
            "SPONSOR-ROUTE-ALLOWLIST",
            route_allowlist,
        );
        let policy_root = cross_rollup_private_messaging_payload_root("SPONSOR-POLICY", policy);
        let sponsor_id = relay_sponsor_pool_id(
            sponsor_commitment,
            &route_allowlist_root,
            fee_asset_id,
            &policy_root,
        );
        let pool = Self {
            sponsor_id,
            sponsor_commitment: sponsor_commitment.to_string(),
            route_allowlist_root,
            fee_asset_id: fee_asset_id.to_string(),
            budget_units,
            reserved_units: 0,
            spent_units: 0,
            max_fee_units_per_packet,
            status: SponsorStatus::Active,
            opened_at_height,
            expires_at_height,
            policy_root,
        };
        pool.validate()?;
        Ok(pool)
    }

    pub fn available_units(&self) -> u64 {
        self.budget_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
    }

    pub fn can_pay(&self, fee_units: u64, height: u64) -> bool {
        self.status.can_spend()
            && self.opened_at_height <= height
            && height < self.expires_at_height
            && fee_units <= self.max_fee_units_per_packet
            && fee_units <= self.available_units()
    }

    pub fn reserve(
        &mut self,
        fee_units: u64,
        height: u64,
    ) -> CrossRollupPrivateMessagingResult<()> {
        if !self.can_pay(fee_units, height) {
            return Err("sponsor cannot cover packet fee".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_add(fee_units);
        Ok(())
    }

    pub fn settle(&mut self, fee_units: u64) -> CrossRollupPrivateMessagingResult<()> {
        if fee_units > self.reserved_units {
            return Err("sponsor settlement exceeds reserved units".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_sub(fee_units);
        self.spent_units = self.spent_units.saturating_add(fee_units);
        if self.available_units() == 0 {
            self.status = SponsorStatus::Exhausted;
        }
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.expires_at_height {
            self.status = SponsorStatus::Expired;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "relay_sponsor_pool",
            "chain_id": CHAIN_ID,
            "protocol_version": CROSS_ROLLUP_PRIVATE_MESSAGING_PROTOCOL_VERSION,
            "sponsor_id": self.sponsor_id,
            "sponsor_commitment": self.sponsor_commitment,
            "route_allowlist_root": self.route_allowlist_root,
            "fee_asset_id": self.fee_asset_id,
            "budget_units": self.budget_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "available_units": self.available_units(),
            "max_fee_units_per_packet": self.max_fee_units_per_packet,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "policy_root": self.policy_root,
        })
    }

    pub fn state_root(&self) -> String {
        cross_rollup_private_messaging_payload_root("RELAY-SPONSOR-POOL", &self.public_record())
    }

    pub fn validate(&self) -> CrossRollupPrivateMessagingResult<()> {
        ensure_non_empty(&self.sponsor_id, "sponsor id")?;
        ensure_non_empty(&self.sponsor_commitment, "sponsor commitment")?;
        ensure_non_empty(&self.route_allowlist_root, "route allowlist root")?;
        ensure_non_empty(&self.fee_asset_id, "fee asset id")?;
        ensure_positive(self.budget_units, "budget units")?;
        ensure_positive(self.max_fee_units_per_packet, "max fee units per packet")?;
        validate_height_window(self.opened_at_height, self.expires_at_height, "sponsor")?;
        if self.reserved_units.saturating_add(self.spent_units) > self.budget_units {
            return Err("sponsor accounting exceeds budget".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryReceipt {
    pub receipt_id: String,
    pub packet_id: String,
    pub route_id: String,
    pub status: DeliveryStatus,
    pub relayer_commitment: String,
    pub delivery_proof_root: String,
    pub target_state_root: String,
    pub fee_debit_root: String,
    pub delivered_at_height: u64,
    pub finalized_at_height: u64,
}

impl DeliveryReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        packet_id: &str,
        route_id: &str,
        relayer_commitment: &str,
        delivery_proof: &Value,
        target_state_root: &str,
        fee_debit: &Value,
        delivered_at_height: u64,
        finalized_at_height: u64,
    ) -> CrossRollupPrivateMessagingResult<Self> {
        ensure_non_empty(packet_id, "packet id")?;
        ensure_non_empty(route_id, "route id")?;
        ensure_non_empty(relayer_commitment, "relayer commitment")?;
        ensure_non_empty(target_state_root, "target state root")?;
        validate_height_window(delivered_at_height, finalized_at_height, "delivery")?;
        let delivery_proof_root =
            cross_rollup_private_messaging_payload_root("DELIVERY-PROOF", delivery_proof);
        let fee_debit_root = cross_rollup_private_messaging_payload_root("FEE-DEBIT", fee_debit);
        let receipt_id = delivery_receipt_id(
            packet_id,
            route_id,
            relayer_commitment,
            &delivery_proof_root,
            delivered_at_height,
        );
        let receipt = Self {
            receipt_id,
            packet_id: packet_id.to_string(),
            route_id: route_id.to_string(),
            status: DeliveryStatus::Posted,
            relayer_commitment: relayer_commitment.to_string(),
            delivery_proof_root,
            target_state_root: target_state_root.to_string(),
            fee_debit_root,
            delivered_at_height,
            finalized_at_height,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.finalized_at_height && self.status == DeliveryStatus::Posted {
            self.status = DeliveryStatus::Finalized;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "cross_rollup_delivery_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": CROSS_ROLLUP_PRIVATE_MESSAGING_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "packet_id": self.packet_id,
            "route_id": self.route_id,
            "status": self.status.as_str(),
            "relayer_commitment": self.relayer_commitment,
            "delivery_proof_root": self.delivery_proof_root,
            "target_state_root": self.target_state_root,
            "fee_debit_root": self.fee_debit_root,
            "delivered_at_height": self.delivered_at_height,
            "finalized_at_height": self.finalized_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        cross_rollup_private_messaging_payload_root("DELIVERY-RECEIPT", &self.public_record())
    }

    pub fn validate(&self) -> CrossRollupPrivateMessagingResult<()> {
        ensure_non_empty(&self.receipt_id, "receipt id")?;
        ensure_non_empty(&self.packet_id, "packet id")?;
        ensure_non_empty(&self.route_id, "route id")?;
        ensure_non_empty(&self.relayer_commitment, "relayer commitment")?;
        ensure_non_empty(&self.delivery_proof_root, "delivery proof root")?;
        ensure_non_empty(&self.target_state_root, "target state root")?;
        ensure_non_empty(&self.fee_debit_root, "fee debit root")?;
        validate_height_window(
            self.delivered_at_height,
            self.finalized_at_height,
            "delivery",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectiveDisclosureReceipt {
    pub disclosure_id: String,
    pub packet_id: String,
    pub requester_commitment: String,
    pub disclosure_scope_root: String,
    pub proof_root: String,
    pub max_disclosure_bps: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl SelectiveDisclosureReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        packet_id: &str,
        requester_commitment: &str,
        disclosure_scope: &Value,
        proof: &Value,
        max_disclosure_bps: u64,
        issued_at_height: u64,
        expires_at_height: u64,
    ) -> CrossRollupPrivateMessagingResult<Self> {
        ensure_non_empty(packet_id, "packet id")?;
        ensure_non_empty(requester_commitment, "requester commitment")?;
        ensure_bps(max_disclosure_bps, "max disclosure bps")?;
        validate_height_window(issued_at_height, expires_at_height, "disclosure")?;
        let disclosure_scope_root =
            cross_rollup_private_messaging_payload_root("DISCLOSURE-SCOPE", disclosure_scope);
        let proof_root = cross_rollup_private_messaging_payload_root("DISCLOSURE-PROOF", proof);
        let disclosure_id = selective_disclosure_receipt_id(
            packet_id,
            requester_commitment,
            &disclosure_scope_root,
            &proof_root,
            issued_at_height,
        );
        let receipt = Self {
            disclosure_id,
            packet_id: packet_id.to_string(),
            requester_commitment: requester_commitment.to_string(),
            disclosure_scope_root,
            proof_root,
            max_disclosure_bps,
            issued_at_height,
            expires_at_height,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "cross_rollup_selective_disclosure",
            "chain_id": CHAIN_ID,
            "protocol_version": CROSS_ROLLUP_PRIVATE_MESSAGING_PROTOCOL_VERSION,
            "disclosure_id": self.disclosure_id,
            "packet_id": self.packet_id,
            "requester_commitment": self.requester_commitment,
            "disclosure_scope_root": self.disclosure_scope_root,
            "proof_root": self.proof_root,
            "max_disclosure_bps": self.max_disclosure_bps,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        cross_rollup_private_messaging_payload_root(
            "SELECTIVE-DISCLOSURE-RECEIPT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> CrossRollupPrivateMessagingResult<()> {
        ensure_non_empty(&self.disclosure_id, "disclosure id")?;
        ensure_non_empty(&self.packet_id, "packet id")?;
        ensure_non_empty(&self.requester_commitment, "requester commitment")?;
        ensure_non_empty(&self.disclosure_scope_root, "disclosure scope root")?;
        ensure_non_empty(&self.proof_root, "proof root")?;
        ensure_bps(self.max_disclosure_bps, "max disclosure bps")?;
        validate_height_window(self.issued_at_height, self.expires_at_height, "disclosure")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossRollupPrivateEvent {
    pub event_id: String,
    pub event_kind: CrossRollupEventKind,
    pub subject_id: String,
    pub emitted_at_height: u64,
    pub payload_root: String,
}

impl CrossRollupPrivateEvent {
    pub fn new(
        event_kind: CrossRollupEventKind,
        subject_id: &str,
        emitted_at_height: u64,
        payload: &Value,
    ) -> CrossRollupPrivateMessagingResult<Self> {
        ensure_non_empty(subject_id, "event subject")?;
        let payload_root = cross_rollup_private_messaging_payload_root("EVENT-PAYLOAD", payload);
        let event_id =
            cross_rollup_private_event_id(event_kind, subject_id, emitted_at_height, &payload_root);
        let event = Self {
            event_id,
            event_kind,
            subject_id: subject_id.to_string(),
            emitted_at_height,
            payload_root,
        };
        event.validate()?;
        Ok(event)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "cross_rollup_private_event",
            "chain_id": CHAIN_ID,
            "protocol_version": CROSS_ROLLUP_PRIVATE_MESSAGING_PROTOCOL_VERSION,
            "event_id": self.event_id,
            "event_kind": self.event_kind.as_str(),
            "subject_id": self.subject_id,
            "emitted_at_height": self.emitted_at_height,
            "payload_root": self.payload_root,
        })
    }

    pub fn validate(&self) -> CrossRollupPrivateMessagingResult<()> {
        ensure_non_empty(&self.event_id, "event id")?;
        ensure_non_empty(&self.subject_id, "event subject")?;
        ensure_non_empty(&self.payload_root, "event payload root")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossRollupPrivateMessagingRoots {
    pub route_root: String,
    pub attestation_root: String,
    pub packet_root: String,
    pub sponsor_root: String,
    pub receipt_root: String,
    pub disclosure_root: String,
    pub event_root: String,
    pub replay_nullifier_root: String,
    pub state_root: String,
}

impl CrossRollupPrivateMessagingRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "cross_rollup_private_messaging_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": CROSS_ROLLUP_PRIVATE_MESSAGING_PROTOCOL_VERSION,
            "route_root": self.route_root,
            "attestation_root": self.attestation_root,
            "packet_root": self.packet_root,
            "sponsor_root": self.sponsor_root,
            "receipt_root": self.receipt_root,
            "disclosure_root": self.disclosure_root,
            "event_root": self.event_root,
            "replay_nullifier_root": self.replay_nullifier_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossRollupPrivateMessagingCounters {
    pub height: u64,
    pub route_count: u64,
    pub active_route_count: u64,
    pub attestation_count: u64,
    pub active_attestation_count: u64,
    pub packet_count: u64,
    pub live_packet_count: u64,
    pub delivered_packet_count: u64,
    pub sponsor_count: u64,
    pub active_sponsor_count: u64,
    pub receipt_count: u64,
    pub finalized_receipt_count: u64,
    pub disclosure_count: u64,
    pub event_count: u64,
    pub total_available_sponsor_units: u64,
    pub total_reserved_sponsor_units: u64,
}

impl CrossRollupPrivateMessagingCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "cross_rollup_private_messaging_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": CROSS_ROLLUP_PRIVATE_MESSAGING_PROTOCOL_VERSION,
            "height": self.height,
            "route_count": self.route_count,
            "active_route_count": self.active_route_count,
            "attestation_count": self.attestation_count,
            "active_attestation_count": self.active_attestation_count,
            "packet_count": self.packet_count,
            "live_packet_count": self.live_packet_count,
            "delivered_packet_count": self.delivered_packet_count,
            "sponsor_count": self.sponsor_count,
            "active_sponsor_count": self.active_sponsor_count,
            "receipt_count": self.receipt_count,
            "finalized_receipt_count": self.finalized_receipt_count,
            "disclosure_count": self.disclosure_count,
            "event_count": self.event_count,
            "total_available_sponsor_units": self.total_available_sponsor_units,
            "total_reserved_sponsor_units": self.total_reserved_sponsor_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossRollupPrivateMessagingState {
    pub config: CrossRollupPrivateMessagingConfig,
    pub height: u64,
    pub routes: BTreeMap<String, CrossRollupRoutePolicy>,
    pub attestations: BTreeMap<String, PqRouteAttestation>,
    pub packets: BTreeMap<String, PrivateMessagePacket>,
    pub sponsors: BTreeMap<String, RelaySponsorPool>,
    pub receipts: BTreeMap<String, DeliveryReceipt>,
    pub disclosures: BTreeMap<String, SelectiveDisclosureReceipt>,
    pub events: BTreeMap<String, CrossRollupPrivateEvent>,
    pub replay_nullifiers: BTreeSet<String>,
}

impl CrossRollupPrivateMessagingState {
    pub fn new(
        config: CrossRollupPrivateMessagingConfig,
    ) -> CrossRollupPrivateMessagingResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height: CROSS_ROLLUP_PRIVATE_MESSAGING_DEVNET_HEIGHT,
            routes: BTreeMap::new(),
            attestations: BTreeMap::new(),
            packets: BTreeMap::new(),
            sponsors: BTreeMap::new(),
            receipts: BTreeMap::new(),
            disclosures: BTreeMap::new(),
            events: BTreeMap::new(),
            replay_nullifiers: BTreeSet::new(),
        })
    }

    pub fn devnet() -> CrossRollupPrivateMessagingResult<Self> {
        let config = CrossRollupPrivateMessagingConfig::devnet();
        let mut state = Self::new(config.clone())?;
        let route = CrossRollupRoutePolicy::new(
            RollupDomainKind::NebulaPrivateDeFi,
            RollupDomainKind::MoneroBridge,
            RouteTrustMode::PqCommittee,
            "devnet-private-defi-to-monero-bridge",
            &cross_rollup_private_messaging_string_root(
                "DEVNET-ENDPOINT",
                "private-defi-monero-bridge",
            ),
            &[
                "devnet-relayer-alpha".to_string(),
                "devnet-relayer-beta".to_string(),
                "devnet-relayer-gamma".to_string(),
            ],
            &[
                "devnet-pq-route-signer-alpha".to_string(),
                "devnet-pq-route-signer-beta".to_string(),
                "devnet-pq-route-signer-gamma".to_string(),
            ],
            config.max_packet_bytes,
            config.max_fee_units,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
            24,
            state.height,
            state.height + config.route_ttl_blocks,
            &json!({"purpose": "private defi calls and monero bridge settlement"}),
        )?;
        let route_id = route.route_id.clone();
        state.insert_route(route)?;
        state.insert_attestation(PqRouteAttestation::new(
            &route_id,
            &cross_rollup_private_messaging_string_root("DEVNET-SIGNER", "route-signer-alpha"),
            &cross_rollup_private_messaging_string_root("DEVNET-PQ-KEY", "ml-dsa-route-alpha"),
            &json!({"scheme": config.pq_auth_scheme, "signature": "devnet"}),
            6_700,
            192,
            state.height,
            state.height + config.route_ttl_blocks,
            &json!({"route_id": route_id, "height": state.height}),
        )?)?;
        let sponsor = RelaySponsorPool::new(
            &cross_rollup_private_messaging_string_root("DEVNET-SPONSOR", "operator-low-fee"),
            std::slice::from_ref(&route_id),
            "piconero-fee-credit",
            config.default_sponsor_budget_units,
            config.max_fee_units,
            state.height,
            state.height + config.sponsor_ttl_blocks,
            &json!({"covers": ["private_contract_call", "monero_withdrawal_intent"]}),
        )?;
        let sponsor_id = sponsor.sponsor_id.clone();
        state.insert_sponsor(sponsor)?;
        let packet = PrivateMessagePacket::new(
            &route_id,
            PrivateMessageKind::ShieldedContractCall,
            PacketPrivacyMode::FullyShielded,
            &cross_rollup_private_messaging_string_root("DEVNET-SENDER", "wallet-alpha"),
            &cross_rollup_private_messaging_string_root("DEVNET-RECIPIENT", "bridge-vault"),
            &json!({"ciphertext": "devnet-private-call"}),
            &json!({"selector": "swap_and_withdraw", "amount_bucket": "private"}),
            &json!({"route": "private-defi-to-monero-bridge"}),
            "piconero-fee-credit",
            7_500,
            18_432,
            192,
            state.height,
            state.height + config.packet_ttl_blocks,
            Some(sponsor_id),
        )?;
        state.insert_packet(packet)?;
        state.insert_event(CrossRollupPrivateEvent::new(
            CrossRollupEventKind::RouteRegistered,
            &route_id,
            state.height,
            &json!({"route": route_id}),
        )?)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> CrossRollupPrivateMessagingResult<()> {
        if height < self.height {
            return Err("cross-rollup messaging height cannot go backwards".to_string());
        }
        self.height = height;
        for route in self.routes.values_mut() {
            route.set_height(height);
        }
        for attestation in self.attestations.values_mut() {
            attestation.set_height(height);
        }
        for packet in self.packets.values_mut() {
            packet.set_height(height);
        }
        for sponsor in self.sponsors.values_mut() {
            sponsor.set_height(height);
        }
        for receipt in self.receipts.values_mut() {
            receipt.set_height(height);
        }
        self.validate()
    }

    pub fn insert_route(
        &mut self,
        route: CrossRollupRoutePolicy,
    ) -> CrossRollupPrivateMessagingResult<()> {
        route.validate()?;
        insert_unique(&mut self.routes, route.route_id.clone(), route, "route")
    }

    pub fn insert_attestation(
        &mut self,
        attestation: PqRouteAttestation,
    ) -> CrossRollupPrivateMessagingResult<()> {
        require_map_key("attestation", &attestation.route_id, &self.routes)?;
        attestation.validate()?;
        insert_unique(
            &mut self.attestations,
            attestation.attestation_id.clone(),
            attestation,
            "attestation",
        )
    }

    pub fn insert_packet(
        &mut self,
        packet: PrivateMessagePacket,
    ) -> CrossRollupPrivateMessagingResult<()> {
        let route = self
            .routes
            .get(&packet.route_id)
            .ok_or_else(|| "packet references unknown route".to_string())?;
        if !route.accepts_packets_at(self.height) {
            return Err("route does not accept packets at current height".to_string());
        }
        if packet.packet_bytes > route.max_packet_bytes {
            return Err("packet exceeds route byte limit".to_string());
        }
        if packet.max_fee_units > route.max_fee_units {
            return Err("packet exceeds route fee limit".to_string());
        }
        if packet.privacy_set_size < route.min_privacy_set_size {
            return Err("packet privacy set below route floor".to_string());
        }
        if packet.privacy_mode.leakage_bps() > self.config.max_public_leakage_bps {
            return Err("packet leaks too much public metadata".to_string());
        }
        if self.replay_nullifiers.contains(&packet.replay_nullifier) {
            return Err("packet replay nullifier already spent".to_string());
        }
        if let Some(sponsor_id) = &packet.sponsor_id {
            let sponsor = self
                .sponsors
                .get_mut(sponsor_id)
                .ok_or_else(|| "packet references unknown sponsor".to_string())?;
            sponsor.reserve(packet.max_fee_units, self.height)?;
        }
        packet.validate()?;
        self.replay_nullifiers
            .insert(packet.replay_nullifier.clone());
        insert_unique(
            &mut self.packets,
            packet.packet_id.clone(),
            packet,
            "packet",
        )
    }

    pub fn insert_sponsor(
        &mut self,
        sponsor: RelaySponsorPool,
    ) -> CrossRollupPrivateMessagingResult<()> {
        sponsor.validate()?;
        insert_unique(
            &mut self.sponsors,
            sponsor.sponsor_id.clone(),
            sponsor,
            "sponsor",
        )
    }

    pub fn insert_receipt(
        &mut self,
        receipt: DeliveryReceipt,
    ) -> CrossRollupPrivateMessagingResult<()> {
        require_map_key("receipt", &receipt.packet_id, &self.packets)?;
        receipt.validate()?;
        if let Some(packet) = self.packets.get_mut(&receipt.packet_id) {
            packet.status = PacketStatus::Delivered;
            if let Some(sponsor_id) = &packet.sponsor_id {
                if let Some(sponsor) = self.sponsors.get_mut(sponsor_id) {
                    sponsor.settle(packet.max_fee_units)?;
                }
            }
        }
        insert_unique(
            &mut self.receipts,
            receipt.receipt_id.clone(),
            receipt,
            "receipt",
        )
    }

    pub fn insert_disclosure(
        &mut self,
        disclosure: SelectiveDisclosureReceipt,
    ) -> CrossRollupPrivateMessagingResult<()> {
        require_map_key("disclosure", &disclosure.packet_id, &self.packets)?;
        disclosure.validate()?;
        insert_unique(
            &mut self.disclosures,
            disclosure.disclosure_id.clone(),
            disclosure,
            "disclosure",
        )
    }

    pub fn insert_event(
        &mut self,
        event: CrossRollupPrivateEvent,
    ) -> CrossRollupPrivateMessagingResult<()> {
        event.validate()?;
        insert_unique(&mut self.events, event.event_id.clone(), event, "event")
    }

    pub fn active_route_ids(&self) -> Vec<String> {
        self.routes
            .values()
            .filter(|route| route.accepts_packets_at(self.height))
            .map(|route| route.route_id.clone())
            .collect()
    }

    pub fn live_packet_ids(&self) -> Vec<String> {
        self.packets
            .values()
            .filter(|packet| packet.status.live())
            .map(|packet| packet.packet_id.clone())
            .collect()
    }

    pub fn ready_for_receipt_ids(&self) -> Vec<String> {
        self.packets
            .values()
            .filter(|packet| {
                matches!(
                    packet.status,
                    PacketStatus::Relayed | PacketStatus::Delivered
                )
            })
            .map(|packet| packet.packet_id.clone())
            .collect()
    }

    pub fn total_available_sponsor_units(&self) -> u64 {
        self.sponsors
            .values()
            .map(RelaySponsorPool::available_units)
            .sum()
    }

    pub fn roots(&self) -> CrossRollupPrivateMessagingRoots {
        let route_root = cross_rollup_private_messaging_record_root(
            "ROUTE",
            self.routes
                .values()
                .map(CrossRollupRoutePolicy::public_record)
                .collect(),
        );
        let attestation_root = cross_rollup_private_messaging_record_root(
            "ATTESTATION",
            self.attestations
                .values()
                .map(PqRouteAttestation::public_record)
                .collect(),
        );
        let packet_root = cross_rollup_private_messaging_record_root(
            "PACKET",
            self.packets
                .values()
                .map(PrivateMessagePacket::public_record)
                .collect(),
        );
        let sponsor_root = cross_rollup_private_messaging_record_root(
            "SPONSOR",
            self.sponsors
                .values()
                .map(RelaySponsorPool::public_record)
                .collect(),
        );
        let receipt_root = cross_rollup_private_messaging_record_root(
            "RECEIPT",
            self.receipts
                .values()
                .map(DeliveryReceipt::public_record)
                .collect(),
        );
        let disclosure_root = cross_rollup_private_messaging_record_root(
            "DISCLOSURE",
            self.disclosures
                .values()
                .map(SelectiveDisclosureReceipt::public_record)
                .collect(),
        );
        let event_root = cross_rollup_private_messaging_record_root(
            "EVENT",
            self.events
                .values()
                .map(CrossRollupPrivateEvent::public_record)
                .collect(),
        );
        let replay_nullifiers = self.replay_nullifiers.iter().cloned().collect::<Vec<_>>();
        let replay_nullifier_root =
            cross_rollup_private_messaging_string_set_root("REPLAY-NULLIFIER", &replay_nullifiers);
        let state_record = json!({
            "route_root": route_root,
            "attestation_root": attestation_root,
            "packet_root": packet_root,
            "sponsor_root": sponsor_root,
            "receipt_root": receipt_root,
            "disclosure_root": disclosure_root,
            "event_root": event_root,
            "replay_nullifier_root": replay_nullifier_root,
            "height": self.height,
        });
        let state_root = cross_rollup_private_messaging_state_root_from_record(&state_record);
        CrossRollupPrivateMessagingRoots {
            route_root,
            attestation_root,
            packet_root,
            sponsor_root,
            receipt_root,
            disclosure_root,
            event_root,
            replay_nullifier_root,
            state_root,
        }
    }

    pub fn counters(&self) -> CrossRollupPrivateMessagingCounters {
        CrossRollupPrivateMessagingCounters {
            height: self.height,
            route_count: self.routes.len() as u64,
            active_route_count: self
                .routes
                .values()
                .filter(|route| route.accepts_packets_at(self.height))
                .count() as u64,
            attestation_count: self.attestations.len() as u64,
            active_attestation_count: self
                .attestations
                .values()
                .filter(|attestation| attestation.status.usable())
                .count() as u64,
            packet_count: self.packets.len() as u64,
            live_packet_count: self
                .packets
                .values()
                .filter(|packet| packet.status.live())
                .count() as u64,
            delivered_packet_count: self
                .packets
                .values()
                .filter(|packet| {
                    matches!(
                        packet.status,
                        PacketStatus::Delivered | PacketStatus::Acknowledged
                    )
                })
                .count() as u64,
            sponsor_count: self.sponsors.len() as u64,
            active_sponsor_count: self
                .sponsors
                .values()
                .filter(|sponsor| sponsor.status.can_spend())
                .count() as u64,
            receipt_count: self.receipts.len() as u64,
            finalized_receipt_count: self
                .receipts
                .values()
                .filter(|receipt| receipt.status == DeliveryStatus::Finalized)
                .count() as u64,
            disclosure_count: self.disclosures.len() as u64,
            event_count: self.events.len() as u64,
            total_available_sponsor_units: self.total_available_sponsor_units(),
            total_reserved_sponsor_units: self
                .sponsors
                .values()
                .map(|sponsor| sponsor.reserved_units)
                .sum(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "cross_rollup_private_messaging_state",
            "chain_id": CHAIN_ID,
            "protocol_version": CROSS_ROLLUP_PRIVATE_MESSAGING_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "active_route_ids": self.active_route_ids(),
            "live_packet_ids": self.live_packet_ids(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn validate(&self) -> CrossRollupPrivateMessagingResult<()> {
        self.config.validate()?;
        if self.routes.len() > CROSS_ROLLUP_PRIVATE_MESSAGING_MAX_ROUTES {
            return Err("cross-rollup route capacity exceeded".to_string());
        }
        if self.attestations.len() > CROSS_ROLLUP_PRIVATE_MESSAGING_MAX_ATTESTATIONS {
            return Err("cross-rollup attestation capacity exceeded".to_string());
        }
        if self.packets.len() > CROSS_ROLLUP_PRIVATE_MESSAGING_MAX_PACKETS {
            return Err("cross-rollup packet capacity exceeded".to_string());
        }
        if self.sponsors.len() > CROSS_ROLLUP_PRIVATE_MESSAGING_MAX_SPONSORS {
            return Err("cross-rollup sponsor capacity exceeded".to_string());
        }
        if self.receipts.len() > CROSS_ROLLUP_PRIVATE_MESSAGING_MAX_RECEIPTS {
            return Err("cross-rollup receipt capacity exceeded".to_string());
        }
        if self.disclosures.len() > CROSS_ROLLUP_PRIVATE_MESSAGING_MAX_DISCLOSURES {
            return Err("cross-rollup disclosure capacity exceeded".to_string());
        }
        if self.events.len() > CROSS_ROLLUP_PRIVATE_MESSAGING_MAX_EVENTS {
            return Err("cross-rollup event capacity exceeded".to_string());
        }
        for route in self.routes.values() {
            route.validate()?;
        }
        for attestation in self.attestations.values() {
            attestation.validate()?;
            require_map_key("attestation", &attestation.route_id, &self.routes)?;
            if attestation.privacy_set_size < self.config.min_privacy_set_size {
                return Err("attestation privacy set below config floor".to_string());
            }
        }
        for packet in self.packets.values() {
            packet.validate()?;
            require_map_key("packet", &packet.route_id, &self.routes)?;
            if packet.packet_bytes > self.config.max_packet_bytes {
                return Err("packet exceeds config byte limit".to_string());
            }
            if packet.max_fee_units > self.config.max_fee_units {
                return Err("packet exceeds config fee limit".to_string());
            }
            if packet.privacy_set_size < self.config.min_privacy_set_size {
                return Err("packet privacy set below config floor".to_string());
            }
            if packet.privacy_mode.leakage_bps() > self.config.max_public_leakage_bps {
                return Err("packet public leakage exceeds config".to_string());
            }
        }
        for sponsor in self.sponsors.values() {
            sponsor.validate()?;
        }
        for receipt in self.receipts.values() {
            receipt.validate()?;
            require_map_key("receipt", &receipt.packet_id, &self.packets)?;
        }
        for disclosure in self.disclosures.values() {
            disclosure.validate()?;
            require_map_key("disclosure", &disclosure.packet_id, &self.packets)?;
        }
        for event in self.events.values() {
            event.validate()?;
        }
        Ok(())
    }
}

pub fn cross_rollup_private_messaging_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "CROSS-ROLLUP-PRIVATE-MESSAGING-STATE",
        &[
            HashPart::Str(CROSS_ROLLUP_PRIVATE_MESSAGING_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn cross_rollup_private_messaging_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("CROSS-ROLLUP-PRIVATE-MESSAGING-{domain}"),
        &[
            HashPart::Str(CROSS_ROLLUP_PRIVATE_MESSAGING_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn cross_rollup_private_messaging_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        &format!("CROSS-ROLLUP-PRIVATE-MESSAGING-{domain}"),
        &[
            HashPart::Str(CROSS_ROLLUP_PRIVATE_MESSAGING_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn cross_rollup_private_messaging_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(Value::String)
        .collect::<Vec<_>>();
    merkle_root(&format!("CROSS-ROLLUP-PRIVATE-MESSAGING-{domain}"), &leaves)
}

pub fn cross_rollup_private_messaging_record_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(
        &format!("CROSS-ROLLUP-PRIVATE-MESSAGING-{domain}"),
        &records,
    )
}

pub fn cross_rollup_route_policy_id(
    source_domain: &RollupDomainKind,
    target_domain: &RollupDomainKind,
    trust_mode: RouteTrustMode,
    lane_key: &str,
    endpoint_commitment: &str,
    relayer_committee_root: &str,
    pq_committee_root: &str,
) -> String {
    let source = source_domain.as_str();
    let target = target_domain.as_str();
    domain_hash(
        "CROSS-ROLLUP-PRIVATE-MESSAGING-ROUTE-ID",
        &[
            HashPart::Str(CROSS_ROLLUP_PRIVATE_MESSAGING_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&source),
            HashPart::Str(&target),
            HashPart::Str(trust_mode.as_str()),
            HashPart::Str(lane_key),
            HashPart::Str(endpoint_commitment),
            HashPart::Str(relayer_committee_root),
            HashPart::Str(pq_committee_root),
        ],
        32,
    )
}

pub fn pq_route_attestation_id(
    route_id: &str,
    signer_commitment: &str,
    pq_public_key_commitment: &str,
    signature_root: &str,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "CROSS-ROLLUP-PRIVATE-MESSAGING-PQ-ATTESTATION-ID",
        &[
            HashPart::Str(CROSS_ROLLUP_PRIVATE_MESSAGING_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(route_id),
            HashPart::Str(signer_commitment),
            HashPart::Str(pq_public_key_commitment),
            HashPart::Str(signature_root),
            HashPart::Int(issued_at_height as i128),
        ],
        32,
    )
}

pub fn cross_rollup_message_replay_nullifier(
    route_id: &str,
    sender_commitment: &str,
    recipient_commitment: &str,
    payload_commitment_root: &str,
    submitted_at_height: u64,
) -> String {
    domain_hash(
        "CROSS-ROLLUP-PRIVATE-MESSAGING-REPLAY-NULLIFIER",
        &[
            HashPart::Str(CROSS_ROLLUP_PRIVATE_MESSAGING_REPLAY_NULLIFIER_SCHEME),
            HashPart::Str(route_id),
            HashPart::Str(sender_commitment),
            HashPart::Str(recipient_commitment),
            HashPart::Str(payload_commitment_root),
            HashPart::Int(submitted_at_height as i128),
        ],
        32,
    )
}

pub fn private_message_packet_id(
    route_id: &str,
    message_kind: &PrivateMessageKind,
    sender_commitment: &str,
    recipient_commitment: &str,
    payload_ciphertext_root: &str,
    replay_nullifier: &str,
) -> String {
    let kind = message_kind.as_str();
    domain_hash(
        "CROSS-ROLLUP-PRIVATE-MESSAGING-PACKET-ID",
        &[
            HashPart::Str(CROSS_ROLLUP_PRIVATE_MESSAGING_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(route_id),
            HashPart::Str(&kind),
            HashPart::Str(sender_commitment),
            HashPart::Str(recipient_commitment),
            HashPart::Str(payload_ciphertext_root),
            HashPart::Str(replay_nullifier),
        ],
        32,
    )
}

pub fn relay_sponsor_pool_id(
    sponsor_commitment: &str,
    route_allowlist_root: &str,
    fee_asset_id: &str,
    policy_root: &str,
) -> String {
    domain_hash(
        "CROSS-ROLLUP-PRIVATE-MESSAGING-SPONSOR-ID",
        &[
            HashPart::Str(CROSS_ROLLUP_PRIVATE_MESSAGING_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(route_allowlist_root),
            HashPart::Str(fee_asset_id),
            HashPart::Str(policy_root),
        ],
        32,
    )
}

pub fn delivery_receipt_id(
    packet_id: &str,
    route_id: &str,
    relayer_commitment: &str,
    delivery_proof_root: &str,
    delivered_at_height: u64,
) -> String {
    domain_hash(
        "CROSS-ROLLUP-PRIVATE-MESSAGING-DELIVERY-RECEIPT-ID",
        &[
            HashPart::Str(CROSS_ROLLUP_PRIVATE_MESSAGING_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(packet_id),
            HashPart::Str(route_id),
            HashPart::Str(relayer_commitment),
            HashPart::Str(delivery_proof_root),
            HashPart::Int(delivered_at_height as i128),
        ],
        32,
    )
}

pub fn selective_disclosure_receipt_id(
    packet_id: &str,
    requester_commitment: &str,
    disclosure_scope_root: &str,
    proof_root: &str,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "CROSS-ROLLUP-PRIVATE-MESSAGING-DISCLOSURE-ID",
        &[
            HashPart::Str(CROSS_ROLLUP_PRIVATE_MESSAGING_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(packet_id),
            HashPart::Str(requester_commitment),
            HashPart::Str(disclosure_scope_root),
            HashPart::Str(proof_root),
            HashPart::Int(issued_at_height as i128),
        ],
        32,
    )
}

pub fn cross_rollup_private_event_id(
    event_kind: CrossRollupEventKind,
    subject_id: &str,
    emitted_at_height: u64,
    payload_root: &str,
) -> String {
    domain_hash(
        "CROSS-ROLLUP-PRIVATE-MESSAGING-EVENT-ID",
        &[
            HashPart::Str(CROSS_ROLLUP_PRIVATE_MESSAGING_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Int(emitted_at_height as i128),
            HashPart::Str(payload_root),
        ],
        32,
    )
}

fn ensure_non_empty(value: &str, label: &str) -> CrossRollupPrivateMessagingResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn ensure_positive(value: u64, label: &str) -> CrossRollupPrivateMessagingResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_bps(value: u64, label: &str) -> CrossRollupPrivateMessagingResult<()> {
    if value > CROSS_ROLLUP_PRIVATE_MESSAGING_MAX_BPS {
        return Err(format!("{label} exceeds 10000 bps"));
    }
    Ok(())
}

fn ensure_string_set(values: &[String], label: &str) -> CrossRollupPrivateMessagingResult<()> {
    if values.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(value, label)?;
        if !seen.insert(value) {
            return Err(format!("{label} contains duplicate value"));
        }
    }
    Ok(())
}

fn validate_height_window(
    start: u64,
    end: u64,
    label: &str,
) -> CrossRollupPrivateMessagingResult<()> {
    if end <= start {
        return Err(format!("{label} height window is invalid"));
    }
    Ok(())
}

fn require_map_key<T>(
    label: &str,
    key: &str,
    map: &BTreeMap<String, T>,
) -> CrossRollupPrivateMessagingResult<()> {
    if !map.contains_key(key) {
        return Err(format!("{label} references unknown id"));
    }
    Ok(())
}

fn insert_unique<T>(
    map: &mut BTreeMap<String, T>,
    id: String,
    value: T,
    label: &str,
) -> CrossRollupPrivateMessagingResult<()> {
    if map.contains_key(&id) {
        return Err(format!("{label} already exists"));
    }
    map.insert(id, value);
    Ok(())
}
