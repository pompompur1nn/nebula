use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    ACCOUNT_SIGNATURE_SCHEME, CHAIN_ID, RECOVERY_SIGNATURE_SCHEME, TARGET_BLOCK_MS,
};

pub type FastRelayMeshResult<T> = Result<T, String>;

pub const FAST_RELAY_MESH_PROTOCOL_VERSION: &str = "nebula-fast-relay-mesh-v1";
pub const FAST_RELAY_MESH_SCHEMA_VERSION: &str = "fast-relay-mesh-state-v1";
pub const FAST_RELAY_MESH_SECURITY_MODEL: &str =
    "deterministic-devnet-relay-scaffolding-not-production-networking";
pub const FAST_RELAY_MESH_TRANSCRIPT_SCHEME: &str = "shake256-canonical-json-transcript";
pub const FAST_RELAY_MESH_COMMITMENT_SCHEME: &str = "shake256-domain-separated-devnet-root";
pub const FAST_RELAY_MESH_PQ_AUTH_SCHEME: &str = ACCOUNT_SIGNATURE_SCHEME;
pub const FAST_RELAY_MESH_PQ_RECOVERY_SCHEME: &str = RECOVERY_SIGNATURE_SCHEME;
pub const FAST_RELAY_MESH_PQ_KEM_SCHEME: &str = "ML-KEM-768";
pub const FAST_RELAY_MESH_HANDSHAKE_SUITE: &str = "ML-KEM-768+ML-DSA-65+SLH-DSA-SHAKE-128s";
pub const FAST_RELAY_MESH_LANE_ENCRYPTION_SCHEME: &str =
    "ML-KEM-768-sealed-XChaCha20-devnet-envelope";
pub const FAST_RELAY_MESH_PRIVATE_MEMPOOL_POLICY: &str =
    "payload-ciphertext-roots-only-delayed-disclosure";
pub const FAST_RELAY_MESH_FAILOVER_POLICY_VERSION: &str = "fast-relay-failover-policy-v1";
pub const FAST_RELAY_MESH_LOW_FEE_POLICY_VERSION: &str = "fast-relay-low-fee-sponsor-v1";
pub const FAST_RELAY_MESH_DEVNET_LABEL: &str = "devnet-fast-relay-mesh";
pub const FAST_RELAY_MESH_MAX_BPS: u64 = 10_000;
pub const FAST_RELAY_MESH_DEFAULT_MICROBATCH_WINDOW_MS: u64 = 80;
pub const FAST_RELAY_MESH_DEFAULT_TARGET_GOSSIP_MS: u64 = 120;
pub const FAST_RELAY_MESH_DEFAULT_TARGET_ACK_MS: u64 = 220;
pub const FAST_RELAY_MESH_DEFAULT_MAX_ROUTE_HOPS: u64 = 5;
pub const FAST_RELAY_MESH_DEFAULT_COMMITMENT_TTL_BLOCKS: u64 = 12;
pub const FAST_RELAY_MESH_DEFAULT_HANDSHAKE_TTL_BLOCKS: u64 = 24;
pub const FAST_RELAY_MESH_DEFAULT_LANE_TTL_BLOCKS: u64 = 288;
pub const FAST_RELAY_MESH_DEFAULT_FAILOVER_GRACE_BLOCKS: u64 = 3;
pub const FAST_RELAY_MESH_DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 96;
pub const FAST_RELAY_MESH_DEFAULT_MIN_PEER_SCORE_BPS: u64 = 6_500;
pub const FAST_RELAY_MESH_DEFAULT_MAX_LOW_FEE_MICRO_UNITS: u64 = 2_500;
pub const FAST_RELAY_MESH_DEFAULT_SPONSOR_BUDGET_UNITS: u64 = 3_000_000;
pub const FAST_RELAY_MESH_DEFAULT_SLASH_LATENCY_BPS: u64 = 500;
pub const FAST_RELAY_MESH_DEFAULT_SLASH_CENSORSHIP_BPS: u64 = 2_500;
pub const FAST_RELAY_MESH_DEFAULT_SLASH_EQUIVOCATION_BPS: u64 = 5_000;
pub const FAST_RELAY_MESH_MAX_REGIONS: usize = 32;
pub const FAST_RELAY_MESH_MAX_PEERS: usize = 256;
pub const FAST_RELAY_MESH_MAX_HANDSHAKES: usize = 512;
pub const FAST_RELAY_MESH_MAX_LANES: usize = 128;
pub const FAST_RELAY_MESH_MAX_COMMITMENTS: usize = 2_048;
pub const FAST_RELAY_MESH_MAX_MICROBATCHES: usize = 512;
pub const FAST_RELAY_MESH_MAX_QOS_OBSERVATIONS: usize = 2_048;
pub const FAST_RELAY_MESH_MAX_EVIDENCE_TICKETS: usize = 512;
pub const FAST_RELAY_MESH_MAX_SPONSOR_POOLS: usize = 128;
pub const FAST_RELAY_MESH_MAX_SPONSOR_TICKETS: usize = 1_024;
pub const FAST_RELAY_MESH_MAX_FAILOVER_POLICIES: usize = 128;
pub const FAST_RELAY_MESH_MAX_PUBLIC_RECORDS: usize = 2_048;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayRegionKind {
    NorthAmericaEast,
    NorthAmericaWest,
    EuropeWest,
    EuropeCentral,
    AsiaPacific,
    MoneroEdge,
    Watchtower,
    SponsorEdge,
}

impl RelayRegionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NorthAmericaEast => "north_america_east",
            Self::NorthAmericaWest => "north_america_west",
            Self::EuropeWest => "europe_west",
            Self::EuropeCentral => "europe_central",
            Self::AsiaPacific => "asia_pacific",
            Self::MoneroEdge => "monero_edge",
            Self::Watchtower => "watchtower",
            Self::SponsorEdge => "sponsor_edge",
        }
    }

    pub fn default_latency_budget_ms(self) -> u64 {
        match self {
            Self::NorthAmericaEast | Self::EuropeWest => 90,
            Self::NorthAmericaWest | Self::EuropeCentral => 110,
            Self::AsiaPacific => 140,
            Self::MoneroEdge => 180,
            Self::Watchtower => 220,
            Self::SponsorEdge => 150,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayRegionStatus {
    Active,
    Standby,
    Draining,
    Quarantined,
    Offline,
}

impl RelayRegionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Standby => "standby",
            Self::Draining => "draining",
            Self::Quarantined => "quarantined",
            Self::Offline => "offline",
        }
    }

    pub fn accepts_traffic(self) -> bool {
        matches!(self, Self::Active | Self::Standby)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayPeerRole {
    Sequencer,
    EdgeRelay,
    PrivateMempool,
    MoneroGateway,
    Watchtower,
    Sponsor,
    FailoverRelay,
    Observer,
}

impl RelayPeerRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sequencer => "sequencer",
            Self::EdgeRelay => "edge_relay",
            Self::PrivateMempool => "private_mempool",
            Self::MoneroGateway => "monero_gateway",
            Self::Watchtower => "watchtower",
            Self::Sponsor => "sponsor",
            Self::FailoverRelay => "failover_relay",
            Self::Observer => "observer",
        }
    }

    pub fn can_ingress(self) -> bool {
        matches!(
            self,
            Self::Sequencer
                | Self::EdgeRelay
                | Self::PrivateMempool
                | Self::MoneroGateway
                | Self::FailoverRelay
        )
    }

    pub fn default_score_bonus_bps(self) -> u64 {
        match self {
            Self::Sequencer => 500,
            Self::PrivateMempool => 400,
            Self::FailoverRelay => 300,
            Self::EdgeRelay => 250,
            Self::MoneroGateway => 200,
            Self::Sponsor => 150,
            Self::Watchtower => 100,
            Self::Observer => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayPeerStatus {
    Active,
    Standby,
    Draining,
    Quarantined,
    Slashed,
    Offline,
}

impl RelayPeerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Standby => "standby",
            Self::Draining => "draining",
            Self::Quarantined => "quarantined",
            Self::Slashed => "slashed",
            Self::Offline => "offline",
        }
    }

    pub fn can_relay(self) -> bool {
        matches!(self, Self::Active | Self::Standby | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqHandshakeStage {
    Offered,
    Encapsulated,
    Authenticated,
    Confirmed,
    Expired,
    Rejected,
    Quarantined,
}

impl PqHandshakeStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Encapsulated => "encapsulated",
            Self::Authenticated => "authenticated",
            Self::Confirmed => "confirmed",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn is_confirmed(self) -> bool {
        matches!(self, Self::Confirmed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptedRelayLaneKind {
    PrivateTransfer,
    PrivateSwap,
    MoneroBridge,
    LowFeePrivate,
    ProofRelay,
    SequencerControl,
    FailoverDrain,
    WatchtowerEvidence,
}

impl EncryptedRelayLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::PrivateSwap => "private_swap",
            Self::MoneroBridge => "monero_bridge",
            Self::LowFeePrivate => "low_fee_private",
            Self::ProofRelay => "proof_relay",
            Self::SequencerControl => "sequencer_control",
            Self::FailoverDrain => "failover_drain",
            Self::WatchtowerEvidence => "watchtower_evidence",
        }
    }

    pub fn privacy_sensitive(self) -> bool {
        matches!(
            self,
            Self::PrivateTransfer
                | Self::PrivateSwap
                | Self::MoneroBridge
                | Self::LowFeePrivate
                | Self::FailoverDrain
        )
    }

    pub fn low_fee(self) -> bool {
        matches!(self, Self::LowFeePrivate | Self::MoneroBridge)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptedRelayLaneStatus {
    Active,
    Standby,
    Congested,
    Draining,
    Retired,
    Quarantined,
}

impl EncryptedRelayLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Standby => "standby",
            Self::Congested => "congested",
            Self::Draining => "draining",
            Self::Retired => "retired",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn accepts_commitments(self) -> bool {
        matches!(self, Self::Active | Self::Standby | Self::Congested)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateMempoolCommitmentStatus {
    Pending,
    Sponsored,
    Batched,
    Propagated,
    Included,
    Expired,
    Rejected,
}

impl PrivateMempoolCommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Sponsored => "sponsored",
            Self::Batched => "batched",
            Self::Propagated => "propagated",
            Self::Included => "included",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn open(self) -> bool {
        matches!(self, Self::Pending | Self::Sponsored)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MicrobatchStatus {
    Open,
    Sealed,
    Propagated,
    Acknowledged,
    Failed,
    Replayed,
}

impl MicrobatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Propagated => "propagated",
            Self::Acknowledged => "acknowledged",
            Self::Failed => "failed",
            Self::Replayed => "replayed",
        }
    }

    pub fn completed(self) -> bool {
        matches!(self, Self::Acknowledged | Self::Failed | Self::Replayed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QosObservationKind {
    RelayRtt,
    AckLatency,
    PacketLoss,
    QueueDepth,
    PrivateLaneDelay,
    LowFeeInclusionDelay,
    FailoverProbe,
}

impl QosObservationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RelayRtt => "relay_rtt",
            Self::AckLatency => "ack_latency",
            Self::PacketLoss => "packet_loss",
            Self::QueueDepth => "queue_depth",
            Self::PrivateLaneDelay => "private_lane_delay",
            Self::LowFeeInclusionDelay => "low_fee_inclusion_delay",
            Self::FailoverProbe => "failover_probe",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceTicketKind {
    LatencySlaMiss,
    Censorship,
    Equivocation,
    InvalidHandshake,
    PrivatePayloadLeak,
    SponsorOvercharge,
    ReplayAttempt,
}

impl EvidenceTicketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LatencySlaMiss => "latency_sla_miss",
            Self::Censorship => "censorship",
            Self::Equivocation => "equivocation",
            Self::InvalidHandshake => "invalid_handshake",
            Self::PrivatePayloadLeak => "private_payload_leak",
            Self::SponsorOvercharge => "sponsor_overcharge",
            Self::ReplayAttempt => "replay_attempt",
        }
    }

    pub fn default_slash_bps(self) -> u64 {
        match self {
            Self::LatencySlaMiss => FAST_RELAY_MESH_DEFAULT_SLASH_LATENCY_BPS,
            Self::Censorship | Self::PrivatePayloadLeak | Self::SponsorOvercharge => {
                FAST_RELAY_MESH_DEFAULT_SLASH_CENSORSHIP_BPS
            }
            Self::Equivocation | Self::InvalidHandshake | Self::ReplayAttempt => {
                FAST_RELAY_MESH_DEFAULT_SLASH_EQUIVOCATION_BPS
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceTicketStatus {
    Pending,
    Accepted,
    Rejected,
    Slashed,
    Expired,
}

impl EvidenceTicketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Active,
    Reserved,
    Spent,
    Exhausted,
    Expired,
    Suspended,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Reserved => "reserved",
            Self::Spent => "spent",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
            Self::Suspended => "suspended",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailoverMode {
    Normal,
    ShadowRelay,
    RegionalDrain,
    SequencerBypass,
    SponsorOnly,
    EmergencyMesh,
}

impl FailoverMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::ShadowRelay => "shadow_relay",
            Self::RegionalDrain => "regional_drain",
            Self::SequencerBypass => "sequencer_bypass",
            Self::SponsorOnly => "sponsor_only",
            Self::EmergencyMesh => "emergency_mesh",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailoverPolicyStatus {
    Armed,
    Triggered,
    Draining,
    Resolved,
    Disabled,
}

impl FailoverPolicyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Armed => "armed",
            Self::Triggered => "triggered",
            Self::Draining => "draining",
            Self::Resolved => "resolved",
            Self::Disabled => "disabled",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastRelayMeshConfig {
    pub config_id: String,
    pub target_gossip_ms: u64,
    pub target_ack_ms: u64,
    pub microbatch_window_ms: u64,
    pub max_route_hops: u64,
    pub commitment_ttl_blocks: u64,
    pub handshake_ttl_blocks: u64,
    pub lane_ttl_blocks: u64,
    pub failover_grace_blocks: u64,
    pub sponsor_ticket_ttl_blocks: u64,
    pub min_peer_score_bps: u64,
    pub max_low_fee_micro_units: u64,
    pub default_sponsor_budget_units: u64,
    pub require_pq_handshake: bool,
    pub require_encrypted_lanes: bool,
    pub allow_payload_roots_only: bool,
    pub enable_private_mempool_commitments: bool,
    pub enable_low_fee_sponsorship: bool,
    pub enable_slashing_tickets: bool,
    pub enable_failover_mesh: bool,
}

impl Default for FastRelayMeshConfig {
    fn default() -> Self {
        let mut config = Self {
            config_id: String::new(),
            target_gossip_ms: FAST_RELAY_MESH_DEFAULT_TARGET_GOSSIP_MS,
            target_ack_ms: FAST_RELAY_MESH_DEFAULT_TARGET_ACK_MS,
            microbatch_window_ms: FAST_RELAY_MESH_DEFAULT_MICROBATCH_WINDOW_MS,
            max_route_hops: FAST_RELAY_MESH_DEFAULT_MAX_ROUTE_HOPS,
            commitment_ttl_blocks: FAST_RELAY_MESH_DEFAULT_COMMITMENT_TTL_BLOCKS,
            handshake_ttl_blocks: FAST_RELAY_MESH_DEFAULT_HANDSHAKE_TTL_BLOCKS,
            lane_ttl_blocks: FAST_RELAY_MESH_DEFAULT_LANE_TTL_BLOCKS,
            failover_grace_blocks: FAST_RELAY_MESH_DEFAULT_FAILOVER_GRACE_BLOCKS,
            sponsor_ticket_ttl_blocks: FAST_RELAY_MESH_DEFAULT_SPONSOR_TTL_BLOCKS,
            min_peer_score_bps: FAST_RELAY_MESH_DEFAULT_MIN_PEER_SCORE_BPS,
            max_low_fee_micro_units: FAST_RELAY_MESH_DEFAULT_MAX_LOW_FEE_MICRO_UNITS,
            default_sponsor_budget_units: FAST_RELAY_MESH_DEFAULT_SPONSOR_BUDGET_UNITS,
            require_pq_handshake: true,
            require_encrypted_lanes: true,
            allow_payload_roots_only: true,
            enable_private_mempool_commitments: true,
            enable_low_fee_sponsorship: true,
            enable_slashing_tickets: true,
            enable_failover_mesh: true,
        };
        config.config_id = fast_relay_mesh_config_id(&config.identity_record());
        config
    }
}

impl FastRelayMeshConfig {
    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "fast_relay_mesh_config_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": FAST_RELAY_MESH_PROTOCOL_VERSION,
            "schema_version": FAST_RELAY_MESH_SCHEMA_VERSION,
            "target_gossip_ms": self.target_gossip_ms,
            "target_ack_ms": self.target_ack_ms,
            "microbatch_window_ms": self.microbatch_window_ms,
            "max_route_hops": self.max_route_hops,
            "commitment_ttl_blocks": self.commitment_ttl_blocks,
            "handshake_ttl_blocks": self.handshake_ttl_blocks,
            "lane_ttl_blocks": self.lane_ttl_blocks,
            "failover_grace_blocks": self.failover_grace_blocks,
            "sponsor_ticket_ttl_blocks": self.sponsor_ticket_ttl_blocks,
            "min_peer_score_bps": self.min_peer_score_bps,
            "max_low_fee_micro_units": self.max_low_fee_micro_units,
            "default_sponsor_budget_units": self.default_sponsor_budget_units,
            "require_pq_handshake": self.require_pq_handshake,
            "require_encrypted_lanes": self.require_encrypted_lanes,
            "allow_payload_roots_only": self.allow_payload_roots_only,
            "enable_private_mempool_commitments": self.enable_private_mempool_commitments,
            "enable_low_fee_sponsorship": self.enable_low_fee_sponsorship,
            "enable_slashing_tickets": self.enable_slashing_tickets,
            "enable_failover_mesh": self.enable_failover_mesh,
        })
    }

    pub fn config_root(&self) -> String {
        fast_relay_mesh_payload_root("FAST-RELAY-MESH-CONFIG", &self.identity_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_relay_mesh_config",
            "chain_id": CHAIN_ID,
            "protocol_version": FAST_RELAY_MESH_PROTOCOL_VERSION,
            "schema_version": FAST_RELAY_MESH_SCHEMA_VERSION,
            "security_model": FAST_RELAY_MESH_SECURITY_MODEL,
            "config_id": self.config_id,
            "target_gossip_ms": self.target_gossip_ms,
            "target_ack_ms": self.target_ack_ms,
            "microbatch_window_ms": self.microbatch_window_ms,
            "max_route_hops": self.max_route_hops,
            "commitment_ttl_blocks": self.commitment_ttl_blocks,
            "handshake_ttl_blocks": self.handshake_ttl_blocks,
            "lane_ttl_blocks": self.lane_ttl_blocks,
            "failover_grace_blocks": self.failover_grace_blocks,
            "sponsor_ticket_ttl_blocks": self.sponsor_ticket_ttl_blocks,
            "min_peer_score_bps": self.min_peer_score_bps,
            "max_low_fee_micro_units": self.max_low_fee_micro_units,
            "default_sponsor_budget_units": self.default_sponsor_budget_units,
            "require_pq_handshake": self.require_pq_handshake,
            "require_encrypted_lanes": self.require_encrypted_lanes,
            "allow_payload_roots_only": self.allow_payload_roots_only,
            "enable_private_mempool_commitments": self.enable_private_mempool_commitments,
            "enable_low_fee_sponsorship": self.enable_low_fee_sponsorship,
            "enable_slashing_tickets": self.enable_slashing_tickets,
            "enable_failover_mesh": self.enable_failover_mesh,
            "config_root": self.config_root(),
        })
    }

    pub fn validate(&self) -> FastRelayMeshResult<String> {
        ensure_non_empty(&self.config_id, "fast relay mesh config id")?;
        ensure_positive(self.target_gossip_ms, "target gossip ms")?;
        ensure_positive(self.target_ack_ms, "target ack ms")?;
        ensure_positive(self.microbatch_window_ms, "microbatch window ms")?;
        ensure_positive(self.max_route_hops, "max route hops")?;
        ensure_positive(self.commitment_ttl_blocks, "commitment ttl blocks")?;
        ensure_positive(self.handshake_ttl_blocks, "handshake ttl blocks")?;
        ensure_positive(self.lane_ttl_blocks, "lane ttl blocks")?;
        ensure_positive(self.sponsor_ticket_ttl_blocks, "sponsor ticket ttl blocks")?;
        ensure_bps(self.min_peer_score_bps, "min peer score bps")?;
        ensure_positive(self.max_low_fee_micro_units, "max low fee micro units")?;
        ensure_positive(
            self.default_sponsor_budget_units,
            "default sponsor budget units",
        )?;
        if self.target_ack_ms < self.target_gossip_ms {
            return Err("fast relay mesh ack target below gossip target".to_string());
        }
        if self.microbatch_window_ms > TARGET_BLOCK_MS {
            return Err("fast relay mesh microbatch window exceeds target block time".to_string());
        }
        let expected = fast_relay_mesh_config_id(&self.identity_record());
        if self.config_id != expected {
            return Err("fast relay mesh config id mismatch".to_string());
        }
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayRegion {
    pub region_id: String,
    pub label: String,
    pub kind: RelayRegionKind,
    pub status: RelayRegionStatus,
    pub priority: u64,
    pub latency_budget_ms: u64,
    pub jurisdiction_codes: BTreeSet<String>,
    pub entry_peer_ids: BTreeSet<String>,
    pub default_lane_ids: BTreeSet<String>,
    pub route_policy_root: String,
}

impl RelayRegion {
    pub fn new(
        label: impl Into<String>,
        kind: RelayRegionKind,
        priority: u64,
        jurisdiction_codes: BTreeSet<String>,
    ) -> FastRelayMeshResult<Self> {
        let label = label.into();
        ensure_non_empty(&label, "relay region label")?;
        ensure_positive(priority, "relay region priority")?;
        let route_policy_root = fast_relay_mesh_payload_root(
            "FAST-RELAY-MESH-REGION-ROUTE-POLICY",
            &json!({
                "label": label,
                "kind": kind.as_str(),
                "priority": priority,
                "latency_budget_ms": kind.default_latency_budget_ms(),
                "jurisdiction_codes": jurisdiction_codes,
            }),
        );
        let region_id = fast_relay_mesh_region_id(&label, kind, &route_policy_root);
        Ok(Self {
            region_id,
            label,
            kind,
            status: RelayRegionStatus::Active,
            priority,
            latency_budget_ms: kind.default_latency_budget_ms(),
            jurisdiction_codes,
            entry_peer_ids: BTreeSet::new(),
            default_lane_ids: BTreeSet::new(),
            route_policy_root,
        })
    }

    pub fn attach_peer(&mut self, peer_id: impl Into<String>) -> FastRelayMeshResult<()> {
        let peer_id = peer_id.into();
        ensure_non_empty(&peer_id, "relay region peer id")?;
        self.entry_peer_ids.insert(peer_id);
        Ok(())
    }

    pub fn attach_lane(&mut self, lane_id: impl Into<String>) -> FastRelayMeshResult<()> {
        let lane_id = lane_id.into();
        ensure_non_empty(&lane_id, "relay region lane id")?;
        self.default_lane_ids.insert(lane_id);
        Ok(())
    }

    pub fn region_root(&self) -> String {
        fast_relay_mesh_payload_root("FAST-RELAY-MESH-REGION", &self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_relay_region",
            "chain_id": CHAIN_ID,
            "protocol_version": FAST_RELAY_MESH_PROTOCOL_VERSION,
            "region_id": self.region_id,
            "label": self.label,
            "region_kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "priority": self.priority,
            "latency_budget_ms": self.latency_budget_ms,
            "jurisdiction_codes": self.jurisdiction_codes,
            "entry_peer_ids": self.entry_peer_ids,
            "default_lane_ids": self.default_lane_ids,
            "route_policy_root": self.route_policy_root,
        })
    }

    pub fn validate(&self) -> FastRelayMeshResult<String> {
        ensure_non_empty(&self.region_id, "relay region id")?;
        ensure_non_empty(&self.label, "relay region label")?;
        ensure_positive(self.priority, "relay region priority")?;
        ensure_positive(self.latency_budget_ms, "relay region latency budget")?;
        ensure_non_empty(&self.route_policy_root, "relay region route policy root")?;
        let expected = fast_relay_mesh_region_id(&self.label, self.kind, &self.route_policy_root);
        if self.region_id != expected {
            return Err("relay region id mismatch".to_string());
        }
        Ok(self.region_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayPeerIdentity {
    pub peer_id: String,
    pub label: String,
    pub role: RelayPeerRole,
    pub status: RelayPeerStatus,
    pub region_id: String,
    pub stake_units: u64,
    pub pq_auth_public_key_commitment: String,
    pub pq_recovery_public_key_commitment: String,
    pub pq_kem_public_key_commitment: String,
    pub route_hint_root: String,
    pub privacy_policy_root: String,
    pub sponsor_account_commitment: Option<String>,
    pub advertised_lane_ids: BTreeSet<String>,
    pub activated_at_height: u64,
    pub last_seen_height: u64,
}

impl RelayPeerIdentity {
    pub fn new(
        label: impl Into<String>,
        role: RelayPeerRole,
        region_id: impl Into<String>,
        stake_units: u64,
        activated_at_height: u64,
    ) -> FastRelayMeshResult<Self> {
        let label = label.into();
        let region_id = region_id.into();
        ensure_non_empty(&label, "relay peer label")?;
        ensure_non_empty(&region_id, "relay peer region id")?;
        let pq_auth_public_key_commitment = fast_relay_mesh_string_root(
            "FAST-RELAY-MESH-PEER-PQ-AUTH-KEY",
            &format!(
                "{}:{}:{}",
                label,
                role.as_str(),
                FAST_RELAY_MESH_PQ_AUTH_SCHEME
            ),
        );
        let pq_recovery_public_key_commitment = fast_relay_mesh_string_root(
            "FAST-RELAY-MESH-PEER-PQ-RECOVERY-KEY",
            &format!(
                "{}:{}:{}",
                label,
                role.as_str(),
                FAST_RELAY_MESH_PQ_RECOVERY_SCHEME
            ),
        );
        let pq_kem_public_key_commitment = fast_relay_mesh_string_root(
            "FAST-RELAY-MESH-PEER-PQ-KEM-KEY",
            &format!(
                "{}:{}:{}",
                label,
                role.as_str(),
                FAST_RELAY_MESH_PQ_KEM_SCHEME
            ),
        );
        let route_hint_root = fast_relay_mesh_payload_root(
            "FAST-RELAY-MESH-PEER-ROUTE-HINT",
            &json!({
                "label": label,
                "role": role.as_str(),
                "region_id": region_id,
                "endpoint_policy": "commitment-only-no-socket-address",
            }),
        );
        let privacy_policy_root = fast_relay_mesh_payload_root(
            "FAST-RELAY-MESH-PEER-PRIVACY-POLICY",
            &json!({
                "label": label,
                "role": role.as_str(),
                "payload_roots_only": true,
                "view_key_disclosure": "delayed-auditor-ticket",
            }),
        );
        let peer_id = fast_relay_mesh_peer_id(
            &label,
            role,
            &region_id,
            &pq_auth_public_key_commitment,
            &pq_kem_public_key_commitment,
        );
        Ok(Self {
            peer_id,
            label,
            role,
            status: RelayPeerStatus::Active,
            region_id,
            stake_units,
            pq_auth_public_key_commitment,
            pq_recovery_public_key_commitment,
            pq_kem_public_key_commitment,
            route_hint_root,
            privacy_policy_root,
            sponsor_account_commitment: None,
            advertised_lane_ids: BTreeSet::new(),
            activated_at_height,
            last_seen_height: activated_at_height,
        })
    }

    pub fn with_sponsor_account(mut self, account_commitment: impl Into<String>) -> Self {
        self.sponsor_account_commitment = Some(account_commitment.into());
        self
    }

    pub fn advertise_lane(&mut self, lane_id: impl Into<String>) -> FastRelayMeshResult<()> {
        let lane_id = lane_id.into();
        ensure_non_empty(&lane_id, "relay peer advertised lane id")?;
        self.advertised_lane_ids.insert(lane_id);
        Ok(())
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.can_relay() && self.activated_at_height <= height
    }

    pub fn peer_root(&self) -> String {
        fast_relay_mesh_payload_root("FAST-RELAY-MESH-PEER", &self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_relay_peer_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": FAST_RELAY_MESH_PROTOCOL_VERSION,
            "peer_id": self.peer_id,
            "label": self.label,
            "role": self.role.as_str(),
            "status": self.status.as_str(),
            "region_id": self.region_id,
            "stake_units": self.stake_units,
            "pq_auth_scheme": FAST_RELAY_MESH_PQ_AUTH_SCHEME,
            "pq_recovery_scheme": FAST_RELAY_MESH_PQ_RECOVERY_SCHEME,
            "pq_kem_scheme": FAST_RELAY_MESH_PQ_KEM_SCHEME,
            "pq_auth_public_key_commitment": self.pq_auth_public_key_commitment,
            "pq_recovery_public_key_commitment": self.pq_recovery_public_key_commitment,
            "pq_kem_public_key_commitment": self.pq_kem_public_key_commitment,
            "route_hint_root": self.route_hint_root,
            "privacy_policy_root": self.privacy_policy_root,
            "sponsor_account_commitment": self.sponsor_account_commitment,
            "advertised_lane_ids": self.advertised_lane_ids,
            "activated_at_height": self.activated_at_height,
            "last_seen_height": self.last_seen_height,
        })
    }

    pub fn validate(&self) -> FastRelayMeshResult<String> {
        ensure_non_empty(&self.peer_id, "relay peer id")?;
        ensure_non_empty(&self.label, "relay peer label")?;
        ensure_non_empty(&self.region_id, "relay peer region id")?;
        ensure_non_empty(
            &self.pq_auth_public_key_commitment,
            "relay peer pq auth key commitment",
        )?;
        ensure_non_empty(
            &self.pq_recovery_public_key_commitment,
            "relay peer pq recovery key commitment",
        )?;
        ensure_non_empty(
            &self.pq_kem_public_key_commitment,
            "relay peer pq kem key commitment",
        )?;
        ensure_non_empty(&self.route_hint_root, "relay peer route hint root")?;
        ensure_non_empty(&self.privacy_policy_root, "relay peer privacy policy root")?;
        if self.last_seen_height < self.activated_at_height {
            return Err("relay peer last seen height before activation".to_string());
        }
        let expected = fast_relay_mesh_peer_id(
            &self.label,
            self.role,
            &self.region_id,
            &self.pq_auth_public_key_commitment,
            &self.pq_kem_public_key_commitment,
        );
        if self.peer_id != expected {
            return Err("relay peer id mismatch".to_string());
        }
        Ok(self.peer_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRelayHandshake {
    pub handshake_id: String,
    pub initiator_peer_id: String,
    pub responder_peer_id: String,
    pub purpose: String,
    pub stage: PqHandshakeStage,
    pub suite: String,
    pub challenge_root: String,
    pub transcript_root: String,
    pub ml_dsa_signature_root: String,
    pub slh_dsa_signature_root: String,
    pub kem_ciphertext_root: String,
    pub shared_secret_commitment: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub authenticated_at_height: Option<u64>,
}

impl PqRelayHandshake {
    pub fn confirmed(
        initiator: &RelayPeerIdentity,
        responder: &RelayPeerIdentity,
        purpose: impl Into<String>,
        created_at_height: u64,
        ttl_blocks: u64,
    ) -> FastRelayMeshResult<Self> {
        let purpose = purpose.into();
        ensure_non_empty(&purpose, "pq relay handshake purpose")?;
        ensure_positive(ttl_blocks, "pq relay handshake ttl blocks")?;
        let challenge_root = fast_relay_mesh_handshake_challenge_root(
            &initiator.peer_id,
            &responder.peer_id,
            &purpose,
            created_at_height,
        );
        let transcript_root = fast_relay_mesh_payload_root(
            "FAST-RELAY-MESH-HANDSHAKE-TRANSCRIPT",
            &json!({
                "initiator_peer_id": initiator.peer_id,
                "responder_peer_id": responder.peer_id,
                "purpose": purpose,
                "challenge_root": challenge_root,
                "suite": FAST_RELAY_MESH_HANDSHAKE_SUITE,
            }),
        );
        let ml_dsa_signature_root = fast_relay_mesh_string_root(
            "FAST-RELAY-MESH-HANDSHAKE-ML-DSA-SIGNATURE",
            &format!(
                "{}:{}:{}",
                initiator.peer_id, responder.peer_id, challenge_root
            ),
        );
        let slh_dsa_signature_root = fast_relay_mesh_string_root(
            "FAST-RELAY-MESH-HANDSHAKE-SLH-DSA-SIGNATURE",
            &format!(
                "{}:{}:{}",
                responder.peer_id, initiator.peer_id, challenge_root
            ),
        );
        let kem_ciphertext_root = fast_relay_mesh_string_root(
            "FAST-RELAY-MESH-HANDSHAKE-KEM-CIPHERTEXT",
            &format!(
                "{}:{}:{}",
                initiator.pq_kem_public_key_commitment,
                responder.pq_kem_public_key_commitment,
                challenge_root
            ),
        );
        let shared_secret_commitment = fast_relay_mesh_string_root(
            "FAST-RELAY-MESH-HANDSHAKE-SHARED-SECRET",
            &format!("{}:{}:{}", transcript_root, kem_ciphertext_root, purpose),
        );
        let expires_at_height = created_at_height.saturating_add(ttl_blocks);
        let handshake_id = fast_relay_mesh_handshake_id(
            &initiator.peer_id,
            &responder.peer_id,
            &purpose,
            &challenge_root,
            created_at_height,
        );
        Ok(Self {
            handshake_id,
            initiator_peer_id: initiator.peer_id.clone(),
            responder_peer_id: responder.peer_id.clone(),
            purpose,
            stage: PqHandshakeStage::Confirmed,
            suite: FAST_RELAY_MESH_HANDSHAKE_SUITE.to_string(),
            challenge_root,
            transcript_root,
            ml_dsa_signature_root,
            slh_dsa_signature_root,
            kem_ciphertext_root,
            shared_secret_commitment,
            created_at_height,
            expires_at_height,
            authenticated_at_height: Some(created_at_height),
        })
    }

    pub fn is_expired(&self, height: u64) -> bool {
        height > self.expires_at_height
    }

    pub fn handshake_root(&self) -> String {
        fast_relay_mesh_payload_root("FAST-RELAY-MESH-HANDSHAKE", &self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_relay_handshake",
            "chain_id": CHAIN_ID,
            "protocol_version": FAST_RELAY_MESH_PROTOCOL_VERSION,
            "handshake_id": self.handshake_id,
            "initiator_peer_id": self.initiator_peer_id,
            "responder_peer_id": self.responder_peer_id,
            "purpose": self.purpose,
            "stage": self.stage.as_str(),
            "suite": self.suite,
            "transcript_scheme": FAST_RELAY_MESH_TRANSCRIPT_SCHEME,
            "challenge_root": self.challenge_root,
            "transcript_root": self.transcript_root,
            "ml_dsa_signature_root": self.ml_dsa_signature_root,
            "slh_dsa_signature_root": self.slh_dsa_signature_root,
            "kem_ciphertext_root": self.kem_ciphertext_root,
            "shared_secret_commitment": self.shared_secret_commitment,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "authenticated_at_height": self.authenticated_at_height,
        })
    }

    pub fn validate(&self) -> FastRelayMeshResult<String> {
        ensure_non_empty(&self.handshake_id, "pq relay handshake id")?;
        ensure_non_empty(&self.initiator_peer_id, "pq relay handshake initiator")?;
        ensure_non_empty(&self.responder_peer_id, "pq relay handshake responder")?;
        ensure_non_empty(&self.purpose, "pq relay handshake purpose")?;
        ensure_non_empty(&self.suite, "pq relay handshake suite")?;
        ensure_non_empty(&self.challenge_root, "pq relay handshake challenge root")?;
        ensure_non_empty(&self.transcript_root, "pq relay handshake transcript root")?;
        ensure_non_empty(
            &self.ml_dsa_signature_root,
            "pq relay handshake ml dsa signature root",
        )?;
        ensure_non_empty(
            &self.slh_dsa_signature_root,
            "pq relay handshake slh dsa signature root",
        )?;
        ensure_non_empty(
            &self.kem_ciphertext_root,
            "pq relay handshake kem ciphertext root",
        )?;
        ensure_non_empty(
            &self.shared_secret_commitment,
            "pq relay handshake shared secret commitment",
        )?;
        if self.initiator_peer_id == self.responder_peer_id {
            return Err("pq relay handshake cannot be self-directed".to_string());
        }
        if self.suite != FAST_RELAY_MESH_HANDSHAKE_SUITE {
            return Err("pq relay handshake suite mismatch".to_string());
        }
        if self.expires_at_height < self.created_at_height {
            return Err("pq relay handshake expires before creation".to_string());
        }
        if self.stage.is_confirmed() && self.authenticated_at_height.is_none() {
            return Err("confirmed pq relay handshake missing authenticated height".to_string());
        }
        let expected = fast_relay_mesh_handshake_id(
            &self.initiator_peer_id,
            &self.responder_peer_id,
            &self.purpose,
            &self.challenge_root,
            self.created_at_height,
        );
        if self.handshake_id != expected {
            return Err("pq relay handshake id mismatch".to_string());
        }
        Ok(self.handshake_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedRelayLane {
    pub lane_id: String,
    pub lane_kind: EncryptedRelayLaneKind,
    pub status: EncryptedRelayLaneStatus,
    pub region_id: String,
    pub ingress_peer_id: String,
    pub egress_peer_ids: BTreeSet<String>,
    pub encryption_scheme: String,
    pub lane_key_root: String,
    pub lane_policy_root: String,
    pub target_latency_ms: u64,
    pub max_fee_micro_units: u64,
    pub max_commitment_bytes: u64,
    pub sponsor_pool_id: Option<String>,
    pub private_commitment_required: bool,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl EncryptedRelayLane {
    pub fn new(
        lane_kind: EncryptedRelayLaneKind,
        region_id: impl Into<String>,
        ingress_peer_id: impl Into<String>,
        egress_peer_ids: BTreeSet<String>,
        target_latency_ms: u64,
        max_fee_micro_units: u64,
        created_at_height: u64,
        ttl_blocks: u64,
    ) -> FastRelayMeshResult<Self> {
        let region_id = region_id.into();
        let ingress_peer_id = ingress_peer_id.into();
        ensure_non_empty(&region_id, "encrypted relay lane region id")?;
        ensure_non_empty(&ingress_peer_id, "encrypted relay lane ingress peer id")?;
        ensure_positive(target_latency_ms, "encrypted relay lane target latency")?;
        ensure_positive(ttl_blocks, "encrypted relay lane ttl blocks")?;
        if egress_peer_ids.is_empty() {
            return Err("encrypted relay lane requires at least one egress peer".to_string());
        }
        let lane_key_root = fast_relay_mesh_payload_root(
            "FAST-RELAY-MESH-LANE-KEY",
            &json!({
                "lane_kind": lane_kind.as_str(),
                "region_id": region_id,
                "ingress_peer_id": ingress_peer_id,
                "egress_peer_ids": egress_peer_ids,
                "created_at_height": created_at_height,
                "encryption_scheme": FAST_RELAY_MESH_LANE_ENCRYPTION_SCHEME,
            }),
        );
        let lane_policy_root = fast_relay_mesh_payload_root(
            "FAST-RELAY-MESH-LANE-POLICY",
            &json!({
                "lane_kind": lane_kind.as_str(),
                "privacy_sensitive": lane_kind.privacy_sensitive(),
                "low_fee": lane_kind.low_fee(),
                "payload_roots_only": true,
                "target_latency_ms": target_latency_ms,
                "max_fee_micro_units": max_fee_micro_units,
            }),
        );
        let lane_id = fast_relay_mesh_lane_id(
            lane_kind,
            &region_id,
            &ingress_peer_id,
            &lane_key_root,
            &lane_policy_root,
        );
        Ok(Self {
            lane_id,
            lane_kind,
            status: EncryptedRelayLaneStatus::Active,
            region_id,
            ingress_peer_id,
            egress_peer_ids,
            encryption_scheme: FAST_RELAY_MESH_LANE_ENCRYPTION_SCHEME.to_string(),
            lane_key_root,
            lane_policy_root,
            target_latency_ms,
            max_fee_micro_units,
            max_commitment_bytes: 8_192,
            sponsor_pool_id: None,
            private_commitment_required: lane_kind.privacy_sensitive(),
            created_at_height,
            expires_at_height: created_at_height.saturating_add(ttl_blocks),
        })
    }

    pub fn with_sponsor_pool(mut self, sponsor_pool_id: impl Into<String>) -> Self {
        self.sponsor_pool_id = Some(sponsor_pool_id.into());
        self
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.accepts_commitments()
            && self.created_at_height <= height
            && height <= self.expires_at_height
    }

    pub fn lane_root(&self) -> String {
        fast_relay_mesh_payload_root("FAST-RELAY-MESH-LANE", &self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_relay_lane",
            "chain_id": CHAIN_ID,
            "protocol_version": FAST_RELAY_MESH_PROTOCOL_VERSION,
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind.as_str(),
            "status": self.status.as_str(),
            "region_id": self.region_id,
            "ingress_peer_id": self.ingress_peer_id,
            "egress_peer_ids": self.egress_peer_ids,
            "encryption_scheme": self.encryption_scheme,
            "lane_key_root": self.lane_key_root,
            "lane_policy_root": self.lane_policy_root,
            "target_latency_ms": self.target_latency_ms,
            "max_fee_micro_units": self.max_fee_micro_units,
            "max_commitment_bytes": self.max_commitment_bytes,
            "sponsor_pool_id": self.sponsor_pool_id,
            "private_commitment_required": self.private_commitment_required,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn validate(&self) -> FastRelayMeshResult<String> {
        ensure_non_empty(&self.lane_id, "encrypted relay lane id")?;
        ensure_non_empty(&self.region_id, "encrypted relay lane region id")?;
        ensure_non_empty(
            &self.ingress_peer_id,
            "encrypted relay lane ingress peer id",
        )?;
        ensure_non_empty(&self.encryption_scheme, "encrypted relay lane scheme")?;
        ensure_non_empty(&self.lane_key_root, "encrypted relay lane key root")?;
        ensure_non_empty(&self.lane_policy_root, "encrypted relay lane policy root")?;
        ensure_positive(
            self.target_latency_ms,
            "encrypted relay lane target latency",
        )?;
        ensure_positive(
            self.max_commitment_bytes,
            "encrypted relay lane max commitment bytes",
        )?;
        if self.encryption_scheme != FAST_RELAY_MESH_LANE_ENCRYPTION_SCHEME {
            return Err("encrypted relay lane scheme mismatch".to_string());
        }
        if self.egress_peer_ids.is_empty() {
            return Err("encrypted relay lane missing egress peers".to_string());
        }
        if self.expires_at_height < self.created_at_height {
            return Err("encrypted relay lane expires before creation".to_string());
        }
        let expected = fast_relay_mesh_lane_id(
            self.lane_kind,
            &self.region_id,
            &self.ingress_peer_id,
            &self.lane_key_root,
            &self.lane_policy_root,
        );
        if self.lane_id != expected {
            return Err("encrypted relay lane id mismatch".to_string());
        }
        Ok(self.lane_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateMempoolCommitment {
    pub commitment_id: String,
    pub lane_id: String,
    pub submitter_commitment: String,
    pub payload_kind: String,
    pub payload_ciphertext_root: String,
    pub fee_commitment_root: String,
    pub nullifier_root: String,
    pub entropy_commitment: String,
    pub fee_micro_units: u64,
    pub payload_size_bytes: u64,
    pub qos_class: String,
    pub status: PrivateMempoolCommitmentStatus,
    pub sponsorship_ticket_id: Option<String>,
    pub received_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivateMempoolCommitment {
    pub fn new(
        lane_id: impl Into<String>,
        submitter_commitment: impl Into<String>,
        payload_kind: impl Into<String>,
        encrypted_payload: &Value,
        fee_micro_units: u64,
        payload_size_bytes: u64,
        qos_class: impl Into<String>,
        sponsorship_ticket_id: Option<String>,
        nonce: u64,
        received_at_height: u64,
        ttl_blocks: u64,
    ) -> FastRelayMeshResult<Self> {
        let lane_id = lane_id.into();
        let submitter_commitment = submitter_commitment.into();
        let payload_kind = payload_kind.into();
        let qos_class = qos_class.into();
        ensure_non_empty(&lane_id, "private mempool commitment lane id")?;
        ensure_non_empty(
            &submitter_commitment,
            "private mempool commitment submitter",
        )?;
        ensure_non_empty(&payload_kind, "private mempool commitment payload kind")?;
        ensure_non_empty(&qos_class, "private mempool commitment qos class")?;
        ensure_positive(
            payload_size_bytes,
            "private mempool commitment payload size",
        )?;
        ensure_positive(ttl_blocks, "private mempool commitment ttl blocks")?;
        let payload_ciphertext_root =
            fast_relay_mesh_payload_root("FAST-RELAY-MESH-PAYLOAD-CIPHERTEXT", encrypted_payload);
        let fee_commitment_root = domain_hash(
            "FAST-RELAY-MESH-FEE-COMMITMENT",
            &[
                HashPart::Str(FAST_RELAY_MESH_PROTOCOL_VERSION),
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&lane_id),
                HashPart::Str(&submitter_commitment),
                HashPart::Int(fee_micro_units as i128),
                HashPart::Int(nonce as i128),
            ],
            32,
        );
        let entropy_commitment = fast_relay_mesh_string_root(
            "FAST-RELAY-MESH-COMMITMENT-ENTROPY",
            &format!(
                "{}:{}:{}:{}",
                lane_id, submitter_commitment, payload_kind, nonce
            ),
        );
        let nullifier_root = fast_relay_mesh_nullifier(
            "FAST-RELAY-MESH-COMMITMENT-NULLIFIER",
            &[
                &lane_id,
                &submitter_commitment,
                &payload_ciphertext_root,
                &nonce.to_string(),
            ],
        );
        let commitment_id = fast_relay_mesh_private_mempool_commitment_id(
            &lane_id,
            &submitter_commitment,
            &payload_ciphertext_root,
            &fee_commitment_root,
            nonce,
        );
        let status = if sponsorship_ticket_id.is_some() {
            PrivateMempoolCommitmentStatus::Sponsored
        } else {
            PrivateMempoolCommitmentStatus::Pending
        };
        Ok(Self {
            commitment_id,
            lane_id,
            submitter_commitment,
            payload_kind,
            payload_ciphertext_root,
            fee_commitment_root,
            nullifier_root,
            entropy_commitment,
            fee_micro_units,
            payload_size_bytes,
            qos_class,
            status,
            sponsorship_ticket_id,
            received_at_height,
            expires_at_height: received_at_height.saturating_add(ttl_blocks),
        })
    }

    pub fn is_expired(&self, height: u64) -> bool {
        height > self.expires_at_height
    }

    pub fn commitment_root(&self) -> String {
        fast_relay_mesh_payload_root(
            "FAST-RELAY-MESH-PRIVATE-MEMPOOL-COMMITMENT",
            &self.public_record(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_mempool_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": FAST_RELAY_MESH_PROTOCOL_VERSION,
            "private_mempool_policy": FAST_RELAY_MESH_PRIVATE_MEMPOOL_POLICY,
            "commitment_id": self.commitment_id,
            "lane_id": self.lane_id,
            "submitter_commitment": self.submitter_commitment,
            "payload_kind": self.payload_kind,
            "payload_ciphertext_root": self.payload_ciphertext_root,
            "fee_commitment_root": self.fee_commitment_root,
            "nullifier_root": self.nullifier_root,
            "entropy_commitment": self.entropy_commitment,
            "fee_micro_units": self.fee_micro_units,
            "payload_size_bytes": self.payload_size_bytes,
            "qos_class": self.qos_class,
            "status": self.status.as_str(),
            "sponsorship_ticket_id": self.sponsorship_ticket_id,
            "received_at_height": self.received_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn validate(&self) -> FastRelayMeshResult<String> {
        ensure_non_empty(&self.commitment_id, "private mempool commitment id")?;
        ensure_non_empty(&self.lane_id, "private mempool commitment lane id")?;
        ensure_non_empty(
            &self.submitter_commitment,
            "private mempool commitment submitter",
        )?;
        ensure_non_empty(
            &self.payload_kind,
            "private mempool commitment payload kind",
        )?;
        ensure_non_empty(
            &self.payload_ciphertext_root,
            "private mempool payload ciphertext root",
        )?;
        ensure_non_empty(
            &self.fee_commitment_root,
            "private mempool fee commitment root",
        )?;
        ensure_non_empty(&self.nullifier_root, "private mempool nullifier root")?;
        ensure_non_empty(
            &self.entropy_commitment,
            "private mempool entropy commitment",
        )?;
        ensure_positive(self.payload_size_bytes, "private mempool payload size")?;
        ensure_non_empty(&self.qos_class, "private mempool qos class")?;
        if self.expires_at_height < self.received_at_height {
            return Err("private mempool commitment expires before receipt".to_string());
        }
        Ok(self.commitment_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicrobatchPropagation {
    pub batch_id: String,
    pub lane_id: String,
    pub source_peer_id: String,
    pub sequence: u64,
    pub commitment_ids: Vec<String>,
    pub commitment_root: String,
    pub payload_root: String,
    pub route_peer_ids: Vec<String>,
    pub region_path: Vec<String>,
    pub first_sent_ms: u64,
    pub ack_deadline_ms: u64,
    pub observed_ack_ms: Option<u64>,
    pub status: MicrobatchStatus,
}

impl MicrobatchPropagation {
    pub fn new(
        lane_id: impl Into<String>,
        source_peer_id: impl Into<String>,
        sequence: u64,
        commitments: &[PrivateMempoolCommitment],
        route_peer_ids: Vec<String>,
        region_path: Vec<String>,
        first_sent_ms: u64,
        target_ack_ms: u64,
    ) -> FastRelayMeshResult<Self> {
        let lane_id = lane_id.into();
        let source_peer_id = source_peer_id.into();
        ensure_non_empty(&lane_id, "microbatch lane id")?;
        ensure_non_empty(&source_peer_id, "microbatch source peer id")?;
        ensure_positive(target_ack_ms, "microbatch target ack ms")?;
        if commitments.is_empty() {
            return Err("microbatch requires commitments".to_string());
        }
        if route_peer_ids.is_empty() {
            return Err("microbatch requires route peers".to_string());
        }
        if region_path.is_empty() {
            return Err("microbatch requires region path".to_string());
        }
        let commitment_ids = commitments
            .iter()
            .map(|commitment| commitment.commitment_id.clone())
            .collect::<Vec<_>>();
        let commitment_leaves = commitments
            .iter()
            .map(PrivateMempoolCommitment::public_record)
            .collect::<Vec<_>>();
        let payload_leaves = commitments
            .iter()
            .map(|commitment| Value::String(commitment.payload_ciphertext_root.clone()))
            .collect::<Vec<_>>();
        let commitment_root =
            merkle_root("FAST-RELAY-MESH-MICROBATCH-COMMITMENTS", &commitment_leaves);
        let payload_root = merkle_root("FAST-RELAY-MESH-MICROBATCH-PAYLOADS", &payload_leaves);
        let batch_id = fast_relay_mesh_microbatch_id(
            &lane_id,
            &source_peer_id,
            sequence,
            &commitment_root,
            first_sent_ms,
        );
        Ok(Self {
            batch_id,
            lane_id,
            source_peer_id,
            sequence,
            commitment_ids,
            commitment_root,
            payload_root,
            route_peer_ids,
            region_path,
            first_sent_ms,
            ack_deadline_ms: first_sent_ms.saturating_add(target_ack_ms),
            observed_ack_ms: None,
            status: MicrobatchStatus::Propagated,
        })
    }

    pub fn acknowledge(&mut self, observed_ack_ms: u64) {
        self.observed_ack_ms = Some(observed_ack_ms);
        self.status = if observed_ack_ms <= self.ack_deadline_ms {
            MicrobatchStatus::Acknowledged
        } else {
            MicrobatchStatus::Failed
        };
    }

    pub fn propagation_root(&self) -> String {
        fast_relay_mesh_payload_root("FAST-RELAY-MESH-MICROBATCH", &self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "microbatch_propagation",
            "chain_id": CHAIN_ID,
            "protocol_version": FAST_RELAY_MESH_PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "source_peer_id": self.source_peer_id,
            "sequence": self.sequence,
            "commitment_ids": self.commitment_ids,
            "commitment_root": self.commitment_root,
            "payload_root": self.payload_root,
            "route_peer_ids": self.route_peer_ids,
            "region_path": self.region_path,
            "first_sent_ms": self.first_sent_ms,
            "ack_deadline_ms": self.ack_deadline_ms,
            "observed_ack_ms": self.observed_ack_ms,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> FastRelayMeshResult<String> {
        ensure_non_empty(&self.batch_id, "microbatch id")?;
        ensure_non_empty(&self.lane_id, "microbatch lane id")?;
        ensure_non_empty(&self.source_peer_id, "microbatch source peer id")?;
        ensure_non_empty(&self.commitment_root, "microbatch commitment root")?;
        ensure_non_empty(&self.payload_root, "microbatch payload root")?;
        if self.commitment_ids.is_empty() {
            return Err("microbatch missing commitments".to_string());
        }
        if self.route_peer_ids.is_empty() {
            return Err("microbatch missing route peers".to_string());
        }
        if self.region_path.is_empty() {
            return Err("microbatch missing region path".to_string());
        }
        if self.ack_deadline_ms < self.first_sent_ms {
            return Err("microbatch ack deadline before send".to_string());
        }
        let expected = fast_relay_mesh_microbatch_id(
            &self.lane_id,
            &self.source_peer_id,
            self.sequence,
            &self.commitment_root,
            self.first_sent_ms,
        );
        if self.batch_id != expected {
            return Err("microbatch id mismatch".to_string());
        }
        Ok(self.propagation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QosLatencyObservation {
    pub observation_id: String,
    pub observation_kind: QosObservationKind,
    pub peer_id: String,
    pub region_id: String,
    pub lane_id: Option<String>,
    pub reporter_peer_id: String,
    pub observed_latency_ms: u64,
    pub jitter_ms: u64,
    pub loss_bps: u64,
    pub queue_depth: u64,
    pub sample_count: u64,
    pub measured_at_height: u64,
    pub evidence_root: String,
}

impl QosLatencyObservation {
    pub fn new(
        observation_kind: QosObservationKind,
        peer_id: impl Into<String>,
        region_id: impl Into<String>,
        lane_id: Option<String>,
        reporter_peer_id: impl Into<String>,
        observed_latency_ms: u64,
        jitter_ms: u64,
        loss_bps: u64,
        queue_depth: u64,
        sample_count: u64,
        measured_at_height: u64,
        evidence: &Value,
    ) -> FastRelayMeshResult<Self> {
        let peer_id = peer_id.into();
        let region_id = region_id.into();
        let reporter_peer_id = reporter_peer_id.into();
        ensure_non_empty(&peer_id, "qos observation peer id")?;
        ensure_non_empty(&region_id, "qos observation region id")?;
        ensure_non_empty(&reporter_peer_id, "qos observation reporter peer id")?;
        ensure_bps(loss_bps, "qos observation loss bps")?;
        ensure_positive(sample_count, "qos observation sample count")?;
        let evidence_root = fast_relay_mesh_payload_root("FAST-RELAY-MESH-QOS-EVIDENCE", evidence);
        let observation_id = fast_relay_mesh_qos_observation_id(
            observation_kind,
            &peer_id,
            lane_id.as_deref(),
            &evidence_root,
            measured_at_height,
        );
        Ok(Self {
            observation_id,
            observation_kind,
            peer_id,
            region_id,
            lane_id,
            reporter_peer_id,
            observed_latency_ms,
            jitter_ms,
            loss_bps,
            queue_depth,
            sample_count,
            measured_at_height,
            evidence_root,
        })
    }

    pub fn score_delta_bps(&self, target_latency_ms: u64) -> i64 {
        let latency_component = if self.observed_latency_ms > target_latency_ms {
            -(((self.observed_latency_ms - target_latency_ms).min(1_000) * 5) as i64)
        } else {
            150
        };
        let jitter_penalty = (self.jitter_ms.min(500) * 2) as i64;
        let loss_penalty = (self.loss_bps.min(FAST_RELAY_MESH_MAX_BPS) / 2) as i64;
        latency_component
            .saturating_sub(jitter_penalty)
            .saturating_sub(loss_penalty)
    }

    pub fn observation_root(&self) -> String {
        fast_relay_mesh_payload_root("FAST-RELAY-MESH-QOS-OBSERVATION", &self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "qos_latency_observation",
            "chain_id": CHAIN_ID,
            "protocol_version": FAST_RELAY_MESH_PROTOCOL_VERSION,
            "observation_id": self.observation_id,
            "observation_kind": self.observation_kind.as_str(),
            "peer_id": self.peer_id,
            "region_id": self.region_id,
            "lane_id": self.lane_id,
            "reporter_peer_id": self.reporter_peer_id,
            "observed_latency_ms": self.observed_latency_ms,
            "jitter_ms": self.jitter_ms,
            "loss_bps": self.loss_bps,
            "queue_depth": self.queue_depth,
            "sample_count": self.sample_count,
            "measured_at_height": self.measured_at_height,
            "evidence_root": self.evidence_root,
        })
    }

    pub fn validate(&self) -> FastRelayMeshResult<String> {
        ensure_non_empty(&self.observation_id, "qos observation id")?;
        ensure_non_empty(&self.peer_id, "qos observation peer id")?;
        ensure_non_empty(&self.region_id, "qos observation region id")?;
        ensure_non_empty(&self.reporter_peer_id, "qos observation reporter peer id")?;
        ensure_non_empty(&self.evidence_root, "qos observation evidence root")?;
        ensure_bps(self.loss_bps, "qos observation loss bps")?;
        ensure_positive(self.sample_count, "qos observation sample count")?;
        let expected = fast_relay_mesh_qos_observation_id(
            self.observation_kind,
            &self.peer_id,
            self.lane_id.as_deref(),
            &self.evidence_root,
            self.measured_at_height,
        );
        if self.observation_id != expected {
            return Err("qos observation id mismatch".to_string());
        }
        Ok(self.observation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerScoreSnapshot {
    pub score_id: String,
    pub peer_id: String,
    pub uptime_score_bps: u64,
    pub latency_score_bps: u64,
    pub privacy_score_bps: u64,
    pub pq_auth_score_bps: u64,
    pub sponsorship_score_bps: u64,
    pub slash_penalty_bps: u64,
    pub qos_observation_root: String,
    pub last_update_height: u64,
}

impl PeerScoreSnapshot {
    pub fn baseline(peer: &RelayPeerIdentity, height: u64) -> Self {
        let base = FAST_RELAY_MESH_MAX_BPS;
        let bonus = peer.role.default_score_bonus_bps();
        let qos_observation_root = merkle_root("FAST-RELAY-MESH-EMPTY-QOS", &[]);
        let score_id = fast_relay_mesh_peer_score_id(&peer.peer_id, &qos_observation_root, height);
        Self {
            score_id,
            peer_id: peer.peer_id.clone(),
            uptime_score_bps: base,
            latency_score_bps: base.saturating_sub(500).saturating_add(bonus).min(base),
            privacy_score_bps: base,
            pq_auth_score_bps: base,
            sponsorship_score_bps: if peer.role == RelayPeerRole::Sponsor {
                base
            } else {
                base.saturating_sub(1_000)
            },
            slash_penalty_bps: 0,
            qos_observation_root,
            last_update_height: height,
        }
    }

    pub fn apply_observation(
        &mut self,
        observation: &QosLatencyObservation,
        target_latency_ms: u64,
    ) {
        let delta = observation.score_delta_bps(target_latency_ms);
        if delta >= 0 {
            self.latency_score_bps = self
                .latency_score_bps
                .saturating_add(delta as u64)
                .min(FAST_RELAY_MESH_MAX_BPS);
        } else {
            self.latency_score_bps = self.latency_score_bps.saturating_sub(delta.unsigned_abs());
        }
        if observation.loss_bps > 0 {
            self.uptime_score_bps = self
                .uptime_score_bps
                .saturating_sub(observation.loss_bps / 2);
        }
        self.qos_observation_root = observation.observation_root();
        self.last_update_height = observation.measured_at_height;
        self.score_id = fast_relay_mesh_peer_score_id(
            &self.peer_id,
            &self.qos_observation_root,
            self.last_update_height,
        );
    }

    pub fn effective_score_bps(&self) -> u64 {
        let gross = self
            .uptime_score_bps
            .saturating_add(self.latency_score_bps)
            .saturating_add(self.privacy_score_bps)
            .saturating_add(self.pq_auth_score_bps)
            .saturating_add(self.sponsorship_score_bps)
            / 5;
        gross.saturating_sub(self.slash_penalty_bps)
    }

    pub fn score_root(&self) -> String {
        fast_relay_mesh_payload_root("FAST-RELAY-MESH-PEER-SCORE", &self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "peer_score_snapshot",
            "chain_id": CHAIN_ID,
            "protocol_version": FAST_RELAY_MESH_PROTOCOL_VERSION,
            "score_id": self.score_id,
            "peer_id": self.peer_id,
            "uptime_score_bps": self.uptime_score_bps,
            "latency_score_bps": self.latency_score_bps,
            "privacy_score_bps": self.privacy_score_bps,
            "pq_auth_score_bps": self.pq_auth_score_bps,
            "sponsorship_score_bps": self.sponsorship_score_bps,
            "slash_penalty_bps": self.slash_penalty_bps,
            "effective_score_bps": self.effective_score_bps(),
            "qos_observation_root": self.qos_observation_root,
            "last_update_height": self.last_update_height,
        })
    }

    pub fn validate(&self) -> FastRelayMeshResult<String> {
        ensure_non_empty(&self.score_id, "peer score id")?;
        ensure_non_empty(&self.peer_id, "peer score peer id")?;
        ensure_bps(self.uptime_score_bps, "peer uptime score")?;
        ensure_bps(self.latency_score_bps, "peer latency score")?;
        ensure_bps(self.privacy_score_bps, "peer privacy score")?;
        ensure_bps(self.pq_auth_score_bps, "peer pq auth score")?;
        ensure_bps(self.sponsorship_score_bps, "peer sponsorship score")?;
        ensure_bps(self.slash_penalty_bps, "peer slash penalty")?;
        ensure_non_empty(&self.qos_observation_root, "peer score qos root")?;
        let expected = fast_relay_mesh_peer_score_id(
            &self.peer_id,
            &self.qos_observation_root,
            self.last_update_height,
        );
        if self.score_id != expected {
            return Err("peer score id mismatch".to_string());
        }
        Ok(self.score_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingEvidenceTicket {
    pub evidence_id: String,
    pub evidence_kind: EvidenceTicketKind,
    pub status: EvidenceTicketStatus,
    pub accused_peer_id: String,
    pub reporter_peer_id: String,
    pub related_object_id: String,
    pub first_record_root: String,
    pub second_record_root: String,
    pub observation_root: String,
    pub severity_bps: u64,
    pub slash_units: u64,
    pub discovered_at_height: u64,
    pub expires_at_height: u64,
}

impl SlashingEvidenceTicket {
    pub fn new(
        evidence_kind: EvidenceTicketKind,
        accused_peer_id: impl Into<String>,
        reporter_peer_id: impl Into<String>,
        related_object_id: impl Into<String>,
        first_record: &Value,
        second_record: &Value,
        observation_root: impl Into<String>,
        stake_units: u64,
        discovered_at_height: u64,
        ttl_blocks: u64,
    ) -> FastRelayMeshResult<Self> {
        let accused_peer_id = accused_peer_id.into();
        let reporter_peer_id = reporter_peer_id.into();
        let related_object_id = related_object_id.into();
        let observation_root = observation_root.into();
        ensure_non_empty(&accused_peer_id, "slashing evidence accused peer")?;
        ensure_non_empty(&reporter_peer_id, "slashing evidence reporter peer")?;
        ensure_non_empty(&related_object_id, "slashing evidence related object")?;
        ensure_non_empty(&observation_root, "slashing evidence observation root")?;
        ensure_positive(ttl_blocks, "slashing evidence ttl blocks")?;
        let first_record_root =
            fast_relay_mesh_payload_root("FAST-RELAY-MESH-EVIDENCE-FIRST", first_record);
        let second_record_root =
            fast_relay_mesh_payload_root("FAST-RELAY-MESH-EVIDENCE-SECOND", second_record);
        let severity_bps = evidence_kind.default_slash_bps();
        let slash_units = stake_units.saturating_mul(severity_bps) / FAST_RELAY_MESH_MAX_BPS;
        let evidence_id = fast_relay_mesh_slashing_evidence_id(
            evidence_kind,
            &accused_peer_id,
            &reporter_peer_id,
            &related_object_id,
            &first_record_root,
            &second_record_root,
            discovered_at_height,
        );
        Ok(Self {
            evidence_id,
            evidence_kind,
            status: EvidenceTicketStatus::Pending,
            accused_peer_id,
            reporter_peer_id,
            related_object_id,
            first_record_root,
            second_record_root,
            observation_root,
            severity_bps,
            slash_units,
            discovered_at_height,
            expires_at_height: discovered_at_height.saturating_add(ttl_blocks),
        })
    }

    pub fn evidence_root(&self) -> String {
        fast_relay_mesh_payload_root("FAST-RELAY-MESH-SLASHING-EVIDENCE", &self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "slashing_evidence_ticket",
            "chain_id": CHAIN_ID,
            "protocol_version": FAST_RELAY_MESH_PROTOCOL_VERSION,
            "evidence_id": self.evidence_id,
            "evidence_kind": self.evidence_kind.as_str(),
            "status": self.status.as_str(),
            "accused_peer_id": self.accused_peer_id,
            "reporter_peer_id": self.reporter_peer_id,
            "related_object_id": self.related_object_id,
            "first_record_root": self.first_record_root,
            "second_record_root": self.second_record_root,
            "observation_root": self.observation_root,
            "severity_bps": self.severity_bps,
            "slash_units": self.slash_units,
            "discovered_at_height": self.discovered_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn validate(&self) -> FastRelayMeshResult<String> {
        ensure_non_empty(&self.evidence_id, "slashing evidence id")?;
        ensure_non_empty(&self.accused_peer_id, "slashing evidence accused peer")?;
        ensure_non_empty(&self.reporter_peer_id, "slashing evidence reporter peer")?;
        ensure_non_empty(&self.related_object_id, "slashing evidence related object")?;
        ensure_non_empty(&self.first_record_root, "slashing evidence first root")?;
        ensure_non_empty(&self.second_record_root, "slashing evidence second root")?;
        ensure_non_empty(&self.observation_root, "slashing evidence observation root")?;
        ensure_bps(self.severity_bps, "slashing evidence severity")?;
        if self.expires_at_height < self.discovered_at_height {
            return Err("slashing evidence expires before discovery".to_string());
        }
        let expected = fast_relay_mesh_slashing_evidence_id(
            self.evidence_kind,
            &self.accused_peer_id,
            &self.reporter_peer_id,
            &self.related_object_id,
            &self.first_record_root,
            &self.second_record_root,
            self.discovered_at_height,
        );
        if self.evidence_id != expected {
            return Err("slashing evidence id mismatch".to_string());
        }
        Ok(self.evidence_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeRelaySponsorshipPool {
    pub pool_id: String,
    pub label: String,
    pub sponsor_peer_id: String,
    pub lane_id: String,
    pub asset_id: String,
    pub budget_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub max_fee_micro_units: u64,
    pub beneficiary_policy_root: String,
    pub status: SponsorshipStatus,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl LowFeeRelaySponsorshipPool {
    pub fn new(
        label: impl Into<String>,
        sponsor_peer_id: impl Into<String>,
        lane_id: impl Into<String>,
        asset_id: impl Into<String>,
        budget_units: u64,
        max_fee_micro_units: u64,
        beneficiary_policy: &Value,
        created_at_height: u64,
        ttl_blocks: u64,
    ) -> FastRelayMeshResult<Self> {
        let label = label.into();
        let sponsor_peer_id = sponsor_peer_id.into();
        let lane_id = lane_id.into();
        let asset_id = asset_id.into();
        ensure_non_empty(&label, "sponsorship pool label")?;
        ensure_non_empty(&sponsor_peer_id, "sponsorship pool sponsor peer")?;
        ensure_non_empty(&lane_id, "sponsorship pool lane id")?;
        ensure_non_empty(&asset_id, "sponsorship pool asset id")?;
        ensure_positive(budget_units, "sponsorship pool budget")?;
        ensure_positive(max_fee_micro_units, "sponsorship pool max fee")?;
        ensure_positive(ttl_blocks, "sponsorship pool ttl blocks")?;
        let beneficiary_policy_root = fast_relay_mesh_payload_root(
            "FAST-RELAY-MESH-SPONSOR-BENEFICIARY-POLICY",
            beneficiary_policy,
        );
        let pool_id = fast_relay_mesh_sponsorship_pool_id(
            &label,
            &sponsor_peer_id,
            &lane_id,
            &asset_id,
            &beneficiary_policy_root,
        );
        Ok(Self {
            pool_id,
            label,
            sponsor_peer_id,
            lane_id,
            asset_id,
            budget_units,
            reserved_units: 0,
            spent_units: 0,
            max_fee_micro_units,
            beneficiary_policy_root,
            status: SponsorshipStatus::Active,
            created_at_height,
            expires_at_height: created_at_height.saturating_add(ttl_blocks),
        })
    }

    pub fn available_units(&self) -> u64 {
        self.budget_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
    }

    pub fn reserve(&mut self, units: u64) -> FastRelayMeshResult<()> {
        ensure_positive(units, "sponsorship reserve units")?;
        if !self.status.usable() {
            return Err("sponsorship pool is not usable".to_string());
        }
        if units > self.available_units() {
            return Err("sponsorship pool insufficient available units".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_add(units);
        if self.available_units() == 0 {
            self.status = SponsorshipStatus::Exhausted;
        }
        Ok(())
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.usable() && self.created_at_height <= height && height <= self.expires_at_height
    }

    pub fn pool_root(&self) -> String {
        fast_relay_mesh_payload_root(
            "FAST-RELAY-MESH-LOW-FEE-SPONSORSHIP-POOL",
            &self.public_record(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_relay_sponsorship_pool",
            "chain_id": CHAIN_ID,
            "protocol_version": FAST_RELAY_MESH_PROTOCOL_VERSION,
            "policy_version": FAST_RELAY_MESH_LOW_FEE_POLICY_VERSION,
            "pool_id": self.pool_id,
            "label": self.label,
            "sponsor_peer_id": self.sponsor_peer_id,
            "lane_id": self.lane_id,
            "asset_id": self.asset_id,
            "budget_units": self.budget_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "available_units": self.available_units(),
            "max_fee_micro_units": self.max_fee_micro_units,
            "beneficiary_policy_root": self.beneficiary_policy_root,
            "status": self.status.as_str(),
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn validate(&self) -> FastRelayMeshResult<String> {
        ensure_non_empty(&self.pool_id, "sponsorship pool id")?;
        ensure_non_empty(&self.label, "sponsorship pool label")?;
        ensure_non_empty(&self.sponsor_peer_id, "sponsorship pool sponsor peer")?;
        ensure_non_empty(&self.lane_id, "sponsorship pool lane id")?;
        ensure_non_empty(&self.asset_id, "sponsorship pool asset id")?;
        ensure_positive(self.budget_units, "sponsorship pool budget")?;
        ensure_positive(self.max_fee_micro_units, "sponsorship pool max fee")?;
        ensure_non_empty(
            &self.beneficiary_policy_root,
            "sponsorship pool beneficiary policy root",
        )?;
        if self.reserved_units.saturating_add(self.spent_units) > self.budget_units {
            return Err("sponsorship pool overspent budget".to_string());
        }
        if self.expires_at_height < self.created_at_height {
            return Err("sponsorship pool expires before creation".to_string());
        }
        let expected = fast_relay_mesh_sponsorship_pool_id(
            &self.label,
            &self.sponsor_peer_id,
            &self.lane_id,
            &self.asset_id,
            &self.beneficiary_policy_root,
        );
        if self.pool_id != expected {
            return Err("sponsorship pool id mismatch".to_string());
        }
        Ok(self.pool_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeRelaySponsorshipTicket {
    pub ticket_id: String,
    pub pool_id: String,
    pub beneficiary_commitment: String,
    pub lane_id: String,
    pub commitment_hint_root: String,
    pub max_fee_micro_units: u64,
    pub reserved_units: u64,
    pub status: SponsorshipStatus,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl LowFeeRelaySponsorshipTicket {
    pub fn new(
        pool: &LowFeeRelaySponsorshipPool,
        beneficiary_commitment: impl Into<String>,
        commitment_hint: &Value,
        max_fee_micro_units: u64,
        reserved_units: u64,
        issued_at_height: u64,
        ttl_blocks: u64,
    ) -> FastRelayMeshResult<Self> {
        let beneficiary_commitment = beneficiary_commitment.into();
        ensure_non_empty(
            &beneficiary_commitment,
            "sponsorship ticket beneficiary commitment",
        )?;
        ensure_positive(max_fee_micro_units, "sponsorship ticket max fee")?;
        ensure_positive(reserved_units, "sponsorship ticket reserved units")?;
        ensure_positive(ttl_blocks, "sponsorship ticket ttl blocks")?;
        if max_fee_micro_units > pool.max_fee_micro_units {
            return Err("sponsorship ticket fee exceeds pool cap".to_string());
        }
        let commitment_hint_root = fast_relay_mesh_payload_root(
            "FAST-RELAY-MESH-SPONSOR-COMMITMENT-HINT",
            commitment_hint,
        );
        let ticket_id = fast_relay_mesh_sponsorship_ticket_id(
            &pool.pool_id,
            &beneficiary_commitment,
            &commitment_hint_root,
            issued_at_height,
        );
        Ok(Self {
            ticket_id,
            pool_id: pool.pool_id.clone(),
            beneficiary_commitment,
            lane_id: pool.lane_id.clone(),
            commitment_hint_root,
            max_fee_micro_units,
            reserved_units,
            status: SponsorshipStatus::Reserved,
            issued_at_height,
            expires_at_height: issued_at_height.saturating_add(ttl_blocks),
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.usable() && self.issued_at_height <= height && height <= self.expires_at_height
    }

    pub fn ticket_root(&self) -> String {
        fast_relay_mesh_payload_root(
            "FAST-RELAY-MESH-LOW-FEE-SPONSORSHIP-TICKET",
            &self.public_record(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_relay_sponsorship_ticket",
            "chain_id": CHAIN_ID,
            "protocol_version": FAST_RELAY_MESH_PROTOCOL_VERSION,
            "policy_version": FAST_RELAY_MESH_LOW_FEE_POLICY_VERSION,
            "ticket_id": self.ticket_id,
            "pool_id": self.pool_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "lane_id": self.lane_id,
            "commitment_hint_root": self.commitment_hint_root,
            "max_fee_micro_units": self.max_fee_micro_units,
            "reserved_units": self.reserved_units,
            "status": self.status.as_str(),
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn validate(&self) -> FastRelayMeshResult<String> {
        ensure_non_empty(&self.ticket_id, "sponsorship ticket id")?;
        ensure_non_empty(&self.pool_id, "sponsorship ticket pool id")?;
        ensure_non_empty(
            &self.beneficiary_commitment,
            "sponsorship ticket beneficiary",
        )?;
        ensure_non_empty(&self.lane_id, "sponsorship ticket lane id")?;
        ensure_non_empty(
            &self.commitment_hint_root,
            "sponsorship ticket commitment hint root",
        )?;
        ensure_positive(self.max_fee_micro_units, "sponsorship ticket max fee")?;
        ensure_positive(self.reserved_units, "sponsorship ticket reserved units")?;
        if self.expires_at_height < self.issued_at_height {
            return Err("sponsorship ticket expires before issue".to_string());
        }
        let expected = fast_relay_mesh_sponsorship_ticket_id(
            &self.pool_id,
            &self.beneficiary_commitment,
            &self.commitment_hint_root,
            self.issued_at_height,
        );
        if self.ticket_id != expected {
            return Err("sponsorship ticket id mismatch".to_string());
        }
        Ok(self.ticket_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayFailoverPolicy {
    pub policy_id: String,
    pub label: String,
    pub mode: FailoverMode,
    pub status: FailoverPolicyStatus,
    pub primary_peer_id: String,
    pub standby_peer_ids: BTreeSet<String>,
    pub watched_lane_ids: BTreeSet<String>,
    pub trigger_latency_ms: u64,
    pub trigger_missed_ack_count: u64,
    pub private_mempool_root: String,
    pub low_fee_lane_root: String,
    pub last_trigger_height: Option<u64>,
    pub created_at_height: u64,
}

impl RelayFailoverPolicy {
    pub fn new(
        label: impl Into<String>,
        mode: FailoverMode,
        primary_peer_id: impl Into<String>,
        standby_peer_ids: BTreeSet<String>,
        watched_lane_ids: BTreeSet<String>,
        trigger_latency_ms: u64,
        trigger_missed_ack_count: u64,
        private_mempool_root: impl Into<String>,
        low_fee_lane_root: impl Into<String>,
        created_at_height: u64,
    ) -> FastRelayMeshResult<Self> {
        let label = label.into();
        let primary_peer_id = primary_peer_id.into();
        let private_mempool_root = private_mempool_root.into();
        let low_fee_lane_root = low_fee_lane_root.into();
        ensure_non_empty(&label, "relay failover policy label")?;
        ensure_non_empty(&primary_peer_id, "relay failover primary peer")?;
        ensure_non_empty(&private_mempool_root, "relay failover private mempool root")?;
        ensure_non_empty(&low_fee_lane_root, "relay failover low fee root")?;
        ensure_positive(trigger_latency_ms, "relay failover trigger latency")?;
        ensure_positive(
            trigger_missed_ack_count,
            "relay failover missed ack threshold",
        )?;
        if standby_peer_ids.is_empty() {
            return Err("relay failover policy requires standby peers".to_string());
        }
        if watched_lane_ids.is_empty() {
            return Err("relay failover policy requires watched lanes".to_string());
        }
        let policy_id = fast_relay_mesh_failover_policy_id(
            &label,
            mode,
            &primary_peer_id,
            &standby_peer_ids,
            &watched_lane_ids,
            created_at_height,
        );
        Ok(Self {
            policy_id,
            label,
            mode,
            status: FailoverPolicyStatus::Armed,
            primary_peer_id,
            standby_peer_ids,
            watched_lane_ids,
            trigger_latency_ms,
            trigger_missed_ack_count,
            private_mempool_root,
            low_fee_lane_root,
            last_trigger_height: None,
            created_at_height,
        })
    }

    pub fn policy_root(&self) -> String {
        fast_relay_mesh_payload_root("FAST-RELAY-MESH-FAILOVER-POLICY", &self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "relay_failover_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": FAST_RELAY_MESH_PROTOCOL_VERSION,
            "policy_version": FAST_RELAY_MESH_FAILOVER_POLICY_VERSION,
            "policy_id": self.policy_id,
            "label": self.label,
            "mode": self.mode.as_str(),
            "status": self.status.as_str(),
            "primary_peer_id": self.primary_peer_id,
            "standby_peer_ids": self.standby_peer_ids,
            "watched_lane_ids": self.watched_lane_ids,
            "trigger_latency_ms": self.trigger_latency_ms,
            "trigger_missed_ack_count": self.trigger_missed_ack_count,
            "private_mempool_root": self.private_mempool_root,
            "low_fee_lane_root": self.low_fee_lane_root,
            "last_trigger_height": self.last_trigger_height,
            "created_at_height": self.created_at_height,
        })
    }

    pub fn validate(&self) -> FastRelayMeshResult<String> {
        ensure_non_empty(&self.policy_id, "relay failover policy id")?;
        ensure_non_empty(&self.label, "relay failover policy label")?;
        ensure_non_empty(&self.primary_peer_id, "relay failover primary peer")?;
        ensure_non_empty(&self.private_mempool_root, "relay failover private root")?;
        ensure_non_empty(&self.low_fee_lane_root, "relay failover low fee root")?;
        ensure_positive(self.trigger_latency_ms, "relay failover trigger latency")?;
        ensure_positive(
            self.trigger_missed_ack_count,
            "relay failover missed ack threshold",
        )?;
        if self.standby_peer_ids.is_empty() {
            return Err("relay failover policy missing standby peers".to_string());
        }
        if self.watched_lane_ids.is_empty() {
            return Err("relay failover policy missing watched lanes".to_string());
        }
        let expected = fast_relay_mesh_failover_policy_id(
            &self.label,
            self.mode,
            &self.primary_peer_id,
            &self.standby_peer_ids,
            &self.watched_lane_ids,
            self.created_at_height,
        );
        if self.policy_id != expected {
            return Err("relay failover policy id mismatch".to_string());
        }
        Ok(self.policy_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastRelayMeshPublicRecord {
    pub record_id: String,
    pub object_kind: String,
    pub object_id: String,
    pub payload_root: String,
    pub redaction_root: String,
    pub published_at_height: u64,
}

impl FastRelayMeshPublicRecord {
    pub fn new(
        object_kind: impl Into<String>,
        object_id: impl Into<String>,
        payload: &Value,
        redaction: &Value,
        published_at_height: u64,
    ) -> FastRelayMeshResult<Self> {
        let object_kind = object_kind.into();
        let object_id = object_id.into();
        ensure_non_empty(&object_kind, "fast relay public record object kind")?;
        ensure_non_empty(&object_id, "fast relay public record object id")?;
        let payload_root =
            fast_relay_mesh_payload_root("FAST-RELAY-MESH-PUBLIC-RECORD-PAYLOAD", payload);
        let redaction_root =
            fast_relay_mesh_payload_root("FAST-RELAY-MESH-PUBLIC-RECORD-REDACTION", redaction);
        let record_id = fast_relay_mesh_public_record_id(
            &object_kind,
            &object_id,
            &payload_root,
            &redaction_root,
            published_at_height,
        );
        Ok(Self {
            record_id,
            object_kind,
            object_id,
            payload_root,
            redaction_root,
            published_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        fast_relay_mesh_payload_root("FAST-RELAY-MESH-PUBLIC-RECORD", &self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_relay_mesh_public_record",
            "chain_id": CHAIN_ID,
            "protocol_version": FAST_RELAY_MESH_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "object_kind": self.object_kind,
            "object_id": self.object_id,
            "payload_root": self.payload_root,
            "redaction_root": self.redaction_root,
            "published_at_height": self.published_at_height,
        })
    }

    pub fn validate(&self) -> FastRelayMeshResult<String> {
        ensure_non_empty(&self.record_id, "fast relay public record id")?;
        ensure_non_empty(&self.object_kind, "fast relay public record object kind")?;
        ensure_non_empty(&self.object_id, "fast relay public record object id")?;
        ensure_non_empty(&self.payload_root, "fast relay public record payload root")?;
        ensure_non_empty(
            &self.redaction_root,
            "fast relay public record redaction root",
        )?;
        let expected = fast_relay_mesh_public_record_id(
            &self.object_kind,
            &self.object_id,
            &self.payload_root,
            &self.redaction_root,
            self.published_at_height,
        );
        if self.record_id != expected {
            return Err("fast relay public record id mismatch".to_string());
        }
        Ok(self.record_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastRelayMeshRoots {
    pub config_root: String,
    pub region_root: String,
    pub peer_root: String,
    pub handshake_root: String,
    pub lane_root: String,
    pub commitment_root: String,
    pub microbatch_root: String,
    pub qos_observation_root: String,
    pub peer_score_root: String,
    pub slashing_evidence_root: String,
    pub sponsorship_pool_root: String,
    pub sponsorship_ticket_root: String,
    pub failover_policy_root: String,
    pub replay_nullifier_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl FastRelayMeshRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_relay_mesh_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": FAST_RELAY_MESH_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "region_root": self.region_root,
            "peer_root": self.peer_root,
            "handshake_root": self.handshake_root,
            "lane_root": self.lane_root,
            "commitment_root": self.commitment_root,
            "microbatch_root": self.microbatch_root,
            "qos_observation_root": self.qos_observation_root,
            "peer_score_root": self.peer_score_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "sponsorship_pool_root": self.sponsorship_pool_root,
            "sponsorship_ticket_root": self.sponsorship_ticket_root,
            "failover_policy_root": self.failover_policy_root,
            "replay_nullifier_root": self.replay_nullifier_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastRelayMeshCounters {
    pub height: u64,
    pub region_count: u64,
    pub active_region_count: u64,
    pub peer_count: u64,
    pub active_peer_count: u64,
    pub handshake_count: u64,
    pub confirmed_handshake_count: u64,
    pub lane_count: u64,
    pub active_lane_count: u64,
    pub commitment_count: u64,
    pub pending_commitment_count: u64,
    pub sponsored_commitment_count: u64,
    pub propagated_commitment_count: u64,
    pub expired_commitment_count: u64,
    pub microbatch_count: u64,
    pub acknowledged_microbatch_count: u64,
    pub failed_microbatch_count: u64,
    pub qos_observation_count: u64,
    pub high_latency_observation_count: u64,
    pub peer_score_count: u64,
    pub slashing_evidence_count: u64,
    pub accepted_slashing_evidence_count: u64,
    pub sponsorship_pool_count: u64,
    pub active_sponsorship_pool_count: u64,
    pub sponsorship_ticket_count: u64,
    pub active_sponsorship_ticket_count: u64,
    pub failover_policy_count: u64,
    pub armed_failover_policy_count: u64,
    pub replay_nullifier_count: u64,
    pub public_record_count: u64,
    pub total_payload_bytes: u64,
    pub total_fee_micro_units: u64,
    pub sponsored_reserved_units: u64,
    pub sponsored_spent_units: u64,
}

impl FastRelayMeshCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_relay_mesh_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": FAST_RELAY_MESH_PROTOCOL_VERSION,
            "height": self.height,
            "region_count": self.region_count,
            "active_region_count": self.active_region_count,
            "peer_count": self.peer_count,
            "active_peer_count": self.active_peer_count,
            "handshake_count": self.handshake_count,
            "confirmed_handshake_count": self.confirmed_handshake_count,
            "lane_count": self.lane_count,
            "active_lane_count": self.active_lane_count,
            "commitment_count": self.commitment_count,
            "pending_commitment_count": self.pending_commitment_count,
            "sponsored_commitment_count": self.sponsored_commitment_count,
            "propagated_commitment_count": self.propagated_commitment_count,
            "expired_commitment_count": self.expired_commitment_count,
            "microbatch_count": self.microbatch_count,
            "acknowledged_microbatch_count": self.acknowledged_microbatch_count,
            "failed_microbatch_count": self.failed_microbatch_count,
            "qos_observation_count": self.qos_observation_count,
            "high_latency_observation_count": self.high_latency_observation_count,
            "peer_score_count": self.peer_score_count,
            "slashing_evidence_count": self.slashing_evidence_count,
            "accepted_slashing_evidence_count": self.accepted_slashing_evidence_count,
            "sponsorship_pool_count": self.sponsorship_pool_count,
            "active_sponsorship_pool_count": self.active_sponsorship_pool_count,
            "sponsorship_ticket_count": self.sponsorship_ticket_count,
            "active_sponsorship_ticket_count": self.active_sponsorship_ticket_count,
            "failover_policy_count": self.failover_policy_count,
            "armed_failover_policy_count": self.armed_failover_policy_count,
            "replay_nullifier_count": self.replay_nullifier_count,
            "public_record_count": self.public_record_count,
            "total_payload_bytes": self.total_payload_bytes,
            "total_fee_micro_units": self.total_fee_micro_units,
            "sponsored_reserved_units": self.sponsored_reserved_units,
            "sponsored_spent_units": self.sponsored_spent_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastRelayMeshState {
    pub height: u64,
    pub mesh_label: String,
    pub config: FastRelayMeshConfig,
    pub regions: BTreeMap<String, RelayRegion>,
    pub peers: BTreeMap<String, RelayPeerIdentity>,
    pub handshakes: BTreeMap<String, PqRelayHandshake>,
    pub lanes: BTreeMap<String, EncryptedRelayLane>,
    pub private_mempool_commitments: BTreeMap<String, PrivateMempoolCommitment>,
    pub microbatches: BTreeMap<String, MicrobatchPropagation>,
    pub qos_observations: BTreeMap<String, QosLatencyObservation>,
    pub peer_scores: BTreeMap<String, PeerScoreSnapshot>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidenceTicket>,
    pub sponsorship_pools: BTreeMap<String, LowFeeRelaySponsorshipPool>,
    pub sponsorship_tickets: BTreeMap<String, LowFeeRelaySponsorshipTicket>,
    pub failover_policies: BTreeMap<String, RelayFailoverPolicy>,
    pub consumed_replay_nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, FastRelayMeshPublicRecord>,
}

impl FastRelayMeshState {
    pub fn new(
        mesh_label: impl Into<String>,
        config: FastRelayMeshConfig,
    ) -> FastRelayMeshResult<Self> {
        config.validate()?;
        let mesh_label = mesh_label.into();
        ensure_non_empty(&mesh_label, "fast relay mesh label")?;
        Ok(Self {
            height: 0,
            mesh_label,
            config,
            regions: BTreeMap::new(),
            peers: BTreeMap::new(),
            handshakes: BTreeMap::new(),
            lanes: BTreeMap::new(),
            private_mempool_commitments: BTreeMap::new(),
            microbatches: BTreeMap::new(),
            qos_observations: BTreeMap::new(),
            peer_scores: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            sponsorship_pools: BTreeMap::new(),
            sponsorship_tickets: BTreeMap::new(),
            failover_policies: BTreeMap::new(),
            consumed_replay_nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        })
    }

    pub fn devnet() -> FastRelayMeshResult<Self> {
        let mut state = Self::new(FAST_RELAY_MESH_DEVNET_LABEL, FastRelayMeshConfig::default())?;
        state.set_height(24);

        let na_region = RelayRegion::new(
            "devnet-na-east",
            RelayRegionKind::NorthAmericaEast,
            1_000,
            btree_set(["US"]),
        )?;
        let eu_region = RelayRegion::new(
            "devnet-eu-west",
            RelayRegionKind::EuropeWest,
            900,
            btree_set(["IE", "DE"]),
        )?;
        let monero_region = RelayRegion::new(
            "devnet-monero-edge",
            RelayRegionKind::MoneroEdge,
            850,
            btree_set(["US", "CA"]),
        )?;
        let na_region_id = state.insert_region(na_region)?;
        let eu_region_id = state.insert_region(eu_region)?;
        let monero_region_id = state.insert_region(monero_region)?;

        let sequencer = RelayPeerIdentity::new(
            "devnet-relay-sequencer",
            RelayPeerRole::Sequencer,
            na_region_id.clone(),
            1_000_000,
            1,
        )?;
        let edge_na = RelayPeerIdentity::new(
            "devnet-relay-edge-na",
            RelayPeerRole::EdgeRelay,
            na_region_id.clone(),
            450_000,
            1,
        )?;
        let edge_eu = RelayPeerIdentity::new(
            "devnet-relay-edge-eu",
            RelayPeerRole::EdgeRelay,
            eu_region_id.clone(),
            420_000,
            1,
        )?;
        let private_mempool = RelayPeerIdentity::new(
            "devnet-private-mempool",
            RelayPeerRole::PrivateMempool,
            eu_region_id.clone(),
            700_000,
            1,
        )?;
        let monero_gateway = RelayPeerIdentity::new(
            "devnet-monero-gateway",
            RelayPeerRole::MoneroGateway,
            monero_region_id.clone(),
            620_000,
            1,
        )?;
        let watchtower = RelayPeerIdentity::new(
            "devnet-relay-watchtower",
            RelayPeerRole::Watchtower,
            na_region_id.clone(),
            300_000,
            1,
        )?;
        let sponsor = RelayPeerIdentity::new(
            "devnet-low-fee-sponsor",
            RelayPeerRole::Sponsor,
            na_region_id.clone(),
            500_000,
            1,
        )?
        .with_sponsor_account("devnet-sponsor-account-commitment");

        let sequencer_id = state.insert_peer(sequencer.clone())?;
        let edge_na_id = state.insert_peer(edge_na.clone())?;
        let edge_eu_id = state.insert_peer(edge_eu.clone())?;
        let private_mempool_id = state.insert_peer(private_mempool.clone())?;
        let monero_gateway_id = state.insert_peer(monero_gateway.clone())?;
        let watchtower_id = state.insert_peer(watchtower.clone())?;
        let sponsor_id = state.insert_peer(sponsor.clone())?;

        for (initiator, responder, purpose) in [
            (&edge_na, &sequencer, "private_fast_path"),
            (&edge_eu, &sequencer, "eu_private_fast_path"),
            (&private_mempool, &sequencer, "sealed_private_mempool"),
            (&monero_gateway, &sequencer, "monero_bridge_exit_lane"),
            (&watchtower, &sequencer, "qos_and_evidence_stream"),
            (&sponsor, &sequencer, "low_fee_sponsor_attestation"),
        ] {
            let handshake = PqRelayHandshake::confirmed(
                initiator,
                responder,
                purpose,
                state.height,
                state.config.handshake_ttl_blocks,
            )?;
            state.insert_handshake(handshake)?;
        }

        let private_lane = EncryptedRelayLane::new(
            EncryptedRelayLaneKind::PrivateTransfer,
            eu_region_id.clone(),
            private_mempool_id.clone(),
            btree_set([sequencer_id.as_str(), edge_na_id.as_str()]),
            140,
            9_000,
            state.height,
            state.config.lane_ttl_blocks,
        )?;
        let private_lane_id = state.insert_lane(private_lane)?;

        let bridge_lane = EncryptedRelayLane::new(
            EncryptedRelayLaneKind::MoneroBridge,
            monero_region_id.clone(),
            monero_gateway_id.clone(),
            btree_set([sequencer_id.as_str(), edge_eu_id.as_str()]),
            180,
            state.config.max_low_fee_micro_units,
            state.height,
            state.config.lane_ttl_blocks,
        )?;
        let bridge_lane_id = state.insert_lane(bridge_lane)?;

        let failover_lane = EncryptedRelayLane::new(
            EncryptedRelayLaneKind::FailoverDrain,
            na_region_id.clone(),
            edge_na_id.clone(),
            btree_set([
                sequencer_id.as_str(),
                edge_eu_id.as_str(),
                watchtower_id.as_str(),
            ]),
            220,
            12_000,
            state.height,
            state.config.lane_ttl_blocks,
        )?;
        let failover_lane_id = state.insert_lane(failover_lane)?;

        let sponsor_pool = LowFeeRelaySponsorshipPool::new(
            "devnet-low-fee-bridge-pool",
            sponsor_id.clone(),
            bridge_lane_id.clone(),
            "asset:wxmr",
            state.config.default_sponsor_budget_units,
            state.config.max_low_fee_micro_units,
            &json!({
                "beneficiaries": "private-wallet-commitments",
                "monero_bridge": true,
                "max_claims_per_block": 128,
            }),
            state.height,
            state.config.sponsor_ticket_ttl_blocks,
        )?;
        let sponsor_pool_id = state.register_sponsorship_pool(sponsor_pool)?;
        if let Some(lane) = state.lanes.get_mut(&bridge_lane_id) {
            lane.sponsor_pool_id = Some(sponsor_pool_id.clone());
        }

        let ticket_id = state.reserve_sponsorship(
            &sponsor_pool_id,
            "beneficiary:devnet-bob",
            &json!({
                "intent": "low_fee_monero_bridge_exit",
                "amount_bucket": "small",
                "payload": "root-only",
            }),
            2_000,
            1_500,
        )?;

        let alice = PrivateMempoolCommitment::new(
            private_lane_id.clone(),
            "submitter:devnet-alice",
            "private_transfer",
            &json!({
                "ciphertext": "devnet-alice-private-transfer",
                "note_commitment": "note:alice:001",
                "recipient_view_tag": "encrypted",
            }),
            7_500,
            2_048,
            "interactive",
            None,
            1,
            state.height,
            state.config.commitment_ttl_blocks,
        )?;
        let bob = PrivateMempoolCommitment::new(
            bridge_lane_id.clone(),
            "beneficiary:devnet-bob",
            "monero_bridge_exit",
            &json!({
                "ciphertext": "devnet-bob-bridge-exit",
                "destination_hash": "monero-destination-hash",
                "fee_bucket": "low",
            }),
            1_900,
            2_560,
            "low_fee_bridge",
            Some(ticket_id.clone()),
            2,
            state.height,
            state.config.commitment_ttl_blocks,
        )?;
        let carol = PrivateMempoolCommitment::new(
            private_lane_id.clone(),
            "submitter:devnet-carol",
            "private_swap",
            &json!({
                "ciphertext": "devnet-carol-private-swap",
                "pair": "wxmr-usdd",
                "amount_bucket": "medium",
            }),
            8_000,
            2_304,
            "interactive",
            None,
            3,
            state.height,
            state.config.commitment_ttl_blocks,
        )?;

        let alice_id = state.submit_commitment(alice)?;
        let bob_id = state.submit_commitment(bob)?;
        let carol_id = state.submit_commitment(carol)?;

        let mut private_batch = state.seal_microbatch(
            &private_lane_id,
            &private_mempool_id,
            vec![alice_id.clone(), carol_id.clone()],
            vec![
                private_mempool_id.clone(),
                edge_na_id.clone(),
                sequencer_id.clone(),
            ],
            vec![eu_region_id.clone(), na_region_id.clone()],
            1_700_000_001_000,
        )?;
        private_batch.acknowledge(1_700_000_001_135);
        state
            .microbatches
            .insert(private_batch.batch_id.clone(), private_batch);

        let mut bridge_batch = state.seal_microbatch(
            &bridge_lane_id,
            &monero_gateway_id,
            vec![bob_id.clone()],
            vec![
                monero_gateway_id.clone(),
                edge_eu_id.clone(),
                sequencer_id.clone(),
            ],
            vec![
                monero_region_id.clone(),
                eu_region_id.clone(),
                na_region_id.clone(),
            ],
            1_700_000_001_080,
        )?;
        bridge_batch.acknowledge(1_700_000_001_260);
        state
            .microbatches
            .insert(bridge_batch.batch_id.clone(), bridge_batch);

        let qos_private = QosLatencyObservation::new(
            QosObservationKind::AckLatency,
            private_mempool_id.clone(),
            eu_region_id.clone(),
            Some(private_lane_id.clone()),
            watchtower_id.clone(),
            135,
            12,
            0,
            8,
            12,
            state.height,
            &json!({
                "batch": "private",
                "ack_ms": 135,
                "route": ["eu", "na"],
            }),
        )?;
        let qos_bridge = QosLatencyObservation::new(
            QosObservationKind::LowFeeInclusionDelay,
            monero_gateway_id.clone(),
            monero_region_id.clone(),
            Some(bridge_lane_id.clone()),
            watchtower_id.clone(),
            180,
            18,
            0,
            4,
            6,
            state.height,
            &json!({
                "batch": "bridge",
                "ack_ms": 180,
                "sponsored": true,
            }),
        )?;
        let qos_slow = QosLatencyObservation::new(
            QosObservationKind::FailoverProbe,
            edge_eu_id.clone(),
            eu_region_id.clone(),
            Some(failover_lane_id.clone()),
            watchtower_id.clone(),
            410,
            40,
            25,
            19,
            5,
            state.height,
            &json!({
                "probe": "shadow relay",
                "missed_ack": 1,
            }),
        )?;
        let qos_slow_root = qos_slow.observation_root();
        state.record_qos_observation(qos_private)?;
        state.record_qos_observation(qos_bridge)?;
        state.record_qos_observation(qos_slow)?;

        let mut evidence = SlashingEvidenceTicket::new(
            EvidenceTicketKind::LatencySlaMiss,
            edge_eu_id.clone(),
            watchtower_id.clone(),
            failover_lane_id.clone(),
            &json!({ "ack_ms": 220, "status": "target" }),
            &json!({ "ack_ms": 410, "status": "observed" }),
            qos_slow_root,
            edge_eu.stake_units,
            state.height,
            128,
        )?;
        evidence.status = EvidenceTicketStatus::Accepted;
        state.insert_slashing_evidence(evidence)?;

        let failover_policy = RelayFailoverPolicy::new(
            "devnet-private-lane-failover",
            FailoverMode::ShadowRelay,
            private_mempool_id.clone(),
            btree_set([edge_na_id.as_str(), edge_eu_id.as_str()]),
            btree_set([
                private_lane_id.as_str(),
                bridge_lane_id.as_str(),
                failover_lane_id.as_str(),
            ]),
            260,
            2,
            state.private_mempool_commitment_root(),
            state.sponsorship_ticket_root(),
            state.height,
        )?;
        state.insert_failover_policy(failover_policy)?;

        for (kind, object_id, payload) in [
            (
                "lane",
                private_lane_id.as_str(),
                state
                    .lanes
                    .get(&private_lane_id)
                    .map(EncryptedRelayLane::public_record),
            ),
            (
                "lane",
                bridge_lane_id.as_str(),
                state
                    .lanes
                    .get(&bridge_lane_id)
                    .map(EncryptedRelayLane::public_record),
            ),
            (
                "commitment",
                alice_id.as_str(),
                state
                    .private_mempool_commitments
                    .get(&alice_id)
                    .map(PrivateMempoolCommitment::public_record),
            ),
        ] {
            let payload = payload
                .ok_or_else(|| "devnet fast relay public record source missing".to_string())?;
            state.publish_public_record(
                kind,
                object_id,
                &payload,
                &json!({
                    "redact_payload_ciphertext": true,
                    "retain_roots": true,
                }),
            )?;
        }

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        self.expire_records();
    }

    pub fn insert_region(&mut self, region: RelayRegion) -> FastRelayMeshResult<String> {
        region.validate()?;
        let region_id = region.region_id.clone();
        self.regions.insert(region_id.clone(), region);
        Ok(region_id)
    }

    pub fn insert_peer(&mut self, peer: RelayPeerIdentity) -> FastRelayMeshResult<String> {
        peer.validate()?;
        if !self.regions.contains_key(&peer.region_id) {
            return Err("relay peer references unknown region".to_string());
        }
        let peer_id = peer.peer_id.clone();
        if let Some(region) = self.regions.get_mut(&peer.region_id) {
            region.attach_peer(peer_id.clone())?;
        }
        self.peer_scores.insert(
            peer_id.clone(),
            PeerScoreSnapshot::baseline(&peer, self.height),
        );
        self.peers.insert(peer_id.clone(), peer);
        Ok(peer_id)
    }

    pub fn insert_handshake(
        &mut self,
        mut handshake: PqRelayHandshake,
    ) -> FastRelayMeshResult<String> {
        handshake.validate()?;
        if !self.peers.contains_key(&handshake.initiator_peer_id) {
            return Err("pq relay handshake references unknown initiator".to_string());
        }
        if !self.peers.contains_key(&handshake.responder_peer_id) {
            return Err("pq relay handshake references unknown responder".to_string());
        }
        if handshake.is_expired(self.height) {
            handshake.stage = PqHandshakeStage::Expired;
        }
        let handshake_id = handshake.handshake_id.clone();
        self.handshakes.insert(handshake_id.clone(), handshake);
        Ok(handshake_id)
    }

    pub fn insert_lane(&mut self, lane: EncryptedRelayLane) -> FastRelayMeshResult<String> {
        lane.validate()?;
        if !self.regions.contains_key(&lane.region_id) {
            return Err("encrypted relay lane references unknown region".to_string());
        }
        if !self.peers.contains_key(&lane.ingress_peer_id) {
            return Err("encrypted relay lane references unknown ingress peer".to_string());
        }
        for peer_id in &lane.egress_peer_ids {
            if !self.peers.contains_key(peer_id) {
                return Err("encrypted relay lane references unknown egress peer".to_string());
            }
        }
        let lane_id = lane.lane_id.clone();
        if let Some(region) = self.regions.get_mut(&lane.region_id) {
            region.attach_lane(lane_id.clone())?;
        }
        if let Some(peer) = self.peers.get_mut(&lane.ingress_peer_id) {
            peer.advertise_lane(lane_id.clone())?;
        }
        for peer_id in &lane.egress_peer_ids {
            if let Some(peer) = self.peers.get_mut(peer_id) {
                peer.advertise_lane(lane_id.clone())?;
            }
        }
        self.lanes.insert(lane_id.clone(), lane);
        Ok(lane_id)
    }

    pub fn register_sponsorship_pool(
        &mut self,
        pool: LowFeeRelaySponsorshipPool,
    ) -> FastRelayMeshResult<String> {
        pool.validate()?;
        if !self.config.enable_low_fee_sponsorship {
            return Err("low fee sponsorship disabled".to_string());
        }
        if !self.peers.contains_key(&pool.sponsor_peer_id) {
            return Err("sponsorship pool references unknown sponsor peer".to_string());
        }
        if !self.lanes.contains_key(&pool.lane_id) {
            return Err("sponsorship pool references unknown lane".to_string());
        }
        let pool_id = pool.pool_id.clone();
        self.sponsorship_pools.insert(pool_id.clone(), pool);
        Ok(pool_id)
    }

    pub fn reserve_sponsorship(
        &mut self,
        pool_id: &str,
        beneficiary_commitment: &str,
        commitment_hint: &Value,
        max_fee_micro_units: u64,
        reserved_units: u64,
    ) -> FastRelayMeshResult<String> {
        let pool = self
            .sponsorship_pools
            .get(pool_id)
            .cloned()
            .ok_or_else(|| "unknown sponsorship pool".to_string())?;
        if !pool.active_at(self.height) {
            return Err("sponsorship pool is not active".to_string());
        }
        let ticket = LowFeeRelaySponsorshipTicket::new(
            &pool,
            beneficiary_commitment,
            commitment_hint,
            max_fee_micro_units,
            reserved_units,
            self.height,
            self.config.sponsor_ticket_ttl_blocks,
        )?;
        let stored_pool = self
            .sponsorship_pools
            .get_mut(pool_id)
            .ok_or_else(|| "unknown sponsorship pool".to_string())?;
        stored_pool.reserve(reserved_units)?;
        let ticket_id = ticket.ticket_id.clone();
        self.sponsorship_tickets.insert(ticket_id.clone(), ticket);
        Ok(ticket_id)
    }

    pub fn submit_commitment(
        &mut self,
        mut commitment: PrivateMempoolCommitment,
    ) -> FastRelayMeshResult<String> {
        commitment.validate()?;
        if !self.config.enable_private_mempool_commitments {
            return Err("private mempool commitments disabled".to_string());
        }
        let lane = self
            .lanes
            .get(&commitment.lane_id)
            .ok_or_else(|| "private mempool commitment references unknown lane".to_string())?;
        if !lane.active_at(self.height) {
            return Err("private mempool commitment lane is not active".to_string());
        }
        if commitment.payload_size_bytes > lane.max_commitment_bytes {
            return Err("private mempool commitment exceeds lane byte limit".to_string());
        }
        if commitment.fee_micro_units > lane.max_fee_micro_units {
            return Err("private mempool commitment fee exceeds lane max".to_string());
        }
        if self
            .consumed_replay_nullifiers
            .contains(&commitment.nullifier_root)
        {
            return Err("private mempool commitment replay nullifier already consumed".to_string());
        }
        if let Some(ticket_id) = &commitment.sponsorship_ticket_id {
            let ticket = self.sponsorship_tickets.get(ticket_id).ok_or_else(|| {
                "private mempool commitment references unknown sponsor ticket".to_string()
            })?;
            if !ticket.active_at(self.height) {
                return Err("private mempool commitment sponsor ticket inactive".to_string());
            }
            if ticket.lane_id != commitment.lane_id {
                return Err("private mempool commitment sponsor ticket lane mismatch".to_string());
            }
            if commitment.fee_micro_units > ticket.max_fee_micro_units {
                return Err("private mempool commitment fee exceeds sponsor ticket".to_string());
            }
            commitment.status = PrivateMempoolCommitmentStatus::Sponsored;
        }
        if commitment.is_expired(self.height) {
            commitment.status = PrivateMempoolCommitmentStatus::Expired;
        }
        let commitment_id = commitment.commitment_id.clone();
        self.consumed_replay_nullifiers
            .insert(commitment.nullifier_root.clone());
        self.private_mempool_commitments
            .insert(commitment_id.clone(), commitment);
        Ok(commitment_id)
    }

    pub fn seal_microbatch(
        &mut self,
        lane_id: &str,
        source_peer_id: &str,
        commitment_ids: Vec<String>,
        route_peer_ids: Vec<String>,
        region_path: Vec<String>,
        first_sent_ms: u64,
    ) -> FastRelayMeshResult<MicrobatchPropagation> {
        let lane = self
            .lanes
            .get(lane_id)
            .ok_or_else(|| "microbatch references unknown lane".to_string())?;
        if !lane.active_at(self.height) {
            return Err("microbatch lane is not active".to_string());
        }
        if !self.peers.contains_key(source_peer_id) {
            return Err("microbatch references unknown source peer".to_string());
        }
        if commitment_ids.is_empty() {
            return Err("microbatch commitment set is empty".to_string());
        }
        if route_peer_ids.len() as u64 > self.config.max_route_hops {
            return Err("microbatch route exceeds max hops".to_string());
        }
        for peer_id in &route_peer_ids {
            if !self.peers.contains_key(peer_id) {
                return Err("microbatch route references unknown peer".to_string());
            }
        }
        for region_id in &region_path {
            if !self.regions.contains_key(region_id) {
                return Err("microbatch route references unknown region".to_string());
            }
        }
        let mut commitments = Vec::new();
        for commitment_id in &commitment_ids {
            let commitment = self
                .private_mempool_commitments
                .get(commitment_id)
                .ok_or_else(|| "microbatch references unknown commitment".to_string())?;
            if commitment.lane_id != lane_id {
                return Err("microbatch commitment lane mismatch".to_string());
            }
            if !commitment.status.open() {
                return Err("microbatch commitment is not open".to_string());
            }
            commitments.push(commitment.clone());
        }
        let sequence = self
            .microbatches
            .values()
            .filter(|batch| batch.lane_id == lane_id)
            .count() as u64;
        let batch = MicrobatchPropagation::new(
            lane_id,
            source_peer_id,
            sequence,
            &commitments,
            route_peer_ids,
            region_path,
            first_sent_ms,
            self.config.target_ack_ms,
        )?;
        for commitment_id in &commitment_ids {
            if let Some(commitment) = self.private_mempool_commitments.get_mut(commitment_id) {
                commitment.status = PrivateMempoolCommitmentStatus::Propagated;
            }
        }
        Ok(batch)
    }

    pub fn record_qos_observation(
        &mut self,
        observation: QosLatencyObservation,
    ) -> FastRelayMeshResult<String> {
        observation.validate()?;
        if !self.peers.contains_key(&observation.peer_id) {
            return Err("qos observation references unknown peer".to_string());
        }
        if !self.peers.contains_key(&observation.reporter_peer_id) {
            return Err("qos observation references unknown reporter".to_string());
        }
        if !self.regions.contains_key(&observation.region_id) {
            return Err("qos observation references unknown region".to_string());
        }
        if let Some(lane_id) = &observation.lane_id {
            if !self.lanes.contains_key(lane_id) {
                return Err("qos observation references unknown lane".to_string());
            }
        }
        let target_latency_ms = match observation
            .lane_id
            .as_ref()
            .and_then(|lane_id| self.lanes.get(lane_id))
        {
            Some(lane) => lane.target_latency_ms,
            None => self.config.target_ack_ms,
        };
        if let Some(score) = self.peer_scores.get_mut(&observation.peer_id) {
            score.apply_observation(&observation, target_latency_ms);
        }
        let observation_id = observation.observation_id.clone();
        self.qos_observations
            .insert(observation_id.clone(), observation);
        Ok(observation_id)
    }

    pub fn insert_slashing_evidence(
        &mut self,
        evidence: SlashingEvidenceTicket,
    ) -> FastRelayMeshResult<String> {
        evidence.validate()?;
        if !self.config.enable_slashing_tickets {
            return Err("slashing tickets disabled".to_string());
        }
        if !self.peers.contains_key(&evidence.accused_peer_id) {
            return Err("slashing evidence references unknown accused peer".to_string());
        }
        if !self.peers.contains_key(&evidence.reporter_peer_id) {
            return Err("slashing evidence references unknown reporter peer".to_string());
        }
        if let Some(score) = self.peer_scores.get_mut(&evidence.accused_peer_id) {
            score.slash_penalty_bps = score
                .slash_penalty_bps
                .saturating_add(evidence.severity_bps)
                .min(FAST_RELAY_MESH_MAX_BPS);
        }
        let evidence_id = evidence.evidence_id.clone();
        self.slashing_evidence.insert(evidence_id.clone(), evidence);
        Ok(evidence_id)
    }

    pub fn insert_failover_policy(
        &mut self,
        policy: RelayFailoverPolicy,
    ) -> FastRelayMeshResult<String> {
        policy.validate()?;
        if !self.config.enable_failover_mesh {
            return Err("relay failover mesh disabled".to_string());
        }
        if !self.peers.contains_key(&policy.primary_peer_id) {
            return Err("failover policy references unknown primary peer".to_string());
        }
        for peer_id in &policy.standby_peer_ids {
            if !self.peers.contains_key(peer_id) {
                return Err("failover policy references unknown standby peer".to_string());
            }
        }
        for lane_id in &policy.watched_lane_ids {
            if !self.lanes.contains_key(lane_id) {
                return Err("failover policy references unknown lane".to_string());
            }
        }
        let policy_id = policy.policy_id.clone();
        self.failover_policies.insert(policy_id.clone(), policy);
        Ok(policy_id)
    }

    pub fn publish_public_record(
        &mut self,
        object_kind: &str,
        object_id: &str,
        payload: &Value,
        redaction: &Value,
    ) -> FastRelayMeshResult<String> {
        let record = FastRelayMeshPublicRecord::new(
            object_kind,
            object_id,
            payload,
            redaction,
            self.height,
        )?;
        let record_id = record.record_id.clone();
        self.public_records.insert(record_id.clone(), record);
        Ok(record_id)
    }

    pub fn expire_records(&mut self) {
        for handshake in self.handshakes.values_mut() {
            if handshake.is_expired(self.height) && !handshake.stage.is_confirmed() {
                handshake.stage = PqHandshakeStage::Expired;
            }
        }
        for lane in self.lanes.values_mut() {
            if self.height > lane.expires_at_height
                && matches!(
                    lane.status,
                    EncryptedRelayLaneStatus::Active
                        | EncryptedRelayLaneStatus::Standby
                        | EncryptedRelayLaneStatus::Congested
                )
            {
                lane.status = EncryptedRelayLaneStatus::Retired;
            }
        }
        for commitment in self.private_mempool_commitments.values_mut() {
            if commitment.is_expired(self.height) && commitment.status.open() {
                commitment.status = PrivateMempoolCommitmentStatus::Expired;
            }
        }
        for pool in self.sponsorship_pools.values_mut() {
            if self.height > pool.expires_at_height && pool.status.usable() {
                pool.status = SponsorshipStatus::Expired;
            }
        }
        for ticket in self.sponsorship_tickets.values_mut() {
            if self.height > ticket.expires_at_height && ticket.status.usable() {
                ticket.status = SponsorshipStatus::Expired;
            }
        }
        for evidence in self.slashing_evidence.values_mut() {
            if self.height > evidence.expires_at_height
                && matches!(evidence.status, EvidenceTicketStatus::Pending)
            {
                evidence.status = EvidenceTicketStatus::Expired;
            }
        }
    }

    pub fn roots(&self) -> FastRelayMeshRoots {
        let config_root = self.config.config_root();
        let region_root = fast_relay_mesh_region_root_from_map(&self.regions);
        let peer_root = fast_relay_mesh_peer_root_from_map(&self.peers);
        let handshake_root = fast_relay_mesh_handshake_root_from_map(&self.handshakes);
        let lane_root = fast_relay_mesh_lane_root_from_map(&self.lanes);
        let commitment_root = fast_relay_mesh_private_mempool_commitment_root_from_map(
            &self.private_mempool_commitments,
        );
        let microbatch_root = fast_relay_mesh_microbatch_root_from_map(&self.microbatches);
        let qos_observation_root =
            fast_relay_mesh_qos_observation_root_from_map(&self.qos_observations);
        let peer_score_root = fast_relay_mesh_peer_score_root_from_map(&self.peer_scores);
        let slashing_evidence_root =
            fast_relay_mesh_slashing_evidence_root_from_map(&self.slashing_evidence);
        let sponsorship_pool_root =
            fast_relay_mesh_sponsorship_pool_root_from_map(&self.sponsorship_pools);
        let sponsorship_ticket_root =
            fast_relay_mesh_sponsorship_ticket_root_from_map(&self.sponsorship_tickets);
        let failover_policy_root =
            fast_relay_mesh_failover_policy_root_from_map(&self.failover_policies);
        let replay_nullifier_root = fast_relay_mesh_string_set_root(
            "FAST-RELAY-MESH-REPLAY-NULLIFIERS",
            &self
                .consumed_replay_nullifiers
                .iter()
                .cloned()
                .collect::<Vec<_>>(),
        );
        let public_record_root = fast_relay_mesh_public_record_root_from_map(&self.public_records);
        let state_record = json!({
            "kind": "fast_relay_mesh_state_root_record",
            "chain_id": CHAIN_ID,
            "protocol_version": FAST_RELAY_MESH_PROTOCOL_VERSION,
            "schema_version": FAST_RELAY_MESH_SCHEMA_VERSION,
            "height": self.height,
            "mesh_label_root": fast_relay_mesh_string_root("FAST-RELAY-MESH-LABEL", &self.mesh_label),
            "config_root": config_root,
            "region_root": region_root,
            "peer_root": peer_root,
            "handshake_root": handshake_root,
            "lane_root": lane_root,
            "commitment_root": commitment_root,
            "microbatch_root": microbatch_root,
            "qos_observation_root": qos_observation_root,
            "peer_score_root": peer_score_root,
            "slashing_evidence_root": slashing_evidence_root,
            "sponsorship_pool_root": sponsorship_pool_root,
            "sponsorship_ticket_root": sponsorship_ticket_root,
            "failover_policy_root": failover_policy_root,
            "replay_nullifier_root": replay_nullifier_root,
            "public_record_root": public_record_root,
            "counters": self.counters().public_record(),
        });
        let state_root = fast_relay_mesh_state_root_from_record(&state_record);
        FastRelayMeshRoots {
            config_root,
            region_root,
            peer_root,
            handshake_root,
            lane_root,
            commitment_root,
            microbatch_root,
            qos_observation_root,
            peer_score_root,
            slashing_evidence_root,
            sponsorship_pool_root,
            sponsorship_ticket_root,
            failover_policy_root,
            replay_nullifier_root,
            public_record_root,
            state_root,
        }
    }

    pub fn counters(&self) -> FastRelayMeshCounters {
        let mut counters = FastRelayMeshCounters {
            height: self.height,
            region_count: self.regions.len() as u64,
            peer_count: self.peers.len() as u64,
            handshake_count: self.handshakes.len() as u64,
            lane_count: self.lanes.len() as u64,
            commitment_count: self.private_mempool_commitments.len() as u64,
            microbatch_count: self.microbatches.len() as u64,
            qos_observation_count: self.qos_observations.len() as u64,
            peer_score_count: self.peer_scores.len() as u64,
            slashing_evidence_count: self.slashing_evidence.len() as u64,
            sponsorship_pool_count: self.sponsorship_pools.len() as u64,
            sponsorship_ticket_count: self.sponsorship_tickets.len() as u64,
            failover_policy_count: self.failover_policies.len() as u64,
            replay_nullifier_count: self.consumed_replay_nullifiers.len() as u64,
            public_record_count: self.public_records.len() as u64,
            ..FastRelayMeshCounters::default()
        };
        for region in self.regions.values() {
            if region.status.accepts_traffic() {
                counters.active_region_count += 1;
            }
        }
        for peer in self.peers.values() {
            if peer.active_at(self.height) {
                counters.active_peer_count += 1;
            }
        }
        for handshake in self.handshakes.values() {
            if handshake.stage.is_confirmed() && !handshake.is_expired(self.height) {
                counters.confirmed_handshake_count += 1;
            }
        }
        for lane in self.lanes.values() {
            if lane.active_at(self.height) {
                counters.active_lane_count += 1;
            }
        }
        for commitment in self.private_mempool_commitments.values() {
            match commitment.status {
                PrivateMempoolCommitmentStatus::Pending => counters.pending_commitment_count += 1,
                PrivateMempoolCommitmentStatus::Sponsored => {
                    counters.sponsored_commitment_count += 1
                }
                PrivateMempoolCommitmentStatus::Propagated
                | PrivateMempoolCommitmentStatus::Batched
                | PrivateMempoolCommitmentStatus::Included => {
                    counters.propagated_commitment_count += 1
                }
                PrivateMempoolCommitmentStatus::Expired => counters.expired_commitment_count += 1,
                PrivateMempoolCommitmentStatus::Rejected => {}
            }
            counters.total_payload_bytes = counters
                .total_payload_bytes
                .saturating_add(commitment.payload_size_bytes);
            counters.total_fee_micro_units = counters
                .total_fee_micro_units
                .saturating_add(commitment.fee_micro_units);
        }
        for batch in self.microbatches.values() {
            match batch.status {
                MicrobatchStatus::Acknowledged => counters.acknowledged_microbatch_count += 1,
                MicrobatchStatus::Failed => counters.failed_microbatch_count += 1,
                MicrobatchStatus::Open
                | MicrobatchStatus::Sealed
                | MicrobatchStatus::Propagated
                | MicrobatchStatus::Replayed => {}
            }
        }
        for observation in self.qos_observations.values() {
            let target = match observation
                .lane_id
                .as_ref()
                .and_then(|lane_id| self.lanes.get(lane_id))
            {
                Some(lane) => lane.target_latency_ms,
                None => self.config.target_ack_ms,
            };
            if observation.observed_latency_ms > target {
                counters.high_latency_observation_count += 1;
            }
        }
        for evidence in self.slashing_evidence.values() {
            if matches!(
                evidence.status,
                EvidenceTicketStatus::Accepted | EvidenceTicketStatus::Slashed
            ) {
                counters.accepted_slashing_evidence_count += 1;
            }
        }
        for pool in self.sponsorship_pools.values() {
            if pool.active_at(self.height) {
                counters.active_sponsorship_pool_count += 1;
            }
            counters.sponsored_reserved_units = counters
                .sponsored_reserved_units
                .saturating_add(pool.reserved_units);
            counters.sponsored_spent_units = counters
                .sponsored_spent_units
                .saturating_add(pool.spent_units);
        }
        for ticket in self.sponsorship_tickets.values() {
            if ticket.active_at(self.height) {
                counters.active_sponsorship_ticket_count += 1;
            }
        }
        for policy in self.failover_policies.values() {
            if matches!(policy.status, FailoverPolicyStatus::Armed) {
                counters.armed_failover_policy_count += 1;
            }
        }
        counters
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "fast_relay_mesh_state",
            "chain_id": CHAIN_ID,
            "protocol_version": FAST_RELAY_MESH_PROTOCOL_VERSION,
            "schema_version": FAST_RELAY_MESH_SCHEMA_VERSION,
            "security_model": FAST_RELAY_MESH_SECURITY_MODEL,
            "height": self.height,
            "mesh_label": self.mesh_label,
            "config": self.config.public_record(),
            "regions": self.regions.values().map(RelayRegion::public_record).collect::<Vec<_>>(),
            "peers": self.peers.values().map(RelayPeerIdentity::public_record).collect::<Vec<_>>(),
            "handshakes": self.handshakes.values().map(PqRelayHandshake::public_record).collect::<Vec<_>>(),
            "lanes": self.lanes.values().map(EncryptedRelayLane::public_record).collect::<Vec<_>>(),
            "private_mempool_commitments": self.private_mempool_commitments.values().map(PrivateMempoolCommitment::public_record).collect::<Vec<_>>(),
            "microbatches": self.microbatches.values().map(MicrobatchPropagation::public_record).collect::<Vec<_>>(),
            "qos_observations": self.qos_observations.values().map(QosLatencyObservation::public_record).collect::<Vec<_>>(),
            "peer_scores": self.peer_scores.values().map(PeerScoreSnapshot::public_record).collect::<Vec<_>>(),
            "slashing_evidence": self.slashing_evidence.values().map(SlashingEvidenceTicket::public_record).collect::<Vec<_>>(),
            "sponsorship_pools": self.sponsorship_pools.values().map(LowFeeRelaySponsorshipPool::public_record).collect::<Vec<_>>(),
            "sponsorship_tickets": self.sponsorship_tickets.values().map(LowFeeRelaySponsorshipTicket::public_record).collect::<Vec<_>>(),
            "failover_policies": self.failover_policies.values().map(RelayFailoverPolicy::public_record).collect::<Vec<_>>(),
            "consumed_replay_nullifiers": self.consumed_replay_nullifiers,
            "public_records": self.public_records.values().map(FastRelayMeshPublicRecord::public_record).collect::<Vec<_>>(),
            "counters": self.counters().public_record(),
            "roots": roots.public_record(),
            "state_root": roots.state_root,
        })
    }

    pub fn validate(&self) -> FastRelayMeshResult<String> {
        ensure_non_empty(&self.mesh_label, "fast relay mesh label")?;
        self.config.validate()?;
        if self.regions.len() > FAST_RELAY_MESH_MAX_REGIONS {
            return Err("fast relay mesh has too many regions".to_string());
        }
        if self.peers.len() > FAST_RELAY_MESH_MAX_PEERS {
            return Err("fast relay mesh has too many peers".to_string());
        }
        if self.handshakes.len() > FAST_RELAY_MESH_MAX_HANDSHAKES {
            return Err("fast relay mesh has too many handshakes".to_string());
        }
        if self.lanes.len() > FAST_RELAY_MESH_MAX_LANES {
            return Err("fast relay mesh has too many lanes".to_string());
        }
        if self.private_mempool_commitments.len() > FAST_RELAY_MESH_MAX_COMMITMENTS {
            return Err("fast relay mesh has too many private mempool commitments".to_string());
        }
        if self.microbatches.len() > FAST_RELAY_MESH_MAX_MICROBATCHES {
            return Err("fast relay mesh has too many microbatches".to_string());
        }
        if self.qos_observations.len() > FAST_RELAY_MESH_MAX_QOS_OBSERVATIONS {
            return Err("fast relay mesh has too many qos observations".to_string());
        }
        if self.slashing_evidence.len() > FAST_RELAY_MESH_MAX_EVIDENCE_TICKETS {
            return Err("fast relay mesh has too many slashing tickets".to_string());
        }
        if self.sponsorship_pools.len() > FAST_RELAY_MESH_MAX_SPONSOR_POOLS {
            return Err("fast relay mesh has too many sponsorship pools".to_string());
        }
        if self.sponsorship_tickets.len() > FAST_RELAY_MESH_MAX_SPONSOR_TICKETS {
            return Err("fast relay mesh has too many sponsorship tickets".to_string());
        }
        if self.failover_policies.len() > FAST_RELAY_MESH_MAX_FAILOVER_POLICIES {
            return Err("fast relay mesh has too many failover policies".to_string());
        }
        if self.public_records.len() > FAST_RELAY_MESH_MAX_PUBLIC_RECORDS {
            return Err("fast relay mesh has too many public records".to_string());
        }
        for region in self.regions.values() {
            region.validate()?;
            for peer_id in &region.entry_peer_ids {
                if !self.peers.contains_key(peer_id) {
                    return Err("relay region references unknown peer".to_string());
                }
            }
            for lane_id in &region.default_lane_ids {
                if !self.lanes.contains_key(lane_id) {
                    return Err("relay region references unknown lane".to_string());
                }
            }
        }
        for peer in self.peers.values() {
            peer.validate()?;
            if !self.regions.contains_key(&peer.region_id) {
                return Err("relay peer references unknown region".to_string());
            }
            for lane_id in &peer.advertised_lane_ids {
                if !self.lanes.contains_key(lane_id) {
                    return Err("relay peer advertises unknown lane".to_string());
                }
            }
        }
        for handshake in self.handshakes.values() {
            handshake.validate()?;
            if !self.peers.contains_key(&handshake.initiator_peer_id)
                || !self.peers.contains_key(&handshake.responder_peer_id)
            {
                return Err("pq relay handshake references unknown peer".to_string());
            }
        }
        for lane in self.lanes.values() {
            lane.validate()?;
            if !self.regions.contains_key(&lane.region_id) {
                return Err("encrypted relay lane references unknown region".to_string());
            }
            if !self.peers.contains_key(&lane.ingress_peer_id) {
                return Err("encrypted relay lane references unknown ingress peer".to_string());
            }
            for peer_id in &lane.egress_peer_ids {
                if !self.peers.contains_key(peer_id) {
                    return Err("encrypted relay lane references unknown egress peer".to_string());
                }
            }
            if let Some(pool_id) = &lane.sponsor_pool_id {
                if !self.sponsorship_pools.contains_key(pool_id) {
                    return Err("encrypted relay lane references unknown sponsor pool".to_string());
                }
            }
        }
        for commitment in self.private_mempool_commitments.values() {
            commitment.validate()?;
            if !self.lanes.contains_key(&commitment.lane_id) {
                return Err("private mempool commitment references unknown lane".to_string());
            }
            if !self
                .consumed_replay_nullifiers
                .contains(&commitment.nullifier_root)
            {
                return Err(
                    "private mempool commitment nullifier missing from replay set".to_string(),
                );
            }
            if let Some(ticket_id) = &commitment.sponsorship_ticket_id {
                if !self.sponsorship_tickets.contains_key(ticket_id) {
                    return Err(
                        "private mempool commitment references unknown sponsorship ticket"
                            .to_string(),
                    );
                }
            }
        }
        for batch in self.microbatches.values() {
            batch.validate()?;
            if !self.lanes.contains_key(&batch.lane_id) {
                return Err("microbatch references unknown lane".to_string());
            }
            if !self.peers.contains_key(&batch.source_peer_id) {
                return Err("microbatch references unknown source peer".to_string());
            }
            for commitment_id in &batch.commitment_ids {
                if !self.private_mempool_commitments.contains_key(commitment_id) {
                    return Err("microbatch references unknown commitment".to_string());
                }
            }
            for peer_id in &batch.route_peer_ids {
                if !self.peers.contains_key(peer_id) {
                    return Err("microbatch references unknown route peer".to_string());
                }
            }
            for region_id in &batch.region_path {
                if !self.regions.contains_key(region_id) {
                    return Err("microbatch references unknown route region".to_string());
                }
            }
        }
        for observation in self.qos_observations.values() {
            observation.validate()?;
            if !self.peers.contains_key(&observation.peer_id)
                || !self.peers.contains_key(&observation.reporter_peer_id)
            {
                return Err("qos observation references unknown peer".to_string());
            }
            if !self.regions.contains_key(&observation.region_id) {
                return Err("qos observation references unknown region".to_string());
            }
            if let Some(lane_id) = &observation.lane_id {
                if !self.lanes.contains_key(lane_id) {
                    return Err("qos observation references unknown lane".to_string());
                }
            }
        }
        for score in self.peer_scores.values() {
            score.validate()?;
            if !self.peers.contains_key(&score.peer_id) {
                return Err("peer score references unknown peer".to_string());
            }
        }
        for evidence in self.slashing_evidence.values() {
            evidence.validate()?;
            if !self.peers.contains_key(&evidence.accused_peer_id)
                || !self.peers.contains_key(&evidence.reporter_peer_id)
            {
                return Err("slashing evidence references unknown peer".to_string());
            }
        }
        for pool in self.sponsorship_pools.values() {
            pool.validate()?;
            if !self.peers.contains_key(&pool.sponsor_peer_id) {
                return Err("sponsorship pool references unknown sponsor peer".to_string());
            }
            if !self.lanes.contains_key(&pool.lane_id) {
                return Err("sponsorship pool references unknown lane".to_string());
            }
        }
        for ticket in self.sponsorship_tickets.values() {
            ticket.validate()?;
            let pool = self
                .sponsorship_pools
                .get(&ticket.pool_id)
                .ok_or_else(|| "sponsorship ticket references unknown pool".to_string())?;
            if pool.lane_id != ticket.lane_id {
                return Err("sponsorship ticket lane mismatch".to_string());
            }
            if ticket.max_fee_micro_units > pool.max_fee_micro_units {
                return Err("sponsorship ticket exceeds pool max fee".to_string());
            }
        }
        for policy in self.failover_policies.values() {
            policy.validate()?;
            if !self.peers.contains_key(&policy.primary_peer_id) {
                return Err("failover policy references unknown primary peer".to_string());
            }
            for peer_id in &policy.standby_peer_ids {
                if !self.peers.contains_key(peer_id) {
                    return Err("failover policy references unknown standby peer".to_string());
                }
            }
            for lane_id in &policy.watched_lane_ids {
                if !self.lanes.contains_key(lane_id) {
                    return Err("failover policy references unknown lane".to_string());
                }
            }
        }
        for record in self.public_records.values() {
            record.validate()?;
        }
        Ok(self.state_root())
    }

    pub fn private_mempool_commitment_root(&self) -> String {
        fast_relay_mesh_private_mempool_commitment_root_from_map(&self.private_mempool_commitments)
    }

    pub fn sponsorship_ticket_root(&self) -> String {
        fast_relay_mesh_sponsorship_ticket_root_from_map(&self.sponsorship_tickets)
    }
}

pub fn fast_relay_mesh_state_root_from_record(record: &Value) -> String {
    fast_relay_mesh_payload_root("FAST-RELAY-MESH-STATE", record)
}

pub fn fast_relay_mesh_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(FAST_RELAY_MESH_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn fast_relay_mesh_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(FAST_RELAY_MESH_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn fast_relay_mesh_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| Value::String(fast_relay_mesh_string_root(domain, value)))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn fast_relay_mesh_nullifier(domain: &str, parts: &[&str]) -> String {
    let leaves = parts
        .iter()
        .map(|part| Value::String((*part).to_string()))
        .collect::<Vec<_>>();
    let parts_root = merkle_root(domain, &leaves);
    domain_hash(
        &format!("{domain}:nullifier"),
        &[
            HashPart::Str(FAST_RELAY_MESH_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&parts_root),
        ],
        32,
    )
}

pub fn fast_relay_mesh_config_id(record: &Value) -> String {
    fast_relay_mesh_payload_root("FAST-RELAY-MESH-CONFIG-ID", record)
}

pub fn fast_relay_mesh_region_id(
    label: &str,
    kind: RelayRegionKind,
    route_policy_root: &str,
) -> String {
    domain_hash(
        "FAST-RELAY-MESH-REGION-ID",
        &[
            HashPart::Str(FAST_RELAY_MESH_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(kind.as_str()),
            HashPart::Str(route_policy_root),
        ],
        32,
    )
}

pub fn fast_relay_mesh_peer_id(
    label: &str,
    role: RelayPeerRole,
    region_id: &str,
    pq_auth_public_key_commitment: &str,
    pq_kem_public_key_commitment: &str,
) -> String {
    domain_hash(
        "FAST-RELAY-MESH-PEER-ID",
        &[
            HashPart::Str(FAST_RELAY_MESH_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(role.as_str()),
            HashPart::Str(region_id),
            HashPart::Str(pq_auth_public_key_commitment),
            HashPart::Str(pq_kem_public_key_commitment),
        ],
        32,
    )
}

pub fn fast_relay_mesh_handshake_challenge_root(
    initiator_peer_id: &str,
    responder_peer_id: &str,
    purpose: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "FAST-RELAY-MESH-HANDSHAKE-CHALLENGE",
        &[
            HashPart::Str(FAST_RELAY_MESH_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(initiator_peer_id),
            HashPart::Str(responder_peer_id),
            HashPart::Str(purpose),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn fast_relay_mesh_handshake_id(
    initiator_peer_id: &str,
    responder_peer_id: &str,
    purpose: &str,
    challenge_root: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "FAST-RELAY-MESH-HANDSHAKE-ID",
        &[
            HashPart::Str(FAST_RELAY_MESH_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(initiator_peer_id),
            HashPart::Str(responder_peer_id),
            HashPart::Str(purpose),
            HashPart::Str(challenge_root),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn fast_relay_mesh_lane_id(
    lane_kind: EncryptedRelayLaneKind,
    region_id: &str,
    ingress_peer_id: &str,
    lane_key_root: &str,
    lane_policy_root: &str,
) -> String {
    domain_hash(
        "FAST-RELAY-MESH-LANE-ID",
        &[
            HashPart::Str(FAST_RELAY_MESH_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_kind.as_str()),
            HashPart::Str(region_id),
            HashPart::Str(ingress_peer_id),
            HashPart::Str(lane_key_root),
            HashPart::Str(lane_policy_root),
        ],
        32,
    )
}

pub fn fast_relay_mesh_private_mempool_commitment_id(
    lane_id: &str,
    submitter_commitment: &str,
    payload_ciphertext_root: &str,
    fee_commitment_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "FAST-RELAY-MESH-PRIVATE-MEMPOOL-COMMITMENT-ID",
        &[
            HashPart::Str(FAST_RELAY_MESH_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(submitter_commitment),
            HashPart::Str(payload_ciphertext_root),
            HashPart::Str(fee_commitment_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn fast_relay_mesh_microbatch_id(
    lane_id: &str,
    source_peer_id: &str,
    sequence: u64,
    commitment_root: &str,
    first_sent_ms: u64,
) -> String {
    domain_hash(
        "FAST-RELAY-MESH-MICROBATCH-ID",
        &[
            HashPart::Str(FAST_RELAY_MESH_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(source_peer_id),
            HashPart::Int(sequence as i128),
            HashPart::Str(commitment_root),
            HashPart::Int(first_sent_ms as i128),
        ],
        32,
    )
}

pub fn fast_relay_mesh_qos_observation_id(
    observation_kind: QosObservationKind,
    peer_id: &str,
    lane_id: Option<&str>,
    evidence_root: &str,
    measured_at_height: u64,
) -> String {
    domain_hash(
        "FAST-RELAY-MESH-QOS-OBSERVATION-ID",
        &[
            HashPart::Str(FAST_RELAY_MESH_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(observation_kind.as_str()),
            HashPart::Str(peer_id),
            HashPart::Str(match lane_id {
                Some(value) => value,
                None => "",
            }),
            HashPart::Str(evidence_root),
            HashPart::Int(measured_at_height as i128),
        ],
        32,
    )
}

pub fn fast_relay_mesh_peer_score_id(
    peer_id: &str,
    qos_observation_root: &str,
    last_update_height: u64,
) -> String {
    domain_hash(
        "FAST-RELAY-MESH-PEER-SCORE-ID",
        &[
            HashPart::Str(FAST_RELAY_MESH_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(peer_id),
            HashPart::Str(qos_observation_root),
            HashPart::Int(last_update_height as i128),
        ],
        32,
    )
}

pub fn fast_relay_mesh_slashing_evidence_id(
    evidence_kind: EvidenceTicketKind,
    accused_peer_id: &str,
    reporter_peer_id: &str,
    related_object_id: &str,
    first_record_root: &str,
    second_record_root: &str,
    discovered_at_height: u64,
) -> String {
    domain_hash(
        "FAST-RELAY-MESH-SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(FAST_RELAY_MESH_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(evidence_kind.as_str()),
            HashPart::Str(accused_peer_id),
            HashPart::Str(reporter_peer_id),
            HashPart::Str(related_object_id),
            HashPart::Str(first_record_root),
            HashPart::Str(second_record_root),
            HashPart::Int(discovered_at_height as i128),
        ],
        32,
    )
}

pub fn fast_relay_mesh_sponsorship_pool_id(
    label: &str,
    sponsor_peer_id: &str,
    lane_id: &str,
    asset_id: &str,
    beneficiary_policy_root: &str,
) -> String {
    domain_hash(
        "FAST-RELAY-MESH-SPONSORSHIP-POOL-ID",
        &[
            HashPart::Str(FAST_RELAY_MESH_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(sponsor_peer_id),
            HashPart::Str(lane_id),
            HashPart::Str(asset_id),
            HashPart::Str(beneficiary_policy_root),
        ],
        32,
    )
}

pub fn fast_relay_mesh_sponsorship_ticket_id(
    pool_id: &str,
    beneficiary_commitment: &str,
    commitment_hint_root: &str,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "FAST-RELAY-MESH-SPONSORSHIP-TICKET-ID",
        &[
            HashPart::Str(FAST_RELAY_MESH_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Str(beneficiary_commitment),
            HashPart::Str(commitment_hint_root),
            HashPart::Int(issued_at_height as i128),
        ],
        32,
    )
}

pub fn fast_relay_mesh_failover_policy_id(
    label: &str,
    mode: FailoverMode,
    primary_peer_id: &str,
    standby_peer_ids: &BTreeSet<String>,
    watched_lane_ids: &BTreeSet<String>,
    created_at_height: u64,
) -> String {
    let standby_root = fast_relay_mesh_string_set_root(
        "FAST-RELAY-MESH-FAILOVER-STANDBY-PEERS",
        &standby_peer_ids.iter().cloned().collect::<Vec<_>>(),
    );
    let lane_root = fast_relay_mesh_string_set_root(
        "FAST-RELAY-MESH-FAILOVER-WATCHED-LANES",
        &watched_lane_ids.iter().cloned().collect::<Vec<_>>(),
    );
    domain_hash(
        "FAST-RELAY-MESH-FAILOVER-POLICY-ID",
        &[
            HashPart::Str(FAST_RELAY_MESH_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(mode.as_str()),
            HashPart::Str(primary_peer_id),
            HashPart::Str(&standby_root),
            HashPart::Str(&lane_root),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn fast_relay_mesh_public_record_id(
    object_kind: &str,
    object_id: &str,
    payload_root: &str,
    redaction_root: &str,
    published_at_height: u64,
) -> String {
    domain_hash(
        "FAST-RELAY-MESH-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(FAST_RELAY_MESH_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(object_kind),
            HashPart::Str(object_id),
            HashPart::Str(payload_root),
            HashPart::Str(redaction_root),
            HashPart::Int(published_at_height as i128),
        ],
        32,
    )
}

pub fn fast_relay_mesh_region_root_from_map(values: &BTreeMap<String, RelayRegion>) -> String {
    merkle_root(
        "FAST-RELAY-MESH-REGION-SET",
        &values
            .values()
            .map(RelayRegion::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn fast_relay_mesh_peer_root_from_map(values: &BTreeMap<String, RelayPeerIdentity>) -> String {
    merkle_root(
        "FAST-RELAY-MESH-PEER-SET",
        &values
            .values()
            .map(RelayPeerIdentity::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn fast_relay_mesh_handshake_root_from_map(
    values: &BTreeMap<String, PqRelayHandshake>,
) -> String {
    merkle_root(
        "FAST-RELAY-MESH-HANDSHAKE-SET",
        &values
            .values()
            .map(PqRelayHandshake::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn fast_relay_mesh_lane_root_from_map(values: &BTreeMap<String, EncryptedRelayLane>) -> String {
    merkle_root(
        "FAST-RELAY-MESH-LANE-SET",
        &values
            .values()
            .map(EncryptedRelayLane::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn fast_relay_mesh_private_mempool_commitment_root_from_map(
    values: &BTreeMap<String, PrivateMempoolCommitment>,
) -> String {
    merkle_root(
        "FAST-RELAY-MESH-PRIVATE-MEMPOOL-COMMITMENT-SET",
        &values
            .values()
            .map(PrivateMempoolCommitment::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn fast_relay_mesh_microbatch_root_from_map(
    values: &BTreeMap<String, MicrobatchPropagation>,
) -> String {
    merkle_root(
        "FAST-RELAY-MESH-MICROBATCH-SET",
        &values
            .values()
            .map(MicrobatchPropagation::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn fast_relay_mesh_qos_observation_root_from_map(
    values: &BTreeMap<String, QosLatencyObservation>,
) -> String {
    merkle_root(
        "FAST-RELAY-MESH-QOS-OBSERVATION-SET",
        &values
            .values()
            .map(QosLatencyObservation::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn fast_relay_mesh_peer_score_root_from_map(
    values: &BTreeMap<String, PeerScoreSnapshot>,
) -> String {
    merkle_root(
        "FAST-RELAY-MESH-PEER-SCORE-SET",
        &values
            .values()
            .map(PeerScoreSnapshot::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn fast_relay_mesh_slashing_evidence_root_from_map(
    values: &BTreeMap<String, SlashingEvidenceTicket>,
) -> String {
    merkle_root(
        "FAST-RELAY-MESH-SLASHING-EVIDENCE-SET",
        &values
            .values()
            .map(SlashingEvidenceTicket::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn fast_relay_mesh_sponsorship_pool_root_from_map(
    values: &BTreeMap<String, LowFeeRelaySponsorshipPool>,
) -> String {
    merkle_root(
        "FAST-RELAY-MESH-SPONSORSHIP-POOL-SET",
        &values
            .values()
            .map(LowFeeRelaySponsorshipPool::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn fast_relay_mesh_sponsorship_ticket_root_from_map(
    values: &BTreeMap<String, LowFeeRelaySponsorshipTicket>,
) -> String {
    merkle_root(
        "FAST-RELAY-MESH-SPONSORSHIP-TICKET-SET",
        &values
            .values()
            .map(LowFeeRelaySponsorshipTicket::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn fast_relay_mesh_failover_policy_root_from_map(
    values: &BTreeMap<String, RelayFailoverPolicy>,
) -> String {
    merkle_root(
        "FAST-RELAY-MESH-FAILOVER-POLICY-SET",
        &values
            .values()
            .map(RelayFailoverPolicy::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn fast_relay_mesh_public_record_root_from_map(
    values: &BTreeMap<String, FastRelayMeshPublicRecord>,
) -> String {
    merkle_root(
        "FAST-RELAY-MESH-PUBLIC-RECORD-SET",
        &values
            .values()
            .map(FastRelayMeshPublicRecord::public_record)
            .collect::<Vec<_>>(),
    )
}

fn btree_set<const N: usize>(values: [&str; N]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn ensure_non_empty(value: &str, label: &str) -> FastRelayMeshResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(())
}

fn ensure_positive(value: u64, label: &str) -> FastRelayMeshResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_bps(value: u64, label: &str) -> FastRelayMeshResult<()> {
    if value > FAST_RELAY_MESH_MAX_BPS {
        return Err(format!("{label} exceeds basis point maximum"));
    }
    Ok(())
}
