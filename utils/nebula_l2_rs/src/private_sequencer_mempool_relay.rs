use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};

pub type PrivateSequencerMempoolRelayResult<T> = Result<T, String>;

pub const PRIVATE_SEQUENCER_MEMPOOL_RELAY_PROTOCOL_VERSION: &str =
    "nebula-private-sequencer-mempool-relay-v1";
pub const PRIVATE_SEQUENCER_MEMPOOL_RELAY_SCHEMA_VERSION: &str =
    "private-sequencer-mempool-relay-state-v1";
pub const PRIVATE_SEQUENCER_MEMPOOL_RELAY_DEVNET_LABEL: &str =
    "devnet-private-sequencer-mempool-relay";
pub const PRIVATE_SEQUENCER_MEMPOOL_RELAY_INTENT_ENCRYPTION_SCHEME: &str =
    "ML-KEM-768+XChaCha20-Poly1305-sealed-intent-devnet";
pub const PRIVATE_SEQUENCER_MEMPOOL_RELAY_PQ_ATTESTATION_SCHEME: &str =
    "ML-DSA-65+SLH-DSA-SHAKE-128s-relay-attestation";
pub const PRIVATE_SEQUENCER_MEMPOOL_RELAY_COMMITMENT_SCHEME: &str =
    "shake256-domain-separated-canonical-json";
pub const PRIVATE_SEQUENCER_MEMPOOL_RELAY_DISCLOSURE_POLICY: &str =
    "operator-records-redacted-by-default-delayed-disclosure";
pub const PRIVATE_SEQUENCER_MEMPOOL_RELAY_LOW_FEE_POLICY: &str = "sponsor-ticket-low-fee-lane-v1";
pub const PRIVATE_SEQUENCER_MEMPOOL_RELAY_ANTI_CENSORSHIP_POLICY: &str =
    "forced-queue-rotation-with-operator-attestation-v1";
pub const PRIVATE_SEQUENCER_MEMPOOL_RELAY_DEFAULT_EPOCH_BLOCKS: u64 = 120;
pub const PRIVATE_SEQUENCER_MEMPOOL_RELAY_DEFAULT_WINDOW_BLOCKS: u64 = 6;
pub const PRIVATE_SEQUENCER_MEMPOOL_RELAY_DEFAULT_INTENT_TTL_BLOCKS: u64 = 36;
pub const PRIVATE_SEQUENCER_MEMPOOL_RELAY_DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 18;
pub const PRIVATE_SEQUENCER_MEMPOOL_RELAY_DEFAULT_SPONSOR_TICKET_TTL_BLOCKS: u64 = 72;
pub const PRIVATE_SEQUENCER_MEMPOOL_RELAY_DEFAULT_DISCLOSURE_DELAY_BLOCKS: u64 = 720;
pub const PRIVATE_SEQUENCER_MEMPOOL_RELAY_DEFAULT_FORCED_GRACE_BLOCKS: u64 = 12;
pub const PRIVATE_SEQUENCER_MEMPOOL_RELAY_DEFAULT_MAX_PAYLOAD_BYTES: u64 = 128 * 1024;
pub const PRIVATE_SEQUENCER_MEMPOOL_RELAY_DEFAULT_MAX_INTENTS_PER_WINDOW: u64 = 1_024;
pub const PRIVATE_SEQUENCER_MEMPOOL_RELAY_DEFAULT_LOW_FEE_CAP_MICRO_UNITS: u64 = 2_500;
pub const PRIVATE_SEQUENCER_MEMPOOL_RELAY_DEFAULT_MIN_OPERATOR_SCORE_BPS: u64 = 7_000;
pub const PRIVATE_SEQUENCER_MEMPOOL_RELAY_DEFAULT_SLASH_CENSORSHIP_BPS: u64 = 2_500;
pub const PRIVATE_SEQUENCER_MEMPOOL_RELAY_DEFAULT_SLASH_DISCLOSURE_BPS: u64 = 5_000;
pub const PRIVATE_SEQUENCER_MEMPOOL_RELAY_MAX_BPS: u64 = 10_000;
pub const PRIVATE_SEQUENCER_MEMPOOL_RELAY_MAX_OPERATORS: usize = 128;
pub const PRIVATE_SEQUENCER_MEMPOOL_RELAY_MAX_LANES: usize = 96;
pub const PRIVATE_SEQUENCER_MEMPOOL_RELAY_MAX_WINDOWS: usize = 512;
pub const PRIVATE_SEQUENCER_MEMPOOL_RELAY_MAX_INTENTS: usize = 8_192;
pub const PRIVATE_SEQUENCER_MEMPOOL_RELAY_MAX_ATTESTATIONS: usize = 8_192;
pub const PRIVATE_SEQUENCER_MEMPOOL_RELAY_MAX_SPONSOR_ACCOUNTS: usize = 512;
pub const PRIVATE_SEQUENCER_MEMPOOL_RELAY_MAX_SPONSOR_TICKETS: usize = 8_192;
pub const PRIVATE_SEQUENCER_MEMPOOL_RELAY_MAX_CENSORSHIP_QUEUE_ITEMS: usize = 4_096;
pub const PRIVATE_SEQUENCER_MEMPOOL_RELAY_MAX_OPERATOR_RECORDS: usize = 8_192;
pub const PRIVATE_SEQUENCER_MEMPOOL_RELAY_MAX_DISCLOSURE_RECEIPTS: usize = 4_096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateRelayLaneKind {
    PrivateTransfer,
    MoneroBridge,
    PrivateSwap,
    ContractCall,
    LowFeePrivate,
    SponsoredBridge,
    ForcedInclusion,
    ProofAggregation,
    WalletRecovery,
    OperatorControl,
}

impl PrivateRelayLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::MoneroBridge => "monero_bridge",
            Self::PrivateSwap => "private_swap",
            Self::ContractCall => "contract_call",
            Self::LowFeePrivate => "low_fee_private",
            Self::SponsoredBridge => "sponsored_bridge",
            Self::ForcedInclusion => "forced_inclusion",
            Self::ProofAggregation => "proof_aggregation",
            Self::WalletRecovery => "wallet_recovery",
            Self::OperatorControl => "operator_control",
        }
    }

    pub fn privacy_sensitive(self) -> bool {
        !matches!(self, Self::OperatorControl)
    }

    pub fn low_fee_eligible(self) -> bool {
        matches!(
            self,
            Self::LowFeePrivate
                | Self::SponsoredBridge
                | Self::WalletRecovery
                | Self::ForcedInclusion
        )
    }

    pub fn default_priority(self) -> u64 {
        match self {
            Self::ForcedInclusion => 0,
            Self::MoneroBridge => 1,
            Self::SponsoredBridge => 2,
            Self::LowFeePrivate => 3,
            Self::PrivateTransfer => 4,
            Self::WalletRecovery => 5,
            Self::PrivateSwap => 6,
            Self::ContractCall => 7,
            Self::ProofAggregation => 8,
            Self::OperatorControl => 9,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateRelayLaneStatus {
    Active,
    Throttled,
    Paused,
    Draining,
    Retired,
}

impl PrivateRelayLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Retired => "retired",
        }
    }

    pub fn admits(self) -> bool {
        matches!(self, Self::Active | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateRelayOperatorRole {
    PrimarySequencer,
    BackupSequencer,
    EdgeRelay,
    SponsorRelay,
    MoneroGateway,
    Watchtower,
    DisclosureAuditor,
}

impl PrivateRelayOperatorRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrimarySequencer => "primary_sequencer",
            Self::BackupSequencer => "backup_sequencer",
            Self::EdgeRelay => "edge_relay",
            Self::SponsorRelay => "sponsor_relay",
            Self::MoneroGateway => "monero_gateway",
            Self::Watchtower => "watchtower",
            Self::DisclosureAuditor => "disclosure_auditor",
        }
    }

    pub fn can_ingress(self) -> bool {
        matches!(
            self,
            Self::PrimarySequencer
                | Self::BackupSequencer
                | Self::EdgeRelay
                | Self::SponsorRelay
                | Self::MoneroGateway
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateRelayOperatorStatus {
    Active,
    Standby,
    Throttled,
    Quarantined,
    Slashed,
    Offline,
    Retired,
}

impl PrivateRelayOperatorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Standby => "standby",
            Self::Throttled => "throttled",
            Self::Quarantined => "quarantined",
            Self::Slashed => "slashed",
            Self::Offline => "offline",
            Self::Retired => "retired",
        }
    }

    pub fn can_relay(self) -> bool {
        matches!(self, Self::Active | Self::Standby | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptedIntentStatus {
    Submitted,
    Queued,
    Sponsored,
    Attested,
    Forwarded,
    Preconfirmed,
    Included,
    Expired,
    Rejected,
    Disputed,
}

impl EncryptedIntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Queued => "queued",
            Self::Sponsored => "sponsored",
            Self::Attested => "attested",
            Self::Forwarded => "forwarded",
            Self::Preconfirmed => "preconfirmed",
            Self::Included => "included",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Disputed => "disputed",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Submitted
                | Self::Queued
                | Self::Sponsored
                | Self::Attested
                | Self::Forwarded
                | Self::Preconfirmed
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayAttestationStatus {
    Pending,
    Valid,
    Superseded,
    Challenged,
    Invalid,
    Expired,
}

impl RelayAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Valid => "valid",
            Self::Superseded => "superseded",
            Self::Challenged => "challenged",
            Self::Invalid => "invalid",
            Self::Expired => "expired",
        }
    }

    pub fn accepted(self) -> bool {
        matches!(self, Self::Valid | Self::Superseded)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorTicketStatus {
    Reserved,
    Funded,
    Assigned,
    Consumed,
    Refunded,
    Expired,
    Revoked,
}

impl SponsorTicketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Funded => "funded",
            Self::Assigned => "assigned",
            Self::Consumed => "consumed",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Funded | Self::Assigned)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorAccountStatus {
    Active,
    Paused,
    Exhausted,
    Slashed,
    Closed,
}

impl SponsorAccountStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Exhausted => "exhausted",
            Self::Slashed => "slashed",
            Self::Closed => "closed",
        }
    }

    pub fn can_issue(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntiCensorshipQueueStatus {
    Open,
    Escalated,
    Forced,
    Satisfied,
    Expired,
    Disputed,
}

impl AntiCensorshipQueueStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Escalated => "escalated",
            Self::Forced => "forced",
            Self::Satisfied => "satisfied",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }

    pub fn needs_action(self) -> bool {
        matches!(self, Self::Open | Self::Escalated | Self::Forced)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorRecordKind {
    IntentIngress,
    AttestationIssued,
    SponsorTicketAssigned,
    QueueEscalated,
    LaneRotated,
    LowFeeAdmitted,
    DisclosureReceipt,
    CensorshipEvidence,
}

impl OperatorRecordKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IntentIngress => "intent_ingress",
            Self::AttestationIssued => "attestation_issued",
            Self::SponsorTicketAssigned => "sponsor_ticket_assigned",
            Self::QueueEscalated => "queue_escalated",
            Self::LaneRotated => "lane_rotated",
            Self::LowFeeAdmitted => "low_fee_admitted",
            Self::DisclosureReceipt => "disclosure_receipt",
            Self::CensorshipEvidence => "censorship_evidence",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureStatus {
    Redacted,
    PendingDelay,
    Disclosed,
    Challenged,
    Withheld,
}

impl DisclosureStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Redacted => "redacted",
            Self::PendingDelay => "pending_delay",
            Self::Disclosed => "disclosed",
            Self::Challenged => "challenged",
            Self::Withheld => "withheld",
        }
    }

    pub fn public_safe(self) -> bool {
        matches!(self, Self::Redacted | Self::PendingDelay | Self::Disclosed)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateSequencerMempoolRelayConfig {
    pub config_id: String,
    pub protocol_version: String,
    pub schema_version: String,
    pub epoch_blocks: u64,
    pub window_blocks: u64,
    pub intent_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub sponsor_ticket_ttl_blocks: u64,
    pub disclosure_delay_blocks: u64,
    pub forced_inclusion_grace_blocks: u64,
    pub max_payload_bytes: u64,
    pub max_intents_per_window: u64,
    pub low_fee_cap_micro_units: u64,
    pub min_operator_score_bps: u64,
    pub slash_censorship_bps: u64,
    pub slash_disclosure_bps: u64,
    pub intent_encryption_scheme: String,
    pub pq_attestation_scheme: String,
    pub commitment_scheme: String,
    pub disclosure_policy: String,
    pub anti_censorship_policy: String,
    pub low_fee_policy: String,
}

impl Default for PrivateSequencerMempoolRelayConfig {
    fn default() -> Self {
        let mut config = Self {
            config_id: String::new(),
            protocol_version: PRIVATE_SEQUENCER_MEMPOOL_RELAY_PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_SEQUENCER_MEMPOOL_RELAY_SCHEMA_VERSION.to_string(),
            epoch_blocks: PRIVATE_SEQUENCER_MEMPOOL_RELAY_DEFAULT_EPOCH_BLOCKS,
            window_blocks: PRIVATE_SEQUENCER_MEMPOOL_RELAY_DEFAULT_WINDOW_BLOCKS,
            intent_ttl_blocks: PRIVATE_SEQUENCER_MEMPOOL_RELAY_DEFAULT_INTENT_TTL_BLOCKS,
            attestation_ttl_blocks: PRIVATE_SEQUENCER_MEMPOOL_RELAY_DEFAULT_ATTESTATION_TTL_BLOCKS,
            sponsor_ticket_ttl_blocks:
                PRIVATE_SEQUENCER_MEMPOOL_RELAY_DEFAULT_SPONSOR_TICKET_TTL_BLOCKS,
            disclosure_delay_blocks:
                PRIVATE_SEQUENCER_MEMPOOL_RELAY_DEFAULT_DISCLOSURE_DELAY_BLOCKS,
            forced_inclusion_grace_blocks:
                PRIVATE_SEQUENCER_MEMPOOL_RELAY_DEFAULT_FORCED_GRACE_BLOCKS,
            max_payload_bytes: PRIVATE_SEQUENCER_MEMPOOL_RELAY_DEFAULT_MAX_PAYLOAD_BYTES,
            max_intents_per_window: PRIVATE_SEQUENCER_MEMPOOL_RELAY_DEFAULT_MAX_INTENTS_PER_WINDOW,
            low_fee_cap_micro_units:
                PRIVATE_SEQUENCER_MEMPOOL_RELAY_DEFAULT_LOW_FEE_CAP_MICRO_UNITS,
            min_operator_score_bps: PRIVATE_SEQUENCER_MEMPOOL_RELAY_DEFAULT_MIN_OPERATOR_SCORE_BPS,
            slash_censorship_bps: PRIVATE_SEQUENCER_MEMPOOL_RELAY_DEFAULT_SLASH_CENSORSHIP_BPS,
            slash_disclosure_bps: PRIVATE_SEQUENCER_MEMPOOL_RELAY_DEFAULT_SLASH_DISCLOSURE_BPS,
            intent_encryption_scheme: PRIVATE_SEQUENCER_MEMPOOL_RELAY_INTENT_ENCRYPTION_SCHEME
                .to_string(),
            pq_attestation_scheme: PRIVATE_SEQUENCER_MEMPOOL_RELAY_PQ_ATTESTATION_SCHEME
                .to_string(),
            commitment_scheme: PRIVATE_SEQUENCER_MEMPOOL_RELAY_COMMITMENT_SCHEME.to_string(),
            disclosure_policy: PRIVATE_SEQUENCER_MEMPOOL_RELAY_DISCLOSURE_POLICY.to_string(),
            anti_censorship_policy: PRIVATE_SEQUENCER_MEMPOOL_RELAY_ANTI_CENSORSHIP_POLICY
                .to_string(),
            low_fee_policy: PRIVATE_SEQUENCER_MEMPOOL_RELAY_LOW_FEE_POLICY.to_string(),
        };
        config.config_id = private_sequencer_mempool_relay_config_id(&config);
        config
    }
}

impl PrivateSequencerMempoolRelayConfig {
    pub fn to_public_json(&self) -> Value {
        json!({
            "config_id": self.config_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "epoch_blocks": self.epoch_blocks,
            "window_blocks": self.window_blocks,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "sponsor_ticket_ttl_blocks": self.sponsor_ticket_ttl_blocks,
            "disclosure_delay_blocks": self.disclosure_delay_blocks,
            "forced_inclusion_grace_blocks": self.forced_inclusion_grace_blocks,
            "max_payload_bytes": self.max_payload_bytes,
            "max_intents_per_window": self.max_intents_per_window,
            "low_fee_cap_micro_units": self.low_fee_cap_micro_units,
            "min_operator_score_bps": self.min_operator_score_bps,
            "slash_censorship_bps": self.slash_censorship_bps,
            "slash_disclosure_bps": self.slash_disclosure_bps,
            "intent_encryption_scheme": self.intent_encryption_scheme,
            "pq_attestation_scheme": self.pq_attestation_scheme,
            "commitment_scheme": self.commitment_scheme,
            "disclosure_policy": self.disclosure_policy,
            "anti_censorship_policy": self.anti_censorship_policy,
            "low_fee_policy": self.low_fee_policy,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVATE-SEQUENCER-MEMPOOL-RELAY-CONFIG",
            &[HashPart::Json(&self.to_public_json())],
            32,
        )
    }

    pub fn validate(&self) -> PrivateSequencerMempoolRelayResult<String> {
        ensure_non_empty(&self.config_id, "private relay config id")?;
        ensure_non_empty(&self.protocol_version, "private relay protocol version")?;
        ensure_non_empty(&self.schema_version, "private relay schema version")?;
        ensure_positive(self.epoch_blocks, "private relay epoch blocks")?;
        ensure_positive(self.window_blocks, "private relay window blocks")?;
        ensure_positive(self.intent_ttl_blocks, "private relay intent ttl blocks")?;
        ensure_positive(
            self.attestation_ttl_blocks,
            "private relay attestation ttl blocks",
        )?;
        ensure_positive(
            self.sponsor_ticket_ttl_blocks,
            "private relay sponsor ticket ttl blocks",
        )?;
        ensure_positive(
            self.disclosure_delay_blocks,
            "private relay disclosure delay blocks",
        )?;
        ensure_positive(
            self.forced_inclusion_grace_blocks,
            "private relay forced inclusion grace blocks",
        )?;
        ensure_positive(self.max_payload_bytes, "private relay max payload bytes")?;
        ensure_positive(
            self.max_intents_per_window,
            "private relay max intents per window",
        )?;
        ensure_bps(
            self.min_operator_score_bps,
            "private relay min operator score",
        )?;
        ensure_bps(
            self.slash_censorship_bps,
            "private relay censorship slash bps",
        )?;
        ensure_bps(
            self.slash_disclosure_bps,
            "private relay disclosure slash bps",
        )?;
        ensure_non_empty(
            &self.intent_encryption_scheme,
            "private relay intent encryption scheme",
        )?;
        ensure_non_empty(
            &self.pq_attestation_scheme,
            "private relay pq attestation scheme",
        )?;
        ensure_non_empty(&self.commitment_scheme, "private relay commitment scheme")?;
        ensure_non_empty(&self.disclosure_policy, "private relay disclosure policy")?;
        ensure_non_empty(
            &self.anti_censorship_policy,
            "private relay anti censorship policy",
        )?;
        ensure_non_empty(&self.low_fee_policy, "private relay low fee policy")?;
        let expected = private_sequencer_mempool_relay_config_id(self);
        if self.config_id != expected {
            return Err("private relay config id does not match parameters".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateRelayOperator {
    pub operator_id: String,
    pub label: String,
    pub role: PrivateRelayOperatorRole,
    pub status: PrivateRelayOperatorStatus,
    pub region: String,
    pub ingress_key_commitment: String,
    pub pq_attestation_key_commitment: String,
    pub disclosure_key_commitment: String,
    pub stake_root: String,
    pub score_bps: u64,
    pub accepted_lane_ids: BTreeSet<String>,
    pub last_seen_height: u64,
}

impl PrivateRelayOperator {
    pub fn new(
        label: &str,
        role: PrivateRelayOperatorRole,
        region: &str,
        ingress_key_commitment: &str,
        pq_attestation_key_commitment: &str,
        disclosure_key_commitment: &str,
        stake_root: &str,
        accepted_lane_ids: BTreeSet<String>,
        height: u64,
    ) -> PrivateSequencerMempoolRelayResult<Self> {
        ensure_non_empty(label, "private relay operator label")?;
        ensure_non_empty(region, "private relay operator region")?;
        ensure_non_empty(
            ingress_key_commitment,
            "private relay operator ingress key commitment",
        )?;
        ensure_non_empty(
            pq_attestation_key_commitment,
            "private relay operator pq attestation key commitment",
        )?;
        ensure_non_empty(
            disclosure_key_commitment,
            "private relay operator disclosure key commitment",
        )?;
        ensure_non_empty(stake_root, "private relay operator stake root")?;
        let operator_id =
            private_relay_operator_id(label, role, region, pq_attestation_key_commitment);
        let operator = Self {
            operator_id,
            label: label.to_string(),
            role,
            status: PrivateRelayOperatorStatus::Active,
            region: region.to_string(),
            ingress_key_commitment: ingress_key_commitment.to_string(),
            pq_attestation_key_commitment: pq_attestation_key_commitment.to_string(),
            disclosure_key_commitment: disclosure_key_commitment.to_string(),
            stake_root: stake_root.to_string(),
            score_bps: 9_200,
            accepted_lane_ids,
            last_seen_height: height,
        };
        operator.validate()?;
        Ok(operator)
    }

    pub fn to_public_json(&self) -> Value {
        json!({
            "operator_id": self.operator_id,
            "label": self.label,
            "role": self.role.as_str(),
            "status": self.status.as_str(),
            "region": self.region,
            "ingress_key_commitment": self.ingress_key_commitment,
            "pq_attestation_key_commitment": self.pq_attestation_key_commitment,
            "disclosure_key_commitment": self.disclosure_key_commitment,
            "stake_root": self.stake_root,
            "score_bps": self.score_bps,
            "accepted_lane_ids": self.accepted_lane_ids.iter().cloned().collect::<Vec<_>>(),
            "last_seen_height": self.last_seen_height,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVATE-RELAY-OPERATOR",
            &[HashPart::Json(&self.to_public_json())],
            32,
        )
    }

    pub fn can_ingress_lane(&self, lane_id: &str) -> bool {
        self.status.can_relay()
            && self.role.can_ingress()
            && self.accepted_lane_ids.contains(lane_id)
    }

    pub fn set_status(
        &mut self,
        status: PrivateRelayOperatorStatus,
        height: u64,
    ) -> PrivateSequencerMempoolRelayResult<String> {
        self.status = status;
        self.last_seen_height = height;
        self.validate()
    }

    pub fn update_score(&mut self, score_bps: u64) -> PrivateSequencerMempoolRelayResult<String> {
        ensure_bps(score_bps, "private relay operator score")?;
        self.score_bps = score_bps;
        self.validate()
    }

    pub fn validate(&self) -> PrivateSequencerMempoolRelayResult<String> {
        ensure_non_empty(&self.operator_id, "private relay operator id")?;
        ensure_non_empty(&self.label, "private relay operator label")?;
        ensure_non_empty(&self.region, "private relay operator region")?;
        ensure_non_empty(
            &self.ingress_key_commitment,
            "private relay operator ingress key commitment",
        )?;
        ensure_non_empty(
            &self.pq_attestation_key_commitment,
            "private relay operator pq key commitment",
        )?;
        ensure_non_empty(
            &self.disclosure_key_commitment,
            "private relay operator disclosure key commitment",
        )?;
        ensure_non_empty(&self.stake_root, "private relay operator stake root")?;
        ensure_bps(self.score_bps, "private relay operator score")?;
        let expected = private_relay_operator_id(
            &self.label,
            self.role,
            &self.region,
            &self.pq_attestation_key_commitment,
        );
        if self.operator_id != expected {
            return Err("private relay operator id does not match identity".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateRelayLane {
    pub lane_id: String,
    pub label: String,
    pub kind: PrivateRelayLaneKind,
    pub status: PrivateRelayLaneStatus,
    pub priority: u64,
    pub max_payload_bytes: u64,
    pub max_intents_per_window: u64,
    pub min_fee_micro_units: u64,
    pub low_fee_cap_micro_units: u64,
    pub operator_set_root: String,
    pub encryption_key_root: String,
    pub queue_salt_commitment: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivateRelayLane {
    pub fn new(
        label: &str,
        kind: PrivateRelayLaneKind,
        operator_set_root: &str,
        encryption_key_root: &str,
        queue_salt_commitment: &str,
        opened_at_height: u64,
        ttl_blocks: u64,
    ) -> PrivateSequencerMempoolRelayResult<Self> {
        ensure_non_empty(label, "private relay lane label")?;
        ensure_non_empty(operator_set_root, "private relay lane operator set root")?;
        ensure_non_empty(
            encryption_key_root,
            "private relay lane encryption key root",
        )?;
        ensure_non_empty(
            queue_salt_commitment,
            "private relay lane queue salt commitment",
        )?;
        ensure_positive(ttl_blocks, "private relay lane ttl blocks")?;
        let lane_id = private_relay_lane_id(label, kind, operator_set_root, encryption_key_root);
        let lane = Self {
            lane_id,
            label: label.to_string(),
            kind,
            status: PrivateRelayLaneStatus::Active,
            priority: kind.default_priority(),
            max_payload_bytes: PRIVATE_SEQUENCER_MEMPOOL_RELAY_DEFAULT_MAX_PAYLOAD_BYTES,
            max_intents_per_window: PRIVATE_SEQUENCER_MEMPOOL_RELAY_DEFAULT_MAX_INTENTS_PER_WINDOW,
            min_fee_micro_units: 100,
            low_fee_cap_micro_units:
                PRIVATE_SEQUENCER_MEMPOOL_RELAY_DEFAULT_LOW_FEE_CAP_MICRO_UNITS,
            operator_set_root: operator_set_root.to_string(),
            encryption_key_root: encryption_key_root.to_string(),
            queue_salt_commitment: queue_salt_commitment.to_string(),
            opened_at_height,
            expires_at_height: opened_at_height.saturating_add(ttl_blocks),
        };
        lane.validate()?;
        Ok(lane)
    }

    pub fn to_public_json(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "label": self.label,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "priority": self.priority,
            "max_payload_bytes": self.max_payload_bytes,
            "max_intents_per_window": self.max_intents_per_window,
            "min_fee_micro_units": self.min_fee_micro_units,
            "low_fee_cap_micro_units": self.low_fee_cap_micro_units,
            "operator_set_root": self.operator_set_root,
            "encryption_key_root": self.encryption_key_root,
            "queue_salt_commitment": self.queue_salt_commitment,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVATE-RELAY-LANE",
            &[HashPart::Json(&self.to_public_json())],
            32,
        )
    }

    pub fn admits_fee(&self, fee_micro_units: u64) -> bool {
        if !self.status.admits() {
            return false;
        }
        if self.kind.low_fee_eligible() {
            fee_micro_units <= self.low_fee_cap_micro_units
        } else {
            fee_micro_units >= self.min_fee_micro_units
        }
    }

    pub fn validate(&self) -> PrivateSequencerMempoolRelayResult<String> {
        ensure_non_empty(&self.lane_id, "private relay lane id")?;
        ensure_non_empty(&self.label, "private relay lane label")?;
        ensure_positive(
            self.max_payload_bytes,
            "private relay lane max payload bytes",
        )?;
        ensure_positive(
            self.max_intents_per_window,
            "private relay lane max intents per window",
        )?;
        ensure_non_empty(
            &self.operator_set_root,
            "private relay lane operator set root",
        )?;
        ensure_non_empty(
            &self.encryption_key_root,
            "private relay lane encryption key root",
        )?;
        ensure_non_empty(
            &self.queue_salt_commitment,
            "private relay lane queue salt commitment",
        )?;
        if self.expires_at_height <= self.opened_at_height {
            return Err("private relay lane expiry must be after open height".to_string());
        }
        let expected = private_relay_lane_id(
            &self.label,
            self.kind,
            &self.operator_set_root,
            &self.encryption_key_root,
        );
        if self.lane_id != expected {
            return Err("private relay lane id does not match lane parameters".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayWindow {
    pub window_id: String,
    pub lane_id: String,
    pub epoch: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub encrypted_intent_root: String,
    pub attestation_root: String,
    pub low_fee_ticket_root: String,
    pub anti_censorship_queue_root: String,
    pub sealed: bool,
}

impl RelayWindow {
    pub fn new(
        lane_id: &str,
        epoch: u64,
        start_height: u64,
        window_blocks: u64,
    ) -> PrivateSequencerMempoolRelayResult<Self> {
        ensure_non_empty(lane_id, "private relay window lane id")?;
        ensure_positive(window_blocks, "private relay window blocks")?;
        let end_height = start_height.saturating_add(window_blocks);
        let empty_root = private_relay_empty_root("window-component");
        let window_id = private_relay_window_id(lane_id, epoch, start_height, end_height);
        let window = Self {
            window_id,
            lane_id: lane_id.to_string(),
            epoch,
            start_height,
            end_height,
            encrypted_intent_root: empty_root.clone(),
            attestation_root: empty_root.clone(),
            low_fee_ticket_root: empty_root.clone(),
            anti_censorship_queue_root: empty_root,
            sealed: false,
        };
        window.validate()?;
        Ok(window)
    }

    pub fn to_public_json(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "lane_id": self.lane_id,
            "epoch": self.epoch,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "encrypted_intent_root": self.encrypted_intent_root,
            "attestation_root": self.attestation_root,
            "low_fee_ticket_root": self.low_fee_ticket_root,
            "anti_censorship_queue_root": self.anti_censorship_queue_root,
            "sealed": self.sealed,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVATE-RELAY-WINDOW",
            &[HashPart::Json(&self.to_public_json())],
            32,
        )
    }

    pub fn contains_height(&self, height: u64) -> bool {
        height >= self.start_height && height < self.end_height
    }

    pub fn seal(
        &mut self,
        encrypted_intent_root: &str,
        attestation_root: &str,
        low_fee_ticket_root: &str,
        anti_censorship_queue_root: &str,
    ) -> PrivateSequencerMempoolRelayResult<String> {
        ensure_non_empty(encrypted_intent_root, "private relay window intent root")?;
        ensure_non_empty(attestation_root, "private relay window attestation root")?;
        ensure_non_empty(low_fee_ticket_root, "private relay window ticket root")?;
        ensure_non_empty(
            anti_censorship_queue_root,
            "private relay window anti censorship queue root",
        )?;
        self.encrypted_intent_root = encrypted_intent_root.to_string();
        self.attestation_root = attestation_root.to_string();
        self.low_fee_ticket_root = low_fee_ticket_root.to_string();
        self.anti_censorship_queue_root = anti_censorship_queue_root.to_string();
        self.sealed = true;
        self.validate()
    }

    pub fn validate(&self) -> PrivateSequencerMempoolRelayResult<String> {
        ensure_non_empty(&self.window_id, "private relay window id")?;
        ensure_non_empty(&self.lane_id, "private relay window lane id")?;
        if self.end_height <= self.start_height {
            return Err("private relay window end must be after start".to_string());
        }
        ensure_non_empty(
            &self.encrypted_intent_root,
            "private relay window intent root",
        )?;
        ensure_non_empty(
            &self.attestation_root,
            "private relay window attestation root",
        )?;
        ensure_non_empty(
            &self.low_fee_ticket_root,
            "private relay window low fee ticket root",
        )?;
        ensure_non_empty(
            &self.anti_censorship_queue_root,
            "private relay window anti censorship queue root",
        )?;
        let expected = private_relay_window_id(
            &self.lane_id,
            self.epoch,
            self.start_height,
            self.end_height,
        );
        if self.window_id != expected {
            return Err("private relay window id does not match parameters".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedIntentEnvelope {
    pub intent_id: String,
    pub lane_id: String,
    pub window_id: String,
    pub submitter_commitment: String,
    pub nullifier_commitment: String,
    pub ciphertext_root: String,
    pub metadata_commitment: String,
    pub payload_bytes: u64,
    pub fee_cap_micro_units: u64,
    pub sponsor_ticket_id: Option<String>,
    pub status: EncryptedIntentStatus,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl EncryptedIntentEnvelope {
    pub fn new(
        lane_id: &str,
        window_id: &str,
        submitter_commitment: &str,
        nullifier_commitment: &str,
        ciphertext_root: &str,
        metadata_commitment: &str,
        payload_bytes: u64,
        fee_cap_micro_units: u64,
        submitted_at_height: u64,
        ttl_blocks: u64,
    ) -> PrivateSequencerMempoolRelayResult<Self> {
        ensure_non_empty(lane_id, "encrypted intent lane id")?;
        ensure_non_empty(window_id, "encrypted intent window id")?;
        ensure_non_empty(
            submitter_commitment,
            "encrypted intent submitter commitment",
        )?;
        ensure_non_empty(
            nullifier_commitment,
            "encrypted intent nullifier commitment",
        )?;
        ensure_non_empty(ciphertext_root, "encrypted intent ciphertext root")?;
        ensure_non_empty(metadata_commitment, "encrypted intent metadata commitment")?;
        ensure_positive(payload_bytes, "encrypted intent payload bytes")?;
        ensure_positive(ttl_blocks, "encrypted intent ttl blocks")?;
        let expires_at_height = submitted_at_height.saturating_add(ttl_blocks);
        let intent_id = encrypted_intent_id(
            lane_id,
            window_id,
            nullifier_commitment,
            ciphertext_root,
            submitted_at_height,
        );
        let envelope = Self {
            intent_id,
            lane_id: lane_id.to_string(),
            window_id: window_id.to_string(),
            submitter_commitment: submitter_commitment.to_string(),
            nullifier_commitment: nullifier_commitment.to_string(),
            ciphertext_root: ciphertext_root.to_string(),
            metadata_commitment: metadata_commitment.to_string(),
            payload_bytes,
            fee_cap_micro_units,
            sponsor_ticket_id: None,
            status: EncryptedIntentStatus::Submitted,
            submitted_at_height,
            expires_at_height,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn to_public_json(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "lane_id": self.lane_id,
            "window_id": self.window_id,
            "submitter_commitment": self.submitter_commitment,
            "nullifier_commitment": self.nullifier_commitment,
            "ciphertext_root": self.ciphertext_root,
            "metadata_commitment": self.metadata_commitment,
            "payload_bytes": self.payload_bytes,
            "fee_cap_micro_units": self.fee_cap_micro_units,
            "sponsor_ticket_id": self.sponsor_ticket_id,
            "status": self.status.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn disclosure_safe_json(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "lane_id": self.lane_id,
            "window_id": self.window_id,
            "ciphertext_root": self.ciphertext_root,
            "metadata_commitment": self.metadata_commitment,
            "payload_bytes": self.payload_bytes,
            "fee_cap_micro_units": self.fee_cap_micro_units,
            "status": self.status.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "ENCRYPTED-INTENT-ENVELOPE",
            &[HashPart::Json(&self.to_public_json())],
            32,
        )
    }

    pub fn disclosure_safe_root(&self) -> String {
        domain_hash(
            "ENCRYPTED-INTENT-DISCLOSURE-SAFE",
            &[HashPart::Json(&self.disclosure_safe_json())],
            32,
        )
    }

    pub fn assign_sponsor_ticket(
        &mut self,
        sponsor_ticket_id: &str,
    ) -> PrivateSequencerMempoolRelayResult<String> {
        ensure_non_empty(sponsor_ticket_id, "encrypted intent sponsor ticket id")?;
        self.sponsor_ticket_id = Some(sponsor_ticket_id.to_string());
        self.status = EncryptedIntentStatus::Sponsored;
        self.validate()
    }

    pub fn set_status(
        &mut self,
        status: EncryptedIntentStatus,
    ) -> PrivateSequencerMempoolRelayResult<String> {
        self.status = status;
        self.validate()
    }

    pub fn expired_at(&self, height: u64) -> bool {
        height >= self.expires_at_height && self.status.is_open()
    }

    pub fn validate(&self) -> PrivateSequencerMempoolRelayResult<String> {
        ensure_non_empty(&self.intent_id, "encrypted intent id")?;
        ensure_non_empty(&self.lane_id, "encrypted intent lane id")?;
        ensure_non_empty(&self.window_id, "encrypted intent window id")?;
        ensure_non_empty(
            &self.submitter_commitment,
            "encrypted intent submitter commitment",
        )?;
        ensure_non_empty(
            &self.nullifier_commitment,
            "encrypted intent nullifier commitment",
        )?;
        ensure_non_empty(&self.ciphertext_root, "encrypted intent ciphertext root")?;
        ensure_non_empty(
            &self.metadata_commitment,
            "encrypted intent metadata commitment",
        )?;
        ensure_positive(self.payload_bytes, "encrypted intent payload bytes")?;
        if self.expires_at_height <= self.submitted_at_height {
            return Err("encrypted intent expiry must be after submission".to_string());
        }
        let expected = encrypted_intent_id(
            &self.lane_id,
            &self.window_id,
            &self.nullifier_commitment,
            &self.ciphertext_root,
            self.submitted_at_height,
        );
        if self.intent_id != expected {
            return Err("encrypted intent id does not match envelope".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqRelayAttestation {
    pub attestation_id: String,
    pub intent_id: String,
    pub operator_id: String,
    pub lane_id: String,
    pub window_id: String,
    pub ciphertext_root: String,
    pub policy_root: String,
    pub transcript_root: String,
    pub signature_root: String,
    pub status: RelayAttestationStatus,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl PqRelayAttestation {
    pub fn new(
        intent_id: &str,
        operator_id: &str,
        lane_id: &str,
        window_id: &str,
        ciphertext_root: &str,
        policy_root: &str,
        transcript_root: &str,
        signature_root: &str,
        issued_at_height: u64,
        ttl_blocks: u64,
    ) -> PrivateSequencerMempoolRelayResult<Self> {
        ensure_non_empty(intent_id, "pq relay attestation intent id")?;
        ensure_non_empty(operator_id, "pq relay attestation operator id")?;
        ensure_non_empty(lane_id, "pq relay attestation lane id")?;
        ensure_non_empty(window_id, "pq relay attestation window id")?;
        ensure_non_empty(ciphertext_root, "pq relay attestation ciphertext root")?;
        ensure_non_empty(policy_root, "pq relay attestation policy root")?;
        ensure_non_empty(transcript_root, "pq relay attestation transcript root")?;
        ensure_non_empty(signature_root, "pq relay attestation signature root")?;
        ensure_positive(ttl_blocks, "pq relay attestation ttl blocks")?;
        let expires_at_height = issued_at_height.saturating_add(ttl_blocks);
        let attestation_id = pq_relay_attestation_id(
            intent_id,
            operator_id,
            ciphertext_root,
            transcript_root,
            issued_at_height,
        );
        let attestation = Self {
            attestation_id,
            intent_id: intent_id.to_string(),
            operator_id: operator_id.to_string(),
            lane_id: lane_id.to_string(),
            window_id: window_id.to_string(),
            ciphertext_root: ciphertext_root.to_string(),
            policy_root: policy_root.to_string(),
            transcript_root: transcript_root.to_string(),
            signature_root: signature_root.to_string(),
            status: RelayAttestationStatus::Valid,
            issued_at_height,
            expires_at_height,
        };
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn to_public_json(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "intent_id": self.intent_id,
            "operator_id": self.operator_id,
            "lane_id": self.lane_id,
            "window_id": self.window_id,
            "ciphertext_root": self.ciphertext_root,
            "policy_root": self.policy_root,
            "transcript_root": self.transcript_root,
            "signature_root": self.signature_root,
            "status": self.status.as_str(),
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PQ-RELAY-ATTESTATION",
            &[HashPart::Json(&self.to_public_json())],
            32,
        )
    }

    pub fn expired_at(&self, height: u64) -> bool {
        height >= self.expires_at_height && matches!(self.status, RelayAttestationStatus::Valid)
    }

    pub fn validate(&self) -> PrivateSequencerMempoolRelayResult<String> {
        ensure_non_empty(&self.attestation_id, "pq relay attestation id")?;
        ensure_non_empty(&self.intent_id, "pq relay attestation intent id")?;
        ensure_non_empty(&self.operator_id, "pq relay attestation operator id")?;
        ensure_non_empty(&self.lane_id, "pq relay attestation lane id")?;
        ensure_non_empty(&self.window_id, "pq relay attestation window id")?;
        ensure_non_empty(
            &self.ciphertext_root,
            "pq relay attestation ciphertext root",
        )?;
        ensure_non_empty(&self.policy_root, "pq relay attestation policy root")?;
        ensure_non_empty(
            &self.transcript_root,
            "pq relay attestation transcript root",
        )?;
        ensure_non_empty(&self.signature_root, "pq relay attestation signature root")?;
        if self.expires_at_height <= self.issued_at_height {
            return Err("pq relay attestation expiry must be after issue height".to_string());
        }
        let expected = pq_relay_attestation_id(
            &self.intent_id,
            &self.operator_id,
            &self.ciphertext_root,
            &self.transcript_root,
            self.issued_at_height,
        );
        if self.attestation_id != expected {
            return Err("pq relay attestation id does not match transcript".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SponsorAccount {
    pub sponsor_id: String,
    pub label: String,
    pub operator_id: String,
    pub status: SponsorAccountStatus,
    pub asset_id: String,
    pub budget_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub lane_allowlist: BTreeSet<String>,
    pub authorization_root: String,
    pub reserve_proof_root: String,
    pub created_at_height: u64,
}

impl SponsorAccount {
    pub fn new(
        label: &str,
        operator_id: &str,
        asset_id: &str,
        budget_units: u64,
        lane_allowlist: BTreeSet<String>,
        authorization_root: &str,
        reserve_proof_root: &str,
        created_at_height: u64,
    ) -> PrivateSequencerMempoolRelayResult<Self> {
        ensure_non_empty(label, "sponsor account label")?;
        ensure_non_empty(operator_id, "sponsor account operator id")?;
        ensure_non_empty(asset_id, "sponsor account asset id")?;
        ensure_positive(budget_units, "sponsor account budget")?;
        ensure_non_empty(authorization_root, "sponsor account authorization root")?;
        ensure_non_empty(reserve_proof_root, "sponsor account reserve proof root")?;
        let sponsor_id = sponsor_account_id(label, operator_id, asset_id, authorization_root);
        let account = Self {
            sponsor_id,
            label: label.to_string(),
            operator_id: operator_id.to_string(),
            status: SponsorAccountStatus::Active,
            asset_id: asset_id.to_string(),
            budget_units,
            reserved_units: 0,
            spent_units: 0,
            lane_allowlist,
            authorization_root: authorization_root.to_string(),
            reserve_proof_root: reserve_proof_root.to_string(),
            created_at_height,
        };
        account.validate()?;
        Ok(account)
    }

    pub fn available_units(&self) -> u64 {
        self.budget_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
    }

    pub fn can_sponsor_lane(&self, lane_id: &str, amount_units: u64) -> bool {
        self.status.can_issue()
            && self.lane_allowlist.contains(lane_id)
            && self.available_units() >= amount_units
    }

    pub fn reserve(&mut self, amount_units: u64) -> PrivateSequencerMempoolRelayResult<String> {
        ensure_positive(amount_units, "sponsor account reservation amount")?;
        if self.available_units() < amount_units {
            return Err("sponsor account has insufficient available units".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_add(amount_units);
        self.validate()
    }

    pub fn spend_reserved(
        &mut self,
        amount_units: u64,
    ) -> PrivateSequencerMempoolRelayResult<String> {
        ensure_positive(amount_units, "sponsor account spend amount")?;
        if self.reserved_units < amount_units {
            return Err("sponsor account reserved units are insufficient".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_sub(amount_units);
        self.spent_units = self.spent_units.saturating_add(amount_units);
        self.validate()
    }

    pub fn to_public_json(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "label": self.label,
            "operator_id": self.operator_id,
            "status": self.status.as_str(),
            "asset_id": self.asset_id,
            "budget_units": self.budget_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "available_units": self.available_units(),
            "lane_allowlist": self.lane_allowlist.iter().cloned().collect::<Vec<_>>(),
            "authorization_root": self.authorization_root,
            "reserve_proof_root": self.reserve_proof_root,
            "created_at_height": self.created_at_height,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVATE-RELAY-SPONSOR-ACCOUNT",
            &[HashPart::Json(&self.to_public_json())],
            32,
        )
    }

    pub fn validate(&self) -> PrivateSequencerMempoolRelayResult<String> {
        ensure_non_empty(&self.sponsor_id, "sponsor account id")?;
        ensure_non_empty(&self.label, "sponsor account label")?;
        ensure_non_empty(&self.operator_id, "sponsor account operator id")?;
        ensure_non_empty(&self.asset_id, "sponsor account asset id")?;
        ensure_positive(self.budget_units, "sponsor account budget")?;
        ensure_non_empty(
            &self.authorization_root,
            "sponsor account authorization root",
        )?;
        ensure_non_empty(
            &self.reserve_proof_root,
            "sponsor account reserve proof root",
        )?;
        if self.reserved_units.saturating_add(self.spent_units) > self.budget_units {
            return Err("sponsor account reserved plus spent exceeds budget".to_string());
        }
        let expected = sponsor_account_id(
            &self.label,
            &self.operator_id,
            &self.asset_id,
            &self.authorization_root,
        );
        if self.sponsor_id != expected {
            return Err("sponsor account id does not match identity".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SponsorTicket {
    pub ticket_id: String,
    pub sponsor_id: String,
    pub lane_id: String,
    pub beneficiary_commitment: String,
    pub nullifier_commitment: String,
    pub amount_units: u64,
    pub fee_cap_micro_units: u64,
    pub status: SponsorTicketStatus,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub consumed_by_intent_id: Option<String>,
}

impl SponsorTicket {
    pub fn new(
        sponsor_id: &str,
        lane_id: &str,
        beneficiary_commitment: &str,
        nullifier_commitment: &str,
        amount_units: u64,
        fee_cap_micro_units: u64,
        issued_at_height: u64,
        ttl_blocks: u64,
    ) -> PrivateSequencerMempoolRelayResult<Self> {
        ensure_non_empty(sponsor_id, "sponsor ticket sponsor id")?;
        ensure_non_empty(lane_id, "sponsor ticket lane id")?;
        ensure_non_empty(
            beneficiary_commitment,
            "sponsor ticket beneficiary commitment",
        )?;
        ensure_non_empty(nullifier_commitment, "sponsor ticket nullifier commitment")?;
        ensure_positive(amount_units, "sponsor ticket amount")?;
        ensure_positive(ttl_blocks, "sponsor ticket ttl blocks")?;
        let expires_at_height = issued_at_height.saturating_add(ttl_blocks);
        let ticket_id = sponsor_ticket_id(
            sponsor_id,
            lane_id,
            beneficiary_commitment,
            nullifier_commitment,
            issued_at_height,
        );
        let ticket = Self {
            ticket_id,
            sponsor_id: sponsor_id.to_string(),
            lane_id: lane_id.to_string(),
            beneficiary_commitment: beneficiary_commitment.to_string(),
            nullifier_commitment: nullifier_commitment.to_string(),
            amount_units,
            fee_cap_micro_units,
            status: SponsorTicketStatus::Funded,
            issued_at_height,
            expires_at_height,
            consumed_by_intent_id: None,
        };
        ticket.validate()?;
        Ok(ticket)
    }

    pub fn consume(&mut self, intent_id: &str) -> PrivateSequencerMempoolRelayResult<String> {
        ensure_non_empty(intent_id, "sponsor ticket consumed intent id")?;
        if !self.status.usable() {
            return Err("sponsor ticket is not usable".to_string());
        }
        self.status = SponsorTicketStatus::Consumed;
        self.consumed_by_intent_id = Some(intent_id.to_string());
        self.validate()
    }

    pub fn expired_at(&self, height: u64) -> bool {
        height >= self.expires_at_height && self.status.usable()
    }

    pub fn to_public_json(&self) -> Value {
        json!({
            "ticket_id": self.ticket_id,
            "sponsor_id": self.sponsor_id,
            "lane_id": self.lane_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "nullifier_commitment": self.nullifier_commitment,
            "amount_units": self.amount_units,
            "fee_cap_micro_units": self.fee_cap_micro_units,
            "status": self.status.as_str(),
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "consumed_by_intent_id": self.consumed_by_intent_id,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVATE-RELAY-SPONSOR-TICKET",
            &[HashPart::Json(&self.to_public_json())],
            32,
        )
    }

    pub fn validate(&self) -> PrivateSequencerMempoolRelayResult<String> {
        ensure_non_empty(&self.ticket_id, "sponsor ticket id")?;
        ensure_non_empty(&self.sponsor_id, "sponsor ticket sponsor id")?;
        ensure_non_empty(&self.lane_id, "sponsor ticket lane id")?;
        ensure_non_empty(
            &self.beneficiary_commitment,
            "sponsor ticket beneficiary commitment",
        )?;
        ensure_non_empty(
            &self.nullifier_commitment,
            "sponsor ticket nullifier commitment",
        )?;
        ensure_positive(self.amount_units, "sponsor ticket amount")?;
        if self.expires_at_height <= self.issued_at_height {
            return Err("sponsor ticket expiry must be after issue height".to_string());
        }
        let expected = sponsor_ticket_id(
            &self.sponsor_id,
            &self.lane_id,
            &self.beneficiary_commitment,
            &self.nullifier_commitment,
            self.issued_at_height,
        );
        if self.ticket_id != expected {
            return Err("sponsor ticket id does not match identity".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AntiCensorshipQueueItem {
    pub queue_item_id: String,
    pub intent_id: String,
    pub lane_id: String,
    pub submitter_commitment: String,
    pub first_seen_height: u64,
    pub force_after_height: u64,
    pub evidence_root: String,
    pub status: AntiCensorshipQueueStatus,
    pub assigned_operator_id: Option<String>,
}

impl AntiCensorshipQueueItem {
    pub fn new(
        intent_id: &str,
        lane_id: &str,
        submitter_commitment: &str,
        evidence_root: &str,
        first_seen_height: u64,
        grace_blocks: u64,
    ) -> PrivateSequencerMempoolRelayResult<Self> {
        ensure_non_empty(intent_id, "anti censorship queue intent id")?;
        ensure_non_empty(lane_id, "anti censorship queue lane id")?;
        ensure_non_empty(
            submitter_commitment,
            "anti censorship queue submitter commitment",
        )?;
        ensure_non_empty(evidence_root, "anti censorship queue evidence root")?;
        ensure_positive(grace_blocks, "anti censorship queue grace blocks")?;
        let force_after_height = first_seen_height.saturating_add(grace_blocks);
        let queue_item_id = anti_censorship_queue_item_id(
            intent_id,
            lane_id,
            submitter_commitment,
            evidence_root,
            first_seen_height,
        );
        let item = Self {
            queue_item_id,
            intent_id: intent_id.to_string(),
            lane_id: lane_id.to_string(),
            submitter_commitment: submitter_commitment.to_string(),
            first_seen_height,
            force_after_height,
            evidence_root: evidence_root.to_string(),
            status: AntiCensorshipQueueStatus::Open,
            assigned_operator_id: None,
        };
        item.validate()?;
        Ok(item)
    }

    pub fn assign_operator(
        &mut self,
        operator_id: &str,
    ) -> PrivateSequencerMempoolRelayResult<String> {
        ensure_non_empty(operator_id, "anti censorship queue assigned operator")?;
        self.assigned_operator_id = Some(operator_id.to_string());
        self.status = AntiCensorshipQueueStatus::Escalated;
        self.validate()
    }

    pub fn ready_to_force(&self, height: u64) -> bool {
        self.status.needs_action() && height >= self.force_after_height
    }

    pub fn to_public_json(&self) -> Value {
        json!({
            "queue_item_id": self.queue_item_id,
            "intent_id": self.intent_id,
            "lane_id": self.lane_id,
            "submitter_commitment": self.submitter_commitment,
            "first_seen_height": self.first_seen_height,
            "force_after_height": self.force_after_height,
            "evidence_root": self.evidence_root,
            "status": self.status.as_str(),
            "assigned_operator_id": self.assigned_operator_id,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVATE-RELAY-ANTI-CENSORSHIP-QUEUE-ITEM",
            &[HashPart::Json(&self.to_public_json())],
            32,
        )
    }

    pub fn validate(&self) -> PrivateSequencerMempoolRelayResult<String> {
        ensure_non_empty(&self.queue_item_id, "anti censorship queue item id")?;
        ensure_non_empty(&self.intent_id, "anti censorship queue intent id")?;
        ensure_non_empty(&self.lane_id, "anti censorship queue lane id")?;
        ensure_non_empty(
            &self.submitter_commitment,
            "anti censorship queue submitter commitment",
        )?;
        ensure_non_empty(&self.evidence_root, "anti censorship queue evidence root")?;
        if self.force_after_height <= self.first_seen_height {
            return Err("anti censorship force height must be after first seen".to_string());
        }
        let expected = anti_censorship_queue_item_id(
            &self.intent_id,
            &self.lane_id,
            &self.submitter_commitment,
            &self.evidence_root,
            self.first_seen_height,
        );
        if self.queue_item_id != expected {
            return Err("anti censorship queue id does not match evidence".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisclosureSafeOperatorRecord {
    pub record_id: String,
    pub operator_id: String,
    pub kind: OperatorRecordKind,
    pub object_id: String,
    pub object_root: String,
    pub redaction_root: String,
    pub public_payload_root: String,
    pub disclosure_status: DisclosureStatus,
    pub event_height: u64,
    pub disclose_after_height: u64,
}

impl DisclosureSafeOperatorRecord {
    pub fn new(
        operator_id: &str,
        kind: OperatorRecordKind,
        object_id: &str,
        object_root: &str,
        redaction_root: &str,
        public_payload_root: &str,
        event_height: u64,
        disclosure_delay_blocks: u64,
    ) -> PrivateSequencerMempoolRelayResult<Self> {
        ensure_non_empty(operator_id, "operator record operator id")?;
        ensure_non_empty(object_id, "operator record object id")?;
        ensure_non_empty(object_root, "operator record object root")?;
        ensure_non_empty(redaction_root, "operator record redaction root")?;
        ensure_non_empty(public_payload_root, "operator record public payload root")?;
        ensure_positive(
            disclosure_delay_blocks,
            "operator record disclosure delay blocks",
        )?;
        let disclose_after_height = event_height.saturating_add(disclosure_delay_blocks);
        let record_id = operator_record_id(
            operator_id,
            kind,
            object_id,
            object_root,
            redaction_root,
            event_height,
        );
        let record = Self {
            record_id,
            operator_id: operator_id.to_string(),
            kind,
            object_id: object_id.to_string(),
            object_root: object_root.to_string(),
            redaction_root: redaction_root.to_string(),
            public_payload_root: public_payload_root.to_string(),
            disclosure_status: DisclosureStatus::Redacted,
            event_height,
            disclose_after_height,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn mark_disclosed(&mut self, height: u64) -> PrivateSequencerMempoolRelayResult<String> {
        if height < self.disclose_after_height {
            return Err("operator record disclosure delay has not elapsed".to_string());
        }
        self.disclosure_status = DisclosureStatus::Disclosed;
        self.validate()
    }

    pub fn to_public_json(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "operator_id": self.operator_id,
            "kind": self.kind.as_str(),
            "object_id": self.object_id,
            "object_root": self.object_root,
            "redaction_root": self.redaction_root,
            "public_payload_root": self.public_payload_root,
            "disclosure_status": self.disclosure_status.as_str(),
            "event_height": self.event_height,
            "disclose_after_height": self.disclose_after_height,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "DISCLOSURE-SAFE-OPERATOR-RECORD",
            &[HashPart::Json(&self.to_public_json())],
            32,
        )
    }

    pub fn validate(&self) -> PrivateSequencerMempoolRelayResult<String> {
        ensure_non_empty(&self.record_id, "operator record id")?;
        ensure_non_empty(&self.operator_id, "operator record operator id")?;
        ensure_non_empty(&self.object_id, "operator record object id")?;
        ensure_non_empty(&self.object_root, "operator record object root")?;
        ensure_non_empty(&self.redaction_root, "operator record redaction root")?;
        ensure_non_empty(
            &self.public_payload_root,
            "operator record public payload root",
        )?;
        if !self.disclosure_status.public_safe() {
            return Err("operator record is not disclosure safe".to_string());
        }
        if self.disclose_after_height <= self.event_height {
            return Err("operator record disclosure height must be after event".to_string());
        }
        let expected = operator_record_id(
            &self.operator_id,
            self.kind,
            &self.object_id,
            &self.object_root,
            &self.redaction_root,
            self.event_height,
        );
        if self.record_id != expected {
            return Err("operator record id does not match record body".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisclosureReceipt {
    pub receipt_id: String,
    pub record_id: String,
    pub operator_id: String,
    pub disclosed_payload_root: String,
    pub verifier_committee_root: String,
    pub audit_result_root: String,
    pub disclosed_at_height: u64,
    pub challenged: bool,
}

impl DisclosureReceipt {
    pub fn new(
        record_id: &str,
        operator_id: &str,
        disclosed_payload_root: &str,
        verifier_committee_root: &str,
        audit_result_root: &str,
        disclosed_at_height: u64,
    ) -> PrivateSequencerMempoolRelayResult<Self> {
        ensure_non_empty(record_id, "disclosure receipt record id")?;
        ensure_non_empty(operator_id, "disclosure receipt operator id")?;
        ensure_non_empty(
            disclosed_payload_root,
            "disclosure receipt disclosed payload root",
        )?;
        ensure_non_empty(
            verifier_committee_root,
            "disclosure receipt verifier committee root",
        )?;
        ensure_non_empty(audit_result_root, "disclosure receipt audit result root")?;
        let receipt_id = disclosure_receipt_id(
            record_id,
            operator_id,
            disclosed_payload_root,
            verifier_committee_root,
            disclosed_at_height,
        );
        let receipt = Self {
            receipt_id,
            record_id: record_id.to_string(),
            operator_id: operator_id.to_string(),
            disclosed_payload_root: disclosed_payload_root.to_string(),
            verifier_committee_root: verifier_committee_root.to_string(),
            audit_result_root: audit_result_root.to_string(),
            disclosed_at_height,
            challenged: false,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn to_public_json(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "record_id": self.record_id,
            "operator_id": self.operator_id,
            "disclosed_payload_root": self.disclosed_payload_root,
            "verifier_committee_root": self.verifier_committee_root,
            "audit_result_root": self.audit_result_root,
            "disclosed_at_height": self.disclosed_at_height,
            "challenged": self.challenged,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVATE-RELAY-DISCLOSURE-RECEIPT",
            &[HashPart::Json(&self.to_public_json())],
            32,
        )
    }

    pub fn validate(&self) -> PrivateSequencerMempoolRelayResult<String> {
        ensure_non_empty(&self.receipt_id, "disclosure receipt id")?;
        ensure_non_empty(&self.record_id, "disclosure receipt record id")?;
        ensure_non_empty(&self.operator_id, "disclosure receipt operator id")?;
        ensure_non_empty(
            &self.disclosed_payload_root,
            "disclosure receipt disclosed payload root",
        )?;
        ensure_non_empty(
            &self.verifier_committee_root,
            "disclosure receipt verifier committee root",
        )?;
        ensure_non_empty(
            &self.audit_result_root,
            "disclosure receipt audit result root",
        )?;
        let expected = disclosure_receipt_id(
            &self.record_id,
            &self.operator_id,
            &self.disclosed_payload_root,
            &self.verifier_committee_root,
            self.disclosed_at_height,
        );
        if self.receipt_id != expected {
            return Err("disclosure receipt id does not match body".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateSequencerMempoolRelayRoots {
    pub config_root: String,
    pub operator_root: String,
    pub lane_root: String,
    pub window_root: String,
    pub encrypted_intent_root: String,
    pub attestation_root: String,
    pub sponsor_account_root: String,
    pub sponsor_ticket_root: String,
    pub anti_censorship_queue_root: String,
    pub operator_record_root: String,
    pub disclosure_receipt_root: String,
    pub state_root: String,
}

impl PrivateSequencerMempoolRelayRoots {
    pub fn to_public_json(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "operator_root": self.operator_root,
            "lane_root": self.lane_root,
            "window_root": self.window_root,
            "encrypted_intent_root": self.encrypted_intent_root,
            "attestation_root": self.attestation_root,
            "sponsor_account_root": self.sponsor_account_root,
            "sponsor_ticket_root": self.sponsor_ticket_root,
            "anti_censorship_queue_root": self.anti_censorship_queue_root,
            "operator_record_root": self.operator_record_root,
            "disclosure_receipt_root": self.disclosure_receipt_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateSequencerMempoolRelayCounters {
    pub height: u64,
    pub operator_count: u64,
    pub active_operator_count: u64,
    pub lane_count: u64,
    pub active_lane_count: u64,
    pub window_count: u64,
    pub sealed_window_count: u64,
    pub encrypted_intent_count: u64,
    pub open_intent_count: u64,
    pub low_fee_intent_count: u64,
    pub attestation_count: u64,
    pub accepted_attestation_count: u64,
    pub sponsor_account_count: u64,
    pub sponsor_ticket_count: u64,
    pub usable_sponsor_ticket_count: u64,
    pub anti_censorship_queue_count: u64,
    pub forced_queue_count: u64,
    pub operator_record_count: u64,
    pub disclosure_receipt_count: u64,
}

impl PrivateSequencerMempoolRelayCounters {
    pub fn to_public_json(&self) -> Value {
        json!({
            "height": self.height,
            "operator_count": self.operator_count,
            "active_operator_count": self.active_operator_count,
            "lane_count": self.lane_count,
            "active_lane_count": self.active_lane_count,
            "window_count": self.window_count,
            "sealed_window_count": self.sealed_window_count,
            "encrypted_intent_count": self.encrypted_intent_count,
            "open_intent_count": self.open_intent_count,
            "low_fee_intent_count": self.low_fee_intent_count,
            "attestation_count": self.attestation_count,
            "accepted_attestation_count": self.accepted_attestation_count,
            "sponsor_account_count": self.sponsor_account_count,
            "sponsor_ticket_count": self.sponsor_ticket_count,
            "usable_sponsor_ticket_count": self.usable_sponsor_ticket_count,
            "anti_censorship_queue_count": self.anti_censorship_queue_count,
            "forced_queue_count": self.forced_queue_count,
            "operator_record_count": self.operator_record_count,
            "disclosure_receipt_count": self.disclosure_receipt_count,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateSequencerMempoolRelayState {
    pub height: u64,
    pub relay_label: String,
    pub config: PrivateSequencerMempoolRelayConfig,
    pub operators: BTreeMap<String, PrivateRelayOperator>,
    pub lanes: BTreeMap<String, PrivateRelayLane>,
    pub windows: BTreeMap<String, RelayWindow>,
    pub encrypted_intents: BTreeMap<String, EncryptedIntentEnvelope>,
    pub attestations: BTreeMap<String, PqRelayAttestation>,
    pub sponsor_accounts: BTreeMap<String, SponsorAccount>,
    pub sponsor_tickets: BTreeMap<String, SponsorTicket>,
    pub anti_censorship_queue: BTreeMap<String, AntiCensorshipQueueItem>,
    pub operator_records: BTreeMap<String, DisclosureSafeOperatorRecord>,
    pub disclosure_receipts: BTreeMap<String, DisclosureReceipt>,
}

impl PrivateSequencerMempoolRelayState {
    pub fn new(
        relay_label: &str,
        config: PrivateSequencerMempoolRelayConfig,
    ) -> PrivateSequencerMempoolRelayResult<Self> {
        ensure_non_empty(relay_label, "private sequencer mempool relay label")?;
        config.validate()?;
        let state = Self {
            height: 0,
            relay_label: relay_label.to_string(),
            config,
            operators: BTreeMap::new(),
            lanes: BTreeMap::new(),
            windows: BTreeMap::new(),
            encrypted_intents: BTreeMap::new(),
            attestations: BTreeMap::new(),
            sponsor_accounts: BTreeMap::new(),
            sponsor_tickets: BTreeMap::new(),
            anti_censorship_queue: BTreeMap::new(),
            operator_records: BTreeMap::new(),
            disclosure_receipts: BTreeMap::new(),
        };
        state.validate()?;
        Ok(state)
    }

    pub fn devnet() -> PrivateSequencerMempoolRelayResult<Self> {
        let mut state = Self::new(
            PRIVATE_SEQUENCER_MEMPOOL_RELAY_DEVNET_LABEL,
            PrivateSequencerMempoolRelayConfig::default(),
        )?;
        state.set_height(42);

        let operator_set_root = private_relay_seed_root("devnet-operator-set");
        let ingress_key_root = private_relay_seed_root("devnet-ingress-key");
        let pq_key_root = private_relay_seed_root("devnet-pq-attestation-key");
        let disclosure_key_root = private_relay_seed_root("devnet-disclosure-key");
        let stake_root = private_relay_seed_root("devnet-operator-stake");

        let private_lane = PrivateRelayLane::new(
            "devnet-private-transfer",
            PrivateRelayLaneKind::PrivateTransfer,
            &operator_set_root,
            &private_relay_seed_root("devnet-private-transfer-encryption-key"),
            &private_relay_seed_root("devnet-private-transfer-queue-salt"),
            36,
            288,
        )?;
        let low_fee_lane = PrivateRelayLane::new(
            "devnet-low-fee-private",
            PrivateRelayLaneKind::LowFeePrivate,
            &operator_set_root,
            &private_relay_seed_root("devnet-low-fee-encryption-key"),
            &private_relay_seed_root("devnet-low-fee-queue-salt"),
            36,
            288,
        )?;
        let bridge_lane = PrivateRelayLane::new(
            "devnet-monero-bridge",
            PrivateRelayLaneKind::MoneroBridge,
            &operator_set_root,
            &private_relay_seed_root("devnet-monero-bridge-encryption-key"),
            &private_relay_seed_root("devnet-monero-bridge-queue-salt"),
            36,
            288,
        )?;

        let private_lane_id = private_lane.lane_id.clone();
        let low_fee_lane_id = low_fee_lane.lane_id.clone();
        let bridge_lane_id = bridge_lane.lane_id.clone();
        state.add_lane(private_lane)?;
        state.add_lane(low_fee_lane)?;
        state.add_lane(bridge_lane)?;

        let mut accepted_lanes = BTreeSet::new();
        accepted_lanes.insert(private_lane_id.clone());
        accepted_lanes.insert(low_fee_lane_id.clone());
        accepted_lanes.insert(bridge_lane_id.clone());
        let primary = PrivateRelayOperator::new(
            "devnet-primary-private-sequencer",
            PrivateRelayOperatorRole::PrimarySequencer,
            "na-east",
            &ingress_key_root,
            &pq_key_root,
            &disclosure_key_root,
            &stake_root,
            accepted_lanes.clone(),
            state.height,
        )?;
        let primary_id = primary.operator_id.clone();
        state.add_operator(primary)?;

        let edge = PrivateRelayOperator::new(
            "devnet-edge-relay",
            PrivateRelayOperatorRole::EdgeRelay,
            "eu-west",
            &private_relay_seed_root("devnet-edge-ingress-key"),
            &private_relay_seed_root("devnet-edge-pq-key"),
            &private_relay_seed_root("devnet-edge-disclosure-key"),
            &private_relay_seed_root("devnet-edge-stake"),
            accepted_lanes,
            state.height,
        )?;
        state.add_operator(edge)?;

        let private_window = RelayWindow::new(&private_lane_id, 0, 42, state.config.window_blocks)?;
        let private_window_id = private_window.window_id.clone();
        state.add_window(private_window)?;
        let low_fee_window = RelayWindow::new(&low_fee_lane_id, 0, 42, state.config.window_blocks)?;
        let low_fee_window_id = low_fee_window.window_id.clone();
        state.add_window(low_fee_window)?;

        let mut sponsor_lanes = BTreeSet::new();
        sponsor_lanes.insert(low_fee_lane_id.clone());
        sponsor_lanes.insert(bridge_lane_id);
        let sponsor = SponsorAccount::new(
            "devnet-low-fee-sponsor",
            &primary_id,
            "wxmr-devnet",
            5_000_000,
            sponsor_lanes,
            &private_relay_seed_root("devnet-sponsor-authorization"),
            &private_relay_seed_root("devnet-sponsor-reserve-proof"),
            state.height,
        )?;
        let sponsor_id = sponsor.sponsor_id.clone();
        state.add_sponsor_account(sponsor)?;

        let ticket = state.issue_sponsor_ticket(
            &sponsor_id,
            &low_fee_lane_id,
            &private_relay_seed_root("devnet-low-fee-beneficiary"),
            &private_relay_seed_root("devnet-low-fee-ticket-nullifier"),
            1_200,
            900,
        )?;

        let intent = EncryptedIntentEnvelope::new(
            &low_fee_lane_id,
            &low_fee_window_id,
            &private_relay_seed_root("devnet-submit-commitment"),
            &private_relay_seed_root("devnet-intent-nullifier"),
            &private_relay_seed_root("devnet-intent-ciphertext"),
            &private_relay_seed_root("devnet-intent-metadata"),
            4_096,
            850,
            state.height,
            state.config.intent_ttl_blocks,
        )?;
        let intent_id = intent.intent_id.clone();
        state.add_encrypted_intent(intent)?;
        state.assign_ticket_to_intent(&ticket.ticket_id, &intent_id)?;
        state.attest_intent(
            &intent_id,
            &primary_id,
            &private_relay_seed_root("devnet-attestation-policy"),
            &private_relay_seed_root("devnet-attestation-transcript"),
            &private_relay_seed_root("devnet-attestation-signature"),
        )?;

        let queue_intent = EncryptedIntentEnvelope::new(
            &private_lane_id,
            &private_window_id,
            &private_relay_seed_root("devnet-forced-submit-commitment"),
            &private_relay_seed_root("devnet-forced-nullifier"),
            &private_relay_seed_root("devnet-forced-ciphertext"),
            &private_relay_seed_root("devnet-forced-metadata"),
            2_048,
            1_200,
            state.height,
            state.config.intent_ttl_blocks,
        )?;
        let queue_intent_id = queue_intent.intent_id.clone();
        state.add_encrypted_intent(queue_intent)?;
        state.enqueue_anti_censorship(
            &queue_intent_id,
            &private_relay_seed_root("devnet-censorship-evidence"),
        )?;

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn add_operator(
        &mut self,
        operator: PrivateRelayOperator,
    ) -> PrivateSequencerMempoolRelayResult<String> {
        if self.operators.len() >= PRIVATE_SEQUENCER_MEMPOOL_RELAY_MAX_OPERATORS {
            return Err("private relay operator limit reached".to_string());
        }
        operator.validate()?;
        let root = operator.root();
        self.operators
            .insert(operator.operator_id.clone(), operator);
        Ok(root)
    }

    pub fn add_lane(
        &mut self,
        lane: PrivateRelayLane,
    ) -> PrivateSequencerMempoolRelayResult<String> {
        if self.lanes.len() >= PRIVATE_SEQUENCER_MEMPOOL_RELAY_MAX_LANES {
            return Err("private relay lane limit reached".to_string());
        }
        lane.validate()?;
        let root = lane.root();
        self.lanes.insert(lane.lane_id.clone(), lane);
        Ok(root)
    }

    pub fn add_window(
        &mut self,
        window: RelayWindow,
    ) -> PrivateSequencerMempoolRelayResult<String> {
        if self.windows.len() >= PRIVATE_SEQUENCER_MEMPOOL_RELAY_MAX_WINDOWS {
            return Err("private relay window limit reached".to_string());
        }
        if !self.lanes.contains_key(&window.lane_id) {
            return Err("private relay window references unknown lane".to_string());
        }
        window.validate()?;
        let root = window.root();
        self.windows.insert(window.window_id.clone(), window);
        Ok(root)
    }

    pub fn add_encrypted_intent(
        &mut self,
        intent: EncryptedIntentEnvelope,
    ) -> PrivateSequencerMempoolRelayResult<String> {
        if self.encrypted_intents.len() >= PRIVATE_SEQUENCER_MEMPOOL_RELAY_MAX_INTENTS {
            return Err("private relay encrypted intent limit reached".to_string());
        }
        let lane = self
            .lanes
            .get(&intent.lane_id)
            .ok_or_else(|| "encrypted intent references unknown lane".to_string())?;
        if !self.windows.contains_key(&intent.window_id) {
            return Err("encrypted intent references unknown window".to_string());
        }
        if intent.payload_bytes > lane.max_payload_bytes {
            return Err("encrypted intent payload exceeds lane limit".to_string());
        }
        if !lane.admits_fee(intent.fee_cap_micro_units) {
            return Err("encrypted intent fee does not satisfy lane policy".to_string());
        }
        intent.validate()?;
        let root = intent.root();
        self.encrypted_intents
            .insert(intent.intent_id.clone(), intent);
        Ok(root)
    }

    pub fn add_sponsor_account(
        &mut self,
        sponsor: SponsorAccount,
    ) -> PrivateSequencerMempoolRelayResult<String> {
        if self.sponsor_accounts.len() >= PRIVATE_SEQUENCER_MEMPOOL_RELAY_MAX_SPONSOR_ACCOUNTS {
            return Err("private relay sponsor account limit reached".to_string());
        }
        if !self.operators.contains_key(&sponsor.operator_id) {
            return Err("sponsor account references unknown operator".to_string());
        }
        sponsor.validate()?;
        let root = sponsor.root();
        self.sponsor_accounts
            .insert(sponsor.sponsor_id.clone(), sponsor);
        Ok(root)
    }

    pub fn issue_sponsor_ticket(
        &mut self,
        sponsor_id: &str,
        lane_id: &str,
        beneficiary_commitment: &str,
        nullifier_commitment: &str,
        amount_units: u64,
        fee_cap_micro_units: u64,
    ) -> PrivateSequencerMempoolRelayResult<SponsorTicket> {
        if self.sponsor_tickets.len() >= PRIVATE_SEQUENCER_MEMPOOL_RELAY_MAX_SPONSOR_TICKETS {
            return Err("private relay sponsor ticket limit reached".to_string());
        }
        let sponsor = self
            .sponsor_accounts
            .get_mut(sponsor_id)
            .ok_or_else(|| "sponsor ticket references unknown sponsor".to_string())?;
        if !self.lanes.contains_key(lane_id) {
            return Err("sponsor ticket references unknown lane".to_string());
        }
        if !sponsor.can_sponsor_lane(lane_id, amount_units) {
            return Err("sponsor account cannot sponsor requested lane or amount".to_string());
        }
        sponsor.reserve(amount_units)?;
        let ticket = SponsorTicket::new(
            sponsor_id,
            lane_id,
            beneficiary_commitment,
            nullifier_commitment,
            amount_units,
            fee_cap_micro_units,
            self.height,
            self.config.sponsor_ticket_ttl_blocks,
        )?;
        self.sponsor_tickets
            .insert(ticket.ticket_id.clone(), ticket.clone());
        Ok(ticket)
    }

    pub fn assign_ticket_to_intent(
        &mut self,
        ticket_id: &str,
        intent_id: &str,
    ) -> PrivateSequencerMempoolRelayResult<String> {
        let ticket = self
            .sponsor_tickets
            .get_mut(ticket_id)
            .ok_or_else(|| "unknown sponsor ticket".to_string())?;
        let intent = self
            .encrypted_intents
            .get_mut(intent_id)
            .ok_or_else(|| "unknown encrypted intent".to_string())?;
        if ticket.lane_id != intent.lane_id {
            return Err("sponsor ticket lane does not match intent lane".to_string());
        }
        if ticket.fee_cap_micro_units < intent.fee_cap_micro_units {
            return Err("sponsor ticket fee cap is below intent fee cap".to_string());
        }
        ticket.consume(intent_id)?;
        intent.assign_sponsor_ticket(ticket_id)?;
        Ok(intent.root())
    }

    pub fn attest_intent(
        &mut self,
        intent_id: &str,
        operator_id: &str,
        policy_root: &str,
        transcript_root: &str,
        signature_root: &str,
    ) -> PrivateSequencerMempoolRelayResult<String> {
        if self.attestations.len() >= PRIVATE_SEQUENCER_MEMPOOL_RELAY_MAX_ATTESTATIONS {
            return Err("private relay attestation limit reached".to_string());
        }
        let intent = self
            .encrypted_intents
            .get(intent_id)
            .ok_or_else(|| "attestation references unknown intent".to_string())?;
        let operator = self
            .operators
            .get(operator_id)
            .ok_or_else(|| "attestation references unknown operator".to_string())?;
        if !operator.can_ingress_lane(&intent.lane_id) {
            return Err("operator cannot attest requested intent lane".to_string());
        }
        let attestation = PqRelayAttestation::new(
            intent_id,
            operator_id,
            &intent.lane_id,
            &intent.window_id,
            &intent.ciphertext_root,
            policy_root,
            transcript_root,
            signature_root,
            self.height,
            self.config.attestation_ttl_blocks,
        )?;
        let root = attestation.root();
        self.attestations
            .insert(attestation.attestation_id.clone(), attestation);
        if let Some(intent) = self.encrypted_intents.get_mut(intent_id) {
            intent.set_status(EncryptedIntentStatus::Attested)?;
        }
        Ok(root)
    }

    pub fn enqueue_anti_censorship(
        &mut self,
        intent_id: &str,
        evidence_root: &str,
    ) -> PrivateSequencerMempoolRelayResult<String> {
        if self.anti_censorship_queue.len()
            >= PRIVATE_SEQUENCER_MEMPOOL_RELAY_MAX_CENSORSHIP_QUEUE_ITEMS
        {
            return Err("private relay anti censorship queue limit reached".to_string());
        }
        let intent = self
            .encrypted_intents
            .get(intent_id)
            .ok_or_else(|| "anti censorship queue references unknown intent".to_string())?;
        let item = AntiCensorshipQueueItem::new(
            intent_id,
            &intent.lane_id,
            &intent.submitter_commitment,
            evidence_root,
            self.height,
            self.config.forced_inclusion_grace_blocks,
        )?;
        let root = item.root();
        self.anti_censorship_queue
            .insert(item.queue_item_id.clone(), item);
        Ok(root)
    }

    pub fn add_operator_record(
        &mut self,
        record: DisclosureSafeOperatorRecord,
    ) -> PrivateSequencerMempoolRelayResult<String> {
        if self.operator_records.len() >= PRIVATE_SEQUENCER_MEMPOOL_RELAY_MAX_OPERATOR_RECORDS {
            return Err("private relay operator record limit reached".to_string());
        }
        if !self.operators.contains_key(&record.operator_id) {
            return Err("operator record references unknown operator".to_string());
        }
        record.validate()?;
        let root = record.root();
        self.operator_records
            .insert(record.record_id.clone(), record);
        Ok(root)
    }

    pub fn public_record(
        &self,
        object_kind: &str,
        object_id: &str,
    ) -> PrivateSequencerMempoolRelayResult<Value> {
        ensure_non_empty(object_kind, "private relay public record object kind")?;
        ensure_non_empty(object_id, "private relay public record object id")?;
        match object_kind {
            "config" => {
                if object_id == self.config.config_id {
                    Ok(self.config.to_public_json())
                } else {
                    Err("unknown private relay config id".to_string())
                }
            }
            "operator" => self
                .operators
                .get(object_id)
                .map(PrivateRelayOperator::to_public_json)
                .ok_or_else(|| "unknown private relay operator id".to_string()),
            "lane" => self
                .lanes
                .get(object_id)
                .map(PrivateRelayLane::to_public_json)
                .ok_or_else(|| "unknown private relay lane id".to_string()),
            "window" => self
                .windows
                .get(object_id)
                .map(RelayWindow::to_public_json)
                .ok_or_else(|| "unknown private relay window id".to_string()),
            "encrypted_intent" => self
                .encrypted_intents
                .get(object_id)
                .map(EncryptedIntentEnvelope::disclosure_safe_json)
                .ok_or_else(|| "unknown encrypted intent id".to_string()),
            "attestation" => self
                .attestations
                .get(object_id)
                .map(PqRelayAttestation::to_public_json)
                .ok_or_else(|| "unknown pq relay attestation id".to_string()),
            "sponsor_account" => self
                .sponsor_accounts
                .get(object_id)
                .map(SponsorAccount::to_public_json)
                .ok_or_else(|| "unknown sponsor account id".to_string()),
            "sponsor_ticket" => self
                .sponsor_tickets
                .get(object_id)
                .map(SponsorTicket::to_public_json)
                .ok_or_else(|| "unknown sponsor ticket id".to_string()),
            "anti_censorship_queue" => self
                .anti_censorship_queue
                .get(object_id)
                .map(AntiCensorshipQueueItem::to_public_json)
                .ok_or_else(|| "unknown anti censorship queue id".to_string()),
            "operator_record" => self
                .operator_records
                .get(object_id)
                .map(DisclosureSafeOperatorRecord::to_public_json)
                .ok_or_else(|| "unknown operator record id".to_string()),
            "disclosure_receipt" => self
                .disclosure_receipts
                .get(object_id)
                .map(DisclosureReceipt::to_public_json)
                .ok_or_else(|| "unknown disclosure receipt id".to_string()),
            _ => Err("unknown private relay public record kind".to_string()),
        }
    }

    pub fn roots(&self) -> PrivateSequencerMempoolRelayRoots {
        let config_root = self.config.root();
        let operator_root = root_from_map("PRIVATE-RELAY-OPERATORS", &self.operators);
        let lane_root = root_from_map("PRIVATE-RELAY-LANES", &self.lanes);
        let window_root = root_from_map("PRIVATE-RELAY-WINDOWS", &self.windows);
        let encrypted_intent_root =
            root_from_map("PRIVATE-RELAY-ENCRYPTED-INTENTS", &self.encrypted_intents);
        let attestation_root = root_from_map("PRIVATE-RELAY-ATTESTATIONS", &self.attestations);
        let sponsor_account_root =
            root_from_map("PRIVATE-RELAY-SPONSOR-ACCOUNTS", &self.sponsor_accounts);
        let sponsor_ticket_root =
            root_from_map("PRIVATE-RELAY-SPONSOR-TICKETS", &self.sponsor_tickets);
        let anti_censorship_queue_root = root_from_map(
            "PRIVATE-RELAY-ANTI-CENSORSHIP-QUEUE",
            &self.anti_censorship_queue,
        );
        let operator_record_root =
            root_from_map("PRIVATE-RELAY-OPERATOR-RECORDS", &self.operator_records);
        let disclosure_receipt_root = root_from_map(
            "PRIVATE-RELAY-DISCLOSURE-RECEIPTS",
            &self.disclosure_receipts,
        );
        let state_root = domain_hash(
            "PRIVATE-SEQUENCER-MEMPOOL-RELAY-STATE-ROOT",
            &[
                HashPart::Str(&self.relay_label),
                HashPart::Int(self.height as i128),
                HashPart::Str(&config_root),
                HashPart::Str(&operator_root),
                HashPart::Str(&lane_root),
                HashPart::Str(&window_root),
                HashPart::Str(&encrypted_intent_root),
                HashPart::Str(&attestation_root),
                HashPart::Str(&sponsor_account_root),
                HashPart::Str(&sponsor_ticket_root),
                HashPart::Str(&anti_censorship_queue_root),
                HashPart::Str(&operator_record_root),
                HashPart::Str(&disclosure_receipt_root),
            ],
            32,
        );
        PrivateSequencerMempoolRelayRoots {
            config_root,
            operator_root,
            lane_root,
            window_root,
            encrypted_intent_root,
            attestation_root,
            sponsor_account_root,
            sponsor_ticket_root,
            anti_censorship_queue_root,
            operator_record_root,
            disclosure_receipt_root,
            state_root,
        }
    }

    pub fn counters(&self) -> PrivateSequencerMempoolRelayCounters {
        PrivateSequencerMempoolRelayCounters {
            height: self.height,
            operator_count: self.operators.len() as u64,
            active_operator_count: self
                .operators
                .values()
                .filter(|operator| operator.status.can_relay())
                .count() as u64,
            lane_count: self.lanes.len() as u64,
            active_lane_count: self
                .lanes
                .values()
                .filter(|lane| lane.status.admits())
                .count() as u64,
            window_count: self.windows.len() as u64,
            sealed_window_count: self.windows.values().filter(|window| window.sealed).count()
                as u64,
            encrypted_intent_count: self.encrypted_intents.len() as u64,
            open_intent_count: self
                .encrypted_intents
                .values()
                .filter(|intent| intent.status.is_open())
                .count() as u64,
            low_fee_intent_count: self
                .encrypted_intents
                .values()
                .filter(|intent| match self.lanes.get(&intent.lane_id) {
                    Some(lane) => lane.kind.low_fee_eligible(),
                    None => false,
                })
                .count() as u64,
            attestation_count: self.attestations.len() as u64,
            accepted_attestation_count: self
                .attestations
                .values()
                .filter(|attestation| attestation.status.accepted())
                .count() as u64,
            sponsor_account_count: self.sponsor_accounts.len() as u64,
            sponsor_ticket_count: self.sponsor_tickets.len() as u64,
            usable_sponsor_ticket_count: self
                .sponsor_tickets
                .values()
                .filter(|ticket| ticket.status.usable())
                .count() as u64,
            anti_censorship_queue_count: self.anti_censorship_queue.len() as u64,
            forced_queue_count: self
                .anti_censorship_queue
                .values()
                .filter(|item| item.ready_to_force(self.height))
                .count() as u64,
            operator_record_count: self.operator_records.len() as u64,
            disclosure_receipt_count: self.disclosure_receipts.len() as u64,
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn validate(&self) -> PrivateSequencerMempoolRelayResult<String> {
        ensure_non_empty(&self.relay_label, "private sequencer mempool relay label")?;
        self.config.validate()?;
        if self.operators.len() > PRIVATE_SEQUENCER_MEMPOOL_RELAY_MAX_OPERATORS {
            return Err("private relay has too many operators".to_string());
        }
        if self.lanes.len() > PRIVATE_SEQUENCER_MEMPOOL_RELAY_MAX_LANES {
            return Err("private relay has too many lanes".to_string());
        }
        if self.windows.len() > PRIVATE_SEQUENCER_MEMPOOL_RELAY_MAX_WINDOWS {
            return Err("private relay has too many windows".to_string());
        }
        if self.encrypted_intents.len() > PRIVATE_SEQUENCER_MEMPOOL_RELAY_MAX_INTENTS {
            return Err("private relay has too many encrypted intents".to_string());
        }
        if self.attestations.len() > PRIVATE_SEQUENCER_MEMPOOL_RELAY_MAX_ATTESTATIONS {
            return Err("private relay has too many attestations".to_string());
        }
        if self.sponsor_accounts.len() > PRIVATE_SEQUENCER_MEMPOOL_RELAY_MAX_SPONSOR_ACCOUNTS {
            return Err("private relay has too many sponsor accounts".to_string());
        }
        if self.sponsor_tickets.len() > PRIVATE_SEQUENCER_MEMPOOL_RELAY_MAX_SPONSOR_TICKETS {
            return Err("private relay has too many sponsor tickets".to_string());
        }
        if self.anti_censorship_queue.len()
            > PRIVATE_SEQUENCER_MEMPOOL_RELAY_MAX_CENSORSHIP_QUEUE_ITEMS
        {
            return Err("private relay has too many anti censorship queue items".to_string());
        }
        if self.operator_records.len() > PRIVATE_SEQUENCER_MEMPOOL_RELAY_MAX_OPERATOR_RECORDS {
            return Err("private relay has too many operator records".to_string());
        }
        if self.disclosure_receipts.len() > PRIVATE_SEQUENCER_MEMPOOL_RELAY_MAX_DISCLOSURE_RECEIPTS
        {
            return Err("private relay has too many disclosure receipts".to_string());
        }
        for operator in self.operators.values() {
            operator.validate()?;
            for lane_id in &operator.accepted_lane_ids {
                if !self.lanes.contains_key(lane_id) {
                    return Err(
                        "private relay operator references unknown accepted lane".to_string()
                    );
                }
            }
        }
        for lane in self.lanes.values() {
            lane.validate()?;
        }
        for window in self.windows.values() {
            window.validate()?;
            if !self.lanes.contains_key(&window.lane_id) {
                return Err("private relay window references unknown lane".to_string());
            }
        }
        for intent in self.encrypted_intents.values() {
            intent.validate()?;
            if !self.lanes.contains_key(&intent.lane_id) {
                return Err("encrypted intent references unknown lane".to_string());
            }
            if !self.windows.contains_key(&intent.window_id) {
                return Err("encrypted intent references unknown window".to_string());
            }
        }
        for attestation in self.attestations.values() {
            attestation.validate()?;
            if !self.encrypted_intents.contains_key(&attestation.intent_id) {
                return Err("pq relay attestation references unknown intent".to_string());
            }
            if !self.operators.contains_key(&attestation.operator_id) {
                return Err("pq relay attestation references unknown operator".to_string());
            }
        }
        for sponsor in self.sponsor_accounts.values() {
            sponsor.validate()?;
            if !self.operators.contains_key(&sponsor.operator_id) {
                return Err("sponsor account references unknown operator".to_string());
            }
            for lane_id in &sponsor.lane_allowlist {
                if !self.lanes.contains_key(lane_id) {
                    return Err("sponsor account references unknown lane".to_string());
                }
            }
        }
        for ticket in self.sponsor_tickets.values() {
            ticket.validate()?;
            if !self.sponsor_accounts.contains_key(&ticket.sponsor_id) {
                return Err("sponsor ticket references unknown sponsor".to_string());
            }
            if !self.lanes.contains_key(&ticket.lane_id) {
                return Err("sponsor ticket references unknown lane".to_string());
            }
        }
        for item in self.anti_censorship_queue.values() {
            item.validate()?;
            if !self.encrypted_intents.contains_key(&item.intent_id) {
                return Err("anti censorship queue references unknown intent".to_string());
            }
        }
        for record in self.operator_records.values() {
            record.validate()?;
            if !self.operators.contains_key(&record.operator_id) {
                return Err("operator record references unknown operator".to_string());
            }
        }
        for receipt in self.disclosure_receipts.values() {
            receipt.validate()?;
            if !self.operator_records.contains_key(&receipt.record_id) {
                return Err("disclosure receipt references unknown operator record".to_string());
            }
        }
        Ok(self.state_root())
    }
}

pub fn private_sequencer_mempool_relay_config_id(
    config: &PrivateSequencerMempoolRelayConfig,
) -> String {
    domain_hash(
        "PRIVATE-SEQUENCER-MEMPOOL-RELAY-CONFIG-ID",
        &[
            HashPart::Str(&config.protocol_version),
            HashPart::Str(&config.schema_version),
            HashPart::Int(config.epoch_blocks as i128),
            HashPart::Int(config.window_blocks as i128),
            HashPart::Int(config.intent_ttl_blocks as i128),
            HashPart::Int(config.low_fee_cap_micro_units as i128),
            HashPart::Str(&config.intent_encryption_scheme),
            HashPart::Str(&config.pq_attestation_scheme),
            HashPart::Str(&config.commitment_scheme),
        ],
        32,
    )
}

pub fn private_relay_operator_id(
    label: &str,
    role: PrivateRelayOperatorRole,
    region: &str,
    pq_attestation_key_commitment: &str,
) -> String {
    domain_hash(
        "PRIVATE-RELAY-OPERATOR-ID",
        &[
            HashPart::Str(label),
            HashPart::Str(role.as_str()),
            HashPart::Str(region),
            HashPart::Str(pq_attestation_key_commitment),
        ],
        32,
    )
}

pub fn private_relay_lane_id(
    label: &str,
    kind: PrivateRelayLaneKind,
    operator_set_root: &str,
    encryption_key_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-RELAY-LANE-ID",
        &[
            HashPart::Str(label),
            HashPart::Str(kind.as_str()),
            HashPart::Str(operator_set_root),
            HashPart::Str(encryption_key_root),
        ],
        32,
    )
}

pub fn private_relay_window_id(
    lane_id: &str,
    epoch: u64,
    start_height: u64,
    end_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-RELAY-WINDOW-ID",
        &[
            HashPart::Str(lane_id),
            HashPart::Int(epoch as i128),
            HashPart::Int(start_height as i128),
            HashPart::Int(end_height as i128),
        ],
        32,
    )
}

pub fn encrypted_intent_id(
    lane_id: &str,
    window_id: &str,
    nullifier_commitment: &str,
    ciphertext_root: &str,
    submitted_at_height: u64,
) -> String {
    domain_hash(
        "ENCRYPTED-INTENT-ID",
        &[
            HashPart::Str(lane_id),
            HashPart::Str(window_id),
            HashPart::Str(nullifier_commitment),
            HashPart::Str(ciphertext_root),
            HashPart::Int(submitted_at_height as i128),
        ],
        32,
    )
}

pub fn pq_relay_attestation_id(
    intent_id: &str,
    operator_id: &str,
    ciphertext_root: &str,
    transcript_root: &str,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "PQ-RELAY-ATTESTATION-ID",
        &[
            HashPart::Str(intent_id),
            HashPart::Str(operator_id),
            HashPart::Str(ciphertext_root),
            HashPart::Str(transcript_root),
            HashPart::Int(issued_at_height as i128),
        ],
        32,
    )
}

pub fn sponsor_account_id(
    label: &str,
    operator_id: &str,
    asset_id: &str,
    authorization_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-RELAY-SPONSOR-ACCOUNT-ID",
        &[
            HashPart::Str(label),
            HashPart::Str(operator_id),
            HashPart::Str(asset_id),
            HashPart::Str(authorization_root),
        ],
        32,
    )
}

pub fn sponsor_ticket_id(
    sponsor_id: &str,
    lane_id: &str,
    beneficiary_commitment: &str,
    nullifier_commitment: &str,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-RELAY-SPONSOR-TICKET-ID",
        &[
            HashPart::Str(sponsor_id),
            HashPart::Str(lane_id),
            HashPart::Str(beneficiary_commitment),
            HashPart::Str(nullifier_commitment),
            HashPart::Int(issued_at_height as i128),
        ],
        32,
    )
}

pub fn anti_censorship_queue_item_id(
    intent_id: &str,
    lane_id: &str,
    submitter_commitment: &str,
    evidence_root: &str,
    first_seen_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-RELAY-ANTI-CENSORSHIP-QUEUE-ID",
        &[
            HashPart::Str(intent_id),
            HashPart::Str(lane_id),
            HashPart::Str(submitter_commitment),
            HashPart::Str(evidence_root),
            HashPart::Int(first_seen_height as i128),
        ],
        32,
    )
}

pub fn operator_record_id(
    operator_id: &str,
    kind: OperatorRecordKind,
    object_id: &str,
    object_root: &str,
    redaction_root: &str,
    event_height: u64,
) -> String {
    domain_hash(
        "DISCLOSURE-SAFE-OPERATOR-RECORD-ID",
        &[
            HashPart::Str(operator_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(object_id),
            HashPart::Str(object_root),
            HashPart::Str(redaction_root),
            HashPart::Int(event_height as i128),
        ],
        32,
    )
}

pub fn disclosure_receipt_id(
    record_id: &str,
    operator_id: &str,
    disclosed_payload_root: &str,
    verifier_committee_root: &str,
    disclosed_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-RELAY-DISCLOSURE-RECEIPT-ID",
        &[
            HashPart::Str(record_id),
            HashPart::Str(operator_id),
            HashPart::Str(disclosed_payload_root),
            HashPart::Str(verifier_committee_root),
            HashPart::Int(disclosed_at_height as i128),
        ],
        32,
    )
}

fn root_from_map<T>(domain: &str, values: &BTreeMap<String, T>) -> String
where
    T: RootedPublicJson,
{
    let leaves = values
        .values()
        .map(RootedPublicJson::public_json)
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

trait RootedPublicJson {
    fn public_json(&self) -> Value;
}

impl RootedPublicJson for PrivateRelayOperator {
    fn public_json(&self) -> Value {
        self.to_public_json()
    }
}

impl RootedPublicJson for PrivateRelayLane {
    fn public_json(&self) -> Value {
        self.to_public_json()
    }
}

impl RootedPublicJson for RelayWindow {
    fn public_json(&self) -> Value {
        self.to_public_json()
    }
}

impl RootedPublicJson for EncryptedIntentEnvelope {
    fn public_json(&self) -> Value {
        self.to_public_json()
    }
}

impl RootedPublicJson for PqRelayAttestation {
    fn public_json(&self) -> Value {
        self.to_public_json()
    }
}

impl RootedPublicJson for SponsorAccount {
    fn public_json(&self) -> Value {
        self.to_public_json()
    }
}

impl RootedPublicJson for SponsorTicket {
    fn public_json(&self) -> Value {
        self.to_public_json()
    }
}

impl RootedPublicJson for AntiCensorshipQueueItem {
    fn public_json(&self) -> Value {
        self.to_public_json()
    }
}

impl RootedPublicJson for DisclosureSafeOperatorRecord {
    fn public_json(&self) -> Value {
        self.to_public_json()
    }
}

impl RootedPublicJson for DisclosureReceipt {
    fn public_json(&self) -> Value {
        self.to_public_json()
    }
}

fn private_relay_seed_root(label: &str) -> String {
    domain_hash(
        "PRIVATE-RELAY-DEVNET-SEED-ROOT",
        &[HashPart::Str(label)],
        32,
    )
}

fn private_relay_empty_root(label: &str) -> String {
    merkle_root(
        "PRIVATE-RELAY-EMPTY-COMPONENT",
        &[json!({
            "label": label,
            "empty": true,
        })],
    )
}

fn ensure_non_empty(value: &str, label: &str) -> PrivateSequencerMempoolRelayResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(())
}

fn ensure_positive(value: u64, label: &str) -> PrivateSequencerMempoolRelayResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_bps(value: u64, label: &str) -> PrivateSequencerMempoolRelayResult<()> {
    if value > PRIVATE_SEQUENCER_MEMPOOL_RELAY_MAX_BPS {
        return Err(format!("{label} must be <= 10000 bps"));
    }
    Ok(())
}
